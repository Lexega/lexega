// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL `BACKUP { DATABASE | LOG }` statement.
//!
//! `BACKUP { DATABASE | LOG } <name> [<file_or_filegroup_list>]
//!  TO { DISK | URL | TAPE } = '...' [, ...] [MIRROR TO ...] [WITH <options>]`
//!
//! Recognition captures the three things downstream analysis needs: what
//! is backed up (database vs log), the destination device class, and whether
//! the backup is encrypted. The device literal is intentionally never
//! surfaced — backup URLs commonly embed SAS credentials.
//!
//! Token reference (`--debug-tokens`, mssql dialect):
//!   BACKUP / DATABASE / LOG / DISK / TAPE → Identifier (not Keyword!)
//!   URL / TO / WITH / ENCRYPTION          → Keyword

use crate::ast::types::{AstMssqlBackup, AstMssqlBackupDestination, AstMssqlBackupTarget, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Disambiguation guard: a statement-leading `BACKUP` identifier introduces a
/// T-SQL BACKUP statement only when the next significant token is `DATABASE`
/// or `LOG` (both Identifiers in our lexer). Keeps a stray `BACKUP` identifier
/// from being hijacked without a dialect branch in the dispatcher.
pub(crate) fn is_mssql_backup_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    let mut i = idx + 1;
    while i < tokens.len() {
        let kind = &tokens[i].kind;
        if matches!(
            kind,
            TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
        ) {
            i += 1;
            continue;
        }
        let lex = tokens[i].lexeme(source);
        return lex.eq_ignore_ascii_case("DATABASE") || lex.eq_ignore_ascii_case("LOG");
    }
    false
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_backup_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("backup")?;
        let start_span = self.current_span();

        // 1. BACKUP keyword (Identifier in our lexer).
        let backup_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["BACKUP".to_string()])?;
        let backup_keyword_span = backup_tok.span;
        let start = backup_tok.span.start;

        // 2. Target: DATABASE | LOG. Any other form (CERTIFICATE / MASTER KEY /
        //    SERVICE MASTER KEY) has a different grammar — error so it degrades
        //    to OpaqueContent rather than being mis-parsed.
        let target_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["DATABASE".to_string(), "LOG".to_string()],
        )?;
        let target_lex = target_tok.lexeme(self.source);
        let target_span = target_tok.span;
        let target = if target_lex.eq_ignore_ascii_case("DATABASE") {
            AstMssqlBackupTarget::Database
        } else if target_lex.eq_ignore_ascii_case("LOG") {
            AstMssqlBackupTarget::Log
        } else {
            let msg =
                format!("Unsupported BACKUP form 'BACKUP {target_lex}' (expected DATABASE or LOG)");
            return Err(ParseError::new(
                target_span,
                ParseErrorKind::InvalidStatement { message: msg },
            ));
        };

        // 3. Object name (possibly qualified).
        let name_span = self.parse_qualified_name_span()?;

        // 4. Skip any FILE / FILEGROUP / READ_WRITE_FILEGROUPS clause up to TO.
        loop {
            let tok = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected TO in BACKUP statement".to_string(),
                    },
                )
            })?;
            if matches!(tok.kind, TokenKind::Keyword(Keyword::To)) {
                break;
            }
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                let span = tok.span;
                return Err(ParseError::new(
                    span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected TO in BACKUP statement".to_string(),
                    },
                ));
            }
            self.advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
        }

        // 5. TO keyword.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;

        // 6. Destination device class. DISK / TAPE are Identifiers; URL a Keyword.
        let dest_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["DISK".to_string(), "URL".to_string(), "TAPE".to_string()],
        )?;
        let dest_span = dest_tok.span;
        let destination = if matches!(dest_tok.kind, TokenKind::Keyword(Keyword::Url)) {
            AstMssqlBackupDestination::Url
        } else {
            let lex = dest_tok.lexeme(self.source);
            if lex.eq_ignore_ascii_case("DISK") {
                AstMssqlBackupDestination::Disk
            } else if lex.eq_ignore_ascii_case("TAPE") {
                AstMssqlBackupDestination::Tape
            } else {
                let msg =
                    format!("Unsupported BACKUP destination '{lex}' (expected DISK, URL or TAPE)");
                return Err(ParseError::new(
                    dest_span,
                    ParseErrorKind::InvalidStatement { message: msg },
                ));
            }
        };
        let mut end = dest_span.end;

        // 7. Consume the remainder of the statement (`= '<device>'`, additional
        //    comma destinations, MIRROR TO, WITH <options>) up to a depth-0
        //    semicolon or EOF, recording whether WITH ENCRYPTION is present.
        let mut encryption = false;
        let mut depth: u32 = 0;
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                TokenKind::Keyword(Keyword::Encryption) => encryption = true,
                _ => {}
            }
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec![";".to_string()])?;
            end = t.span.end;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlBackup {
            node_id: self.id_gen.next(),
            span: stmt_span,
            backup_keyword_span,
            target,
            name_span,
            destination,
            encryption,
        };
        Ok(AstStmt::MssqlBackup(Box::new(ast)))
    }
}
