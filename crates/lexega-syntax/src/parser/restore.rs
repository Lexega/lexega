// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL `RESTORE { DATABASE | LOG }` statement.
//!
//! `RESTORE { DATABASE | LOG } <name> FROM { DISK | URL | TAPE } = '...'
//!  [, ...] [WITH <options>]`
//!
//! Counterpart of [`crate::parser::backup`]. Recognition needs what is
//! restored (database vs log), the source device class, and whether
//! `WITH REPLACE` is present. The source literal is intentionally never
//! surfaced — restore URLs commonly embed SAS credentials.
//!
//! Dispatch disambiguates this from the Databricks time-travel
//! `RESTORE [TABLE] <name> TO {TIMESTAMP|VERSION} AS OF` via
//! `is_mssql_restore_at` (the next significant token is `DATABASE`/`LOG`).
//!
//! Token reference (`--debug-tokens`, mssql dialect):
//!   RESTORE / DATABASE / LOG / DISK / TAPE → Identifier (not Keyword!)
//!   FROM / URL / WITH / REPLACE            → Keyword

use crate::ast::types::{AstMssqlRestore, AstMssqlRestoreSource, AstMssqlRestoreTarget, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Disambiguation guard: a statement-leading `RESTORE` identifier introduces a
/// T-SQL RESTORE statement only when the next significant token is `DATABASE`
/// or `LOG` (both Identifiers in our lexer). Otherwise it is the Databricks
/// time-travel `RESTORE [TABLE] … TO {TIMESTAMP|VERSION}` form.
pub(crate) fn is_mssql_restore_at(tokens: &[Token], idx: usize, source: &str) -> bool {
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
    pub(crate) fn try_parse_mssql_restore_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("restore_db")?;
        let start_span = self.current_span();

        // 1. RESTORE keyword (Identifier in our lexer).
        let restore_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["RESTORE".to_string()])?;
        let restore_keyword_span = restore_tok.span;
        let start = restore_tok.span.start;

        // 2. Target: DATABASE | LOG. The dispatch guard guarantees one of these.
        let target_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["DATABASE".to_string(), "LOG".to_string()],
        )?;
        let target_lex = target_tok.lexeme(self.source);
        let target_span = target_tok.span;
        let target = if target_lex.eq_ignore_ascii_case("DATABASE") {
            AstMssqlRestoreTarget::Database
        } else if target_lex.eq_ignore_ascii_case("LOG") {
            AstMssqlRestoreTarget::Log
        } else {
            let msg = format!(
                "Unsupported RESTORE form 'RESTORE {target_lex}' (expected DATABASE or LOG)"
            );
            return Err(ParseError::new(
                target_span,
                ParseErrorKind::InvalidStatement { message: msg },
            ));
        };

        // 3. Object name (possibly qualified).
        let name_span = self.parse_qualified_name_span()?;

        // 4. A bare `RESTORE DATABASE <name> [WITH ...]` (no FROM) is valid —
        //    recovery-only / bringing a database online. Stop scanning for a
        //    source at WITH or statement end; otherwise skip up to FROM.
        let mut has_from = false;
        loop {
            let tok = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Unexpected end of RESTORE statement".to_string(),
                    },
                )
            })?;
            if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
                has_from = true;
                break;
            }
            if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::With)
                    | TokenKind::Punctuation(Punctuation::Semi)
                    | TokenKind::Eof
            ) {
                break;
            }
            self.advance()
                .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;
        }

        // 5. Source device class (only when a FROM clause is present; the
        //    recovery-only form names no source device).
        let mut source = None;
        let mut end = name_span.end;
        if has_from {
            self.advance()
                .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;
            let src_tok = self.advance().ok_or_eof(
                self.current_span(),
                vec!["DISK".to_string(), "URL".to_string(), "TAPE".to_string()],
            )?;
            let src_span = src_tok.span;
            let kind = if matches!(src_tok.kind, TokenKind::Keyword(Keyword::Url)) {
                AstMssqlRestoreSource::Url
            } else {
                let lex = src_tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("DISK") {
                    AstMssqlRestoreSource::Disk
                } else if lex.eq_ignore_ascii_case("TAPE") {
                    AstMssqlRestoreSource::Tape
                } else {
                    let msg =
                        format!("Unsupported RESTORE source '{lex}' (expected DISK, URL or TAPE)");
                    return Err(ParseError::new(
                        src_span,
                        ParseErrorKind::InvalidStatement { message: msg },
                    ));
                }
            };
            source = Some(kind);
            end = src_span.end;
        }

        // 6. Consume the remainder of the statement (`= '<device>'`, additional
        //    comma sources, WITH <options>) up to a depth-0 semicolon or EOF,
        //    recording whether WITH REPLACE is present.
        let mut replace = false;
        let mut depth: u32 = 0;
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                TokenKind::Keyword(Keyword::Replace) => replace = true,
                _ => {}
            }
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec![";".to_string()])?;
            end = t.span.end;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlRestore {
            node_id: self.id_gen.next(),
            span: stmt_span,
            restore_keyword_span,
            target,
            name_span,
            source,
            replace,
        };
        Ok(AstStmt::MssqlRestore(Box::new(ast)))
    }
}
