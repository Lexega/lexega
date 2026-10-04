// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the MySQL `RENAME TABLE` statement.
//!
//! `RENAME TABLE tbl_name TO new_tbl_name [, tbl_name2 TO new_tbl_name2] ...`
//!
//! Renames one or more tables atomically. Each `<from> TO <to>` pair is
//! parsed into a typed [`AstRenameTablePair`] (names may be schema-qualified)
//! so consumers see every pair, not just the first. Dispatched
//! from the `RENAME` arm in `core.rs` when `is_rename_table_at` sees a
//! statement-leading `RENAME TABLE`.

use crate::ast::types::{AstMysqlRenameTable, AstRenameTablePair, AstStmt};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Disambiguation guard: a statement-leading `RENAME` is this statement only
/// when the next significant token is `TABLE`. Scans from `idx` (the RENAME
/// position).
pub(crate) fn is_rename_table_at(tokens: &[Token], idx: usize) -> bool {
    let mut i = idx + 1;
    while i < tokens.len() {
        match tokens[i].kind {
            TokenKind::LineComment | TokenKind::BlockComment => {
                i += 1;
                continue;
            }
            TokenKind::Keyword(Keyword::Table) => return true,
            _ => return false,
        }
    }
    false
}

impl Parser<'_> {
    pub(crate) fn try_parse_mysql_rename_table(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mysql_rename_table")?;

        let rename_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["RENAME".to_string()])?;
        let rename_span = rename_tok.span;

        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
        if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
            return Err(ParseError::new(
                table_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLE after RENAME".to_string(),
                },
            ));
        }
        let table_span = table_tok.span;

        let mut pairs = Vec::new();
        loop {
            let from_name_span = self.parse_qualified_name_span()?;

            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected TO after table name in RENAME TABLE".to_string(),
                    },
                ));
            }
            let to_span = to_tok.span;

            let to_name_span = self.parse_qualified_name_span()?;

            pairs.push(AstRenameTablePair {
                node_id: self.id_gen.next(),
                span: Span {
                    start: from_name_span.start,
                    end: to_name_span.end,
                },
                from_name_span,
                to_span,
                to_name_span,
            });

            match self.peek_non_trivia() {
                Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)) => {
                    self.advance().expect_invariant("comma consumed after peek");
                    continue;
                }
                _ => break,
            }
        }

        let end = pairs.last().map(|p| p.span.end).unwrap_or(table_span.end);
        let stmt = AstMysqlRenameTable {
            node_id: self.id_gen.next(),
            span: Span {
                start: rename_span.start,
                end,
            },
            rename_span,
            table_span,
            pairs,
        };
        Ok(AstStmt::MysqlRenameTable(Box::new(stmt)))
    }
}
