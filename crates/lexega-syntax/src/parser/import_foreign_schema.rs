// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the SQL/MED `IMPORT FOREIGN SCHEMA` statement (PostgreSQL FDW).
//!
//! `IMPORT FOREIGN SCHEMA remote_schema
//!    [ { LIMIT TO | EXCEPT } ( table [, …] ) ]
//!    FROM SERVER server INTO local_schema [ OPTIONS ( … ) ]`
//!
//! Bulk-exposes a remote schema's tables locally in a single statement — the
//! bulk sibling of `CREATE FOREIGN TABLE`. Recognition lifts the remote schema,
//! the foreign server, the local schema, and the table-selection filter mode
//! (`All` / `LimitTo` / `Except`), which determines how much of the remote
//! surface is exposed. The named table list itself is not surfaced.
//!
//! Dispatched from the leading-`IMPORT` arm in `core.rs`, gated on the
//! structural `FOREIGN SCHEMA` lookahead (`is_import_foreign_schema_at`) so a
//! stray `IMPORT` identifier is not hijacked.
//!
//! Token reference (`--debug-tokens`, postgresql dialect):
//!   IMPORT / SCHEMA / SERVER / OPTIONS → Identifier (not keywords)
//!   FOREIGN / FROM / INTO / LIMIT / TO / EXCEPT → Keyword

use crate::ast::types::{AstImportFilterMode, AstImportForeignSchema, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Structural lookahead: `IMPORT` followed by `FOREIGN` (keyword) then an
/// identifier `SCHEMA`. Dialect-neutral — `IMPORT FOREIGN SCHEMA` is
/// unambiguous regardless of dialect.
pub(crate) fn is_import_foreign_schema_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    // Collect the next 3 significant tokens (skip comments / EOF), starting at
    // the leading IMPORT (idx).
    let mut sig = Vec::with_capacity(3);
    for t in &tokens[idx..] {
        if matches!(
            t.kind,
            TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
        ) {
            continue;
        }
        sig.push(t);
        if sig.len() == 3 {
            break;
        }
    }
    if sig.len() < 3 {
        return false;
    }
    sig[0].lexeme(source).eq_ignore_ascii_case("IMPORT")
        && matches!(sig[1].kind, TokenKind::Keyword(Keyword::Foreign))
        && sig[2].lexeme(source).eq_ignore_ascii_case("SCHEMA")
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_import_foreign_schema(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("import_foreign_schema")?;
        let result = (|| {
            // 1. IMPORT FOREIGN SCHEMA. The dispatch guard guarantees all three.
            let import_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["IMPORT".to_string()])?;
            let import_span = import_tok.span;
            let start = import_span.start;
            self.advance()
                .ok_or_eof(self.current_span(), vec!["FOREIGN".to_string()])?;
            self.advance()
                .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;

            // 2. Remote schema name.
            let remote_schema_span = self.parse_qualified_name_span()?;

            // 3. Optional { LIMIT TO | EXCEPT } ( table [, …] ). Read the marker
            //    as a Copy discriminant first so the peek borrow ends before the
            //    mutating arms (TokenKind is not Copy).
            let is_limit = matches!(
                self.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::Limit))
            );
            let is_except = matches!(
                self.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::Except))
            );
            let filter_mode = if is_limit {
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["LIMIT".to_string()])?;
                let to = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                if !matches!(to.kind, TokenKind::Keyword(Keyword::To)) {
                    return Err(ParseError::new(
                        to.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TO after LIMIT in IMPORT FOREIGN SCHEMA".to_string(),
                        },
                    ));
                }
                self.expect_balanced_parens()?;
                AstImportFilterMode::LimitTo
            } else if is_except {
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["EXCEPT".to_string()])?;
                self.expect_balanced_parens()?;
                AstImportFilterMode::Except
            } else {
                AstImportFilterMode::All
            };

            // 4. FROM SERVER server.
            let from = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;
            if !matches!(from.kind, TokenKind::Keyword(Keyword::From)) {
                return Err(ParseError::new(
                    from.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected FROM in IMPORT FOREIGN SCHEMA".to_string(),
                    },
                ));
            }
            let server_kw = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["SERVER".to_string()])?;
            if !server_kw.lexeme(self.source).eq_ignore_ascii_case("SERVER") {
                return Err(ParseError::new(
                    server_kw.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected SERVER after FROM in IMPORT FOREIGN SCHEMA".to_string(),
                    },
                ));
            }
            let server_span = self.parse_qualified_name_span()?;

            // 5. INTO local_schema.
            let into = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["INTO".to_string()])?;
            if !matches!(into.kind, TokenKind::Keyword(Keyword::Into)) {
                return Err(ParseError::new(
                    into.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected INTO in IMPORT FOREIGN SCHEMA".to_string(),
                    },
                ));
            }
            let local_schema_span = self.parse_qualified_name_span()?;
            let mut end = local_schema_span.end;

            // 6. Optional OPTIONS ( … ).
            let mut options_present = false;
            if self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("OPTIONS"))
                .unwrap_or(false)
            {
                options_present = true;
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["OPTIONS".to_string()])?;
                end = self.expect_balanced_parens()?.end;
            }

            Ok(AstStmt::ImportForeignSchema(Box::new(
                AstImportForeignSchema {
                    node_id: self.id_gen.next(),
                    span: Span { start, end },
                    import_span,
                    remote_schema_span,
                    server_span,
                    local_schema_span,
                    filter_mode,
                    options_present,
                },
            )))
        })();
        result
    }

    /// Verify the next token is `(`, then consume the balanced group via the
    /// shared [`Parser::consume_balanced_parens`]. Errors if it is not `(`.
    fn expect_balanced_parens(&mut self) -> ParseResult<Span> {
        let is_lparen = self
            .peek_non_trivia()
            .map(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)))
            .unwrap_or(false);
        if !is_lparen {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected ( in IMPORT FOREIGN SCHEMA".to_string(),
                },
            ));
        }
        self.consume_balanced_parens()
    }
}
