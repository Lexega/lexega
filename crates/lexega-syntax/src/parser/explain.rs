// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for PostgreSQL EXPLAIN statement.
//!
//! Handles all forms:
//! - `EXPLAIN <stmt>`
//! - `EXPLAIN ANALYZE <stmt>`
//! - `EXPLAIN (option [, ...]) <stmt>`
//!
//! Options can be bare names (`ANALYZE, COSTS`) or key-value (`ANALYZE true, BUFFERS false`).
//! The inner statement must be SELECT, INSERT, UPDATE, DELETE, or MERGE.

use crate::ast::types::{AstExplain, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult};
use crate::lexer::{Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse an EXPLAIN statement.
    ///
    /// Called when the current token is an Identifier with lexeme "EXPLAIN".
    ///
    /// Grammar:
    /// ```text
    /// EXPLAIN [ANALYZE] <stmt>
    /// EXPLAIN ( option [, option ...] ) <stmt>
    ///
    /// option := name [boolean_value]
    /// ```
    pub(crate) fn try_parse_explain_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("explain")?;

        // Consume EXPLAIN
        let explain_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected EXPLAIN keyword".to_string(),
                },
            )
        })?;
        let explain_span = explain_tok.span;

        // Determine options form
        let options_span = self.parse_explain_options()?;

        // Parse the inner statement (SELECT, INSERT, UPDATE, DELETE, MERGE)
        let inner_stmt = self.parse_explain_inner_stmt()?;

        let stmt_end = inner_stmt.span().end;
        let span = Span {
            start: explain_span.start,
            end: stmt_end,
        };

        let node_id = self.id_gen.next();

        let ast = AstExplain {
            node_id,
            span,
            explain_span,
            options_span,
            inner_stmt: Box::new(inner_stmt),
        };
        Ok(AstStmt::Explain(Box::new(ast)))
    }

    /// Parse EXPLAIN options: either bare `ANALYZE` or parenthesized `(ANALYZE, COSTS, ...)`.
    /// Returns the span covering the options, or None if no options present.
    fn parse_explain_options(&mut self) -> ParseResult<Option<Span>> {
        let next = match self.peek_non_trivia() {
            Some(tok) => tok,
            None => return Ok(None),
        };

        match next.kind {
            // Parenthesized options: EXPLAIN (ANALYZE, COSTS, VERBOSE, FORMAT JSON) ...
            TokenKind::Punctuation(Punctuation::LParen) => {
                let lparen = self.advance().unwrap();
                let start = lparen.span.start;

                // Consume everything up to and including the closing RParen.
                // Options are identifier/keyword tokens separated by commas,
                // optionally followed by boolean literals or identifier values.
                // We don't need to semantically interpret them — just capture the span.
                let mut depth: u32 = 1;
                let mut last_end = lparen.span.end;

                while depth > 0 {
                    let tok = self.advance().ok_or_else(|| {
                        ParseError::new(
                            Span {
                                start,
                                end: last_end,
                            },
                            ParseErrorKind::InvalidStatement {
                                message: "Unterminated EXPLAIN options list — missing ')'"
                                    .to_string(),
                            },
                        )
                    })?;
                    last_end = tok.span.end;
                    match tok.kind {
                        TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                        _ => {}
                    }
                }

                Ok(Some(Span {
                    start,
                    end: last_end,
                }))
            }

            // Bare ANALYZE: EXPLAIN ANALYZE SELECT ...
            TokenKind::Identifier { .. }
                if next.lexeme(self.source).eq_ignore_ascii_case("ANALYZE")
                    || next.lexeme(self.source).eq_ignore_ascii_case("ANALYSE") =>
            {
                // Only treat as option if the NEXT token after ANALYZE is a statement keyword,
                // not another identifier (which would mean ANALYZE is being used as a table name).
                let saved_idx = self.idx;
                let analyze_tok = self.advance().unwrap();

                if let Some(following) = self.peek_non_trivia() {
                    if self.is_explain_inner_stmt_start(following) {
                        // ANALYZE is an option
                        return Ok(Some(analyze_tok.span));
                    }
                }
                // Not an option — restore and let inner stmt parse handle it
                self.idx = saved_idx;
                Ok(None)
            }

            _ => Ok(None),
        }
    }

    /// Check if a token can start an inner statement for EXPLAIN.
    fn is_explain_inner_stmt_start(&self, tok: &crate::lexer::Token) -> bool {
        use crate::lexer::Keyword;
        matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Select)
                | TokenKind::Keyword(Keyword::Insert)
                | TokenKind::Keyword(Keyword::Update)
                | TokenKind::Keyword(Keyword::Delete)
                | TokenKind::Keyword(Keyword::Merge)
                | TokenKind::Keyword(Keyword::With)
                | TokenKind::Keyword(Keyword::Create)
                | TokenKind::Keyword(Keyword::Values)
        )
    }

    /// Parse the inner statement of EXPLAIN.
    fn parse_explain_inner_stmt(&mut self) -> ParseResult<AstStmt> {
        let next = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected a statement after EXPLAIN".to_string(),
                },
            )
        })?;

        if !self.is_explain_inner_stmt_start(next) {
            return Err(ParseError::new(
                next.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected SELECT, INSERT, UPDATE, DELETE, or MERGE after EXPLAIN, found '{}'",
                        next.lexeme(self.source)
                    ),
                },
            ));
        }

        // Delegate to the main statement parser — it will parse SELECT/INSERT/etc.
        self.parse_flow_statement()
    }
}
