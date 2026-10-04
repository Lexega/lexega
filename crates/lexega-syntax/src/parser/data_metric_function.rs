// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Snowflake CREATE DATA METRIC FUNCTION (span-only).
//!
//! Syntax:
//! ```text
//! CREATE [OR REPLACE] [SECURE] DATA METRIC FUNCTION [IF NOT EXISTS]
//!   <name> (<arg> TABLE(<col> <type>) [, ...]) RETURNS NUMBER [[NOT] NULL]
//!   [LANGUAGE SQL] [COMMENT = '<string>'] AS '<expression>'
//! ```
//!
//! `DATA` / `METRIC` lex as Identifiers, `FUNCTION` / `SECURE` as Keywords.
//! The argument list and the string-literal body are captured as spans;
//! DROP DATA METRIC FUNCTION routes through the generic `Drop` path.

use crate::ast::types::AstCreateDataMetricFunction;
use crate::ast::AstStmt;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `CREATE [OR REPLACE] [SECURE] DATA METRIC FUNCTION …`.
    /// Entry expects the cursor at the CREATE token.
    pub(crate) fn try_parse_create_data_metric_function(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_data_metric_function")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;

        // Optional SECURE
        let secure_span = match self.peek_non_trivia() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Secure)) => {
                let tok = self
                    .advance()
                    .expect_invariant("SECURE consumed after peek");
                Some(tok.span)
            }
            _ => None,
        };

        let data_span = self.expect_dmf_identifier("DATA")?;
        let metric_span = self.expect_dmf_identifier("METRIC")?;
        let function_span = self.expect_keyword(Keyword::Function)?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;

        // Argument list `(<arg> TABLE(...))` — balanced-paren span.
        let params_span = match self.peek_non_trivia() {
            Some(tok) if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) => {
                self.consume_balanced_parens()?
            }
            _ => {
                return Err(ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected '(' argument list in CREATE DATA METRIC FUNCTION"
                            .to_string(),
                    },
                ));
            }
        };
        let mut end = params_span.end;

        // Scan the post-argument clauses (RETURNS NUMBER [NOT] NULL,
        // LANGUAGE SQL, COMMENT = '…') up to the AS keyword. Capture the
        // COMMENT value span along the way.
        let mut comment_span: Option<Span> = None;
        let mut saw_as = false;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                let as_tok = self.advance().expect_invariant("AS consumed after peek");
                end = as_tok.span.end;
                saw_as = true;
                break;
            }
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                self.advance()
                    .expect_invariant("COMMENT consumed after peek");
                // optional '='
                if let Some(eq) = self.peek_non_trivia() {
                    if matches!(eq.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                        self.advance().expect_invariant("= consumed after peek");
                    }
                }
                if self.peek_non_trivia().is_some() {
                    let val_tok = self
                        .advance()
                        .expect_invariant("comment value consumed after peek");
                    comment_span = Some(val_tok.span);
                    end = val_tok.span.end;
                }
                continue;
            }
            let t = self
                .advance()
                .expect_invariant("clause token consumed after peek");
            end = t.span.end;
        }

        // Body: everything after AS up to the statement terminator.
        let mut body_span: Option<Span> = None;
        if saw_as {
            let body_start = self.peek_non_trivia().map(|t| t.span.start);
            let mut body_end = end;
            while let Some(tok) = self.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                ) {
                    break;
                }
                let t = self
                    .advance()
                    .expect_invariant("body token consumed after peek");
                body_end = t.span.end;
            }
            if let Some(start) = body_start {
                body_span = Some(Span {
                    start,
                    end: body_end,
                });
                end = body_end;
            }
        }

        let ast = AstCreateDataMetricFunction {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            secure_span,
            data_span,
            metric_span,
            function_span,
            if_not_exists_span,
            name_span,
            params_span,
            comment_span,
            body_span,
        };
        Ok(AstStmt::CreateDataMetricFunction(Box::new(ast)))
    }

    /// Expect an Identifier with the given lexeme (DATA / METRIC).
    fn expect_dmf_identifier(&mut self, expected: &str) -> ParseResult<Span> {
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![expected.to_string()])?;
        if !matches!(tok.kind, TokenKind::Identifier { .. })
            || !tok.lexeme(self.source).eq_ignore_ascii_case(expected)
        {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected {} keyword", expected),
                },
            ));
        }
        Ok(tok.span)
    }
}
