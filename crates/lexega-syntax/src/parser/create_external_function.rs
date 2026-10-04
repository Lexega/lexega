// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Snowflake `CREATE [OR REPLACE] [SECURE] EXTERNAL FUNCTION`.
//!
//! An external function ships row data to an external HTTPS endpoint (the
//! `AS '<url>'` proxy/resource) through an `API_INTEGRATION`. Distinct grammar
//! from a code-bearing UDF (no LANGUAGE/HANDLER/AS-body) — it gets its own
//! statement node. Recognition captures the egress surface: endpoint, API
//! integration, SECURE, and the request/response translators.

use crate::ast::{AstCreateExternalFunction, AstStmt};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `CREATE [OR REPLACE] [SECURE] EXTERNAL FUNCTION <name>(<args>)
    ///   RETURNS <type> [modifiers] API_INTEGRATION = <int>
    ///   [HEADERS = (…)] [CONTEXT_HEADERS = (…)]
    ///   [REQUEST_TRANSLATOR = <udf>] [RESPONSE_TRANSLATOR = <udf>]
    ///   AS '<url>'`. The cursor starts at `CREATE`.
    pub(crate) fn try_parse_create_external_function(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_external_function")?;

        self.parse_create_external_function_inner()
    }

    fn parse_create_external_function_inner(&mut self) -> ParseResult<AstStmt> {
        let create_kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_kw.span.start;

        // OR REPLACE
        let or_replace_span = self.parse_optional_or_replace()?;

        // SECURE (lexes as the reserved keyword `Secure`)
        let secure_span = self.consume_keyword_ident("SECURE");

        // EXTERNAL (lexes as an identifier) — gated by the caller, consume it.
        let _ = self.consume_keyword_ident("EXTERNAL");

        // FUNCTION keyword
        let func_kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FUNCTION".to_string()])?;
        if !matches!(
            func_kw.kind,
            TokenKind::Keyword(crate::lexer::Keyword::Function)
        ) {
            return Err(ParseError::new(
                func_kw.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected FUNCTION in CREATE EXTERNAL FUNCTION".to_string(),
                },
            ));
        }

        // Function name (possibly qualified) — reuse the canonical helper.
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Parameter list `( … )` — consumed as a depth-balanced run (params are
        // not governance-bearing; the statement span covers them).
        if let Some(sp) = self.consume_paren_group_span() {
            end = sp.end;
        }

        // RETURNS <type> — consume the type up to the first modifier/clause
        // starter or AS.
        let mut api_integration_span: Option<Span> = None;
        let mut endpoint_url_span: Option<Span> = None;
        let mut headers_span: Option<Span> = None;
        let mut context_headers_span: Option<Span> = None;
        let mut request_translator_span: Option<Span> = None;
        let mut response_translator_span: Option<Span> = None;

        // Clause/modifier walk: everything from after the function name to the
        // statement terminator. Recognized governance clauses are captured;
        // type tokens and null-input/volatility modifiers are consumed.
        loop {
            self.skip_trivia();
            let Some(tok) = self.peek_non_trivia() else {
                break;
            };
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let lexeme = tok.lexeme(self.source).to_string();

            // `AS '<url>'` — the egress endpoint; terminal clause.
            if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::As)) {
                let as_kw = self.advance().expect_invariant("AS consumed after peek");
                end = as_kw.span.end;
                self.skip_trivia();
                if let Some(url_tok) = self.peek_non_trivia() {
                    if matches!(
                        url_tok.kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::String)
                    ) {
                        let sp = url_tok.span;
                        endpoint_url_span = Some(sp);
                        end = sp.end;
                        self.advance()
                            .expect_invariant("endpoint URL consumed after peek");
                    }
                }
                continue;
            }

            // `<KEY> = <value>` governance clauses. The cursor is at the key
            // (after skip_trivia), so the token after it is `peek_ahead(1)`.
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let next_is_eq = matches!(
                    self.peek_ahead(1),
                    Some(t) if matches!(t.kind, TokenKind::Operator(Operator::Eq))
                );
                {
                    if next_is_eq {
                        if lexeme.eq_ignore_ascii_case("HEADERS") {
                            let _ = self.advance(); // key
                            self.consume_eq();
                            if let Some(g) = self.consume_paren_group_span() {
                                headers_span = Some(g);
                                end = g.end;
                            }
                            continue;
                        }
                        if lexeme.eq_ignore_ascii_case("CONTEXT_HEADERS") {
                            let _ = self.advance();
                            self.consume_eq();
                            if let Some(g) = self.consume_paren_group_span() {
                                context_headers_span = Some(g);
                                end = g.end;
                            }
                            continue;
                        }
                        // Single-value clauses.
                        let target: Option<&mut Option<Span>> =
                            if lexeme.eq_ignore_ascii_case("API_INTEGRATION") {
                                Some(&mut api_integration_span)
                            } else if lexeme.eq_ignore_ascii_case("REQUEST_TRANSLATOR") {
                                Some(&mut request_translator_span)
                            } else if lexeme.eq_ignore_ascii_case("RESPONSE_TRANSLATOR") {
                                Some(&mut response_translator_span)
                            } else {
                                None
                            };
                        let _ = self.advance(); // key
                        self.consume_eq();
                        if let Some(value_span) = self.consume_qualified_value_span() {
                            end = value_span.end;
                            if let Some(slot) = target {
                                *slot = Some(value_span);
                            }
                        }
                        continue;
                    }
                }
            }

            // Any other token (return type, NOT NULL, CALLED ON NULL INPUT,
            // VOLATILE/IMMUTABLE, COMMENT = '…', MAX_BATCH_ROWS = n,
            // COMPRESSION = …): consume it. Value-bearing low-governance
            // clauses fold through naturally — their `=` and value are consumed
            // as ordinary tokens on subsequent iterations.
            let consumed = self.advance().expect_invariant("clause token consumed");
            end = consumed.span.end;
        }

        let ast = AstCreateExternalFunction {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            secure_span,
            name_span,
            api_integration_span,
            endpoint_url_span,
            headers_span,
            context_headers_span,
            request_translator_span,
            response_translator_span,
        };
        Ok(AstStmt::CreateExternalFunction(Box::new(ast)))
    }

    /// Consume a token whose lexeme matches `kw` (case-insensitive),
    /// returning its span. Matches whether the lexer emitted the word as an
    /// `Identifier` (`EXTERNAL`) or a reserved `Keyword` (`SECURE`).
    fn consume_keyword_ident(&mut self, kw: &str) -> Option<Span> {
        let matches = matches!(
            self.peek_non_trivia(),
            Some(tok)
                if matches!(tok.kind, TokenKind::Identifier { .. } | TokenKind::Keyword(_))
                    && tok.lexeme(self.source).eq_ignore_ascii_case(kw)
        );
        if matches {
            let tok = self
                .advance()
                .expect_invariant("keyword-ident consumed after peek");
            Some(tok.span)
        } else {
            None
        }
    }

    /// Consume a balanced `( … )` group starting at the current position,
    /// returning its covering span. `None` when the next token is not `(`.
    fn consume_paren_group_span(&mut self) -> Option<Span> {
        let is_lparen = matches!(
            self.peek_non_trivia(),
            Some(tok) if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen))
        );
        if !is_lparen {
            return None;
        }
        let lp = self.advance().expect_invariant("( consumed after peek");
        let start = lp.span.start;
        let mut end = lp.span.end;
        let mut depth = 1usize;
        while depth > 0 {
            let Some(tok) = self.advance() else { break };
            end = tok.span.end;
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth -= 1;
            } else if matches!(tok.kind, TokenKind::Eof) {
                break;
            }
        }
        Some(Span { start, end })
    }

    /// Consume an `=` operator if present at the cursor.
    fn consume_eq(&mut self) {
        if matches!(
            self.peek_non_trivia(),
            Some(tok) if matches!(tok.kind, TokenKind::Operator(Operator::Eq))
        ) {
            self.advance().expect_invariant("= consumed after peek");
        }
    }

    /// Consume a value as a (possibly dotted) qualified name or single literal,
    /// returning its covering span. Used for `API_INTEGRATION = <name>` and
    /// translator UDF names.
    fn consume_qualified_value_span(&mut self) -> Option<Span> {
        self.skip_trivia();
        let first = self.advance()?;
        let start = first.span.start;
        let mut end = first.span.end;
        loop {
            let is_dot = matches!(
                self.peek_non_trivia(),
                Some(tok) if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot))
            );
            if !is_dot {
                break;
            }
            self.advance().expect_invariant(". consumed after peek");
            let Some(part) = self.advance() else { break };
            end = part.span.end;
        }
        Some(Span { start, end })
    }
}
