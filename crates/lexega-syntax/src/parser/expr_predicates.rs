// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Compound predicate parsing (IS, IN, BETWEEN, LIKE).
//!
//! Handles complex predicates that follow a left-hand expression:
//! - `expr IS [NOT] NULL`
//! - `expr IS [NOT] DISTINCT FROM expr`
//! - `expr [NOT] IN (values)` or `expr [NOT] IN (SELECT ...)`
//! - `expr [NOT] BETWEEN low AND high`
//! - `expr [NOT] LIKE pattern [ESCAPE char]`
//! - `expr [NOT] ILIKE pattern`
//! - `expr [NOT] RLIKE pattern`
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/operators>

use crate::ast::AstExpr;
use crate::error::{ParseError, ParseResult};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;

/// Parsed LIKE/SIMILAR TO escape clause (native `ESCAPE <expr>` or the ODBC
/// form `{escape <expr>}`).
pub(crate) struct ParsedEscapeClause {
    pub(crate) expr: Box<AstExpr>,
    /// `Some` for the ODBC form; covers `{`..`}` for verbatim re-emission.
    pub(crate) odbc_span: Option<Span>,
}

impl<'a> Parser<'a> {
    /// Parse an optional escape clause after a LIKE/SIMILAR TO pattern:
    /// `ESCAPE <expr>` or the ODBC escape form `{escape <expr>}`. Returns
    /// `Ok(None)` with the parser position unchanged when neither follows.
    pub(crate) fn parse_optional_escape_clause(
        &mut self,
    ) -> ParseResult<Option<ParsedEscapeClause>> {
        // Native form: ESCAPE <expr>
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Escape)) {
                let _ = self.advance();
                let escape_expr = self.parse_add_expr_in_mode()?;
                return Ok(Some(ParsedEscapeClause {
                    expr: Box::new(escape_expr),
                    odbc_span: None,
                }));
            }
        }

        // ODBC form: probe for `{` immediately followed by the ESCAPE keyword.
        let is_odbc = if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LCurly)
            ) {
                let save_idx = self.idx;
                let _ = self.advance();
                let hit = matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::Keyword(Keyword::Escape))
                );
                self.idx = save_idx;
                hit
            } else {
                false
            }
        } else {
            false
        };
        if !is_odbc {
            return Ok(None);
        }

        let lcurly = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["{".to_string()])
        })?;
        let _escape_kw = self.advance(); // ESCAPE keyword, validated by probe
        self.odbc_depth += 1;
        let escape_result = self.parse_add_expr_in_mode();
        self.odbc_depth -= 1;
        let escape_expr = escape_result?;
        let rcurly_span = self.expect_odbc_rcurly()?;
        Ok(Some(ParsedEscapeClause {
            expr: Box::new(escape_expr),
            odbc_span: Some(Span {
                start: lcurly.span.start,
                end: rcurly_span.end,
            }),
        }))
    }
    /// Parse a compound predicate (IS, IN, BETWEEN, LIKE) with a pre-parsed left-hand side.
    /// This is called from parse_expr_bp when it encounters these predicates.
    pub(crate) fn parse_cmp_predicate_with_lhs(&mut self, expr: AstExpr) -> ParseResult<AstExpr> {
        let tok = match self.peek() {
            Some(t) => t.clone(),
            None => return Ok(expr),
        };

        // IS [NOT] NULL or IS [NOT] DISTINCT FROM predicate
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Is)) {
            let is_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["IS".to_string()])
            })?;

            // Check for optional NOT
            let mut not_span: Option<Span> = None;
            if let Some(next) = self.peek() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Not)) {
                    let not_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["NOT".to_string()])
                    })?;
                    not_span = Some(not_tok.span);
                }
            }

            // Check what follows: NULL or DISTINCT
            let next = self.peek();
            if let Some(n) = next {
                if matches!(
                    n.kind,
                    TokenKind::Keyword(Keyword::Null)
                        | TokenKind::Literal(crate::lexer::LiteralKind::Null)
                ) {
                    // IS [NOT] NULL
                    let null_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["NULL".to_string()])
                    })?;

                    let span = Span {
                        start: crate::parser::scripting::expr_span_start(&expr),
                        end: null_tok.span.end,
                    };

                    return Ok(AstExpr::IsNull {
                        node_id: self.id_gen.next(),
                        expr: Box::new(expr),
                        is_span: is_tok.span,
                        not_span,
                        null_span: null_tok.span,
                        span,
                    });
                } else if matches!(n.kind, TokenKind::Keyword(Keyword::Distinct)) {
                    // IS [NOT] DISTINCT FROM <expr>
                    let distinct_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["DISTINCT".to_string()],
                        )
                    })?;

                    // Expect FROM keyword
                    let from_tok = match self.peek() {
                        Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::From)) => {
                            self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["FROM".to_string()],
                                )
                            })?
                        }
                        _ => {
                            return Err(ParseError::new(
                                self.current_span(),
                                crate::error::ParseErrorKind::InvalidSyntax {
                                    message: "Expected FROM after IS [NOT] DISTINCT".to_string(),
                                },
                            ));
                        }
                    };

                    // Parse the right-hand expression
                    let right_expr = self.parse_cmp_expr_in_mode()?;

                    let span = Span {
                        start: crate::parser::scripting::expr_span_start(&expr),
                        end: right_expr.span().end,
                    };

                    return Ok(AstExpr::IsDistinctFrom {
                        node_id: self.id_gen.next(),
                        left: Box::new(expr),
                        right: Box::new(right_expr),
                        is_span: is_tok.span,
                        not_span,
                        distinct_span: distinct_tok.span,
                        from_span: from_tok.span,
                        span,
                    });
                }
            }
            // IS TRUE/FALSE not supported yet - error
            return Err(ParseError::invalid_expression(
                self.current_span(),
                "Expected NULL or DISTINCT after IS [NOT]".to_string(),
            ));
        }

        // Check for [NOT] IN
        let is_not_followed_by_in = if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
            let save_idx = self.idx;
            let _ = self.advance();
            let is_in = matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::In))
            );
            self.idx = save_idx;
            is_in
        } else {
            false
        };

        if matches!(tok.kind, TokenKind::Keyword(Keyword::In)) || is_not_followed_by_in {
            let mut not_span: Option<Span> = None;
            let mut not_token_id: Option<crate::cst::TokenId> = None;

            // Handle optional NOT before IN
            let first_token_id = self.current_token_id();
            let first_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["IN".to_string()])
            })?;

            let in_tok = match &first_tok.kind {
                TokenKind::Keyword(Keyword::Not) => {
                    not_span = Some(first_tok.span);
                    not_token_id = Some(first_token_id);
                    self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["IN".to_string()])
                    })?
                }
                TokenKind::Keyword(Keyword::In) => first_tok,
                _ => return Ok(expr), // Not actually an IN predicate
            };

            let in_token_id = if not_token_id.is_some() {
                self.last_token_id()
            } else {
                first_token_id
            };

            // Check for UNNEST(...) — BigQuery's IN UNNEST(array_expr) syntax.
            // UNNEST is tokenized as Identifier, not a keyword.
            if let Some(next_tok) = self.peek_non_trivia() {
                if self.can_be_identifier_token(next_tok)
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("UNNEST")
                {
                    // Consume UNNEST identifier
                    let unnest_tok = self.advance().unwrap();
                    let unnest_start = unnest_tok.span.start;

                    // Consume opening paren
                    let lp = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["( after UNNEST".to_string()],
                        )
                    })?;
                    if !matches!(
                        lp.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            lp.span,
                            vec!["(".to_string()],
                            Parser::token_description(lp, self.source),
                        ));
                    }

                    // Consume everything inside balanced parens
                    let mut depth: u32 = 1;
                    let mut last_end = lp.span.end;
                    while depth > 0 {
                        let t = self.advance().ok_or_else(|| {
                            ParseError::unexpected_eof(
                                self.current_span(),
                                vec![") to close UNNEST".to_string()],
                            )
                        })?;
                        match &t.kind {
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                depth += 1;
                            }
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                depth -= 1;
                            }
                            _ => {}
                        }
                        last_end = t.span.end;
                    }

                    let list_span = Span {
                        start: unnest_start,
                        end: last_end,
                    };

                    let left_start = crate::parser::scripting::expr_span_start(&expr);
                    let span = Span {
                        start: match not_span {
                            Some(s) => s.start.min(left_start),
                            None => left_start,
                        },
                        end: last_end,
                    };

                    return Ok(AstExpr::InListOpaque {
                        node_id: self.id_gen.next(),
                        expr: Box::new(expr),
                        not_span,
                        in_span: in_tok.span,
                        list_span,
                        span,
                    });
                }
            }

            // Expect opening parenthesis
            let lparen_token_id = self.current_token_id();
            let lp = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["( after IN".to_string()])
            })?;
            if !matches!(
                lp.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                return Err(ParseError::unexpected_token(
                    lp.span,
                    vec!["(".to_string()],
                    Parser::token_description(lp, self.source),
                ));
            }

            // Check if this is a subquery (starts with SELECT)
            if let Some(next) = self.peek() {
                if matches!(
                    next.kind,
                    TokenKind::Keyword(Keyword::Select) | TokenKind::Keyword(Keyword::Values)
                ) {
                    let subquery = if matches!(next.kind, TokenKind::Keyword(Keyword::Values)) {
                        self.try_parse_values_query_stmt()?
                    } else {
                        self.try_parse_set_or_select_stmt()?
                    };

                    let rparen = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec![") after subquery".to_string()],
                        )
                    })?;
                    if !matches!(
                        rparen.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            rparen.span,
                            vec![")".to_string()],
                            Parser::token_description(rparen, self.source),
                        ));
                    }
                    let rparen_token_id = self.last_token_id();

                    let left_start = crate::parser::scripting::expr_span_start(&expr);
                    let span = Span {
                        start: match not_span {
                            Some(s) => s.start.min(left_start),
                            None => left_start,
                        },
                        end: rparen.span.end,
                    };

                    let syntax_in_subquery = crate::syntax::SyntaxInSubquery {
                        not_keyword: not_token_id,
                        in_keyword: in_token_id,
                        l_paren: lparen_token_id,
                        r_paren: rparen_token_id,
                        span: Span {
                            start: not_span.unwrap_or(in_tok.span).start,
                            end: in_tok.span.end,
                        },
                    };
                    let syntax_id = self.syntax_arena.alloc_in_subquery(syntax_in_subquery);

                    return Ok(AstExpr::InSubquery {
                        node_id: self.id_gen.next(),
                        syntax_id,
                        expr: Box::new(expr),
                        subquery: Box::new(subquery),
                        negated: not_token_id.is_some(),
                        span,
                    });
                }
            }

            // Parse list of expressions
            let mut list = Vec::new();

            // Check for empty list: IN ()
            let is_empty_list = matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Punctuation(crate::lexer::Punctuation::RParen))
            );

            if is_empty_list {
                // Empty list - just consume the closing paren
                let rparen_token_id = self.current_token_id();
                let rparen = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec![") after IN list".to_string()],
                    )
                })?;
                let left_start = crate::parser::scripting::expr_span_start(&expr);
                let span = Span {
                    start: match not_span {
                        Some(s) => s.start.min(left_start),
                        None => left_start,
                    },
                    end: rparen.span.end,
                };

                let syntax_in_list = crate::syntax::SyntaxInList {
                    not_keyword: not_token_id,
                    in_keyword: in_token_id,
                    l_paren: lparen_token_id,
                    r_paren: rparen_token_id,
                    span: Span {
                        start: not_span.unwrap_or(in_tok.span).start,
                        end: rparen.span.end,
                    },
                };
                let syntax_id = self.syntax_arena.alloc_in_list(syntax_in_list);

                return Ok(AstExpr::InList {
                    node_id: self.id_gen.next(),
                    syntax_id,
                    expr: Box::new(expr),
                    list,
                    negated: not_span.is_some(),
                    span,
                });
            } else {
                loop {
                    let item = self.parse_expr()?;
                    list.push(item);

                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance();
                            continue;
                        }
                    }
                    break;
                }
            }

            let rparen_token_id = self.current_token_id();
            let rparen = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec![") after IN list".to_string()])
            })?;
            if !matches!(
                rparen.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                return Err(ParseError::unexpected_token(
                    rparen.span,
                    vec![")".to_string()],
                    Parser::token_description(rparen, self.source),
                ));
            }

            let left_start = crate::parser::scripting::expr_span_start(&expr);
            let span = Span {
                start: match not_span {
                    Some(s) => s.start.min(left_start),
                    None => left_start,
                },
                end: rparen.span.end,
            };

            let syntax_in_list = crate::syntax::SyntaxInList {
                not_keyword: not_token_id,
                in_keyword: in_token_id,
                l_paren: lparen_token_id,
                r_paren: rparen_token_id,
                span: Span {
                    start: not_span.unwrap_or(in_tok.span).start,
                    end: rparen.span.end,
                },
            };
            let syntax_id = self.syntax_arena.alloc_in_list(syntax_in_list);

            return Ok(AstExpr::InList {
                node_id: self.id_gen.next(),
                syntax_id,
                expr: Box::new(expr),
                list,
                negated: not_span.is_some(),
                span,
            });
        }

        // Check for [NOT] BETWEEN
        let is_not_followed_by_between = if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
            let save_idx = self.idx;
            let _ = self.advance();
            let is_between = matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::Between))
            );
            self.idx = save_idx;
            is_between
        } else {
            false
        };

        if matches!(tok.kind, TokenKind::Keyword(Keyword::Between)) || is_not_followed_by_between {
            let mut not_span: Option<Span> = None;
            let mut not_token_id: Option<crate::cst::TokenId> = None;

            // Handle optional NOT before BETWEEN
            let first_token_id = self.current_token_id();
            let first_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["BETWEEN".to_string()])
            })?;

            let (between_tok, between_token_id) = match &first_tok.kind {
                TokenKind::Keyword(Keyword::Not) => {
                    not_span = Some(first_tok.span);
                    not_token_id = Some(first_token_id);
                    let between_token_id = self.current_token_id();
                    let between_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["BETWEEN".to_string()])
                    })?;
                    (between_tok, between_token_id)
                }
                TokenKind::Keyword(Keyword::Between) => (first_tok, first_token_id),
                _ => return Ok(expr), // Not actually a BETWEEN predicate
            };

            // Check for optional SYMMETRIC keyword (PG-specific)
            let symmetric_token_id = if let Some(next) = self.peek() {
                if matches!(next.kind, TokenKind::Identifier { .. })
                    && next.lexeme(self.source).eq_ignore_ascii_case("SYMMETRIC")
                {
                    let sym_token_id = self.current_token_id();
                    let _ = self.advance(); // consume SYMMETRIC
                    Some(sym_token_id)
                } else {
                    None
                }
            } else {
                None
            };

            // Parse lower bound (at additive precedence to avoid grabbing AND)
            let lower = self.parse_expr_bp(40)?;

            // Expect AND
            let and_token_id = self.current_token_id();
            let and_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["AND".to_string()])
            })?;
            if !matches!(and_tok.kind, TokenKind::Keyword(Keyword::And)) {
                return Err(ParseError::unexpected_token(
                    and_tok.span,
                    vec!["AND".to_string()],
                    Parser::token_description(and_tok, self.source),
                ));
            }

            // Parse upper bound
            let upper = self.parse_expr_bp(40)?;

            let span = Span {
                start: crate::parser::scripting::expr_span_start(&expr),
                end: crate::parser::scripting::expr_span_end(&upper),
            };

            let syntax_between = crate::syntax::SyntaxBetweenExpr {
                not_keyword: not_token_id,
                between_keyword: between_token_id,
                symmetric_keyword: symmetric_token_id,
                and_keyword: and_token_id,
                span: Span {
                    start: not_span.unwrap_or(between_tok.span).start,
                    end: crate::parser::scripting::expr_span_end(&upper),
                },
            };
            let syntax_id = self.syntax_arena.alloc_between_expr(syntax_between);

            return Ok(AstExpr::Between {
                node_id: self.id_gen.next(),
                syntax_id,
                expr: Box::new(expr),
                lower: Box::new(lower),
                upper: Box::new(upper),
                negated: not_span.is_some(),
                span,
            });
        }

        // Check for [NOT] LIKE/ILIKE/RLIKE
        let is_not_followed_by_like = if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
            let save_idx = self.idx;
            let _ = self.advance();
            let is_like = matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::Like))
                    | Some(TokenKind::Keyword(Keyword::Ilike))
                    | Some(TokenKind::Keyword(Keyword::Rlike))
                    | Some(TokenKind::Keyword(Keyword::Regexp))
            );
            self.idx = save_idx;
            is_like
        } else {
            false
        };

        let is_like_op = matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Like)
                | TokenKind::Keyword(Keyword::Ilike)
                | TokenKind::Keyword(Keyword::Rlike)
                | TokenKind::Keyword(Keyword::Regexp)
        );

        if is_like_op || is_not_followed_by_like {
            let mut not_span: Option<Span> = None;

            // Handle optional NOT before LIKE
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                let not_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["NOT".to_string()])
                })?;
                not_span = Some(not_tok.span);
            }

            let like_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(
                    self.current_span(),
                    vec!["LIKE/ILIKE/RLIKE".to_string()],
                )
            })?;

            // Parse pattern - use parse_add_expr_in_mode to avoid recursion guard.
            // LIKE patterns are typically string literals or simple expressions,
            // never containing OR/AND which belong to the outer expression.
            let pattern = self.parse_add_expr_in_mode()?;

            // Check for optional ESCAPE clause (native or ODBC {escape 'c'})
            let escape = self.parse_optional_escape_clause()?;
            let (escape_clause, odbc_escape_span) = match escape {
                Some(esc) => (Some(esc.expr), esc.odbc_span),
                None => (None, None),
            };

            let end_pos = if let Some(sp) = odbc_escape_span {
                sp.end
            } else if let Some(esc) = &escape_clause {
                crate::parser::scripting::expr_span_end(esc)
            } else {
                crate::parser::scripting::expr_span_end(&pattern)
            };

            let span = Span {
                start: crate::parser::scripting::expr_span_start(&expr),
                end: end_pos,
            };

            return Ok(AstExpr::Like {
                node_id: self.id_gen.next(),
                expr: Box::new(expr),
                not_span,
                like_kind_span: like_tok.span,
                pattern: Box::new(pattern),
                escape_clause,
                odbc_escape_span,
                span,
            });
        }

        // Check for [NOT] SIMILAR TO
        let is_similar_to = if let TokenKind::Identifier { .. } = &tok.kind {
            tok.lexeme(self.source).eq_ignore_ascii_case("SIMILAR") && {
                let save_idx = self.idx;
                let _ = self.advance(); // consume SIMILAR
                let has_to = matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::Keyword(Keyword::To))
                );
                self.idx = save_idx;
                has_to
            }
        } else {
            false
        };

        let is_not_similar_to =
            if !is_similar_to && matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                let save_idx = self.idx;
                let _ = self.advance(); // consume NOT
                if let Some(next) = self.peek() {
                    if let TokenKind::Identifier { .. } = &next.kind {
                        if next.lexeme(self.source).eq_ignore_ascii_case("SIMILAR") {
                            let _ = self.advance(); // consume SIMILAR
                            let has_to = matches!(
                                self.peek().map(|t| &t.kind),
                                Some(TokenKind::Keyword(Keyword::To))
                            );
                            self.idx = save_idx;
                            has_to
                        } else {
                            self.idx = save_idx;
                            false
                        }
                    } else {
                        self.idx = save_idx;
                        false
                    }
                } else {
                    self.idx = save_idx;
                    false
                }
            } else {
                false
            };

        if is_similar_to || is_not_similar_to {
            let mut not_span: Option<Span> = None;

            if is_not_similar_to {
                let not_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["NOT".to_string()])
                })?;
                not_span = Some(not_tok.span);
            }

            let similar_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["SIMILAR".to_string()])
            })?;
            let to_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["TO".to_string()])
            })?;
            let similar_to_span = Span {
                start: similar_tok.span.start,
                end: to_tok.span.end,
            };

            let pattern = self.parse_add_expr_in_mode()?;

            let escape = self.parse_optional_escape_clause()?;
            let (escape_clause, odbc_escape_span) = match escape {
                Some(esc) => (Some(esc.expr), esc.odbc_span),
                None => (None, None),
            };

            let end_pos = if let Some(sp) = odbc_escape_span {
                sp.end
            } else if let Some(esc) = &escape_clause {
                crate::parser::scripting::expr_span_end(esc)
            } else {
                crate::parser::scripting::expr_span_end(&pattern)
            };

            let span = Span {
                start: crate::parser::scripting::expr_span_start(&expr),
                end: end_pos,
            };

            return Ok(AstExpr::SimilarTo {
                node_id: self.id_gen.next(),
                expr: Box::new(expr),
                not_span,
                similar_to_span,
                pattern: Box::new(pattern),
                escape_clause,
                odbc_escape_span,
                span,
            });
        }

        // No compound predicate found
        Ok(expr)
    }
}
