// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Function call and window specification parsing.
//!
//! Handles:
//! - Regular function calls: `func(arg1, arg2, ...)`
//! - Aggregate functions: `COUNT(*)`, `SUM(DISTINCT x)`
//! - Window functions: `ROW_NUMBER() OVER (PARTITION BY ... ORDER BY ...)`
//! - dbt functions: `ref()`, `source()`, `var()`, `config()`
//! - Lambda expressions: `(x, y) -> x + y`
//! - NULL handling: `RESPECT NULLS`, `IGNORE NULLS`
//! - WITHIN GROUP: `LISTAGG(...) WITHIN GROUP (ORDER BY ...)`
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/functions>

use crate::ast::{AstExpr, AstIdentifier, AstLiteral, AstOrderItem};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, Token, TokenKind};
use crate::parser::core::{track_depth, Parser};

impl<'a> Parser<'a> {
    /// Parse a function call starting from after the function name.
    /// Handles empty args, COUNT(*), regular args, and OVER clause for window functions.
    /// Returns the parsed expression (either FunctionCall or WindowFn).
    pub(crate) fn parse_function_call_from_lparen(
        &mut self,
        func_name_span: Span,
        approximate: Option<(crate::cst::TokenId, Span)>,
    ) -> ParseResult<AstExpr> {
        let _guard = track_depth("parse_function_call_from_lparen", func_name_span)?;

        // Redshift `APPROXIMATE` aggregate modifier, threaded in by the caller
        // (it precedes the function name). Its keyword token is recorded on the
        // syntax node so the formatter emits it byte-exact, and the semantic
        // flag is set on the resulting node — parallel to the DISTINCT/ALL
        // quantifier. The caller extends the node span to cover `APPROXIMATE`.
        let approximate_keyword: Option<crate::cst::TokenId> = approximate.map(|(tok, _)| tok);
        let approximate_span: Option<Span> = approximate.map(|(_, span)| span);

        // Expect '('. Capture token ID before advancing so the syntax layer
        // can own the structural token.
        let func_name_token_id = self.current_token_id();
        let lparen_token_id = {
            // LParen is the next token after the function name
            self.peek()
                .ok_or_eof(func_name_span, vec!["(".to_string()])?;
            // Index of the lparen is the current index in the token stream
            self.current_token_id()
        };
        let lparen = self
            .advance()
            .ok_or_eof(func_name_span, vec!["(".to_string()])?;
        if !matches!(
            lparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lparen.span,
                vec!["(".to_string()],
                Parser::token_description(lparen, self.source),
            ));
        }

        // Check for DISTINCT or ALL quantifier after opening paren. The AST only
        // stores the quantifier *kind*; the DISTINCT/ALL keyword token itself is
        // owned by the syntax layer.
        let (quantifier, quantifier_with_span, quantifier_token_id): (
            Option<crate::ast::AstSetQuantifier>,
            Option<(crate::ast::AstSetQuantifier, Span)>,
            Option<crate::cst::TokenId>,
        ) = if let Some(tok) = self.peek() {
            match tok.kind {
                TokenKind::Keyword(Keyword::Distinct) => {
                    let distinct_tok = self
                        .advance()
                        .expect_invariant("DISTINCT keyword available after peek");
                    // Use last_token_id() to get the token we just consumed (DISTINCT)
                    (
                        Some(crate::ast::AstSetQuantifier::Distinct),
                        Some((crate::ast::AstSetQuantifier::Distinct, distinct_tok.span)),
                        Some(self.last_token_id()),
                    )
                }
                TokenKind::Keyword(Keyword::All) => {
                    let all_tok = self
                        .advance()
                        .expect_invariant("ALL keyword available after peek");
                    // Use last_token_id() to get the token we just consumed (ALL)
                    (
                        Some(crate::ast::AstSetQuantifier::All),
                        Some((crate::ast::AstSetQuantifier::All, all_tok.span)),
                        Some(self.last_token_id()),
                    )
                }
                _ => (None, None, None),
            }
        } else {
            (None, None, None)
        };

        let mut args: Vec<Box<crate::ast::AstFunctionArg>> = Vec::new();
        // MySQL GROUP_CONCAT `SEPARATOR 'str'` tail (dialect-gated);
        // captured after the last argument or after in-args ORDER BY.
        let mut separator_span: Option<Span> = None;

        // T-SQL `OPENROWSET(BULK '<file>', …)`: the `BULK` prefix on the first
        // argument is not an expression, so the generic arg parser below can't
        // read it. Recognized by function name (OPENROWSET is already a
        // dialect-gated TVF upstream) so a `BULK` identifier elsewhere is
        // untouched.
        let is_openrowset = self
            .source
            .get(func_name_span.start as usize..func_name_span.end as usize)
            .map(|n| n.trim().eq_ignore_ascii_case("OPENROWSET"))
            .unwrap_or(false);

        // Check for empty argument list: func() or func(DISTINCT) without args (invalid but handle gracefully)
        if let Some(rp) = self.peek() {
            if matches!(
                rp.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                let rparen = self
                    .advance()
                    .expect_invariant("RParen token should be available after peek");

                // Check for WITHIN GROUP before OVER
                let within_group = self.parse_within_group()?;

                // Check for FILTER (WHERE ...) clause (PG aggregate modifier)
                let filter = self.parse_filter_clause()?;

                // Check for IGNORE NULLS / RESPECT NULLS (window functions only)
                let null_handling_result = self.parse_null_handling();
                let (null_handling_ast, null_handling_tokens) =
                    if let Some((is_ignore, span, tok1, tok2)) = null_handling_result {
                        (Some((is_ignore, span)), Some((tok1, tok2)))
                    } else {
                        (None, None)
                    };

                // Check for OVER clause (window function)
                if let Some(over_tok) = self.peek() {
                    if matches!(over_tok.kind, TokenKind::Keyword(Keyword::Over)) {
                        match self.parse_window_spec_opt(null_handling_tokens) {
                            Some(Ok((over_span, window_spec))) => {
                                let window_span = Span {
                                    start: func_name_span.start,
                                    end: over_span.end,
                                };
                                return Ok(AstExpr::WindowFn {
                                    node_id: self.id_gen.next(),
                                    func_name: AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: func_name_span,
                                    },
                                    approximate: approximate_span,
                                    lparen_span: lparen.span,
                                    quantifier: quantifier_with_span,
                                    args,
                                    rparen_span: rparen.span,
                                    within_group,
                                    filter,
                                    null_handling: null_handling_ast,
                                    over_span,
                                    window: Box::new(window_spec),
                                    span: window_span,
                                });
                            }
                            Some(Err(e)) => {
                                // Parse error in window spec - return error
                                return Err(e);
                            }
                            None => {
                                // No window spec found, continue
                            }
                        }
                    }
                }

                let func_span = Span {
                    start: func_name_span.start,
                    end: filter
                        .as_ref()
                        .map(|f| f.span.end)
                        .or(within_group.as_ref().map(|wg| wg.span.end))
                        .unwrap_or(rparen.span.end),
                };

                // Capture closing paren token ID for the syntax layer
                let rparen_token_id = self.last_token_id();

                let syntax_fn = crate::syntax::SyntaxFunctionCall {
                    func_name: func_name_token_id,
                    l_paren: lparen_token_id,
                    distinct_keyword: quantifier_token_id,
                    approximate_keyword,
                    r_paren: rparen_token_id,
                    span: func_span,
                };
                let syntax_id = self.syntax_arena.alloc_function_call(syntax_fn);

                return Ok(AstExpr::FunctionCall {
                    node_id: self.id_gen.next(),
                    syntax_id,
                    func_name: AstIdentifier {
                        node_id: self.id_gen.next(),
                        span: func_name_span,
                    },
                    quantifier,
                    args,
                    approximate: approximate_keyword.is_some(),
                    odbc_fn: false,
                    order_by_span: None,
                    inline_order_by: None,
                    separator_span: None,
                    within_group,
                    filter,
                    span: func_span,
                });
            }
        }

        // Parse comma-separated argument list
        loop {
            // Check for special case: COUNT(*) or similar
            if let Some(star) = self.peek() {
                if matches!(star.kind, TokenKind::Operator(crate::lexer::Operator::Star)) {
                    let star_tok = self
                        .advance()
                        .expect_invariant("Star operator should be available after peek");
                    // Represent * as UnqualifiedStar (semantically correct)
                    args.push(Box::new(crate::ast::AstFunctionArg::Positional(Box::new(
                        AstExpr::UnqualifiedStar {
                            node_id: self.id_gen.next(),
                            star_span: star_tok.span,
                            exclude: None,
                            replace: None,
                            rename: None,
                            span: star_tok.span,
                        },
                    ))));

                    // Expect closing paren after *
                    if let Some(rp) = self.advance() {
                        if matches!(
                            rp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        ) {
                            // Parse optional WITHIN GROUP clause
                            let within_group = self.parse_within_group()?;

                            // Check for FILTER (WHERE ...) clause (PG aggregate modifier)
                            let filter = self.parse_filter_clause()?;

                            // Check for IGNORE NULLS / RESPECT NULLS (window functions only)
                            let null_handling_result = self.parse_null_handling();
                            let (null_handling_ast, null_handling_tokens) =
                                if let Some((is_ignore, span, tok1, tok2)) = null_handling_result {
                                    (Some((is_ignore, span)), Some((tok1, tok2)))
                                } else {
                                    (None, None)
                                };

                            // Calculate span including WITHIN GROUP / FILTER if present
                            let func_span = Span {
                                start: func_name_span.start,
                                end: filter
                                    .as_ref()
                                    .map(|f| f.span.end)
                                    .or(within_group.as_ref().map(|wg| wg.span.end))
                                    .unwrap_or(rp.span.end),
                            };

                            // Check for OVER clause (window function)
                            if let Some(over_tok) = self.peek() {
                                if matches!(over_tok.kind, TokenKind::Keyword(Keyword::Over)) {
                                    match self.parse_window_spec_opt(null_handling_tokens) {
                                        Some(Ok((over_span, window_spec))) => {
                                            let window_span = Span {
                                                start: func_name_span.start,
                                                end: over_span.end,
                                            };
                                            return Ok(AstExpr::WindowFn {
                                                node_id: self.id_gen.next(),
                                                func_name: AstIdentifier {
                                                    node_id: self.id_gen.next(),
                                                    span: func_name_span,
                                                },
                                                approximate: approximate_span,
                                                lparen_span: lparen.span,
                                                quantifier: quantifier_with_span,
                                                args,
                                                rparen_span: rp.span,
                                                within_group,
                                                filter,
                                                null_handling: null_handling_ast,
                                                over_span,
                                                window: Box::new(window_spec),
                                                span: window_span,
                                            });
                                        }
                                        Some(Err(e)) => {
                                            // Parse error in window spec - return error
                                            return Err(e);
                                        }
                                        None => {
                                            // No window spec found, continue
                                        }
                                    }
                                }
                            }

                            let rparen_token_id = self.last_token_id();

                            let syntax_fn = crate::syntax::SyntaxFunctionCall {
                                func_name: func_name_token_id,
                                l_paren: lparen_token_id,
                                distinct_keyword: quantifier_token_id,
                                approximate_keyword,
                                r_paren: rparen_token_id,
                                span: func_span,
                            };
                            let syntax_id = self.syntax_arena.alloc_function_call(syntax_fn);

                            return Ok(AstExpr::FunctionCall {
                                node_id: self.id_gen.next(),
                                syntax_id,
                                func_name: AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: func_name_span,
                                },
                                quantifier,
                                args,
                                approximate: approximate_keyword.is_some(),
                                odbc_fn: false,
                                order_by_span: None,
                                inline_order_by: None,
                                separator_span: None,
                                within_group,
                                filter,
                                span: func_span,
                            });
                        }
                    }
                    return Err(ParseError::new(
                        star_tok.span,
                        ParseErrorKind::UnexpectedEof {
                            expected: vec![")".to_string()],
                        },
                    )); // Missing ) after *
                }
            }

            // Parse regular expression argument, named argument, or lambda expression
            // Note: quantifier was already parsed at the top of this function
            // Check for:
            // - Named argument: identifier => value
            // - Lambda: identifier -> expr OR (ident, ident) -> expr
            let arg = if let Some(tok) = self.peek() {
                // T-SQL OPENROWSET(BULK '<file>', …): `BULK` identifier prefix
                // directly followed by the file-path literal (no comma). Captured
                // as a single BulkArg so the file literal stays attached to the
                // OPENROWSET call and the form is recognizable as a file read.
                if is_openrowset
                    && matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(self.source).eq_ignore_ascii_case("BULK")
                    && self.peek_ahead(1).is_some_and(|t| {
                        matches!(
                            t.kind,
                            TokenKind::Literal(crate::lexer::LiteralKind::String)
                        )
                    })
                {
                    let bulk_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["BULK".to_string()])?;
                    let value = self.parse_expr_with_recovery()?;
                    crate::ast::AstFunctionArg::BulkArg {
                        bulk_span: bulk_tok.span,
                        value: Box::new(value),
                    }
                } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Execute)) {
                    // EXECUTE IMMEDIATE as function argument → statement-form
                    // subquery, e.g. Snowflake `RETURN TABLE(EXECUTE IMMEDIATE :q)`.
                    // Same SubqueryArg shape as ARRAY(SELECT ...): parens belong to
                    // the call; downstream walkers reach the EXECUTE IMMEDIATE
                    // through the expression tree.
                    // Checked before the identifier branch — EXECUTE is unreserved
                    // in most dialects and would otherwise be consumed as a name.
                    // Speculative parse with rollback, mirroring the parenthesized
                    // `(EXECUTE IMMEDIATE ...)` form in expr.rs.
                    let ei_start = tok.span.start;
                    let saved_idx = self.idx;
                    match crate::parser::scripting::try_parse_execute_immediate_stmt(self) {
                        Ok(ei_stmt) => {
                            let span = Span {
                                start: ei_start,
                                end: ei_stmt.span().end,
                            };
                            crate::ast::AstFunctionArg::Positional(Box::new(AstExpr::SubqueryArg {
                                node_id: self.id_gen.next(),
                                subquery: Box::new(ei_stmt),
                                span,
                            }))
                        }
                        Err(err) => {
                            if err.kind.is_resource_exhaustion() {
                                return Err(err);
                            }
                            // Restore and fall back to plain expression parsing
                            // (EXECUTE used as an ordinary identifier argument).
                            self.idx = saved_idx;
                            let expr = self.parse_expr_with_recovery()?;
                            crate::ast::AstFunctionArg::Positional(Box::new(expr))
                        }
                    }
                } else if self.can_be_identifier_token(tok) {
                    let next = self.peek_ahead(1);
                    let is_named_arrow = next.is_some_and(|t| {
                        matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::EqGt))
                    });
                    let is_lambda_arrow = next.is_some_and(|t| {
                        matches!(
                            t.kind,
                            TokenKind::Operator(crate::lexer::Operator::RightArrow)
                        )
                    });

                    if is_named_arrow {
                        // This is a named argument: name => value
                        let name_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                        let arrow_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=>".to_string()])?;
                        // Use error recovery for the value expression
                        let value = self.parse_expr_with_recovery()?;

                        crate::ast::AstFunctionArg::Named {
                            name: crate::ast::AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: name_tok.span,
                            },
                            arrow_span: arrow_tok.span,
                            value: Box::new(value),
                        }
                    } else if is_lambda_arrow {
                        // This is a lambda expression: x -> expr
                        let param_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                        let param_start = param_tok.span.start;
                        let arrow_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["->".to_string()])?;
                        // Parse lambda body expression
                        let body = self.parse_expr_with_recovery()?;
                        let body_end = body.span().end;

                        crate::ast::AstFunctionArg::Lambda {
                            params: vec![crate::ast::AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: param_tok.span,
                            }],
                            arrow_span: arrow_tok.span,
                            body: Box::new(body),
                            span: Span {
                                start: param_start,
                                end: body_end,
                            },
                        }
                    } else {
                        // Regular positional argument - use error recovery
                        let expr = self.parse_expr_with_recovery()?;
                        crate::ast::AstFunctionArg::Positional(Box::new(expr))
                    }
                } else if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    // Could be a lambda with multiple params: (x, y) -> expr
                    // Or just a parenthesized expression
                    // Peek ahead to find -> after the closing paren
                    let is_lambda = self.is_lambda_params();
                    if is_lambda {
                        self.parse_lambda_arg()?
                    } else {
                        // Regular positional argument - use error recovery
                        let expr = self.parse_expr_with_recovery()?;
                        crate::ast::AstFunctionArg::Positional(Box::new(expr))
                    }
                } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Select)) {
                    // SELECT keyword as function argument → subquery argument
                    // e.g., ARRAY(SELECT AS STRUCT id, name FROM users)
                    // Use SubqueryArg (not ScalarSubquery) because the parens belong
                    // to the function call, not the subquery itself.
                    let select_start = tok.span.start;
                    let subquery = self.try_parse_set_or_select_stmt().map_err(|_| {
                        ParseError::invalid_expression(
                            self.current_span(),
                            "Expected SELECT subquery as function argument".to_string(),
                        )
                    })?;
                    let subquery_span = subquery.span();
                    let span = Span {
                        start: select_start,
                        end: subquery_span.end,
                    };
                    crate::ast::AstFunctionArg::Positional(Box::new(AstExpr::SubqueryArg {
                        node_id: self.id_gen.next(),
                        subquery: Box::new(subquery),
                        span,
                    }))
                } else {
                    // Not an identifier, must be a positional expression - use error recovery
                    let expr = self.parse_expr_with_recovery()?;
                    crate::ast::AstFunctionArg::Positional(Box::new(expr))
                }
            } else {
                return Err(ParseError::new(
                    lparen.span,
                    ParseErrorKind::UnexpectedEof {
                        expected: vec!["expression".to_string(), ")".to_string()],
                    },
                )); // Unexpected EOF
            };

            // Check for trailing AS alias (BigQuery STRUCT constructor syntax)
            // e.g., STRUCT(1 AS x, 'hello' AS y)
            // Only promote Positional args — Named and Lambda already have their own semantics.
            let arg = if matches!(arg, crate::ast::AstFunctionArg::Positional(_)) {
                if let Some(next) = self.peek() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::As)) {
                        let as_tok = self.advance().unwrap(); // consume AS
                        if let Some(alias_tok) = self.advance() {
                            if let crate::ast::AstFunctionArg::Positional(value) = arg {
                                crate::ast::AstFunctionArg::AliasedArg {
                                    value,
                                    as_span: as_tok.span,
                                    alias: crate::ast::AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: alias_tok.span,
                                    },
                                }
                            } else {
                                unreachable!() // guarded by outer match
                            }
                        } else {
                            arg // EOF after AS — leave as-is, let downstream handle
                        }
                    } else {
                        arg
                    }
                } else {
                    arg
                }
            } else {
                arg
            };

            args.push(Box::new(arg));

            // MySQL GROUP_CONCAT `SEPARATOR 'str'` directly after the last
            // argument (no in-args ORDER BY): GROUP_CONCAT(name SEPARATOR ', ').
            if separator_span.is_none() && self.dialect.supports_group_concat_separator() {
                if let Some(sep_tok) = self.peek() {
                    if matches!(
                        sep_tok.kind,
                        TokenKind::Identifier {
                            kind: crate::lexer::IdentifierKind::Unquoted
                        }
                    ) && sep_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("SEPARATOR")
                        && self.peek_ahead(1).is_some_and(|t| {
                            matches!(
                                t.kind,
                                TokenKind::Literal(crate::lexer::LiteralKind::String)
                            )
                        })
                    {
                        let sep = self.advance().expect_invariant("SEPARATOR after peek");
                        let sep_start = sep.span.start;
                        let lit = self.advance().expect_invariant("string after SEPARATOR");
                        separator_span = Some(Span {
                            start: sep_start,
                            end: lit.span.end,
                        });
                    }
                }
            }

            // Check for IGNORE NULLS / RESPECT NULLS inside parentheses (alternate Snowflake syntax)
            // e.g., LAST_VALUE(expr IGNORE NULLS) OVER (...)
            let inner_null_handling = self.parse_null_handling_inside_parens();

            // Check for comma (more arguments), ORDER BY (aggregate ordering), or closing paren
            if let Some(next) = self.peek() {
                match &next.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        let _ = self.advance(); // consume comma
                        continue;
                    }
                    // Aggregate ORDER BY: ARRAY_AGG(expr ORDER BY expr [ASC|DESC] [, ...])
                    TokenKind::Keyword(Keyword::Order) => {
                        let order_tok = self.advance().expect_invariant("ORDER keyword after peek");
                        let order_by_start = order_tok.span.start;

                        // Expect BY
                        let by_tok = self.advance();
                        if by_tok.is_none()
                            || !matches!(by_tok.unwrap().kind, TokenKind::Keyword(Keyword::By))
                        {
                            return Err(ParseError::new(
                                order_tok.span,
                                ParseErrorKind::InvalidSyntax {
                                    message: "Expected BY after ORDER".to_string(),
                                },
                            ));
                        }

                        // Parse order items until we hit RParen
                        let mut order_by_end = by_tok.unwrap().span.end;
                        let mut order_items: Vec<Box<crate::ast::AstOrderItem>> = Vec::new();
                        while let Some(item) = self.parse_order_by_item()? {
                            order_by_end = item.span.end;
                            order_items.push(Box::new(item));
                            // Check for comma (more order items) or RParen
                            if let Some(t) = self.peek() {
                                if matches!(
                                    t.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                                ) {
                                    let _ = self.advance(); // consume comma
                                    continue;
                                }
                            }
                            break;
                        }

                        let order_by_span = Some(Span {
                            start: order_by_start,
                            end: order_by_end,
                        });

                        // Check for LIMIT inside aggregate function (BigQuery extension)
                        // e.g., ARRAY_AGG(DISTINCT name ORDER BY name LIMIT 10)
                        let order_by_span = if let Some(limit_tok) = self.peek() {
                            if matches!(limit_tok.kind, TokenKind::Keyword(Keyword::Limit)) {
                                let _limit =
                                    self.advance().expect_invariant("LIMIT keyword after peek");
                                // Parse the limit value expression
                                if let Some(val_tok) = self.peek() {
                                    if !matches!(
                                        val_tok.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                    ) {
                                        let limit_val =
                                            self.advance().expect_invariant("LIMIT value");
                                        Some(Span {
                                            start: order_by_start,
                                            end: limit_val.span.end,
                                        })
                                    } else {
                                        Some(Span {
                                            start: order_by_start,
                                            end: _limit.span.end,
                                        })
                                    }
                                } else {
                                    Some(Span {
                                        start: order_by_start,
                                        end: _limit.span.end,
                                    })
                                }
                            } else {
                                order_by_span
                            }
                        } else {
                            order_by_span
                        };

                        // MySQL GROUP_CONCAT `SEPARATOR 'str'` after in-args
                        // ORDER BY: GROUP_CONCAT(x ORDER BY x SEPARATOR '|').
                        if separator_span.is_none()
                            && self.dialect.supports_group_concat_separator()
                        {
                            if let Some(sep_tok) = self.peek() {
                                if matches!(
                                    sep_tok.kind,
                                    TokenKind::Identifier {
                                        kind: crate::lexer::IdentifierKind::Unquoted
                                    }
                                ) && sep_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("SEPARATOR")
                                    && self.peek_ahead(1).is_some_and(|t| {
                                        matches!(
                                            t.kind,
                                            TokenKind::Literal(crate::lexer::LiteralKind::String)
                                        )
                                    })
                                {
                                    let sep =
                                        self.advance().expect_invariant("SEPARATOR after peek");
                                    let sep_start = sep.span.start;
                                    let lit =
                                        self.advance().expect_invariant("string after SEPARATOR");
                                    separator_span = Some(Span {
                                        start: sep_start,
                                        end: lit.span.end,
                                    });
                                }
                            }
                        }

                        // Now expect RParen
                        let rparen = if let Some(rp) = self.peek() {
                            if matches!(
                                rp.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                self.advance()
                                    .expect_invariant("RParen after order by items")
                            } else {
                                return Err(ParseError::unexpected_token(
                                    rp.span,
                                    vec![")".to_string()],
                                    Parser::token_description(rp, self.source),
                                ));
                            }
                        } else {
                            return Err(ParseError::new(
                                Span {
                                    start: order_by_start,
                                    end: order_by_end,
                                },
                                ParseErrorKind::UnexpectedEof {
                                    expected: vec![")".to_string()],
                                },
                            ));
                        };

                        // Parse optional WITHIN GROUP clause
                        let within_group = self.parse_within_group()?;

                        // Check for FILTER (WHERE ...) clause
                        let filter = self.parse_filter_clause()?;

                        // Check for IGNORE NULLS / RESPECT NULLS
                        let null_handling_result = if inner_null_handling.is_some() {
                            inner_null_handling
                        } else {
                            self.parse_null_handling()
                        };
                        let (null_handling_ast, null_handling_tokens) =
                            if let Some((is_ignore, span, tok1, tok2)) = null_handling_result {
                                (Some((is_ignore, span)), Some((tok1, tok2)))
                            } else {
                                (None, None)
                            };

                        let func_span = Span {
                            start: func_name_span.start,
                            end: filter
                                .as_ref()
                                .map(|f| f.span.end)
                                .or(within_group.as_ref().map(|wg| wg.span.end))
                                .unwrap_or(rparen.span.end),
                        };

                        // Check for OVER clause (window function)
                        if let Some(over_tok) = self.peek() {
                            if matches!(over_tok.kind, TokenKind::Keyword(Keyword::Over)) {
                                match self.parse_window_spec_opt(null_handling_tokens) {
                                    Some(Ok((over_span, window_spec))) => {
                                        let window_span = Span {
                                            start: func_name_span.start,
                                            end: over_span.end,
                                        };
                                        return Ok(AstExpr::WindowFn {
                                            node_id: self.id_gen.next(),
                                            func_name: AstIdentifier {
                                                node_id: self.id_gen.next(),
                                                span: func_name_span,
                                            },
                                            approximate: approximate_span,
                                            lparen_span: lparen.span,
                                            quantifier: quantifier_with_span,
                                            args,
                                            rparen_span: rparen.span,
                                            within_group,
                                            filter,
                                            null_handling: null_handling_ast,
                                            over_span,
                                            window: Box::new(window_spec),
                                            span: window_span,
                                        });
                                    }
                                    Some(Err(e)) => {
                                        return Err(e);
                                    }
                                    None => {}
                                }
                            }
                        }

                        let rparen_token_id = self.last_token_id();

                        let syntax_fn = crate::syntax::SyntaxFunctionCall {
                            func_name: func_name_token_id,
                            l_paren: lparen_token_id,
                            distinct_keyword: quantifier_token_id,
                            approximate_keyword,
                            r_paren: rparen_token_id,
                            span: func_span,
                        };
                        let syntax_id = self.syntax_arena.alloc_function_call(syntax_fn);

                        return Ok(AstExpr::FunctionCall {
                            node_id: self.id_gen.next(),
                            syntax_id,
                            func_name: AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: func_name_span,
                            },
                            quantifier,
                            args,
                            approximate: approximate_keyword.is_some(),
                            odbc_fn: false,
                            order_by_span,
                            inline_order_by: if order_items.is_empty() {
                                None
                            } else {
                                Some(order_items)
                            },
                            separator_span,
                            within_group,
                            filter,
                            span: func_span,
                        });
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        let rparen = self
                            .advance()
                            .expect_invariant("RParen should be available after matching in peek");

                        // Parse optional WITHIN GROUP clause
                        let within_group = self.parse_within_group()?;

                        // Check for FILTER (WHERE ...) clause (PG aggregate modifier)
                        let filter = self.parse_filter_clause()?;

                        // Check for IGNORE NULLS / RESPECT NULLS after closing paren (standard syntax)
                        // But prefer the inner version if we already found it
                        let null_handling_result = if inner_null_handling.is_some() {
                            inner_null_handling
                        } else {
                            self.parse_null_handling()
                        };
                        let (null_handling_ast, null_handling_tokens) =
                            if let Some((is_ignore, span, tok1, tok2)) = null_handling_result {
                                (Some((is_ignore, span)), Some((tok1, tok2)))
                            } else {
                                (None, None)
                            };

                        // Calculate span including WITHIN GROUP / FILTER if present
                        let func_span = Span {
                            start: func_name_span.start,
                            end: filter
                                .as_ref()
                                .map(|f| f.span.end)
                                .or(within_group.as_ref().map(|wg| wg.span.end))
                                .unwrap_or(rparen.span.end),
                        };

                        // Check for OVER clause (window function)
                        if let Some(over_tok) = self.peek() {
                            if matches!(over_tok.kind, TokenKind::Keyword(Keyword::Over)) {
                                match self.parse_window_spec_opt(null_handling_tokens) {
                                    Some(Ok((over_span, window_spec))) => {
                                        let window_span = Span {
                                            start: func_name_span.start,
                                            end: over_span.end,
                                        };
                                        return Ok(AstExpr::WindowFn {
                                            node_id: self.id_gen.next(),
                                            func_name: AstIdentifier {
                                                node_id: self.id_gen.next(),
                                                span: func_name_span,
                                            },
                                            approximate: approximate_span,
                                            lparen_span: lparen.span,
                                            quantifier: quantifier_with_span,
                                            args,
                                            rparen_span: rparen.span,
                                            within_group,
                                            filter,
                                            null_handling: null_handling_ast,
                                            over_span,
                                            window: Box::new(window_spec),
                                            span: window_span,
                                        });
                                    }
                                    Some(Err(e)) => {
                                        // Parse error in window spec - return error
                                        return Err(e);
                                    }
                                    None => {
                                        // No window spec found, continue
                                    }
                                }
                            }
                        }

                        let rparen_token_id = self.last_token_id();

                        let syntax_fn = crate::syntax::SyntaxFunctionCall {
                            func_name: func_name_token_id,
                            l_paren: lparen_token_id,
                            distinct_keyword: quantifier_token_id,
                            approximate_keyword,
                            r_paren: rparen_token_id,
                            span: func_span,
                        };
                        let syntax_id = self.syntax_arena.alloc_function_call(syntax_fn);

                        return Ok(AstExpr::FunctionCall {
                            node_id: self.id_gen.next(),
                            syntax_id,
                            func_name: AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: func_name_span,
                            },
                            quantifier,
                            args,
                            approximate: approximate_keyword.is_some(),
                            odbc_fn: false,
                            order_by_span: None,
                            inline_order_by: None,
                            separator_span,
                            within_group,
                            filter,
                            span: func_span,
                        });
                    }
                    _ => {
                        // Check if previous argument contained Jinja - if so, comma may be conditional
                        // This handles dbt patterns like: CONCAT({% if cond %}'val',{% endif %}name)
                        // When cond is false, there's no comma between empty block and next arg
                        let prev_arg_has_jinja = args.last().is_some_and(|arg| {
                            Self::expr_contains_jinja(match arg.as_ref() {
                                crate::ast::AstFunctionArg::Positional(e) => e,
                                crate::ast::AstFunctionArg::Named { value, .. } => value,
                                crate::ast::AstFunctionArg::Lambda { body, .. } => body,
                                crate::ast::AstFunctionArg::AliasedArg { value, .. } => value,
                                crate::ast::AstFunctionArg::BulkArg { value, .. } => value,
                            })
                        });

                        if prev_arg_has_jinja && self.is_likely_function_arg_start(next) {
                            // Tolerate missing comma after Jinja block
                            continue;
                        }

                        return Err(ParseError::unexpected_token(
                            next.span,
                            vec![",".to_string(), ")".to_string()],
                            Parser::token_description(next, self.source),
                        )); // Unexpected token
                    }
                }
            } else {
                return Err(ParseError::new(
                    lparen.span,
                    ParseErrorKind::UnexpectedEof {
                        expected: vec![",".to_string(), ")".to_string()],
                    },
                )); // Unexpected EOF
            }
        }
    }

    /// Check if an expression contains any Jinja constructs
    fn expr_contains_jinja(expr: &AstExpr) -> bool {
        match expr {
            AstExpr::JinjaPlaceholder { .. } | AstExpr::JinjaConditional { .. } => true,
            AstExpr::BinaryOp { left, right, .. } => {
                Self::expr_contains_jinja(left) || Self::expr_contains_jinja(right)
            }
            AstExpr::Parenthesized { expr, .. } => Self::expr_contains_jinja(expr),
            AstExpr::FunctionCall { args, .. } | AstExpr::WindowFn { args, .. } => {
                args.iter().any(|arg| match arg.as_ref() {
                    crate::ast::AstFunctionArg::Positional(e) => Self::expr_contains_jinja(e),
                    crate::ast::AstFunctionArg::Named { value, .. } => {
                        Self::expr_contains_jinja(value)
                    }
                    crate::ast::AstFunctionArg::Lambda { body, .. } => {
                        Self::expr_contains_jinja(body)
                    }
                    crate::ast::AstFunctionArg::AliasedArg { value, .. } => {
                        Self::expr_contains_jinja(value)
                    }
                    crate::ast::AstFunctionArg::BulkArg { value, .. } => {
                        Self::expr_contains_jinja(value)
                    }
                })
            }
            AstExpr::Cast { expr, .. }
            | AstExpr::TryCast { expr, .. }
            | AstExpr::TypeCast { expr, .. }
            | AstExpr::Extract { expr, .. } => Self::expr_contains_jinja(expr),
            AstExpr::Trim { chars, source, .. } => {
                chars.as_ref().is_some_and(|c| Self::expr_contains_jinja(c))
                    || Self::expr_contains_jinja(source)
            }
            AstExpr::Substring {
                source,
                from,
                for_len,
                ..
            } => {
                Self::expr_contains_jinja(source)
                    || from.as_ref().is_some_and(|f| Self::expr_contains_jinja(f))
                    || for_len
                        .as_ref()
                        .is_some_and(|f| Self::expr_contains_jinja(f))
            }
            AstExpr::Case {
                operand,
                whens,
                else_expr,
                ..
            } => {
                operand
                    .as_ref()
                    .is_some_and(|e| Self::expr_contains_jinja(e))
                    || whens.iter().any(|w| {
                        Self::expr_contains_jinja(&w.cond) || Self::expr_contains_jinja(&w.result)
                    })
                    || else_expr
                        .as_ref()
                        .is_some_and(|e| Self::expr_contains_jinja(e))
            }
            _ => false,
        }
    }

    /// Check if a token looks like the start of a function argument
    /// Used for tolerant parsing of Jinja patterns with conditional commas
    fn is_likely_function_arg_start(&self, tok: &Token) -> bool {
        matches!(
            tok.kind,
            TokenKind::Identifier { .. }
                | TokenKind::Literal { .. }
                | TokenKind::Keyword(Keyword::Null)
                | TokenKind::Keyword(Keyword::True)
                | TokenKind::Keyword(Keyword::False)
                | TokenKind::Keyword(Keyword::Case)
                | TokenKind::Keyword(Keyword::Cast)
                | TokenKind::Keyword(Keyword::Not)
                | TokenKind::Keyword(Keyword::Exists)
                | TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                | TokenKind::Operator(crate::lexer::Operator::Minus)
                | TokenKind::Operator(crate::lexer::Operator::Plus)
        )
    }

    /// Parse dbt ref() function: ref('model') or ref('package', 'model')
    /// Returns DbtRef AST node with inner literal spans for precise refactoring
    pub(crate) fn parse_dbt_ref(&mut self, func_name_span: Span) -> ParseResult<AstExpr> {
        // Expect '('
        let lp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
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

        // Parse first string argument (required)
        let first_arg = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["string literal".to_string()])
        })?;
        let first_str = self.extract_string_literal(first_arg)?;
        let first_span = first_arg.span;

        // Check for comma (second argument - package name)
        let (model_name, model_name_span, package_name, package_name_span) =
            if let Some(next) = self.peek() {
                if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance(); // consume comma
                    let second_arg = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["string literal".to_string()],
                        )
                    })?;
                    let second_str = self.extract_string_literal(second_arg)?;
                    // When two args: ref('package', 'model') - first is package, second is model
                    (
                        second_str,
                        second_arg.span,
                        Some(first_str),
                        Some(first_span),
                    )
                } else {
                    // Single arg: ref('model')
                    (first_str, first_span, None, None)
                }
            } else {
                (first_str, first_span, None, None)
            };

        // Expect ')'
        let rp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
        })?;
        if !matches!(
            rp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp.span,
                vec![")".to_string()],
                Parser::token_description(rp, self.source),
            ));
        }

        let span = Span {
            start: func_name_span.start,
            end: rp.span.end,
        };
        Ok(AstExpr::DbtRef {
            node_id: self.id_gen.next(),
            func_name_span,
            lparen_span: lp.span,
            model_name,
            model_name_span,
            package_name,
            package_name_span,
            rparen_span: rp.span,
            span,
        })
    }

    /// Parse dbt source() function: source('source_name', 'table_name')
    pub(crate) fn parse_dbt_source(&mut self, func_name_span: Span) -> ParseResult<AstExpr> {
        // Expect '('
        let lp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
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

        // Parse first argument: source_name
        let source_arg = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["string literal".to_string()])
        })?;
        let source_name = self.extract_string_literal(source_arg)?;
        let source_name_span = source_arg.span;

        // Expect ','
        let comma = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![",".to_string()])
        })?;
        if !matches!(
            comma.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
        ) {
            return Err(ParseError::unexpected_token(
                comma.span,
                vec![",".to_string()],
                Parser::token_description(comma, self.source),
            ));
        }

        // Parse second argument: table_name
        let table_arg = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["string literal".to_string()])
        })?;
        let table_name = self.extract_string_literal(table_arg)?;
        let table_name_span = table_arg.span;

        // Expect ')'
        let rp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
        })?;
        if !matches!(
            rp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp.span,
                vec![")".to_string()],
                Parser::token_description(rp, self.source),
            ));
        }

        let span = Span {
            start: func_name_span.start,
            end: rp.span.end,
        };
        Ok(AstExpr::DbtSource {
            node_id: self.id_gen.next(),
            func_name_span,
            lparen_span: lp.span,
            source_name,
            source_name_span,
            table_name,
            table_name_span,
            rparen_span: rp.span,
            span,
        })
    }

    /// Parse dbt var() function: var('name') or var('name', default_expr)
    pub(crate) fn parse_dbt_var(&mut self, func_name_span: Span) -> ParseResult<AstExpr> {
        // Expect '('
        let lp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
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

        // Parse first argument: var_name
        let var_arg = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["string literal".to_string()])
        })?;
        let var_name = self.extract_string_literal(var_arg)?;
        let var_name_span = var_arg.span;

        // Check for optional default value
        let (default_value, default_value_span) = if let Some(next) = self.peek() {
            if matches!(
                next.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            ) {
                self.advance(); // consume comma
                                // Parse default value expression - capture raw text
                let default_start = self.current_span().start;
                let default_expr = self.parse_expr()?;
                let default_end = default_expr.span().end;
                let default_span = Span {
                    start: default_start,
                    end: default_end,
                };
                // Convert expression to string representation (for now just use source text)
                let default_text = format!("{:?}", default_expr); // Placeholder - ideally reconstruct from source
                (Some(default_text), Some(default_span))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Expect ')'
        let rp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
        })?;
        if !matches!(
            rp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp.span,
                vec![")".to_string()],
                Parser::token_description(rp, self.source),
            ));
        }

        let span = Span {
            start: func_name_span.start,
            end: rp.span.end,
        };
        Ok(AstExpr::DbtVar {
            node_id: self.id_gen.next(),
            func_name_span,
            lparen_span: lp.span,
            var_name,
            var_name_span,
            default_value,
            default_value_span,
            rparen_span: rp.span,
            span,
        })
    }

    /// Parse dbt config() function: config(materialized='table', ...)
    pub(crate) fn parse_dbt_config(&mut self, func_name_span: Span) -> ParseResult<AstExpr> {
        // Expect '('
        let lp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
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

        // Parse key=value pairs
        let mut args: Vec<(String, String)> = Vec::new();
        loop {
            // Check for closing paren
            if let Some(next) = self.peek() {
                if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    break;
                }
            }

            // Parse key
            let key_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["identifier".to_string()])
            })?;
            let key = if self.can_be_identifier_token(key_tok) {
                key_tok.lexeme(self.source).to_string()
            } else {
                return Err(ParseError::unexpected_token(
                    key_tok.span,
                    vec!["identifier".to_string()],
                    Parser::token_description(key_tok, self.source),
                ));
            };

            // Expect '='
            let eq_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["=".to_string()])
            })?;
            if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                return Err(ParseError::unexpected_token(
                    eq_tok.span,
                    vec!["=".to_string()],
                    Parser::token_description(eq_tok, self.source),
                ));
            }

            // Parse value (simple: string literal, identifier, or number)
            let val_tok = self.advance().ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["value".to_string()])
            })?;
            let value = match &val_tok.kind {
                TokenKind::Literal(crate::lexer::LiteralKind::String) => {
                    self.extract_string_literal(val_tok)?
                }
                _ if self.can_be_identifier_token(val_tok) => {
                    val_tok.lexeme(self.source).to_string()
                }
                TokenKind::Literal(_) => val_tok.lexeme(self.source).to_string(),
                _ => {
                    return Err(ParseError::unexpected_token(
                        val_tok.span,
                        vec!["value".to_string()],
                        Parser::token_description(val_tok, self.source),
                    ))
                }
            };

            args.push((key, value));

            // Check for comma (more args) or end
            if let Some(next) = self.peek() {
                if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance(); // consume comma
                }
            }
        }

        // Expect ')'
        let rp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
        })?;
        if !matches!(
            rp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp.span,
                vec![")".to_string()],
                Parser::token_description(rp, self.source),
            ));
        }

        let span = Span {
            start: func_name_span.start,
            end: rp.span.end,
        };
        Ok(AstExpr::DbtConfig {
            node_id: self.id_gen.next(),
            func_name_span,
            lparen_span: lp.span,
            args,
            rparen_span: rp.span,
            span,
        })
    }

    /// Helper to extract string value from a string literal token
    fn extract_string_literal(&self, tok: &Token) -> ParseResult<String> {
        match &tok.kind {
            TokenKind::Literal(crate::lexer::LiteralKind::String) => {
                // Remove surrounding quotes
                let s = &tok.lexeme(self.source);
                if s.len() >= 2 && (s.starts_with('\'') || s.starts_with('"')) {
                    Ok(s[1..s.len() - 1].to_string())
                } else {
                    Ok(s.to_string())
                }
            }
            _ => Err(ParseError::unexpected_token(
                tok.span,
                vec!["string literal".to_string()],
                Parser::token_description(tok, self.source),
            )),
        }
    }

    /// Parse a string literal containing Jinja expressions.
    /// The lexer produces: StringFragment('prefix) + JinjaExpression({{ expr }}) + StringFragment(suffix')
    /// We combine them into a single StringWithJinja literal spanning from first to last token.
    pub(crate) fn parse_string_with_jinja(&mut self) -> ParseResult<AstExpr> {
        // First token must be a StringFragment
        let first_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["string fragment".to_string()])
        })?;
        let start = first_tok.span.start;
        let mut end = first_tok.span.end;

        // Continue consuming tokens until we find a StringFragment that ends with a quote
        // (indicating the string is complete)
        loop {
            let next = self.peek();
            match next {
                Some(tok) if matches!(tok.kind, TokenKind::JinjaComment) => {
                    let tok = self
                        .advance()
                        .expect_invariant("JinjaComment token available after peek");
                    end = tok.span.end;
                }
                Some(tok) if matches!(tok.kind, TokenKind::JinjaExprOpen) => {
                    // Consume the entire Jinja expression: {{ ... }}
                    let tok = self
                        .advance()
                        .expect_invariant("JinjaExprOpen token available after peek");
                    end = tok.span.end;
                    // Skip tokens until we find the closing }}
                    while let Some(inner_tok) = self.peek() {
                        if matches!(inner_tok.kind, TokenKind::JinjaExprClose) {
                            let close = self
                                .advance()
                                .expect_invariant("JinjaExprClose token available after peek");
                            end = close.span.end;
                            break;
                        } else {
                            let inner = self.advance().expect_invariant(
                                "Jinja expression inner token available after peek",
                            );
                            end = inner.span.end;
                        }
                    }
                }
                Some(tok) if matches!(tok.kind, TokenKind::JinjaStmtOpen) => {
                    // Consume the entire Jinja statement block: {% ... %}
                    let tok = self
                        .advance()
                        .expect_invariant("JinjaStmtOpen token available after peek");
                    end = tok.span.end;
                    // Skip tokens until we find the closing %}
                    while let Some(inner_tok) = self.peek() {
                        if matches!(inner_tok.kind, TokenKind::JinjaStmtClose) {
                            let close = self
                                .advance()
                                .expect_invariant("JinjaStmtClose token available after peek");
                            end = close.span.end;
                            break;
                        } else {
                            let inner = self.advance().expect_invariant(
                                "Jinja statement inner token available after peek",
                            );
                            end = inner.span.end;
                        }
                    }
                }
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::StringFragment)
                    ) =>
                {
                    let tok = self
                        .advance()
                        .expect_invariant("StringFragment token available after peek");
                    end = tok.span.end;
                    // Check if this fragment ends the string (contains closing quote)
                    if tok.lexeme(self.source).ends_with('\'') {
                        break;
                    }
                }
                _ => {
                    // Unexpected token or EOF - the string wasn't properly closed
                    // This is an error case, but for robustness we'll just stop here
                    break;
                }
            }
        }

        Ok(AstExpr::Literal {
            node_id: self.id_gen.next(),
            literal: AstLiteral::StringWithJinja {
                span: Span { start, end },
            },
        })
    }

    /// Check if the current position starts a lambda parameter list: (x, y) ->
    /// This peeks ahead to find matching paren and arrow without consuming tokens
    fn is_lambda_params(&self) -> bool {
        // Current token should be LParen
        if !matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
        ) {
            return false;
        }

        // Scan for matching RParen, then check for ->
        let mut depth = 0;
        let mut offset = 0;

        loop {
            let Some(tok) = self.peek_ahead(offset) else {
                return false;
            };

            match &tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        // Found matching RParen, check next token for ->
                        let next = self.peek_ahead(offset + 1);
                        return next.is_some_and(|t| {
                            matches!(
                                t.kind,
                                TokenKind::Operator(crate::lexer::Operator::RightArrow)
                            )
                        });
                    }
                }
                TokenKind::Eof => return false,
                _ => {}
            }
            offset += 1;

            // Sanity limit to avoid infinite loops
            if offset > 100 {
                return false;
            }
        }
    }

    /// Parse a lambda expression with parenthesized parameters: (x, y) -> expr
    fn parse_lambda_arg(&mut self) -> ParseResult<crate::ast::AstFunctionArg> {
        // Consume LParen
        let lparen = self
            .advance()
            .expect_invariant("LParen expected for lambda");
        let start = lparen.span.start;

        let mut params = Vec::new();

        // Parse parameter list
        while let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                // Empty params or end of params
                break;
            }

            // Expect identifier
            if self.can_be_identifier_token(tok) {
                let param_tok = self
                    .advance()
                    .expect_invariant("lambda parameter identifier available after peek");
                params.push(crate::ast::AstIdentifier {
                    node_id: self.id_gen.next(),
                    span: param_tok.span,
                });

                // Check for comma or rparen
                if let Some(next) = self.peek() {
                    if matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) {
                        self.advance(); // consume comma
                        continue;
                    } else if matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        break;
                    }
                }
            } else {
                break; // Not an identifier, stop
            }
        }

        // Consume RParen
        let _rparen = self.advance(); // RParen

        // Consume -> arrow
        let arrow = self.advance().expect_invariant("Arrow expected for lambda");

        // Parse lambda body
        let body = self.parse_expr_with_recovery()?;
        let end = body.span().end;

        Ok(crate::ast::AstFunctionArg::Lambda {
            params,
            arrow_span: arrow.span,
            body: Box::new(body),
            span: Span { start, end },
        })
    }

    /// Parse optional IGNORE NULLS / RESPECT NULLS clause for window functions
    /// Returns Some((is_ignore, span, ignore_respect_token_id, nulls_token_id))
    fn parse_null_handling(
        &mut self,
    ) -> Option<(bool, Span, crate::cst::TokenId, crate::cst::TokenId)> {
        let first_tok = self.peek()?;

        // Check for IGNORE or RESPECT
        let is_ignore = if first_tok.lexeme(self.source).eq_ignore_ascii_case("IGNORE") {
            true
        } else if first_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("RESPECT")
        {
            false
        } else {
            return None;
        };

        let ignore_respect_token_id = self.current_token_id();
        let start = self.advance()?.span.start;

        // Expect NULLS
        let nulls_tok = self.peek()?;
        if !nulls_tok.lexeme(self.source).eq_ignore_ascii_case("NULLS")
            && !matches!(nulls_tok.kind, TokenKind::Keyword(Keyword::Nulls))
        {
            // Not a null handling clause, rewind
            self.idx -= 1;
            return None;
        }

        let nulls_token_id = self.current_token_id();
        let end = self.advance()?.span.end;

        Some((
            is_ignore,
            Span { start, end },
            ignore_respect_token_id,
            nulls_token_id,
        ))
    }

    /// Parse IGNORE NULLS / RESPECT NULLS inside function parentheses (alternate Snowflake syntax)
    /// e.g., LAST_VALUE(expr IGNORE NULLS) OVER (...)
    /// This is called after parsing an argument, before checking for comma/rparen.
    /// Returns Some((is_ignore, span, token_id1, token_id2)) if found.
    fn parse_null_handling_inside_parens(
        &mut self,
    ) -> Option<(bool, Span, crate::cst::TokenId, crate::cst::TokenId)> {
        let first_tok = self.peek()?;

        // Check for IGNORE or RESPECT (these are parsed as Identifier, not Keyword)
        let is_ignore = if first_tok.lexeme(self.source).eq_ignore_ascii_case("IGNORE") {
            true
        } else if first_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("RESPECT")
        {
            false
        } else {
            return None;
        };

        // Peek ahead to verify NULLS follows
        let nulls_tok = self.peek_ahead(1)?;
        if !nulls_tok.lexeme(self.source).eq_ignore_ascii_case("NULLS")
            && !matches!(nulls_tok.kind, TokenKind::Keyword(Keyword::Nulls))
        {
            return None;
        }

        // Also verify that after NULLS we have ) - this distinguishes from other uses of IGNORE
        let after_nulls = self.peek_ahead(2)?;
        if !matches!(
            after_nulls.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return None;
        }

        // Now consume both tokens
        let ignore_respect_token_id = self.current_token_id();
        let start = self.advance()?.span.start;

        let nulls_token_id = self.current_token_id();
        let end = self.advance()?.span.end;

        Some((
            is_ignore,
            Span { start, end },
            ignore_respect_token_id,
            nulls_token_id,
        ))
    }

    /// Parse a FILTER (WHERE expr) clause on an aggregate or window function.
    /// Returns Ok(Some(AstFilterClause)) if FILTER keyword is present, Ok(None) if not.
    /// Grammar: FILTER ( WHERE filter_expr )
    fn parse_filter_clause(&mut self) -> ParseResult<Option<Box<crate::ast::AstFilterClause>>> {
        // FILTER is an Identifier, not a Keyword
        let filter_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        if !filter_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("FILTER")
        {
            return Ok(None);
        }
        let filter_span_start = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FILTER".to_string()])?
            .span
            .start;

        // Expect (
        let lparen_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lparen_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lparen_tok.span,
                vec!["(".to_string()],
                Parser::token_description(lparen_tok, self.source),
            ));
        }
        let _ = self.advance();

        // Expect WHERE keyword
        let where_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["WHERE".to_string()])?;
        if !matches!(where_tok.kind, TokenKind::Keyword(Keyword::Where)) {
            return Err(ParseError::unexpected_token(
                where_tok.span,
                vec!["WHERE".to_string()],
                Parser::token_description(where_tok, self.source),
            ));
        }
        let _ = self.advance();

        // Parse filter predicate expression
        let expr = self.parse_expr()?;

        // Expect )
        let rparen_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rparen_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rparen_tok.span,
                vec![")".to_string()],
                Parser::token_description(rparen_tok, self.source),
            ));
        }
        let rparen_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?
            .span;

        let span = Span {
            start: filter_span_start,
            end: rparen_span.end,
        };

        Ok(Some(Box::new(crate::ast::AstFilterClause {
            node_id: self.id_gen.next(),
            expr: Box::new(expr),
            span,
        })))
    }

    /// Parse a WITHIN GROUP clause: WITHIN GROUP (ORDER BY expr [ASC|DESC], ...)
    /// Returns Ok(Some(AstWithinGroup)) if present, Ok(None) if not.
    fn parse_within_group(&mut self) -> ParseResult<Option<Box<crate::ast::AstWithinGroup>>> {
        // Check for WITHIN keyword
        let within_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        if !within_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("WITHIN")
        {
            return Ok(None);
        }
        let within_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["WITHIN".to_string()])?
            .span;

        // Expect GROUP keyword
        let group_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["GROUP".to_string()])?;
        if !group_tok.lexeme(self.source).eq_ignore_ascii_case("GROUP") {
            return Err(ParseError::unexpected_token(
                group_tok.span,
                vec!["GROUP".to_string()],
                Parser::token_description(group_tok, self.source),
            ));
        }
        let group_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["GROUP".to_string()])?
            .span;

        // Expect (
        let lparen_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lparen_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lparen_tok.span,
                vec!["(".to_string()],
                Parser::token_description(lparen_tok, self.source),
            ));
        }
        let _ = self.advance();

        // Expect ORDER BY
        let order_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["ORDER".to_string()])?;
        if !matches!(order_tok.kind, TokenKind::Keyword(Keyword::Order)) {
            return Err(ParseError::unexpected_token(
                order_tok.span,
                vec!["ORDER".to_string()],
                Parser::token_description(order_tok, self.source),
            ));
        }
        let _ = self.advance();

        let by_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["BY".to_string()])?;
        if !by_tok.lexeme(self.source).eq_ignore_ascii_case("BY") {
            return Err(ParseError::unexpected_token(
                by_tok.span,
                vec!["BY".to_string()],
                Parser::token_description(by_tok, self.source),
            ));
        }
        let _ = self.advance();

        // Parse ORDER BY items
        let mut order_items: Vec<crate::ast::AstOrderItem> = Vec::new();
        loop {
            // Use shared parse_order_by_item method for consistency
            let item = self.parse_order_by_item()?.ok_or_else(|| {
                ParseError::unexpected_eof(self.current_span(), vec!["ORDER BY item".to_string()])
            })?;
            order_items.push(item);

            // Check for comma (more items) or closing paren
            if let Some(tok) = self.peek() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    let _ = self.advance();
                    continue;
                }
            }
            break;
        }

        // Expect closing )
        let rparen = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
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
        let rparen_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?
            .span;

        let span = Span {
            start: within_span.start,
            end: rparen_span.end,
        };

        Ok(Some(Box::new(crate::ast::AstWithinGroup {
            node_id: self.id_gen.next(),
            within_span,
            group_span,
            order_by: order_items,
            span,
        })))
    }

    /// Parse a window specification: OVER (PARTITION BY ... ORDER BY ... ROWS ...)
    /// Returns (over_span, window_spec) where over_span covers from OVER to closing )
    ///
    /// null_handling_tokens: Optional (ignore_respect_token_id, nulls_token_id) from caller
    pub(crate) fn parse_window_spec_opt(
        &mut self,
        null_handling_tokens: Option<(crate::cst::TokenId, crate::cst::TokenId)>,
    ) -> Option<ParseResult<(Span, crate::ast::AstWindowSpec)>> {
        use crate::syntax::SyntaxOverClause;

        // Expect OVER keyword
        let over_kw = self.peek()?;
        if !matches!(over_kw.kind, TokenKind::Keyword(Keyword::Over)) {
            return None;
        }
        // Capture token ID BEFORE advancing
        let over_token_id = self.current_token_id();
        let over_start = self.advance()?.span.start;

        // Check what follows OVER: either '(' for parenthesized spec, or identifier for bare ref
        let next = self.peek()?;
        if !matches!(
            next.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            // Bare window reference: OVER w (PostgreSQL / Databricks)
            // In Snowflake, OVER must always be followed by '('.
            if self.dialect.supports_named_window_clause()
                && matches!(next.kind, TokenKind::Identifier { .. })
            {
                let name_span = next.span;
                let over_end = name_span.end;
                self.advance(); // consume the identifier

                let over_span = Span {
                    start: over_start,
                    end: over_end,
                };

                // Create syntax node for bare OVER w (no parens)
                let syntax_over_clause = SyntaxOverClause {
                    null_handling_keyword: null_handling_tokens.map(|(tok1, _)| tok1),
                    nulls_keyword: null_handling_tokens.map(|(_, tok2)| tok2),
                    over_keyword: Some(over_token_id),
                    l_paren: None,
                    partition_keyword: None,
                    partition_by_keyword: None,
                    order_keyword: None,
                    order_by_keyword: None,
                    r_paren: None,
                    span: over_span,
                };

                let syntax_id = self.syntax_arena.alloc_over_clause(syntax_over_clause);

                let window_spec = crate::ast::AstWindowSpec {
                    node_id: self.id_gen.next(),
                    syntax_id,
                    existing_window_name: Some(name_span),
                    partition_by: Vec::new(),
                    order_by: Vec::new(),
                    frame: None,
                };

                return Some(Ok((over_span, window_spec)));
            }
            // Not an identifier after OVER and not '(' - return None (not a window spec)
            return None;
        }

        // Parenthesized form: OVER (...)
        self.parse_parenthesized_window_spec(
            null_handling_tokens,
            Some(over_token_id),
            Some(over_start),
        )
    }

    /// Parse a parenthesized window specification with the cursor at `(`:
    /// `( [existing_name] [PARTITION BY ...] [ORDER BY ...] [frame] )`.
    /// Shared by inline `OVER (...)` and the named `WINDOW w AS (...)` clause
    /// (`over_token_id` / `over_start` are absent in the named form).
    pub(crate) fn parse_parenthesized_window_spec(
        &mut self,
        null_handling_tokens: Option<(crate::cst::TokenId, crate::cst::TokenId)>,
        over_token_id: Option<crate::cst::TokenId>,
        over_start: Option<u32>,
    ) -> Option<ParseResult<(Span, crate::ast::AstWindowSpec)>> {
        use crate::cst::TokenId;
        use crate::syntax::SyntaxOverClause;

        // Capture token ID BEFORE advancing
        let lparen_token_id = self.current_token_id();
        let lparen_span = self.advance()?.span;
        let over_start = over_start.unwrap_or(lparen_span.start);

        let mut partition_by: Vec<AstExpr> = Vec::new();
        let mut order_items: Vec<AstOrderItem> = Vec::new();
        let mut frame_opt: Option<crate::ast::AstWindowFrame> = None;
        let mut over_end = lparen_span.end;
        let mut rparen_token_id = lparen_token_id; // Will be updated when we find the closing paren
        let mut existing_window_name: Option<Span> = None;

        // Token ID tracking for syntax layer
        let mut partition_keyword_id: Option<TokenId> = None;
        let mut partition_by_keyword_id: Option<TokenId> = None;
        let mut order_keyword_id: Option<TokenId> = None;
        let mut order_by_keyword_id: Option<TokenId> = None;

        // Check for existing window name reference: OVER (w ORDER BY ...)
        // PostgreSQL / Databricks only — an identifier at the start of the spec
        // that refines a named window.
        if self.dialect.supports_named_window_clause() {
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Identifier { .. }) {
                    let lexeme = tok.lexeme(self.source);
                    // Make sure it's not a keyword-like identifier that starts a clause
                    if !lexeme.eq_ignore_ascii_case("PARTITION")
                        && !lexeme.eq_ignore_ascii_case("ROWS")
                        && !lexeme.eq_ignore_ascii_case("RANGE")
                        && !lexeme.eq_ignore_ascii_case("GROUPS")
                    {
                        existing_window_name = Some(tok.span);
                        self.advance(); // consume the window name
                    }
                }
            }
        }

        // Parse window spec components
        while let Some(tok) = self.peek() {
            match &tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    rparen_token_id = self.current_token_id();
                    let rparen_span = self.advance()?.span;
                    over_end = rparen_span.end;
                    break;
                }
                TokenKind::Keyword(Keyword::Partition) => {
                    partition_keyword_id = Some(self.current_token_id());
                    let _partition_tok = self.advance()?;
                    // After PARTITION, we MUST see BY - otherwise it's a syntax error
                    partition_by_keyword_id = Some(self.current_token_id());
                    let by_tok = self.advance()?;
                    if !by_tok.lexeme(self.source).eq_ignore_ascii_case("BY") {
                        // Syntax error: PARTITION must be followed by BY
                        return Some(Err(ParseError::unexpected_token(
                            by_tok.span,
                            vec!["BY".to_string()],
                            by_tok.lexeme(self.source).to_string(),
                        )));
                    }
                    loop {
                        let expr = match self.parse_expr() {
                            Ok(e) => e,
                            Err(e) => return Some(Err(e)),
                        };
                        partition_by.push(expr);
                        if let Some(comma) = self.peek() {
                            if matches!(
                                comma.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                let _ = self.advance();
                                continue;
                            }
                        }
                        break;
                    }
                }
                TokenKind::Keyword(Keyword::Order) => {
                    order_keyword_id = Some(self.current_token_id());
                    let _order_tok = self.advance()?;
                    // After ORDER, we MUST see BY - otherwise it's a syntax error
                    order_by_keyword_id = Some(self.current_token_id());
                    let by_tok = self.advance()?;
                    if !by_tok.lexeme(self.source).eq_ignore_ascii_case("BY") {
                        // Syntax error: ORDER must be followed by BY
                        return Some(Err(ParseError::unexpected_token(
                            by_tok.span,
                            vec!["BY".to_string()],
                            by_tok.lexeme(self.source).to_string(),
                        )));
                    }
                    loop {
                        // Use shared helper with ExprMode::Sql for window functions
                        let item = match self.parse_order_by_item() {
                            Ok(Some(item)) => item,
                            Ok(None) => break,
                            Err(e) => return Some(Err(e)),
                        };
                        order_items.push(item);

                        if let Some(comma) = self.peek() {
                            if matches!(
                                comma.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                let _ = self.advance();
                                continue;
                            }
                        }
                        break;
                    }
                }
                TokenKind::Keyword(Keyword::Rows) => {
                    let rows_tok = self.advance()?;
                    let rows_span = rows_tok.span;

                    // Check if next token is BETWEEN or a shorthand bound
                    let next_tok = self.peek();
                    let has_between = next_tok
                        .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("BETWEEN"));

                    if has_between {
                        // Full syntax: ROWS BETWEEN <start> AND <end>
                        let between_tok = self.advance()?;
                        let between_span = between_tok.span;

                        // Parse start bound: UNBOUNDED PRECEDING | N PRECEDING | CURRENT ROW
                        let start_bound = if let Some(first_tok) = self.peek() {
                            if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Unbounded))
                                || first_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("UNBOUNDED")
                            {
                                // UNBOUNDED PRECEDING
                                let unbounded_tok = self.advance()?;
                                let prec_tok = self.advance()?;
                                let is_prec =
                                    matches!(prec_tok.kind, TokenKind::Keyword(Keyword::Preceding))
                                        || prec_tok
                                            .lexeme(self.source)
                                            .eq_ignore_ascii_case("PRECEDING");
                                if !is_prec {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::UnboundedPreceding,
                                    value: None,
                                    span: Span {
                                        start: unbounded_tok.span.start,
                                        end: prec_tok.span.end,
                                    },
                                }
                            } else if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Current))
                                || first_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("CURRENT")
                            {
                                // CURRENT ROW
                                let current_tok = self.advance()?;
                                let row_tok = self.advance()?;
                                let is_row =
                                    matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row))
                                        || row_tok.lexeme(self.source).eq_ignore_ascii_case("ROW");
                                if !is_row {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::CurrentRow,
                                    value: None,
                                    span: Span {
                                        start: current_tok.span.start,
                                        end: row_tok.span.end,
                                    },
                                }
                            } else if matches!(first_tok.kind, TokenKind::Literal { .. }) {
                                // N PRECEDING or N FOLLOWING
                                let value_expr = match self.parse_expr() {
                                    Ok(e) => e,
                                    Err(_) => break,
                                };
                                let value_span_start = value_expr.span().start;
                                if let Some(dir_tok) = self.advance() {
                                    if matches!(
                                        dir_tok.kind,
                                        TokenKind::Keyword(Keyword::Preceding)
                                    ) || dir_tok
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("PRECEDING")
                                    {
                                        crate::ast::AstFrameBound {
                                            node_id: self.id_gen.next(),
                                            kind: crate::ast::AstFrameBoundKind::Preceding,
                                            value: Some(Box::new(value_expr)),
                                            span: Span {
                                                start: value_span_start,
                                                end: dir_tok.span.end,
                                            },
                                        }
                                    } else if matches!(
                                        dir_tok.kind,
                                        TokenKind::Keyword(Keyword::Following)
                                    ) || dir_tok
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("FOLLOWING")
                                    {
                                        crate::ast::AstFrameBound {
                                            node_id: self.id_gen.next(),
                                            kind: crate::ast::AstFrameBoundKind::Following,
                                            value: Some(Box::new(value_expr)),
                                            span: Span {
                                                start: value_span_start,
                                                end: dir_tok.span.end,
                                            },
                                        }
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        };

                        // Parse AND
                        let and_tok = self.advance()?;
                        let and_span = and_tok.span;
                        if !and_tok.lexeme(self.source).eq_ignore_ascii_case("AND") {
                            break;
                        }

                        // Parse end bound: CURRENT ROW | N FOLLOWING | UNBOUNDED FOLLOWING
                        let end_bound = if let Some(end_tok) = self.peek() {
                            if matches!(end_tok.kind, TokenKind::Keyword(Keyword::Current))
                                || end_tok.lexeme(self.source).eq_ignore_ascii_case("CURRENT")
                            {
                                // CURRENT ROW
                                let current_tok = self.advance()?;
                                let row_tok = self.advance()?;
                                let is_row =
                                    matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row))
                                        || row_tok.lexeme(self.source).eq_ignore_ascii_case("ROW");
                                if !is_row {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::CurrentRow,
                                    value: None,
                                    span: Span {
                                        start: current_tok.span.start,
                                        end: row_tok.span.end,
                                    },
                                }
                            } else if matches!(end_tok.kind, TokenKind::Keyword(Keyword::Unbounded))
                                || end_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("UNBOUNDED")
                            {
                                // UNBOUNDED FOLLOWING
                                let unbounded_tok = self.advance()?;
                                let foll_tok = self.advance()?;
                                let is_foll =
                                    matches!(foll_tok.kind, TokenKind::Keyword(Keyword::Following))
                                        || foll_tok
                                            .lexeme(self.source)
                                            .eq_ignore_ascii_case("FOLLOWING");
                                if !is_foll {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::UnboundedFollowing,
                                    value: None,
                                    span: Span {
                                        start: unbounded_tok.span.start,
                                        end: foll_tok.span.end,
                                    },
                                }
                            } else if matches!(end_tok.kind, TokenKind::Literal { .. }) {
                                // N FOLLOWING
                                let value_expr = match self.parse_expr() {
                                    Ok(e) => e,
                                    Err(_) => break,
                                };
                                let value_span_start = value_expr.span().start;
                                let foll_tok = self.advance()?;
                                let is_foll =
                                    matches!(foll_tok.kind, TokenKind::Keyword(Keyword::Following))
                                        || foll_tok
                                            .lexeme(self.source)
                                            .eq_ignore_ascii_case("FOLLOWING");
                                if !is_foll {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::Following,
                                    value: Some(Box::new(value_expr)),
                                    span: Span {
                                        start: value_span_start,
                                        end: foll_tok.span.end,
                                    },
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        };

                        frame_opt = Some(crate::ast::AstWindowFrame {
                            node_id: self.id_gen.next(),
                            kind_span: rows_span,
                            kind: crate::ast::AstWindowFrameKind::Rows,
                            between_span: Some(between_span),
                            start: start_bound,
                            and_span: Some(and_span),
                            end: Some(end_bound),
                        });
                    } else {
                        // Shorthand syntax: ROWS UNBOUNDED PRECEDING | ROWS N PRECEDING | ROWS CURRENT ROW
                        // Parse the single bound
                        let bound = if let Some(tok) = self.peek() {
                            if matches!(tok.kind, TokenKind::Keyword(Keyword::Unbounded))
                                || tok.lexeme(self.source).eq_ignore_ascii_case("UNBOUNDED")
                            {
                                let unbounded_tok = self.advance()?;
                                let prec_tok = self.advance()?;
                                if !matches!(prec_tok.kind, TokenKind::Keyword(Keyword::Preceding))
                                    && !prec_tok
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("PRECEDING")
                                {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::UnboundedPreceding,
                                    value: None,
                                    span: Span {
                                        start: unbounded_tok.span.start,
                                        end: prec_tok.span.end,
                                    },
                                }
                            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Current))
                                || tok.lexeme(self.source).eq_ignore_ascii_case("CURRENT")
                            {
                                let current_tok = self.advance()?;
                                let row_tok = self.advance()?;
                                if !matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row))
                                    && !row_tok.lexeme(self.source).eq_ignore_ascii_case("ROW")
                                {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::CurrentRow,
                                    value: None,
                                    span: Span {
                                        start: current_tok.span.start,
                                        end: row_tok.span.end,
                                    },
                                }
                            } else if matches!(tok.kind, TokenKind::Literal { .. }) {
                                let value_expr = match self.parse_expr() {
                                    Ok(e) => e,
                                    Err(_) => break,
                                };
                                let value_span_start = value_expr.span().start;
                                let dir_tok = self.advance()?;
                                if matches!(dir_tok.kind, TokenKind::Keyword(Keyword::Preceding))
                                    || dir_tok
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("PRECEDING")
                                {
                                    crate::ast::AstFrameBound {
                                        node_id: self.id_gen.next(),
                                        kind: crate::ast::AstFrameBoundKind::Preceding,
                                        value: Some(Box::new(value_expr)),
                                        span: Span {
                                            start: value_span_start,
                                            end: dir_tok.span.end,
                                        },
                                    }
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        };

                        frame_opt = Some(crate::ast::AstWindowFrame {
                            node_id: self.id_gen.next(),
                            kind_span: rows_span,
                            kind: crate::ast::AstWindowFrameKind::Rows,
                            between_span: None,
                            start: bound,
                            and_span: None,
                            end: None,
                        });
                    }
                }
                TokenKind::Keyword(Keyword::Range) => {
                    let range_tok = self.advance()?;
                    let range_span = range_tok.span;

                    // Check if next token is BETWEEN or a shorthand bound
                    let next_tok = self.peek();
                    let has_between = next_tok
                        .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("BETWEEN"));

                    if has_between {
                        // Full syntax: RANGE BETWEEN <start> AND <end>
                        let between_tok = self.advance()?;
                        let between_span = between_tok.span;

                        // Parse start bound - same logic as ROWS but handle INTERVAL expressions
                        let start_bound = if let Some(first_tok) = self.peek() {
                            if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Unbounded))
                                || first_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("UNBOUNDED")
                            {
                                // UNBOUNDED PRECEDING
                                let unbounded_tok = self.advance()?;
                                let prec_tok = self.advance()?;
                                let is_prec =
                                    matches!(prec_tok.kind, TokenKind::Keyword(Keyword::Preceding))
                                        || prec_tok
                                            .lexeme(self.source)
                                            .eq_ignore_ascii_case("PRECEDING");
                                if !is_prec {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::UnboundedPreceding,
                                    value: None,
                                    span: Span {
                                        start: unbounded_tok.span.start,
                                        end: prec_tok.span.end,
                                    },
                                }
                            } else if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Current))
                                || first_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("CURRENT")
                            {
                                // CURRENT ROW
                                let current_tok = self.advance()?;
                                let row_tok = self.advance()?;
                                let is_row =
                                    matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row))
                                        || row_tok.lexeme(self.source).eq_ignore_ascii_case("ROW");
                                if !is_row {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::CurrentRow,
                                    value: None,
                                    span: Span {
                                        start: current_tok.span.start,
                                        end: row_tok.span.end,
                                    },
                                }
                            } else {
                                // INTERVAL '...' DAY/HOUR/etc PRECEDING/FOLLOWING or numeric N PRECEDING/FOLLOWING
                                let value_expr = match self.parse_expr() {
                                    Ok(e) => e,
                                    Err(_) => break,
                                };
                                let value_span_start = value_expr.span().start;

                                // Check for PRECEDING or FOLLOWING
                                if let Some(dir_tok) = self.advance() {
                                    if matches!(
                                        dir_tok.kind,
                                        TokenKind::Keyword(Keyword::Preceding)
                                    ) || dir_tok
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("PRECEDING")
                                    {
                                        crate::ast::AstFrameBound {
                                            node_id: self.id_gen.next(),
                                            kind: crate::ast::AstFrameBoundKind::Preceding,
                                            value: Some(Box::new(value_expr)),
                                            span: Span {
                                                start: value_span_start,
                                                end: dir_tok.span.end,
                                            },
                                        }
                                    } else if matches!(
                                        dir_tok.kind,
                                        TokenKind::Keyword(Keyword::Following)
                                    ) || dir_tok
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("FOLLOWING")
                                    {
                                        crate::ast::AstFrameBound {
                                            node_id: self.id_gen.next(),
                                            kind: crate::ast::AstFrameBoundKind::Following,
                                            value: Some(Box::new(value_expr)),
                                            span: Span {
                                                start: value_span_start,
                                                end: dir_tok.span.end,
                                            },
                                        }
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        } else {
                            break;
                        };

                        // Parse AND
                        let and_tok = self.advance()?;
                        let and_span = and_tok.span;
                        if !and_tok.lexeme(self.source).eq_ignore_ascii_case("AND") {
                            break;
                        }

                        // Parse end bound
                        let end_bound = if let Some(end_tok) = self.peek() {
                            if matches!(end_tok.kind, TokenKind::Keyword(Keyword::Current))
                                || end_tok.lexeme(self.source).eq_ignore_ascii_case("CURRENT")
                            {
                                // CURRENT ROW
                                let current_tok = self.advance()?;
                                let row_tok = self.advance()?;
                                let is_row =
                                    matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row))
                                        || row_tok.lexeme(self.source).eq_ignore_ascii_case("ROW");
                                if !is_row {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::CurrentRow,
                                    value: None,
                                    span: Span {
                                        start: current_tok.span.start,
                                        end: row_tok.span.end,
                                    },
                                }
                            } else if matches!(end_tok.kind, TokenKind::Keyword(Keyword::Unbounded))
                                || end_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("UNBOUNDED")
                            {
                                // UNBOUNDED FOLLOWING
                                let unbounded_tok = self.advance()?;
                                let foll_tok = self.advance()?;
                                let is_foll =
                                    matches!(foll_tok.kind, TokenKind::Keyword(Keyword::Following))
                                        || foll_tok
                                            .lexeme(self.source)
                                            .eq_ignore_ascii_case("FOLLOWING");
                                if !is_foll {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::UnboundedFollowing,
                                    value: None,
                                    span: Span {
                                        start: unbounded_tok.span.start,
                                        end: foll_tok.span.end,
                                    },
                                }
                            } else {
                                // INTERVAL '...' DAY/HOUR/etc FOLLOWING or N FOLLOWING
                                let value_expr = match self.parse_expr() {
                                    Ok(e) => e,
                                    Err(_) => break,
                                };
                                let value_span_start = value_expr.span().start;
                                let foll_tok = self.advance()?;
                                let is_foll =
                                    matches!(foll_tok.kind, TokenKind::Keyword(Keyword::Following))
                                        || foll_tok
                                            .lexeme(self.source)
                                            .eq_ignore_ascii_case("FOLLOWING");
                                if !is_foll {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::Following,
                                    value: Some(Box::new(value_expr)),
                                    span: Span {
                                        start: value_span_start,
                                        end: foll_tok.span.end,
                                    },
                                }
                            }
                        } else {
                            break;
                        };

                        frame_opt = Some(crate::ast::AstWindowFrame {
                            node_id: self.id_gen.next(),
                            kind_span: range_span,
                            kind: crate::ast::AstWindowFrameKind::Range,
                            between_span: Some(between_span),
                            start: start_bound,
                            and_span: Some(and_span),
                            end: Some(end_bound),
                        });
                    } else {
                        // Shorthand syntax: RANGE <single_bound>
                        // This is shorthand for: RANGE BETWEEN <bound> AND CURRENT ROW
                        let bound = if let Some(first_tok) = self.peek() {
                            if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Unbounded))
                                || first_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("UNBOUNDED")
                            {
                                // UNBOUNDED PRECEDING
                                let unbounded_tok = self.advance()?;
                                let prec_tok = self.advance()?;
                                let is_prec =
                                    matches!(prec_tok.kind, TokenKind::Keyword(Keyword::Preceding))
                                        || prec_tok
                                            .lexeme(self.source)
                                            .eq_ignore_ascii_case("PRECEDING");
                                if !is_prec {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::UnboundedPreceding,
                                    value: None,
                                    span: Span {
                                        start: unbounded_tok.span.start,
                                        end: prec_tok.span.end,
                                    },
                                }
                            } else if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Current))
                                || first_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("CURRENT")
                            {
                                // CURRENT ROW
                                let current_tok = self.advance()?;
                                let row_tok = self.advance()?;
                                let is_row =
                                    matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row))
                                        || row_tok.lexeme(self.source).eq_ignore_ascii_case("ROW");
                                if !is_row {
                                    break;
                                }
                                crate::ast::AstFrameBound {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::AstFrameBoundKind::CurrentRow,
                                    value: None,
                                    span: Span {
                                        start: current_tok.span.start,
                                        end: row_tok.span.end,
                                    },
                                }
                            } else {
                                // INTERVAL '...' DAY/HOUR/etc PRECEDING or N PRECEDING
                                let value_expr = match self.parse_expr() {
                                    Ok(e) => e,
                                    Err(_) => break,
                                };
                                let value_span_start = value_expr.span().start;

                                // Check for PRECEDING
                                if let Some(dir_tok) = self.advance() {
                                    if matches!(
                                        dir_tok.kind,
                                        TokenKind::Keyword(Keyword::Preceding)
                                    ) || dir_tok
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("PRECEDING")
                                    {
                                        crate::ast::AstFrameBound {
                                            node_id: self.id_gen.next(),
                                            kind: crate::ast::AstFrameBoundKind::Preceding,
                                            value: Some(Box::new(value_expr)),
                                            span: Span {
                                                start: value_span_start,
                                                end: dir_tok.span.end,
                                            },
                                        }
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        } else {
                            break;
                        };

                        frame_opt = Some(crate::ast::AstWindowFrame {
                            node_id: self.id_gen.next(),
                            kind_span: range_span,
                            kind: crate::ast::AstWindowFrameKind::Range,
                            between_span: None, // Shorthand has no BETWEEN
                            start: bound,
                            and_span: None, // Shorthand has no AND
                            end: None,      // Shorthand has no explicit end (implicit CURRENT ROW)
                        });
                    }
                }
                _ => break,
            }
        }

        let over_span = Span {
            start: over_start,
            end: over_end,
        };

        // Create the syntax node that owns all structural tokens
        let syntax_over_clause = SyntaxOverClause {
            null_handling_keyword: null_handling_tokens.map(|(tok1, _)| tok1),
            nulls_keyword: null_handling_tokens.map(|(_, tok2)| tok2),
            over_keyword: over_token_id,
            l_paren: Some(lparen_token_id),
            partition_keyword: partition_keyword_id,
            partition_by_keyword: partition_by_keyword_id,
            order_keyword: order_keyword_id,
            order_by_keyword: order_by_keyword_id,
            r_paren: Some(rparen_token_id),
            span: over_span,
        };

        // Allocate in the syntax arena and get the ID
        let syntax_id = self.syntax_arena.alloc_over_clause(syntax_over_clause);

        let window_spec = crate::ast::AstWindowSpec {
            node_id: self.id_gen.next(),
            syntax_id,
            existing_window_name,
            partition_by,
            order_by: order_items,
            frame: frame_opt.map(Box::new),
        };

        Some(Ok((over_span, window_spec)))
    }
}
