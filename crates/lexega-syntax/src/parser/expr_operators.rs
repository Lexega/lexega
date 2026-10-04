// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Binary and unary operator parsing with precedence handling.
//!
//! Implements a Pratt parser for expression precedence:
//! - Arithmetic: `+`, `-`, `*`, `/`, `%`
//! - Comparison: `=`, `<>`, `<`, `>`, `<=`, `>=`
//! - Logical: `AND`, `OR`, `NOT`
//! - String: `||` (concatenation), `LIKE`, `ILIKE`
//! - Set membership: `IN`, `NOT IN`, `BETWEEN`
//! - NULL checks: `IS NULL`, `IS NOT NULL`
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/operators>

use crate::ast::{AstExpr, AstLiteral, AstQuantifier};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, Token, TokenKind};
use crate::parser::core::{track_depth, Parser};
use crate::parser::expr::{
    compound_predicate_binding_power, flatten_logical_chains, infix_binding_power,
    is_expr_terminator,
};

impl<'a> Parser<'a> {
    /// Map a token to a BinaryOperator enum variant.
    ///
    /// Handles normalization (e.g., both `!=` and `<>` map to `NotEqual`).
    /// Returns None for tokens that are not binary operators.
    pub(crate) fn token_to_binary_operator(
        &self,
        tok: &Token,
    ) -> Option<crate::ast::BinaryOperator> {
        use crate::ast::BinaryOperator;
        use crate::lexer::{Keyword, Operator};

        match &tok.kind {
            // Arithmetic operators
            TokenKind::Operator(Operator::Plus) => Some(BinaryOperator::Plus),
            TokenKind::Operator(Operator::Minus) => Some(BinaryOperator::Minus),
            TokenKind::Operator(Operator::Star) => Some(BinaryOperator::Multiply),
            TokenKind::Operator(Operator::Slash) => Some(BinaryOperator::Divide),
            TokenKind::Operator(Operator::Percent) => Some(BinaryOperator::Modulo),

            // Comparison operators (normalize aliases)
            TokenKind::Operator(Operator::Eq) => Some(BinaryOperator::Equal),
            TokenKind::Operator(Operator::NotEq) | TokenKind::Operator(Operator::AngleNotEq) => {
                Some(BinaryOperator::NotEqual)
            }
            TokenKind::Operator(Operator::Lt) => Some(BinaryOperator::LessThan),
            TokenKind::Operator(Operator::Le) => Some(BinaryOperator::LessThanOrEqual),
            TokenKind::Operator(Operator::LtEqGt) => Some(BinaryOperator::NullSafeEqual),
            TokenKind::Operator(Operator::Gt) => Some(BinaryOperator::GreaterThan),
            TokenKind::Operator(Operator::Ge) => Some(BinaryOperator::GreaterThanOrEqual),

            // Logical operators
            TokenKind::Keyword(Keyword::And) => Some(BinaryOperator::And),
            TokenKind::Keyword(Keyword::Or) => Some(BinaryOperator::Or),
            TokenKind::Keyword(Keyword::Not) => Some(BinaryOperator::Not),

            // || operator: dialect-dependent semantics
            TokenKind::Operator(Operator::PipePipe) => {
                if self.dialect.pipe_pipe_is_concat() {
                    Some(BinaryOperator::Concat)
                } else {
                    Some(BinaryOperator::LogicalOr)
                }
            }

            // Pattern matching operators
            TokenKind::Keyword(Keyword::Like) => Some(BinaryOperator::Like),
            TokenKind::Keyword(Keyword::Ilike) => Some(BinaryOperator::ILike),
            TokenKind::Keyword(Keyword::Rlike) => Some(BinaryOperator::RLike),
            TokenKind::Keyword(Keyword::Regexp) => Some(BinaryOperator::RLike), // REGEXP is alias for RLIKE

            // PostgreSQL geometric operators
            TokenKind::Operator(Operator::LtMinusGt) => Some(BinaryOperator::Distance),

            // PostgreSQL array operators
            TokenKind::Operator(Operator::AtGt) => Some(BinaryOperator::ArrayContains),
            TokenKind::Operator(Operator::LtAt) => Some(BinaryOperator::ArrayContainedBy),
            TokenKind::Operator(Operator::AmpAmp) => Some(BinaryOperator::ArrayOverlap),

            // PostgreSQL / MySQL JSON operators (lexer uses RightArrow for ->).
            // `->>` lexes to `MinusGtGt` only in JSON dialects (the lexer makes
            // that dialect decision); elsewhere it stays `Pipe`, the pipe-chain
            // operator, and is not a binary operator here.
            TokenKind::Operator(Operator::RightArrow) => Some(BinaryOperator::JsonField),
            TokenKind::Operator(Operator::MinusGtGt) => Some(BinaryOperator::JsonFieldText),
            TokenKind::Operator(Operator::HashGt) => Some(BinaryOperator::JsonPath),
            TokenKind::Operator(Operator::HashGtGt) => Some(BinaryOperator::JsonPathText),
            TokenKind::Operator(Operator::AtQuestion) => Some(BinaryOperator::JsonContains),
            TokenKind::Operator(Operator::QuestionQuestion) => Some(BinaryOperator::JsonExists),

            // PostgreSQL regex operators
            TokenKind::Operator(Operator::Tilde) | TokenKind::Operator(Operator::RegexMatch) => {
                Some(BinaryOperator::RegexMatch)
            }
            TokenKind::Operator(Operator::RegexMatchI) => Some(BinaryOperator::RegexMatchI),
            TokenKind::Operator(Operator::RegexNotMatch) => Some(BinaryOperator::RegexNotMatch),
            TokenKind::Operator(Operator::RegexNotMatchI) => Some(BinaryOperator::RegexNotMatchI),

            // Bitwise operators
            TokenKind::Operator(Operator::LtLt) => Some(BinaryOperator::LeftShift),
            TokenKind::Operator(Operator::GtGt) => Some(BinaryOperator::RightShift),
            TokenKind::Operator(Operator::Caret) => Some(BinaryOperator::BitwiseXor),
            TokenKind::Operator(Operator::Hash) => Some(BinaryOperator::BitwiseXorPg),

            _ => None,
        }
    }

    pub(crate) fn parse_mul_expr_in_mode(&mut self) -> ParseResult<AstExpr> {
        let _guard = track_depth("parse_mul_expr_in_mode", self.current_span())?;

        // Allow a leading spread operator at multiplicative precedence so
        // forms like "col IN (** [1,2,3])" parse correctly. If the first
        // token is "**", build a Spread node around the following primary
        // expression, otherwise parse a normal primary expression.
        let mut expr = if let Some(tok) = self.peek() {
            match &tok.kind {
                TokenKind::Operator(crate::lexer::Operator::StarStar) => {
                    let stars_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["** operator".to_string()],
                        )
                    })?;
                    let inner = self.parse_primary_expr_in_mode()?;
                    let span = Span {
                        start: stars_tok.span.start,
                        end: stars_tok.span.end,
                    };
                    AstExpr::Spread {
                        stars_span: stars_tok.span,
                        expr: Box::new(inner),
                        span,
                        node_id: self.id_gen.next(),
                    }
                }
                _ => self.parse_primary_expr_in_mode()?,
            }
        } else {
            return Err(ParseError::unexpected_eof(
                self.current_span(),
                vec!["expression".to_string()],
            ));
        };

        // Handle postfix operators: ::, [], :field, ['field']
        // These can chain: data:items[0]:price
        while let Some(tok) = self.peek() {
            match &tok.kind {
                // :: type cast operator (PostgreSQL-style) - non-repeating, terminates postfix chain
                TokenKind::Operator(crate::lexer::Operator::ColonColon) => {
                    let colons_token_id = self.current_token_id();
                    let colons_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["::".to_string()])?;
                    let target_type = self.parse_data_type().ok_or_else(|| {
                        ParseError::invalid_expression(
                            self.current_span(),
                            "Expected type after :: cast operator".to_string(),
                        )
                    })??;
                    let span = Span {
                        start: crate::parser::scripting::expr_span_start(&expr),
                        end: self.data_type_span_end(&target_type),
                    };

                    // Build and allocate syntax node for type cast
                    let syntax_type_cast = crate::syntax::SyntaxTypeCast {
                        double_colon: colons_token_id,
                        span: colons_tok.span,
                    };
                    let syntax_id = self.syntax_arena.alloc_type_cast(syntax_type_cast);

                    expr = AstExpr::TypeCast {
                        node_id: self.id_gen.next(),
                        syntax_id,
                        expr: Box::new(expr),
                        target_type,
                        span,
                    };
                    // Continue loop to allow chained casts like ::NUMBER::TIMESTAMP
                }

                // Array subscript: expr[index] or Object field bracket notation: expr['field']
                // Special case: ARRAY[...] is a PostgreSQL array constructor, not a subscript
                TokenKind::Punctuation(crate::lexer::Punctuation::LBracket) => {
                    // Check if this is ARRAY[...] constructor (PostgreSQL syntax)
                    // We need to check if the preceding expression is a simple identifier "ARRAY"
                    let is_array_constructor = if let AstExpr::Ident { column_ref, .. } = &expr {
                        if column_ref.qualifier.is_none() {
                            // Find the token at the identifier's span position
                            let ident_span = column_ref.name.span;
                            self.tokens.iter().any(|t| {
                                t.span == ident_span
                                    && t.lexeme(self.source).eq_ignore_ascii_case("ARRAY")
                            })
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    let lbracket_token_id = self.current_token_id();
                    let lbracket_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["[".to_string()])?;

                    if is_array_constructor {
                        // Parse PostgreSQL ARRAY[elem1, elem2, ...] constructor
                        let array_start = crate::parser::scripting::expr_span_start(&expr);
                        let mut elements: Vec<AstExpr> = Vec::new();

                        loop {
                            let next = self.peek().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["]".to_string()],
                                )
                            })?;

                            match &next.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::RBracket) => {
                                    let rbracket_token_id = self.current_token_id();
                                    let rb = self.advance().expect_invariant(
                                        "RBracket confirmed by peek in ARRAY constructor",
                                    );
                                    let span = Span {
                                        start: array_start,
                                        end: rb.span.end,
                                    };

                                    // Build syntax node for array literal
                                    let syntax_array = crate::syntax::SyntaxArrayLiteral {
                                        l_bracket: lbracket_token_id,
                                        r_bracket: rbracket_token_id,
                                        span,
                                    };
                                    let syntax_id =
                                        self.syntax_arena.alloc_array_literal(syntax_array);

                                    // Replace the ARRAY identifier with an Array expression
                                    // array_keyword_span covers just the ARRAY keyword (no type params)
                                    let kw_span = if let AstExpr::Ident { column_ref, .. } = &expr {
                                        Some(column_ref.name.span)
                                    } else {
                                        None
                                    };
                                    expr = AstExpr::Array {
                                        syntax_id,
                                        elements,
                                        span,
                                        node_id: self.id_gen.next(),
                                        has_array_keyword: true,
                                        array_keyword_span: kw_span,
                                    };
                                    break;
                                }
                                _ => {
                                    let elem = self.parse_expr()?;
                                    elements.push(elem);

                                    if let Some(sep) = self.peek() {
                                        match sep.kind {
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::Comma,
                                            ) => {
                                                let _ = self.advance();
                                            }
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::RBracket,
                                            ) => {
                                                continue;
                                            }
                                            _ => {
                                                return Err(ParseError::unexpected_token(
                                                    sep.span,
                                                    vec![",".to_string(), "]".to_string()],
                                                    Parser::token_description(sep, self.source),
                                                ));
                                            }
                                        }
                                    } else {
                                        return Err(ParseError::new(
                                            lbracket_tok.span,
                                            ParseErrorKind::UnexpectedEof {
                                                expected: vec![",".to_string(), "]".to_string()],
                                            },
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        // Normal array subscript or object field bracket notation
                        let index_or_field = self.parse_expr()?;
                        let rbracket_token_id = self.current_token_id();
                        let rbracket_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["]".to_string()])?;
                        if !matches!(
                            rbracket_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RBracket)
                        ) {
                            return Err(ParseError::unexpected_token(
                                rbracket_tok.span,
                                vec!["]".to_string()],
                                Parser::token_description(rbracket_tok, self.source),
                            ));
                        }
                        let span = Span {
                            start: crate::parser::scripting::expr_span_start(&expr),
                            end: rbracket_tok.span.end,
                        };

                        // Distinguish between array subscript and object field bracket notation
                        // based on whether the index expression is a string literal
                        match &index_or_field {
                            AstExpr::Literal {
                                node_id: _,
                                literal: AstLiteral::String { .. },
                            } => {
                                // Build and allocate syntax node for object field bracket
                                let syntax_bracket = crate::syntax::SyntaxBracketField {
                                    l_bracket: lbracket_token_id,
                                    r_bracket: rbracket_token_id,
                                    span,
                                };
                                let syntax_id =
                                    self.syntax_arena.alloc_bracket_field(syntax_bracket);

                                expr = AstExpr::ObjectFieldBracket {
                                    node_id: self.id_gen.next(),
                                    syntax_id,
                                    base: Box::new(expr),
                                    field: Box::new(index_or_field),
                                    span,
                                };
                            }
                            _ => {
                                // Build and allocate syntax node for array subscript
                                let syntax_subscript = crate::syntax::SyntaxArraySubscript {
                                    l_bracket: lbracket_token_id,
                                    r_bracket: rbracket_token_id,
                                    span,
                                };
                                let syntax_id =
                                    self.syntax_arena.alloc_array_subscript(syntax_subscript);

                                expr = AstExpr::ArraySubscript {
                                    node_id: self.id_gen.next(),
                                    syntax_id,
                                    base: Box::new(expr),
                                    index: Box::new(index_or_field),
                                    span,
                                };
                            }
                        }
                    }
                }

                // Object field colon notation: expr:field
                // In postfix position (after an expression), : is always field access,
                // even in Scripting mode. Variable references (:var) only occur at
                // the START of an expression, not as postfix operators.
                TokenKind::Punctuation(crate::lexer::Punctuation::Colon) => {
                    let colon_token_id = self.current_token_id();
                    let colon_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![":".to_string()])?;
                    let field_tok = self.peek().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["field name after :".to_string()],
                        )
                    })?;

                    // Field must be an identifier, keyword (keywords can be field names in semi-structured data),
                    // or quoted identifier from string literal
                    match &field_tok.kind {
                        TokenKind::Identifier { .. }
                        | TokenKind::Keyword(_)
                        | TokenKind::Literal(crate::lexer::LiteralKind::String) => {
                            let field = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["field name".to_string()])?;
                            let span = Span {
                                start: crate::parser::scripting::expr_span_start(&expr),
                                end: field.span.end,
                            };

                            // Build and allocate syntax node for colon field access
                            let syntax_colon = crate::syntax::SyntaxColonField {
                                colon: colon_token_id,
                                span: colon_tok.span,
                            };
                            let syntax_id = self.syntax_arena.alloc_colon_field(syntax_colon);

                            expr = AstExpr::ObjectFieldColon {
                                node_id: self.id_gen.next(),
                                syntax_id,
                                base: Box::new(expr),
                                field_span: field.span,
                                span,
                            };
                        }
                        _ => {
                            // Not a valid field access, rewind and stop postfix chain
                            self.idx -= 1;
                            break;
                        }
                    }
                }

                // Object field dot notation: expr.field
                // This handles Snowflake semi-structured data access like data['key'].subfield
                // Note: In primary expression parsing, we handle qualified identifiers (table.column)
                // directly. This branch handles dot access on arbitrary expressions, especially
                // after bracket access like data['foo'].bar or after function calls.
                TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                    let dot_token_id = self.current_token_id();
                    let dot_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![".".to_string()])?;
                    let field_tok = self.peek().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["field name after .".to_string()],
                        )
                    })?;

                    // Field must be an identifier or keyword (keywords can be field names in semi-structured data)
                    match &field_tok.kind {
                        TokenKind::Identifier { .. } | TokenKind::Keyword(_) => {
                            let field = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["field name".to_string()])?;

                            // Build and allocate syntax node for dot field access
                            let syntax_dot = crate::syntax::SyntaxDotField {
                                dot: dot_token_id,
                                span: dot_tok.span,
                            };
                            let syntax_id = self.syntax_arena.alloc_dot_field(syntax_dot);

                            // Check if this is a method call: expr.method(args)
                            // e.g., (SELECT ... FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)')
                            if let Some(next) = self.peek() {
                                if matches!(
                                    next.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                ) {
                                    // Method call — consume ( args )
                                    let lparen = self
                                        .advance()
                                        .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                                    let lparen_span = lparen.span;
                                    let mut args = Vec::new();
                                    loop {
                                        if let Some(t) = self.peek() {
                                            if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::RParen
                                                )
                                            ) {
                                                break;
                                            }
                                        } else {
                                            return Err(ParseError::unexpected_eof(
                                                self.current_span(),
                                                vec![")".to_string()],
                                            ));
                                        }
                                        let arg = self.parse_expr()?;
                                        args.push(arg);
                                        if let Some(t) = self.peek() {
                                            if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::Comma
                                                )
                                            ) {
                                                self.advance(); // consume comma
                                            }
                                        }
                                    }
                                    let rparen = self
                                        .advance()
                                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                                    let span = Span {
                                        start: crate::parser::scripting::expr_span_start(&expr),
                                        end: rparen.span.end,
                                    };
                                    expr = AstExpr::MethodCall {
                                        node_id: self.id_gen.next(),
                                        syntax_id,
                                        base: Box::new(expr),
                                        method_name_span: field.span,
                                        args,
                                        lparen_span,
                                        rparen_span: rparen.span,
                                        span,
                                    };
                                    continue;
                                }
                            }

                            // Plain field access: expr.field
                            let span = Span {
                                start: crate::parser::scripting::expr_span_start(&expr),
                                end: field.span.end,
                            };

                            expr = AstExpr::ObjectFieldDot {
                                node_id: self.id_gen.next(),
                                syntax_id,
                                base: Box::new(expr),
                                field_span: field.span,
                                span,
                            };
                        }
                        // Handle expr.* (qualified star from expression)
                        TokenKind::Operator(crate::lexer::Operator::Star) => {
                            let star = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["*".to_string()])?;
                            let span = Span {
                                start: crate::parser::scripting::expr_span_start(&expr),
                                end: star.span.end,
                            };
                            // Wrap as QualifiedStar with expr as qualifier
                            // For now, treat expr as base for a qualified star reference
                            expr = AstExpr::QualifiedStarFromExpr {
                                node_id: self.id_gen.next(),
                                base: Box::new(expr),
                                star_span: star.span,
                                span,
                            };
                        }
                        _ => {
                            // Not a valid field access, rewind and stop postfix chain
                            self.idx -= 1;
                            break;
                        }
                    }
                }

                // COLLATE 'spec' - postfix collation operator
                TokenKind::Identifier { .. }
                    if tok.lexeme(self.source).eq_ignore_ascii_case("COLLATE") =>
                {
                    let collate_token_id = self.current_token_id();
                    let collate_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["COLLATE".to_string()])?;

                    // Expect a string literal for the collation specification
                    let spec_tok = self.peek().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["collation specification string".to_string()],
                        )
                    })?;

                    if !matches!(
                        spec_tok.kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::String)
                    ) {
                        return Err(ParseError::unexpected_token(
                            spec_tok.span,
                            vec!["collation specification string (e.g., 'en-ci')".to_string()],
                            Parser::token_description(spec_tok, self.source),
                        ));
                    }

                    let spec_token_id = self.current_token_id();
                    let spec_tok = self.advance().ok_or_eof(
                        self.current_span(),
                        vec!["collation specification".to_string()],
                    )?;

                    let span = Span {
                        start: crate::parser::scripting::expr_span_start(&expr),
                        end: spec_tok.span.end,
                    };

                    // Build and allocate syntax node for COLLATE
                    let syntax_collate = crate::syntax::SyntaxCollate {
                        collate_keyword: collate_token_id,
                        spec_literal: spec_token_id,
                        span: Span {
                            start: collate_tok.span.start,
                            end: spec_tok.span.end,
                        },
                    };
                    let syntax_id = self.syntax_arena.alloc_collate(syntax_collate);

                    expr = AstExpr::Collate {
                        node_id: self.id_gen.next(),
                        syntax_id,
                        expr: Box::new(expr),
                        span,
                    };
                    // COLLATE does NOT terminate the chain - you can do col COLLATE 'en'::VARCHAR
                }

                // AGAINST (...) — MySQL full-text predicate, valid only as a
                // postfix on a call named MATCH. Unambiguous (nothing else is
                // legal there), so recognition is ungated like ON CONFLICT.
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::Unquoted,
                } if tok.lexeme(self.source).eq_ignore_ascii_case("AGAINST")
                    && matches!(
                        &expr,
                        AstExpr::FunctionCall { func_name, .. }
                            if self
                                .source
                                .get(func_name.span.start as usize..func_name.span.end as usize)
                                .is_some_and(|n| n.eq_ignore_ascii_case("MATCH"))
                    )
                    && self.peek_ahead(1).is_some_and(|t| {
                        matches!(
                            t.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        )
                    }) =>
                {
                    expr = self.parse_against_postfix(expr)?;
                    break; // AGAINST terminates the postfix chain
                }

                // WITH ( schema ) — MSSQL TVF schema clause (OPENJSON, OPENXML, etc.)
                // Only valid after a FunctionCall, and only when WITH is followed by '('.
                // Builds TvfWithSchema AST node that wraps the function call.
                TokenKind::Keyword(crate::lexer::Keyword::With)
                    if matches!(expr, AstExpr::FunctionCall { .. })
                        && self.peek_ahead(1).is_some_and(|t| {
                            matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            )
                        }) =>
                {
                    let base_span = expr.span();
                    let with_tok = self.advance().expect_invariant("WITH confirmed by peek");
                    let with_start = with_tok.span.start;

                    // Consume balanced (...)
                    let _lparen = self
                        .advance()
                        .expect_invariant("LParen confirmed by peek_ahead");
                    let mut depth: u32 = 1;
                    let mut end = _lparen.span.end;

                    while depth > 0 {
                        let t = self.advance().ok_or_else(|| {
                            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
                        })?;
                        match t.kind {
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                depth -= 1;
                                if depth == 0 {
                                    end = t.span.end;
                                }
                            }
                            TokenKind::Eof => {
                                return Err(ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec![")".to_string()],
                                ));
                            }
                            _ => {}
                        }
                    }

                    let with_schema_span = Span {
                        start: with_start,
                        end,
                    };
                    let full_span = Span {
                        start: base_span.start,
                        end,
                    };

                    expr = AstExpr::TvfWithSchema {
                        node_id: self.id_gen.next(),
                        func_call: Box::new(expr),
                        with_schema_span,
                        span: full_span,
                    };
                }

                // OVER keyword: window function spec after expression.
                // Handles two cases:
                //   1. func(...) OVER (...) — bare function call followed by OVER:
                //      Destructures FunctionCall into WindowFn (preserves all existing behavior).
                //   2. <any_other_expr> OVER (...) — e.g., BigQuery's
                //      APPROX_QUANTILES(val, 100)[OFFSET(50)] OVER (PARTITION BY grp):
                //      Wraps the expression in WindowExpr, preserving source order exactly.
                TokenKind::Keyword(crate::lexer::Keyword::Over) => {
                    match expr {
                        // ODBC-marked calls (`{fn F(x)}`) fall to Case 2: the braced
                        // span is surface-frozen, so the WindowFn conversion (which
                        // re-derives spans from inner CST tokens) must not apply.
                        AstExpr::FunctionCall {
                            node_id: fc_node_id,
                            syntax_id: fc_syntax_id,
                            odbc_fn: false,
                            func_name,
                            quantifier,
                            args,
                            order_by_span: _,
                            inline_order_by: _,
                            separator_span: fc_separator_span,
                            within_group,
                            filter,
                            approximate: fc_approximate,
                            span: fc_span,
                        } => {
                            // Case 1: bare function call → build WindowFn (existing behavior)
                            let syntax_fc = self.syntax_arena.get_function_call(fc_syntax_id);
                            let lparen_span = self.tokens[syntax_fc.l_paren.0 as usize].span;
                            let rparen_span = self.tokens[syntax_fc.r_paren.0 as usize].span;
                            // Preserve the Redshift APPROXIMATE modifier across the
                            // FunctionCall → WindowFn conversion. WindowFn carries it as
                            // a span; recover it from the CST token captured on the call.
                            let approximate_window_span = if fc_approximate {
                                syntax_fc
                                    .approximate_keyword
                                    .map(|t| self.tokens[t.0 as usize].span)
                            } else {
                                None
                            };

                            let quantifier_with_span = quantifier.as_ref().map(|q| {
                                let q_span = if let Some(tok_id) = syntax_fc.distinct_keyword {
                                    self.tokens[tok_id.0 as usize].span
                                } else {
                                    fc_span // fallback
                                };
                                (q.clone(), q_span)
                            });

                            match self.parse_window_spec_opt(None) {
                                Some(Ok((over_span, window_spec))) => {
                                    let window_span = Span {
                                        start: fc_span.start,
                                        end: over_span.end,
                                    };
                                    expr = AstExpr::WindowFn {
                                        node_id: self.id_gen.next(),
                                        func_name,
                                        approximate: approximate_window_span,
                                        lparen_span,
                                        quantifier: quantifier_with_span,
                                        args,
                                        rparen_span,
                                        within_group,
                                        filter,
                                        null_handling: None,
                                        over_span,
                                        window: Box::new(window_spec),
                                        span: window_span,
                                    };
                                }
                                Some(Err(e)) => return Err(e),
                                None => {
                                    // No OVER clause after all — reconstruct FunctionCall
                                    expr = AstExpr::FunctionCall {
                                        node_id: fc_node_id,
                                        syntax_id: fc_syntax_id,
                                        approximate: fc_approximate,
                                        odbc_fn: false,
                                        func_name,
                                        quantifier,
                                        args,
                                        order_by_span: None,
                                        inline_order_by: None,
                                        separator_span: fc_separator_span,
                                        within_group,
                                        filter,
                                        span: fc_span,
                                    };
                                    break;
                                }
                            }
                        }
                        other_expr => {
                            // Case 2: non-FunctionCall expression (e.g., ArraySubscript)
                            // → wrap in WindowExpr, preserving source order exactly.
                            let base_span = other_expr.span();
                            match self.parse_window_spec_opt(None) {
                                Some(Ok((over_span, window_spec))) => {
                                    let full_span = Span {
                                        start: base_span.start,
                                        end: over_span.end,
                                    };
                                    expr = AstExpr::WindowExpr {
                                        node_id: self.id_gen.next(),
                                        base: Box::new(other_expr),
                                        over_span,
                                        window: Box::new(window_spec),
                                        span: full_span,
                                    };
                                }
                                Some(Err(e)) => return Err(e),
                                None => {
                                    // No OVER clause — put expression back and break
                                    expr = other_expr;
                                    break;
                                }
                            }
                        }
                    }
                }

                _ => break, // No more postfix operators
            }
        }

        // Multiplicative operators (*, /, %) are now handled by the Pratt parser in parse_expr_bp
        // This function only handles postfix operators (::, [], :field) and returns to let
        // the Pratt parser handle all infix operators with proper precedence.
        Ok(expr)
    }

    /// Parse `AGAINST ('search' [modifier])` after a MATCH(...) call.
    /// Caller has verified: current token is AGAINST and the next is `(`.
    /// Modifiers: IN BOOLEAN MODE / IN NATURAL LANGUAGE MODE
    /// [WITH QUERY EXPANSION] / WITH QUERY EXPANSION.
    fn parse_against_postfix(&mut self, match_call: AstExpr) -> ParseResult<AstExpr> {
        let against_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AGAINST".to_string()])?;
        let against_span = against_tok.span;
        let lparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        let lparen_span = lparen_tok.span;

        // Parse below comparison level: the modifier starts with IN
        // (`IN BOOLEAN MODE`), which parse_expr would swallow as an
        // IN-list predicate.
        let search = self.parse_add_expr_in_mode()?;

        // Optional search modifier.
        let modifier = self.parse_against_modifier()?;

        let rparen_tok = self.peek().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
        })?;
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
        let rparen_span = rparen_tok.span;
        self.advance();

        let span = Span {
            start: crate::parser::scripting::expr_span_start(&match_call),
            end: rparen_span.end,
        };
        Ok(AstExpr::MatchAgainst {
            node_id: self.id_gen.next(),
            match_call: Box::new(match_call),
            against_span,
            lparen_span,
            search: Box::new(search),
            modifier,
            rparen_span,
            span,
        })
    }

    /// Parse the optional modifier inside AGAINST(...). Returns None when
    /// the next token is `)` (no modifier). Errors on a malformed modifier
    /// so the statement degrades to an honest opaque instead of shearing.
    fn parse_against_modifier(&mut self) -> ParseResult<Option<crate::ast::AstTextSearchModifier>> {
        use crate::ast::{AstTextSearchModifier, AstTextSearchModifierKind};

        let first = match self.peek() {
            Some(t) => t.clone(),
            None => return Ok(None),
        };
        // Helper: consume one token whose lexeme matches, else error.
        let expect_lexeme = |p: &mut Self, word: &str| -> ParseResult<Span> {
            let tok = p
                .peek()
                .ok_or_else(|| {
                    ParseError::unexpected_eof(p.current_span(), vec![word.to_string()])
                })?
                .clone();
            if !tok.lexeme(p.source).eq_ignore_ascii_case(word) {
                return Err(ParseError::unexpected_token(
                    tok.span,
                    vec![word.to_string()],
                    Parser::token_description(&tok, p.source),
                ));
            }
            p.advance();
            Ok(tok.span)
        };

        if matches!(first.kind, TokenKind::Keyword(Keyword::In)) {
            let start = first.span.start;
            self.advance(); // IN
            let next = self.peek().ok_or_else(|| {
                ParseError::unexpected_eof(
                    self.current_span(),
                    vec!["BOOLEAN".to_string(), "NATURAL".to_string()],
                )
            })?;
            if next.lexeme(self.source).eq_ignore_ascii_case("BOOLEAN") {
                self.advance();
                let mode_span = expect_lexeme(self, "MODE")?;
                return Ok(Some(AstTextSearchModifier {
                    kind: AstTextSearchModifierKind::Boolean,
                    span: Span {
                        start,
                        end: mode_span.end,
                    },
                }));
            }
            if matches!(next.kind, TokenKind::Keyword(Keyword::Natural)) {
                self.advance();
                expect_lexeme(self, "LANGUAGE")?;
                let mode_span = expect_lexeme(self, "MODE")?;
                // Optional WITH QUERY EXPANSION tail.
                if self
                    .peek()
                    .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::With)))
                {
                    self.advance();
                    expect_lexeme(self, "QUERY")?;
                    let exp_span = expect_lexeme(self, "EXPANSION")?;
                    return Ok(Some(AstTextSearchModifier {
                        kind: AstTextSearchModifierKind::NaturalLanguageQueryExpansion,
                        span: Span {
                            start,
                            end: exp_span.end,
                        },
                    }));
                }
                return Ok(Some(AstTextSearchModifier {
                    kind: AstTextSearchModifierKind::NaturalLanguage,
                    span: Span {
                        start,
                        end: mode_span.end,
                    },
                }));
            }
            return Err(ParseError::unexpected_token(
                next.span,
                vec!["BOOLEAN".to_string(), "NATURAL".to_string()],
                Parser::token_description(next, self.source),
            ));
        }
        if matches!(first.kind, TokenKind::Keyword(Keyword::With)) {
            let start = first.span.start;
            self.advance(); // WITH
            expect_lexeme(self, "QUERY")?;
            let exp_span = expect_lexeme(self, "EXPANSION")?;
            return Ok(Some(AstTextSearchModifier {
                kind: AstTextSearchModifierKind::QueryExpansion,
                span: Span {
                    start,
                    end: exp_span.end,
                },
            }));
        }
        Ok(None)
    }

    pub(crate) fn parse_cmp_expr_in_mode(&mut self) -> ParseResult<AstExpr> {
        let mut expr = self.parse_add_expr_in_mode()?;
        while let Some(tok) = self.peek() {
            // Stop comparison parsing if we hit CASE control keywords that belong to the
            // surrounding CASE expression rather than this comparison.
            if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Then)
                    | TokenKind::Keyword(Keyword::Else)
                    | TokenKind::Keyword(Keyword::End)
            ) {
                break;
            }
            // [NOT] IN predicate: <expr> [NOT] IN (expr, expr, ...) or (SELECT ...)
            // Check for IN or (NOT IN) - but NOT if NOT is followed by LIKE/BETWEEN
            let is_not_followed_by_in = if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                // Look ahead to see what follows NOT
                let save_idx = self.idx;
                let _ = self.advance(); // consume NOT
                let next_is_in = if let Some(next) = self.peek() {
                    matches!(next.kind, TokenKind::Keyword(Keyword::In))
                } else {
                    false
                };
                self.idx = save_idx; // restore position
                next_is_in
            } else {
                false
            };

            if matches!(tok.kind, TokenKind::Keyword(Keyword::In)) || is_not_followed_by_in {
                let mut not_span: Option<Span> = None;
                let mut not_token_id: Option<crate::cst::TokenId> = None;
                // Handle optional NOT before IN. Capture token ID before advancing.
                let first_token_id = self.current_token_id();
                let first_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["IN".to_string()])?;
                let in_tok = match &first_tok.kind {
                    TokenKind::Keyword(Keyword::Not) => {
                        not_span = Some(first_tok.span);
                        not_token_id = Some(first_token_id); // Assign captured NOT token ID
                        let next = self.peek().ok_or_else(|| {
                            ParseError::unexpected_eof(
                                self.current_span(),
                                vec!["IN after NOT".to_string()],
                            )
                        })?;
                        match &next.kind {
                            TokenKind::Keyword(Keyword::In) => {
                                let _in_token_id = self.current_token_id(); // Captured in variable above
                                self.advance()
                                    .ok_or_eof(self.current_span(), vec!["IN".to_string()])?
                            }
                            _ => {
                                // This should not happen due to our lookahead check above
                                self.idx -= 1;
                                break;
                            }
                        }
                    }
                    TokenKind::Keyword(Keyword::In) => {
                        // first_tok is IN, so we already captured its ID
                        first_tok
                    }
                    _ => {
                        // Not an IN predicate; rewind and stop comparisons.
                        self.idx -= 1;
                        break;
                    }
                };
                // The IN token ID is either first_token_id (if no NOT) or captured above
                let in_token_id = if not_token_id.is_some() {
                    // IN came after NOT, so we need to get last_token_id
                    self.last_token_id()
                } else {
                    // IN is first_tok, so use first_token_id
                    first_token_id
                };
                // Expect opening parenthesis for the list or subquery.
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
                let lparen_token_id = self.last_token_id(); // Capture after advance
                                                            // Peek to decide between IN(list), IN(subquery), and IN(VALUES):
                                                            // if the next token starts a SELECT or VALUES, treat as subquery.
                if let Some(next) = self.peek() {
                    if matches!(
                        next.kind,
                        TokenKind::Keyword(Keyword::Select) | TokenKind::Keyword(Keyword::Values)
                    ) {
                        // Parse subquery/VALUES using natural descent
                        let subquery = if matches!(next.kind, TokenKind::Keyword(Keyword::Values)) {
                            self.try_parse_values_query_stmt()?
                        } else {
                            self.try_parse_set_or_select_stmt()?
                        };

                        // Expect closing paren
                        let rparen = if let Some(tok) = self.advance() {
                            if !matches!(
                                tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                return Err(ParseError::unexpected_token(
                                    tok.span,
                                    vec![")".to_string()],
                                    Parser::token_description(tok, self.source),
                                ));
                            }
                            tok
                        } else {
                            return Err(ParseError::unexpected_eof(
                                self.current_span(),
                                vec![") after subquery".to_string()],
                            ));
                        };
                        let rparen_token_id = self.last_token_id();

                        let left_start = crate::parser::scripting::expr_span_start(&expr);
                        let span = Span {
                            start: match not_span {
                                Some(s) => s.start.min(left_start),
                                None => left_start,
                            },
                            end: rparen.span.end,
                        };

                        // Build and allocate syntax node for IN subquery
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

                        expr = AstExpr::InSubquery {
                            syntax_id,
                            expr: Box::new(expr),
                            subquery: Box::new(subquery),
                            negated: not_token_id.is_some(),
                            span,
                            node_id: self.id_gen.next(),
                        };
                    } else {
                        // IN(list) case: Check if list contains Jinja control flow
                        // Dead code: contains_jinja_in_parens always returns false
                        let has_jinja = false;

                        if has_jinja {
                            // Opaque mode: capture content between parens as opaque span
                            let list_span = Span { start: 0, end: 0 }; // Dead code

                            let rp = self
                                .advance()
                                .expect_invariant("RParen should be available");
                            let left_start = crate::parser::scripting::expr_span_start(&expr);
                            let span = Span {
                                start: match not_span {
                                    Some(s) => s.start.min(left_start),
                                    None => left_start,
                                },
                                end: rp.span.end,
                            };

                            expr = AstExpr::InListOpaque {
                                expr: Box::new(expr),
                                not_span,
                                in_span: in_tok.span,
                                list_span,
                                span,
                                node_id: self.id_gen.next(),
                            };
                        } else {
                            // Normal mode: parse individual expressions
                            let list = self
                                .parse_expr_list(|parser| parser.parse_add_expr_in_mode().ok())
                                .ok_or_else(|| {
                                    ParseError::invalid_expression(
                                        self.current_span(),
                                        "Failed to parse expression list for IN".to_string(),
                                    )
                                })?;

                            let rp = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
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

                            let rparen_token_id = self.last_token_id(); // Capture after advance

                            let left_start = crate::parser::scripting::expr_span_start(&expr);
                            let span = Span {
                                start: match not_span {
                                    Some(s) => s.start.min(left_start),
                                    None => left_start,
                                },
                                end: rp.span.end,
                            };

                            // Allocate syntax node
                            let syntax_in_list = crate::syntax::SyntaxInList {
                                not_keyword: not_token_id,
                                in_keyword: in_token_id,
                                l_paren: lparen_token_id,
                                r_paren: rparen_token_id,
                                span,
                            };
                            let syntax_id = self.syntax_arena.alloc_in_list(syntax_in_list);

                            expr = AstExpr::InList {
                                node_id: self.id_gen.next(),
                                syntax_id,
                                expr: Box::new(expr),
                                list,
                                negated: not_span.is_some(),
                                span,
                            };
                        }
                    }
                } else {
                    return Err(ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["expression or SELECT after (".to_string()],
                    ));
                }
                continue;
            }

            // IS [NOT] NULL predicate: <expr> IS [NOT] NULL
            // IS [NOT] DISTINCT FROM predicate: <expr1> IS [NOT] DISTINCT FROM <expr2>
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Is)) {
                let is_tok = self
                    .advance()
                    .expect_invariant("IS keyword confirmed by matches! check");
                let mut not_span: Option<Span> = None;

                // Check for optional NOT
                if let Some(next) = self.peek() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Not)) {
                        let not_tok = self.advance().expect_invariant(
                            "NOT keyword confirmed by matches! check in IS predicate",
                        );
                        not_span = Some(not_tok.span);
                    }
                }

                // Check what follows: NULL, DISTINCT, TRUE, FALSE, etc.
                match self.peek() {
                    Some(t)
                        if matches!(
                            t.kind,
                            TokenKind::Keyword(Keyword::Null)
                                | TokenKind::Literal(crate::lexer::LiteralKind::Null)
                        ) =>
                    {
                        // IS [NOT] NULL
                        let null_tok = self.advance().expect_invariant(
                            "NULL keyword confirmed by matches! check in IS NULL predicate",
                        );

                        let span = Span {
                            start: crate::parser::scripting::expr_span_start(&expr),
                            end: null_tok.span.end,
                        };

                        expr = AstExpr::IsNull {
                            node_id: self.id_gen.next(),
                            expr: Box::new(expr),
                            is_span: is_tok.span,
                            not_span,
                            null_span: null_tok.span,
                            span,
                        };
                        continue;
                    }
                    Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Distinct)) => {
                        // IS [NOT] DISTINCT FROM <expr>
                        let distinct_tok = self
                            .advance()
                            .expect_invariant("DISTINCT keyword confirmed by matches! check");

                        // Expect FROM keyword
                        let from_tok = match self.peek() {
                            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::From)) => {
                                self.advance().expect_invariant(
                                    "FROM keyword confirmed by matches! check in IS DISTINCT FROM",
                                )
                            }
                            _ => {
                                return Err(ParseError::new(
                                    self.current_span(),
                                    crate::error::ParseErrorKind::InvalidSyntax {
                                        message: "Expected FROM after IS [NOT] DISTINCT"
                                            .to_string(),
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

                        expr = AstExpr::IsDistinctFrom {
                            node_id: self.id_gen.next(),
                            left: Box::new(expr),
                            right: Box::new(right_expr),
                            is_span: is_tok.span,
                            not_span,
                            distinct_span: distinct_tok.span,
                            from_span: from_tok.span,
                            span,
                        };
                        continue;
                    }
                    _ => {
                        // Not IS NULL or IS DISTINCT FROM - could be IS TRUE, IS FALSE, etc.
                        // For now, just break and let it fail naturally
                        break;
                    }
                }
            }

            // [NOT] BETWEEN predicate: <expr> [NOT] BETWEEN lower AND upper
            // Check for BETWEEN or (NOT BETWEEN) - but NOT if NOT is followed by LIKE/IN
            let is_not_followed_by_between = if matches!(tok.kind, TokenKind::Keyword(Keyword::Not))
            {
                // Look ahead to see what follows NOT
                let save_idx = self.idx;
                let _ = self.advance(); // consume NOT
                let next_is_between = if let Some(next) = self.peek() {
                    matches!(next.kind, TokenKind::Keyword(Keyword::Between))
                } else {
                    false
                };
                self.idx = save_idx; // restore position
                next_is_between
            } else {
                false
            };

            if matches!(tok.kind, TokenKind::Keyword(Keyword::Between))
                || is_not_followed_by_between
            {
                let mut _not_span: Option<Span> = None;
                let mut not_token_id: Option<crate::cst::TokenId> = None;

                // Handle optional NOT before BETWEEN - capture token ID before advancing
                let first_token_id = self.current_token_id();
                let first_tok = self
                    .advance()
                    .expect_invariant("BETWEEN or NOT keyword confirmed by matches! check");
                let (_, between_token_id) = match &first_tok.kind {
                    TokenKind::Keyword(Keyword::Not) => {
                        _not_span = Some(first_tok.span);
                        not_token_id = Some(first_token_id);
                        let next = self.peek().ok_or_else(|| {
                            ParseError::unexpected_eof(
                                self.current_span(),
                                vec!["BETWEEN after NOT".to_string()],
                            )
                        })?;
                        match &next.kind {
                            TokenKind::Keyword(Keyword::Between) => {
                                let between_token_id = self.current_token_id();
                                let tok = self.advance().expect_invariant(
                                    "BETWEEN keyword confirmed by matches! check after NOT",
                                );
                                (tok, between_token_id)
                            }
                            _ => {
                                // This should not happen due to our lookahead check above
                                self.idx -= 1;
                                break;
                            }
                        }
                    }
                    TokenKind::Keyword(Keyword::Between) => (first_tok, first_token_id),
                    _ => {
                        // Not a BETWEEN predicate; rewind and stop comparisons.
                        self.idx -= 1;
                        break;
                    }
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

                // Parse lower bound (use add_expr to avoid re-entering comparison level)
                let lower = self.parse_add_expr_in_mode()?;

                // Expect AND keyword
                let and_token_id = self.current_token_id();
                let and_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["AND".to_string()])?;
                if !matches!(and_tok.kind, TokenKind::Keyword(Keyword::And)) {
                    return Err(ParseError::unexpected_token(
                        and_tok.span,
                        vec!["AND".to_string()],
                        Parser::token_description(and_tok, self.source),
                    ));
                }

                // Parse upper bound (use add_expr to avoid re-entering comparison level)
                let upper = self.parse_add_expr_in_mode()?;

                let span = Span {
                    start: crate::parser::scripting::expr_span_start(&expr),
                    end: crate::parser::scripting::expr_span_end(&upper),
                };

                // Build and allocate syntax node
                let syntax_between = crate::syntax::SyntaxBetweenExpr {
                    not_keyword: not_token_id,
                    between_keyword: between_token_id,
                    symmetric_keyword: symmetric_token_id,
                    and_keyword: and_token_id,
                    span,
                };
                let syntax_id = self.syntax_arena.alloc_between_expr(syntax_between);

                expr = AstExpr::Between {
                    node_id: self.id_gen.next(),
                    syntax_id,
                    expr: Box::new(expr),
                    lower: Box::new(lower),
                    upper: Box::new(upper),
                    negated: not_token_id.is_some(),
                    span,
                };
                continue;
            }

            // [NOT] LIKE/ILIKE/RLIKE/REGEXP predicate: <expr> [NOT] LIKE/ILIKE/RLIKE/REGEXP pattern [ESCAPE char]
            let is_like_op = matches!(
                tok.kind,
                TokenKind::Keyword(
                    Keyword::Like | Keyword::Ilike | Keyword::Rlike | Keyword::Regexp
                )
            );
            let mut not_span_for_like: Option<Span> = None;

            // Check for NOT before LIKE/ILIKE/RLIKE
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                // Look ahead to see if this is NOT LIKE/ILIKE/RLIKE
                let save_idx = self.idx;
                let _ = self.advance(); // consume NOT
                if let Some(next) = self.peek() {
                    if matches!(
                        next.kind,
                        TokenKind::Keyword(
                            Keyword::Like | Keyword::Ilike | Keyword::Rlike | Keyword::Regexp
                        )
                    ) {
                        // This is NOT LIKE/ILIKE/RLIKE/REGEXP
                        not_span_for_like = Some(tok.span);
                        // Don't restore idx, we've consumed the NOT
                    } else {
                        // Not a LIKE operator, restore position
                        self.idx = save_idx;
                    }
                } else {
                    self.idx = save_idx;
                }
            }

            let is_like = is_like_op || not_span_for_like.is_some();

            if is_like {
                let like_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["LIKE/ILIKE/RLIKE".to_string()])?;
                // Use parse_add_expr_in_mode instead of parse_expr to avoid recursion guard.
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

                expr = AstExpr::Like {
                    node_id: self.id_gen.next(),
                    expr: Box::new(expr),
                    not_span: not_span_for_like,
                    like_kind_span: like_tok.span,
                    pattern: Box::new(pattern),
                    escape_clause,
                    odbc_escape_span,
                    span,
                };
                continue;
            }

            // [NOT] SIMILAR TO predicate: <expr> [NOT] SIMILAR TO pattern [ESCAPE char]
            let is_similar_to_op = if let TokenKind::Identifier { .. } = &tok.kind {
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

            let mut not_span_for_similar: Option<Span> = None;

            if !is_similar_to_op && matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                let save_idx = self.idx;
                let _ = self.advance(); // consume NOT
                if let Some(next) = self.peek() {
                    if let TokenKind::Identifier { .. } = &next.kind {
                        if next.lexeme(self.source).eq_ignore_ascii_case("SIMILAR") {
                            let _ = self.advance(); // consume SIMILAR
                            if matches!(
                                self.peek().map(|t| &t.kind),
                                Some(TokenKind::Keyword(Keyword::To))
                            ) {
                                // This is NOT SIMILAR TO
                                not_span_for_similar = Some(tok.span);
                                // Restore to just after NOT (we'll re-consume SIMILAR below)
                                self.idx = save_idx + 1;
                            } else {
                                self.idx = save_idx;
                            }
                        } else {
                            self.idx = save_idx;
                        }
                    } else {
                        self.idx = save_idx;
                    }
                } else {
                    self.idx = save_idx;
                }
            }

            let is_similar = is_similar_to_op || not_span_for_similar.is_some();

            if is_similar {
                let similar_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["SIMILAR".to_string()])?;
                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
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

                expr = AstExpr::SimilarTo {
                    node_id: self.id_gen.next(),
                    expr: Box::new(expr),
                    not_span: not_span_for_similar,
                    similar_to_span,
                    pattern: Box::new(pattern),
                    escape_clause,
                    odbc_escape_span,
                    span,
                };
                continue;
            }

            let is_op = matches!(
                tok.kind,
                TokenKind::Operator(
                    crate::lexer::Operator::Eq
                        | crate::lexer::Operator::NotEq
                        | crate::lexer::Operator::AngleNotEq
                        | crate::lexer::Operator::Lt
                        | crate::lexer::Operator::Le
                        | crate::lexer::Operator::Gt
                        | crate::lexer::Operator::Ge
                        | crate::lexer::Operator::LtEqGt
                ),
            );
            if !is_op {
                break;
            }
            let op_token_id = self.current_token_id();
            let op_tok = self
                .advance()
                .expect_invariant("Comparison operator confirmed by is_op check");
            // Look for quantified subquery: <expr> <op> ANY/ALL (SELECT ...).
            // ANY and ALL are lexed as keywords, not identifiers.
            if let Some(qtok) = self.peek() {
                let quantifier = match &qtok.kind {
                    TokenKind::Keyword(Keyword::Any) => Some(AstQuantifier::Any),
                    TokenKind::Keyword(Keyword::All) => Some(AstQuantifier::All),
                    _ => None,
                };
                if let Some(q) = quantifier {
                    let quantifier_token_id = self.current_token_id();
                    let _qtok = self.advance().expect_invariant(
                        "ANY/ALL quantifier confirmed by match in parse_cmp_expr_in_mode",
                    );
                    // Expect opening parenthesis.
                    let lp = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
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
                    // Next token must start SELECT for quantified subquery.
                    if let Some(next) = self.peek() {
                        if matches!(next.kind, TokenKind::Keyword(Keyword::Select)) {
                            // Parse subquery using natural descent
                            let subquery = self.try_parse_set_or_select_stmt()?;

                            // Expect closing paren
                            let rparen = if let Some(tok) = self.advance() {
                                if !matches!(
                                    tok.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                ) {
                                    return Err(ParseError::unexpected_token(
                                        tok.span,
                                        vec![")".to_string()],
                                        Parser::token_description(tok, self.source),
                                    ));
                                }
                                tok
                            } else {
                                return Err(ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec![") after subquery".to_string()],
                                ));
                            };

                            // Map operator token to enum
                            let operator = self.token_to_binary_operator(op_tok)
                                    .ok_or_else(|| ParseError::invalid_expression(
                                        op_tok.span,
                                        format!("Invalid comparison operator for quantified subquery: {}", op_tok.lexeme(self.source)),
                                    ))?;

                            // Allocate syntax node
                            let syntax_id = self.syntax_arena.alloc_quantified_subquery(
                                crate::syntax::SyntaxQuantifiedSubquery {
                                    op_token: op_token_id,
                                    quantifier_keyword: quantifier_token_id,
                                    span: Span {
                                        start: op_tok.span.start,
                                        end: rparen.span.end,
                                    },
                                },
                            );

                            let span = Span {
                                start: op_tok.span.start,
                                end: rparen.span.end,
                            };
                            expr = AstExpr::QuantifiedSubquery {
                                node_id: self.id_gen.next(),
                                left: Box::new(expr),
                                operator,
                                syntax_id,
                                quantifier: q,
                                subquery: Box::new(subquery),
                                span,
                            };
                            continue;
                        }
                    }
                }
            }
            let operator = self.token_to_binary_operator(op_tok).ok_or_else(|| {
                ParseError::invalid_expression(
                    op_tok.span,
                    format!(
                        "Invalid comparison operator: {}",
                        op_tok.lexeme(self.source)
                    ),
                )
            })?;
            let rhs = self.parse_add_expr_in_mode()?;
            let left_start = crate::parser::scripting::expr_span_start(&expr);
            let right_end = crate::parser::scripting::expr_span_end(&rhs);
            let syntax_id = self
                .syntax_arena
                .alloc_binary_op(crate::syntax::SyntaxBinaryOp {
                    op_token: op_token_id,
                    span: op_tok.span,
                });
            expr = AstExpr::BinaryOp {
                node_id: self.id_gen.next(),
                left: Box::new(expr),
                operator,
                syntax_id,
                right: Box::new(rhs),
                span: Span {
                    start: left_start,
                    end: right_end,
                },
            };
        }
        Ok(expr)
    }

    pub(crate) fn parse_add_expr_in_mode(&mut self) -> ParseResult<AstExpr> {
        let mut expr = self.parse_mul_expr_in_mode()?;
        while let Some(tok) = self.peek() {
            let is_op = matches!(
                tok.kind,
                TokenKind::Operator(
                    crate::lexer::Operator::Plus
                        | crate::lexer::Operator::Minus
                        | crate::lexer::Operator::LtMinusGt
                ),
            ) || (matches!(
                tok.kind,
                TokenKind::Operator(crate::lexer::Operator::PipePipe)
            ) && self.dialect.pipe_pipe_is_concat());
            if !is_op {
                break;
            }
            let op_token_id = self.current_token_id();
            let op_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["arithmetic operator".to_string()])?;
            let operator = self.token_to_binary_operator(op_tok).ok_or_else(|| {
                ParseError::invalid_expression(
                    op_tok.span,
                    format!("Invalid binary operator: {}", op_tok.lexeme(self.source)),
                )
            })?;
            let rhs = self.parse_mul_expr_in_mode()?;
            let left_start = crate::parser::scripting::expr_span_start(&expr);
            let right_end = crate::parser::scripting::expr_span_end(&rhs);
            let syntax_id = self
                .syntax_arena
                .alloc_binary_op(crate::syntax::SyntaxBinaryOp {
                    op_token: op_token_id,
                    span: op_tok.span,
                });
            expr = AstExpr::BinaryOp {
                node_id: self.id_gen.next(),
                left: Box::new(expr),
                operator,
                syntax_id,
                right: Box::new(rhs),
                span: Span {
                    start: left_start,
                    end: right_end,
                },
            };
        }
        Ok(expr)
    }

    /// Parse an expression, returning a Result with error information.
    /// This is the primary expression parsing entry point.
    pub(crate) fn parse_expr_in_mode(&mut self) -> ParseResult<AstExpr> {
        // Use Pratt parser for reduced stack depth
        self.parse_expr_bp(0)
    }

    /// Parse an expression, returning a Result with error information.
    /// This is the main public entry point for expression parsing.
    ///
    /// After parsing, flattens chains of OR/AND operations into LogicalChain
    /// to prevent stack overflow on deeply nested boolean expressions.
    pub(crate) fn parse_expr(&mut self) -> ParseResult<AstExpr> {
        let expr = self.parse_expr_in_mode()?;
        Ok(flatten_logical_chains(expr))
    }

    // ========================================================================
    // Pratt Parser Implementation
    // ========================================================================
    //
    // This is the main expression parser using Pratt parsing (binding power).
    // It replaces the deeply nested recursive descent chain:
    //   parse_or -> parse_and -> parse_not -> parse_cmp -> parse_add -> parse_mul -> parse_primary
    // with a single iterative function that uses binding power for precedence.
    //
    // Benefits:
    // - Reduces stack depth from O(nesting * 7) to O(nesting)
    // - Prevents stack overflow on deeply nested expressions
    // - Same AST output as before
    // ========================================================================

    /// Parse an expression using Pratt parsing with the given minimum binding power.
    /// This is the core of the expression parser.
    ///
    /// min_bp = 0 parses a full expression (lowest precedence)
    /// Higher min_bp values parse only higher-precedence subexpressions
    pub(crate) fn parse_expr_bp(&mut self, min_bp: u8) -> ParseResult<AstExpr> {
        // Guard against excessive recursion
        let _depth = self.track_depth("expression")?;

        self.parse_expr_bp_impl(min_bp)
    }

    fn parse_expr_bp_impl(&mut self, min_bp: u8) -> ParseResult<AstExpr> {
        let _guard = track_depth("parse_expr_bp", self.current_span())?;

        // Step 1: Parse the left-hand side atom (includes prefix operators and postfix)
        // Use parse_mul_expr_in_mode which handles:
        // - Spread operator (**)
        // - Primary expressions (literals, identifiers, function calls, subqueries)
        // - Postfix operators (::, [], :field)
        let mut lhs = self.parse_mul_expr_in_mode()?;

        // Step 2: Loop over infix operators using binding power
        while let Some(tok) = self.peek() {
            let tok = tok.clone();

            // Check for expression terminators (FROM, WHERE, etc.)
            // In normal expression parsing, we're at depth 0 (not in error recovery)
            if is_expr_terminator(&tok, 0) {
                break;
            }

            // Check for NOT prefix - special case for NOT IN, NOT BETWEEN, NOT LIKE
            // These are compound predicates at comparison level (bp 30)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                // Look ahead to see what follows
                let save_idx = self.idx;
                let _ = self.advance();
                if let Some(next) = self.peek() {
                    let is_compound = matches!(
                        next.kind,
                        TokenKind::Keyword(Keyword::In)
                            | TokenKind::Keyword(Keyword::Between)
                            | TokenKind::Keyword(Keyword::Like)
                            | TokenKind::Keyword(Keyword::Ilike)
                            | TokenKind::Keyword(Keyword::Rlike)
                            | TokenKind::Keyword(Keyword::Regexp)
                    );
                    self.idx = save_idx;

                    if is_compound {
                        // This is a compound predicate (NOT IN, NOT BETWEEN, NOT LIKE)
                        if 30 < min_bp {
                            break;
                        }
                        // Call the helper to parse the compound predicate
                        let saved_idx = self.idx;
                        lhs = self.parse_cmp_predicate_with_lhs(lhs)?;
                        // Defensive guard: if the predicate parser didn't advance
                        // despite is_compound being true, break to prevent infinite loop.
                        if self.idx == saved_idx {
                            break;
                        }
                        continue;
                    }
                    // NOT as prefix boolean negation - fall through to infix handling
                } else {
                    self.idx = save_idx;
                }
            }

            // [NOT] SIMILAR TO — `SIMILAR` lexes as an identifier, so it is
            // invisible to `compound_predicate_binding_power` (which only sees
            // the token kind). `NOT SIMILAR TO` already routes via the
            // `Keyword::Not` arm above; the non-negated form needs an explicit
            // dispatch here into the shared compound-predicate parser, which
            // builds `AstExpr::SimilarTo`. Comparison precedence (bp 30).
            let is_similar_pred = matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("SIMILAR")
                && {
                    let save_idx = self.idx;
                    let _ = self.advance(); // SIMILAR
                    let has_to = matches!(
                        self.peek().map(|t| &t.kind),
                        Some(TokenKind::Keyword(Keyword::To))
                    );
                    self.idx = save_idx;
                    has_to
                };
            if is_similar_pred {
                if 30 < min_bp {
                    break;
                }
                let saved_idx = self.idx;
                lhs = self.parse_cmp_predicate_with_lhs(lhs)?;
                if self.idx == saved_idx {
                    break;
                }
                continue;
            }

            // Check for compound predicates: IS, IN, BETWEEN, LIKE at comparison level
            if let Some((l_bp, _r_bp)) = compound_predicate_binding_power(&tok) {
                if l_bp < min_bp {
                    break;
                }
                // Call the helper to parse the compound predicate
                let saved_idx = self.idx;
                lhs = self.parse_cmp_predicate_with_lhs(lhs)?;
                // Guard: if the predicate parser didn't advance (e.g. NOT followed
                // by something other than IN/BETWEEN/LIKE), break to avoid an
                // infinite loop.
                if self.idx == saved_idx {
                    break;
                }
                continue;
            }

            // Check for AT TIME ZONE / AT LOCAL (identifier-based postfix operator)
            // AT is an Identifier, not a Keyword, so it won't match infix_binding_power.
            // We check for AT followed by TIME ZONE or LOCAL.
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("AT")
            {
                // Peek ahead to distinguish AT TIME ZONE / AT LOCAL from AT as alias
                let save_idx = self.idx;
                let _ = self.advance(); // consume AT

                let is_at_time_zone_or_local = if let Some(next) = self.peek() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Local)) {
                        true // AT LOCAL
                    } else if matches!(next.kind, TokenKind::Identifier { .. })
                        && next.lexeme(self.source).eq_ignore_ascii_case("TIME")
                    {
                        // Check for TIME followed by ZONE
                        let save_idx2 = self.idx;
                        let _ = self.advance(); // consume TIME
                        let has_zone = if let Some(zone_tok) = self.peek() {
                            matches!(zone_tok.kind, TokenKind::Identifier { .. })
                                && zone_tok.lexeme(self.source).eq_ignore_ascii_case("ZONE")
                        } else {
                            false
                        };
                        self.idx = save_idx2; // restore to after AT
                        has_zone
                    } else {
                        false
                    }
                } else {
                    false
                };

                self.idx = save_idx; // restore to before AT

                if is_at_time_zone_or_local {
                    // Same precedence as comparison (30)
                    if 30 < min_bp {
                        break;
                    }
                    lhs = self.parse_at_time_zone(lhs)?;
                    continue;
                }
                // AT is not followed by TIME ZONE or LOCAL - it's probably an alias.
                // Fall through to the break at the bottom (no infix match).
            }

            // Check for simple infix operators (+, -, *, /, =, <, >, AND, OR, etc.)
            if let Some((l_bp, r_bp)) = infix_binding_power(&tok, self.dialect) {
                if l_bp < min_bp {
                    break;
                }

                // Consume the operator token
                let op_token_id = self.current_token_id();
                let op_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["operator".to_string()])
                })?;

                // Check for quantified subquery: <expr> <cmp_op> ANY/ALL (SELECT ...)
                // This only applies to comparison operators: =, !=, <>, <, <=, >, >=
                let is_comparison_op = matches!(
                    op_tok.kind,
                    TokenKind::Operator(
                        crate::lexer::Operator::Eq
                            | crate::lexer::Operator::NotEq
                            | crate::lexer::Operator::AngleNotEq
                            | crate::lexer::Operator::Lt
                            | crate::lexer::Operator::Le
                            | crate::lexer::Operator::Gt
                            | crate::lexer::Operator::Ge
                    )
                );

                if is_comparison_op {
                    if let Some(qtok) = self.peek() {
                        let quantifier = match &qtok.kind {
                            TokenKind::Keyword(Keyword::Any) => {
                                Some(crate::ast::AstQuantifier::Any)
                            }
                            TokenKind::Keyword(Keyword::All) => {
                                Some(crate::ast::AstQuantifier::All)
                            }
                            _ => None,
                        };
                        if let Some(q) = quantifier {
                            let quantifier_token_id = self.current_token_id();
                            let _qtok = self.advance().expect_invariant(
                                "ANY/ALL quantifier confirmed by match in parse_expr_bp",
                            );

                            // Expect opening parenthesis
                            let lp = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["(".to_string()],
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

                            // Next token must start SELECT for quantified subquery
                            if let Some(next) = self.peek() {
                                if matches!(next.kind, TokenKind::Keyword(Keyword::Select)) {
                                    let subquery = self.try_parse_set_or_select_stmt()?;

                                    // Expect closing paren
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

                                    let operator = self.token_to_binary_operator(op_tok).ok_or_else(|| {
                                        ParseError::invalid_expression(
                                            op_tok.span,
                                            format!("Invalid comparison operator for quantified subquery: {}", op_tok.lexeme(self.source)),
                                        )
                                    })?;

                                    let syntax_id = self.syntax_arena.alloc_quantified_subquery(
                                        crate::syntax::SyntaxQuantifiedSubquery {
                                            op_token: op_token_id,
                                            quantifier_keyword: quantifier_token_id,
                                            span: Span {
                                                start: op_tok.span.start,
                                                end: rparen.span.end,
                                            },
                                        },
                                    );

                                    let left_start =
                                        crate::parser::scripting::expr_span_start(&lhs);
                                    let span = Span {
                                        start: left_start,
                                        end: rparen.span.end,
                                    };

                                    lhs = AstExpr::QuantifiedSubquery {
                                        node_id: self.id_gen.next(),
                                        left: Box::new(lhs),
                                        operator,
                                        syntax_id,
                                        quantifier: q,
                                        subquery: Box::new(subquery),
                                        span,
                                    };
                                    continue;
                                }
                            }
                            // Not a SELECT - this is an error (ANY/ALL must be followed by subquery)
                            return Err(ParseError::invalid_expression(
                                lp.span,
                                "ANY/ALL must be followed by a subquery (SELECT)".to_string(),
                            ));
                        }
                    }
                }

                let operator = self.token_to_binary_operator(op_tok).ok_or_else(|| {
                    ParseError::invalid_expression(
                        op_tok.span,
                        format!("Invalid binary operator: {}", op_tok.lexeme(self.source)),
                    )
                })?;

                // Count each binary operator against recursion limit to prevent
                // stack overflow on expressions with thousands of operators.
                // Each operator increments on entry and decrements after building the node,
                // so the counter tracks the current depth of the binary operator chain
                // (not accumulated across all expressions in the file).
                let _depth = self.track_depth("binary_operator")?;

                // Recursively parse the right-hand side with the right binding power
                let rhs = self.parse_expr_bp(r_bp)?;

                // Build the BinaryOp node
                let left_start = crate::parser::scripting::expr_span_start(&lhs);
                let right_end = crate::parser::scripting::expr_span_end(&rhs);
                let syntax_id = self
                    .syntax_arena
                    .alloc_binary_op(crate::syntax::SyntaxBinaryOp {
                        op_token: op_token_id,
                        span: op_tok.span,
                    });

                lhs = AstExpr::BinaryOp {
                    node_id: self.id_gen.next(),
                    left: Box::new(lhs),
                    operator,
                    syntax_id,
                    right: Box::new(rhs),
                    span: Span {
                        start: left_start,
                        end: right_end,
                    },
                };

                // Exit recursion after building the node.
                // This tracks the depth of nested binary operators in the current expression,
                // but the counter resets naturally as we unwind. The CTE loop's baseline
                // reset ensures we don't accumulate across independent CTEs.
                continue;
            }

            // No infix operator matched - we're done
            break;
        }

        Ok(lhs)
    }

    /// Parse AT TIME ZONE zone_expr or AT LOCAL.
    /// Called after the left-hand side expression has been parsed and AT has been
    /// confirmed to be followed by TIME ZONE or LOCAL.
    fn parse_at_time_zone(&mut self, lhs: AstExpr) -> ParseResult<AstExpr> {
        let left_start = crate::parser::scripting::expr_span_start(&lhs);

        // Consume AT (identifier) and capture token ID
        let at_tok = self
            .advance()
            .expect_invariant("AT confirmed by peek in parse_expr_bp");
        let at_token_id = self.last_token_id();

        // Check for LOCAL vs TIME ZONE
        if let Some(next) = self.peek() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::Local)) {
                // AT LOCAL
                let local_tok = self.advance().expect_invariant("LOCAL confirmed by peek");
                let local_token_id = self.last_token_id();
                let span = Span {
                    start: left_start,
                    end: local_tok.span.end,
                };

                // Build CST node for AT LOCAL
                let syntax_node = crate::syntax::SyntaxAtTimeZone {
                    at_token: at_token_id,
                    time_token: None,
                    zone_token: None,
                    local_token: Some(local_token_id),
                    span: Span {
                        start: at_tok.span.start,
                        end: local_tok.span.end,
                    },
                };
                let syntax_id = self.syntax_arena.alloc_at_time_zone(syntax_node);

                return Ok(AstExpr::AtTimeZone {
                    node_id: self.id_gen.next(),
                    syntax_id,
                    expr: Box::new(lhs),
                    zone: None, // AT LOCAL = session timezone
                    span,
                });
            }
        }

        // Consume TIME (identifier) and capture token ID
        let _time_tok = self
            .advance()
            .expect_invariant("TIME confirmed by lookahead in parse_expr_bp");
        let time_token_id = self.last_token_id();

        // Consume ZONE (identifier) and capture token ID
        let _zone_tok = self
            .advance()
            .expect_invariant("ZONE confirmed by lookahead in parse_expr_bp");
        let zone_token_id = self.last_token_id();

        // Parse the timezone expression (string literal, interval, column ref, etc.)
        // Use a higher binding power (31) so we don't consume operators like > or AND
        // that belong to the outer expression.
        let zone_expr = self.parse_expr_bp(31)?;

        let zone_end = crate::parser::scripting::expr_span_end(&zone_expr);
        let span = Span {
            start: left_start,
            end: zone_end,
        };

        // Build CST node for AT TIME ZONE
        let syntax_node = crate::syntax::SyntaxAtTimeZone {
            at_token: at_token_id,
            time_token: Some(time_token_id),
            zone_token: Some(zone_token_id),
            local_token: None,
            span: Span {
                start: at_tok.span.start,
                end: zone_end,
            },
        };
        let syntax_id = self.syntax_arena.alloc_at_time_zone(syntax_node);

        Ok(AstExpr::AtTimeZone {
            node_id: self.id_gen.next(),
            syntax_id,
            expr: Box::new(lhs),
            zone: Some(Box::new(zone_expr)),
            span,
        })
    }
}
