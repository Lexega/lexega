// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for CREATE MASKING POLICY statements.
//! Follows the same pattern as alter_stage.rs for consistency.

use crate::ast::AstStmt;
use crate::ast::{AstCreateMaskingPolicy, AstPolicyParameter};
use crate::cst::TokenId;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Result of parsing an IF NOT EXISTS clause
struct IfNotExistsClause {
    span: Option<Span>,
    if_token_id: Option<TokenId>,
    not_token_id: Option<TokenId>,
    exists_token_id: Option<TokenId>,
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_create_masking_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_masking_policy")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let create_token_id = self.last_token_id();

        // Optional OR REPLACE
        let (or_replace_span, or_token_id, replace_token_id) =
            self.parse_or_replace_clause_masking()?;

        // MASKING POLICY (MASKING is identifier, not keyword)
        let masking_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MASKING".to_string()])?;

        if !masking_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("MASKING")
        {
            return Err(ParseError::new(
                masking_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected MASKING keyword".to_string(),
                },
            ));
        }
        let masking_span = masking_tok.span;
        let masking_token_id = self.last_token_id();

        let policy_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected POLICY keyword".to_string(),
                },
            ));
        }
        let policy_span = policy_tok.span;
        let policy_token_id = self.last_token_id();

        // Optional IF NOT EXISTS
        let if_not_exists = self.parse_if_not_exists_clause_masking()?;
        let if_not_exists_span = if_not_exists.span;
        let if_token_id = if_not_exists.if_token_id;
        let not_token_id = if_not_exists.not_token_id;
        let exists_token_id = if_not_exists.exists_token_id;

        // Policy name
        let policy_name_span = self.parse_policy_name_masking()?;

        // AS keyword (REQUIRED for MASKING POLICY)
        let as_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
        if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
            return Err(ParseError::new(
                as_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AS keyword".to_string(),
                },
            ));
        }
        let as_span = as_tok.span;
        let as_token_id = self.last_token_id();

        // Parse signature: ( arg1 type1, arg2 type2, ... )
        let (signature_span, parameters, lparen_token_id, rparen_token_id) =
            self.parse_masking_policy_signature()?;

        // RETURNS <type>
        let returns_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["RETURNS".to_string()])?;
        if !matches!(returns_tok.kind, TokenKind::Keyword(Keyword::Returns)) {
            return Err(ParseError::new(
                returns_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected RETURNS keyword".to_string(),
                },
            ));
        }
        let returns_span = returns_tok.span;
        let returns_token_id = self.last_token_id();

        // Return type (e.g., STRING, VARCHAR, VARIANT) - it's an identifier, not a keyword
        let return_type_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["type name".to_string()])?;
        let return_type_span = return_type_tok.span;

        // Arrow operator (->)
        let arrow_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["->".to_string()])?;
        if !matches!(arrow_tok.kind, TokenKind::Operator(Operator::RightArrow)) {
            return Err(ParseError::new(
                arrow_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected -> operator".to_string(),
                },
            ));
        }
        let arrow_span = arrow_tok.span;
        let arrow_token_id = self.last_token_id();

        // Parse body expression
        let body_start_pos = self.current_span().start;
        let body_expr = self.parse_expr()?;
        let body_end_pos = body_expr.span().end;
        let body_expr_span = Span {
            start: body_start_pos,
            end: body_end_pos,
        };

        // Optional COMMENT clause
        let comment_span = self.parse_optional_comment_masking()?;

        // Optional EXEMPT_OTHER_POLICIES clause
        let (exempt_other_policies_span, exempt_other_policies_value) =
            self.parse_exempt_other_policies()?;

        // Calculate full statement span
        let stmt_span = Span {
            start: create_span.start,
            end: exempt_other_policies_span
                .or(comment_span)
                .map(|s| s.end)
                .unwrap_or(body_expr_span.end),
        };

        // Build CST node
        let syntax_node = crate::syntax::SyntaxCreateMaskingPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            masking_keyword: masking_token_id,
            policy_keyword: policy_token_id,
            as_keyword: as_token_id,
            returns_keyword: returns_token_id,
            lparen: lparen_token_id,
            rparen: rparen_token_id,
            arrow_token: arrow_token_id,
            policy_name_span,
            signature_span,
            return_type_span,
            body_expr_span,
            comment_span,
            exempt_other_policies_span,
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_create_masking_policy(syntax_node);

        // Build AST node
        let ast = AstCreateMaskingPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            masking_span,
            policy_span,
            policy_name_span,
            as_span,
            signature_span,
            returns_span,
            return_type_span,
            arrow_span,
            body_expr_span,
            comment_span,
            exempt_other_policies_span,
            parameters,
            body: Box::new(body_expr),
            exempt_other_policies_value,
        };
        Ok(AstStmt::CreateMaskingPolicy(Box::new(ast)))
    }

    // Helper methods following alter_stage.rs pattern

    fn parse_or_replace_clause_masking(
        &mut self,
    ) -> ParseResult<(
        Option<Span>,
        Option<crate::cst::TokenId>,
        Option<crate::cst::TokenId>,
    )> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                let or_tok = self
                    .advance()
                    .expect_invariant("OR token available after peek");
                let or_token_id = Some(self.last_token_id());

                if let Some(replace_tok) = self.peek_non_trivia() {
                    if matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                        let r = self
                            .advance()
                            .expect_invariant("REPLACE token available after peek");
                        let replace_token_id = Some(self.last_token_id());
                        let or_replace_span = Some(Span {
                            start: or_tok.span.start,
                            end: r.span.end,
                        });
                        return Ok((or_replace_span, or_token_id, replace_token_id));
                    }
                }

                return Err(ParseError::new(
                    or_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "CREATE MASKING POLICY OR requires REPLACE".to_string(),
                    },
                ));
            }
        }
        Ok((None, None, None))
    }

    fn parse_if_not_exists_clause_masking(&mut self) -> ParseResult<IfNotExistsClause> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF token available after peek");
                let if_token_id = Some(self.last_token_id());

                let not_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
                if !matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    return Err(ParseError::new(
                        not_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected NOT after IF".to_string(),
                        },
                    ));
                }
                let not_token_id = Some(self.last_token_id());

                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF NOT".to_string(),
                        },
                    ));
                }
                let exists_token_id = Some(self.last_token_id());

                let span = Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                });

                return Ok(IfNotExistsClause {
                    span,
                    if_token_id,
                    not_token_id,
                    exists_token_id,
                });
            }
        }
        Ok(IfNotExistsClause {
            span: None,
            if_token_id: None,
            not_token_id: None,
            exists_token_id: None,
        })
    }

    fn parse_policy_name_masking(&mut self) -> ParseResult<Span> {
        // Parse identifier (possibly qualified: db.schema.policy)
        let first_tok = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                self.advance()
                    .expect_invariant("policy name identifier available after peek")
            } else {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: vec!["identifier".to_string()],
                        found: tok.lexeme(self.source).to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected policy name".to_string(),
                },
            ));
        };

        let start_pos = first_tok.span.start;
        let mut end_pos = first_tok.span.end;

        // Consume optional dot-separated parts
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                if let Some(id_tok) = self.peek_non_trivia() {
                    if matches!(id_tok.kind, TokenKind::Identifier { .. }) {
                        let t = self.advance().expect_invariant(
                            "qualified policy name identifier available after peek",
                        );
                        end_pos = t.span.end;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(Span {
            start: start_pos,
            end: end_pos,
        })
    }

    fn parse_masking_policy_signature(
        &mut self,
    ) -> ParseResult<(
        Span,
        Vec<AstPolicyParameter>,
        crate::cst::TokenId,
        crate::cst::TokenId,
    )> {
        // Expect left paren
        let lparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ( for signature".to_string(),
                },
            ));
        }
        let lparen_token_id = self.last_token_id();
        let start = lparen_tok.span.start;

        let mut parameters = Vec::new();

        // Parse at least one parameter
        loop {
            // Parameter name
            let param_name_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["parameter name".to_string()])?;
            if !matches!(param_name_tok.kind, TokenKind::Identifier { .. }) {
                return Err(ParseError::new(
                    param_name_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected parameter name".to_string(),
                    },
                ));
            }
            let param_name_span = param_name_tok.span;

            // Parameter type
            let param_type_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["parameter type".to_string()])?;
            let param_type_span = param_type_tok.span;

            let param_span = Span {
                start: param_name_span.start,
                end: param_type_span.end,
            };

            parameters.push(AstPolicyParameter {
                node_id: self.id_gen.next(),
                span: param_span,
                name_span: param_name_span,
                type_span: param_type_span,
            });

            // Check for comma or closing paren
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance(); // consume comma
                    continue;
                } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    break;
                } else {
                    return Err(ParseError::new(
                        tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected , or ) in signature".to_string(),
                        },
                    ));
                }
            } else {
                return Err(ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Unexpected end in signature".to_string(),
                    },
                ));
            }
        }

        // Expect right paren
        let rparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ) after signature".to_string(),
                },
            ));
        }
        let rparen_token_id = self.last_token_id();
        let end = rparen_tok.span.end;

        let signature_span = Span { start, end };

        Ok((signature_span, parameters, lparen_token_id, rparen_token_id))
    }

    fn parse_optional_comment_masking(&mut self) -> ParseResult<Option<Span>> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let comment_start = tok.span.start;
                self.advance(); // consume COMMENT

                // Expect = 'string'
                let eq_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                    return Err(ParseError::new(
                        eq_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected = after COMMENT".to_string(),
                        },
                    ));
                }

                let value_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
                let comment_span = Span {
                    start: comment_start,
                    end: value_tok.span.end,
                };

                return Ok(Some(comment_span));
            }
        }
        Ok(None)
    }

    fn parse_exempt_other_policies(&mut self) -> ParseResult<(Option<Span>, Option<bool>)> {
        if let Some(tok) = self.peek_non_trivia() {
            // Handle both "EXEMPT_OTHER_POLICIES" (single token) and "EXEMPT OTHER POLICIES" (three tokens)
            if tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("EXEMPT_OTHER_POLICIES")
                || tok.lexeme(self.source).eq_ignore_ascii_case("EXEMPT")
            {
                let exempt_start = tok.span.start;
                self.advance(); // consume EXEMPT or EXEMPT_OTHER_POLICIES

                // If we consumed the combined form, we're done with keywords
                let consumed_combined = tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("EXEMPT_OTHER_POLICIES");

                if !consumed_combined {
                    // Need to consume OTHER and POLICIES separately
                    let other_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["OTHER".to_string()])?;
                    if !other_tok.lexeme(self.source).eq_ignore_ascii_case("OTHER") {
                        return Err(ParseError::new(
                            other_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected OTHER after EXEMPT".to_string(),
                            },
                        ));
                    }

                    let policies_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["POLICIES".to_string()])?;
                    if !policies_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("POLICIES")
                    {
                        return Err(ParseError::new(
                            policies_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected POLICIES after EXEMPT OTHER".to_string(),
                            },
                        ));
                    }
                }

                // = TRUE | FALSE
                let eq_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                    return Err(ParseError::new(
                        eq_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected = after EXEMPT_OTHER_POLICIES".to_string(),
                        },
                    ));
                }

                let bool_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TRUE or FALSE".to_string()])?;

                // TRUE/FALSE may arrive as an identifier token
                let value = if bool_tok.lexeme(self.source).eq_ignore_ascii_case("TRUE") {
                    Some(true)
                } else if bool_tok.lexeme(self.source).eq_ignore_ascii_case("FALSE") {
                    Some(false)
                } else {
                    return Err(ParseError::new(
                        bool_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TRUE or FALSE for EXEMPT_OTHER_POLICIES".to_string(),
                        },
                    ));
                };

                let span = Some(Span {
                    start: exempt_start,
                    end: bool_tok.span.end,
                });

                return Ok((span, value));
            }
        }
        Ok((None, None))
    }

    /// Parse DROP MASKING POLICY statement.
    ///
    /// Syntax: DROP MASKING POLICY [IF EXISTS] <name>
    pub(crate) fn try_parse_drop_masking_policy(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstDropMaskingPolicy;
        use crate::syntax::SyntaxDropMaskingPolicy;

        let _depth = self.track_depth("drop_masking_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // MASKING (Identifier, NOT Keyword!)
        let masking_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MASKING".to_string()])?;

        if !matches!(masking_tok.kind, TokenKind::Identifier { .. })
            || !masking_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("MASKING")
        {
            return Err(ParseError::new(
                masking_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected MASKING keyword".to_string(),
                },
            ));
        }
        let masking_span = masking_tok.span;
        let masking_token_id = self.last_token_id();

        // POLICY (Keyword)
        let policy_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected POLICY keyword".to_string(),
                },
            ));
        }
        let policy_span = policy_tok.span;
        let policy_token_id = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self.advance().expect_invariant(
                        "IF keyword available after peek in drop_masking_policy IF EXISTS",
                    );
                    let if_token_id = self.last_token_id();

                    let exists_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                    if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                        return Err(ParseError::new(
                            exists_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected EXISTS after IF".to_string(),
                            },
                        ));
                    }
                    let exists_token_id = self.last_token_id();

                    let if_exists_span = Span {
                        start: if_tok.span.start,
                        end: exists_tok.span.end,
                    };
                    (
                        Some(if_exists_span),
                        Some(if_token_id),
                        Some(exists_token_id),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        // Policy name (may be qualified: db.schema.name)
        let policy_name_span = self.parse_qualified_name_span()?;

        // Calculate full statement span
        let stmt_span = Span {
            start: drop_span.start,
            end: policy_name_span.end,
        };

        // Build CST node
        let syntax_node = SyntaxDropMaskingPolicy {
            drop_keyword: drop_token_id,
            masking_token: masking_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            policy_name_span,
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_drop_masking_policy(syntax_node);

        // Build AST node
        let ast = AstDropMaskingPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            masking_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropMaskingPolicy(Box::new(ast)))
    }
}
