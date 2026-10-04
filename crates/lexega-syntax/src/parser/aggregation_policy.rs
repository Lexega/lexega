// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for AGGREGATION POLICY statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] AGGREGATION POLICY [IF NOT EXISTS] name AS () RETURNS AGGREGATION_CONSTRAINT -> <body> [COMMENT = '<string>']`
//! - `ALTER AGGREGATION POLICY [IF EXISTS] name { RENAME TO | SET BODY -> | SET/UNSET TAG | SET/UNSET COMMENT }`
//! - `DROP AGGREGATION POLICY [IF EXISTS] name`
//!
//! Token reference:
//! - AGGREGATION is Identifier, NOT Keyword
//! - AGGREGATION_CONSTRAINT, MIN_GROUP_SIZE, NO_AGGREGATION_CONSTRAINT are Identifiers
//! - -> is Operator(RightArrow), => is Operator(EqGt)
//! - Must use lexeme matching with eq_ignore_ascii_case() for AGGREGATION

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterAggregationPolicy, AstAlterAggregationPolicyAction,
    AstAlterAggregationPolicyActionKind, AstCreateAggregationPolicy, AstDropAggregationPolicy,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterAggregationPolicy, SyntaxAlterAggregationPolicyAction,
    SyntaxCreateAggregationPolicy, SyntaxDropAggregationPolicy,
};

impl<'a> Parser<'a> {
    /// Parse CREATE AGGREGATION POLICY statement.
    ///
    /// Syntax:
    /// CREATE [ OR REPLACE ] AGGREGATION POLICY [ IF NOT EXISTS ] <name>
    ///   AS () RETURNS AGGREGATION_CONSTRAINT -> <body>
    ///   [ COMMENT = '<string_literal>' ]
    pub(crate) fn try_parse_create_aggregation_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_aggregation_policy")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let create_token_id = self.last_token_id();

        // Optional OR REPLACE
        let (or_replace_span, or_token_id, replace_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                    let or_tok = self.advance().expect_invariant("OR keyword after peek");
                    let or_token_id = self.last_token_id();

                    let replace_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?;
                    if !matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                        return Err(ParseError::new(
                            replace_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected REPLACE after OR".to_string(),
                            },
                        ));
                    }
                    let replace_token_id = self.last_token_id();

                    let or_replace_span = Span {
                        start: or_tok.span.start,
                        end: replace_tok.span.end,
                    };
                    (
                        Some(or_replace_span),
                        Some(or_token_id),
                        Some(replace_token_id),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        // AGGREGATION (Identifier, NOT Keyword!)
        let aggregation_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AGGREGATION".to_string()])?;

        if !matches!(aggregation_tok.kind, TokenKind::Identifier { .. })
            || !aggregation_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("AGGREGATION")
        {
            return Err(ParseError::new(
                aggregation_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AGGREGATION keyword".to_string(),
                },
            ));
        }
        let aggregation_span = aggregation_tok.span;
        let aggregation_token_id = self.last_token_id();

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

        // Optional IF NOT EXISTS
        let (if_not_exists_span, if_token_id, not_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword after peek for IF NOT EXISTS");
                    let if_token_id = self.last_token_id();

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
                    let not_token_id = self.last_token_id();

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
                    let exists_token_id = self.last_token_id();

                    let if_not_exists_span = Span {
                        start: if_tok.span.start,
                        end: exists_tok.span.end,
                    };
                    (
                        Some(if_not_exists_span),
                        Some(if_token_id),
                        Some(not_token_id),
                        Some(exists_token_id),
                    )
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            };

        // Policy name
        let policy_name_span = self.parse_qualified_name_span()?;
        // AS keyword
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
        let as_token_id = self.last_token_id();
        let as_signature_start = as_tok.span.start;

        // Opening paren
        let lparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after AS".to_string(),
                },
            ));
        }
        let lparen_token_id = self.last_token_id();

        // Closing paren (aggregation policies have empty parameter list)
        let rparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ')' for aggregation policy signature".to_string(),
                },
            ));
        }
        let rparen_token_id = self.last_token_id();

        // RETURNS keyword
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
        let returns_token_id = self.last_token_id();
        let returns_start = returns_tok.span.start;

        // AGGREGATION_CONSTRAINT (Identifier, single token)
        let constraint_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["AGGREGATION_CONSTRAINT".to_string()],
        )?;
        if !matches!(constraint_tok.kind, TokenKind::Identifier { .. })
            || !constraint_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("AGGREGATION_CONSTRAINT")
        {
            return Err(ParseError::new(
                constraint_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AGGREGATION_CONSTRAINT return type".to_string(),
                },
            ));
        }
        let as_signature_span = Span {
            start: as_signature_start,
            end: rparen_tok.span.end,
        };

        let return_type_span = constraint_tok.span;
        let returns_span = Span {
            start: returns_start,
            end: constraint_tok.span.end,
        };

        // -> operator (RightArrow)
        let arrow_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["->".to_string()])?;
        if !matches!(arrow_tok.kind, TokenKind::Operator(Operator::RightArrow)) {
            return Err(ParseError::new(
                arrow_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '->' operator".to_string(),
                },
            ));
        }
        let arrow_token_id = self.last_token_id();

        // Parse body expression (can be simple function call or complex CASE expression)
        let body_expr = self.parse_expr().map_err(|_| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidExpression {
                    message: "Expected body expression after '->' operator".to_string(),
                },
            )
        })?;
        let body_expr_span = body_expr.span();
        let body_span = Span {
            start: body_expr_span.start,
            end: body_expr_span.end,
        };

        // Optional COMMENT = 'string'
        let comment_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let comment_start = tok.span.start;
                self.advance(); // consume COMMENT

                let eq_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                    return Err(ParseError::new(
                        eq_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected '=' after COMMENT".to_string(),
                        },
                    ));
                }

                let value_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["string".to_string()])?;

                Some(Span {
                    start: comment_start,
                    end: value_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        // Calculate full statement span
        let stmt_span = Span {
            start: create_span.start,
            end: comment_span.map(|s| s.end).unwrap_or(body_span.end),
        };

        // Build CST node
        let syntax_node = SyntaxCreateAggregationPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            aggregation_token: aggregation_token_id,
            policy_keyword: policy_token_id,
            policy_name_span,
            as_keyword: as_token_id,
            lparen_token: lparen_token_id,
            rparen_token: rparen_token_id,
            as_signature_span,
            returns_keyword: returns_token_id,
            return_type_span,
            returns_span,
            arrow_token: arrow_token_id,
            body_span,
            comment_span,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_create_aggregation_policy(syntax_node);

        // Build AST node
        let ast = AstCreateAggregationPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            aggregation_span,
            policy_span,
            policy_name_span,
            as_signature_span,
            returns_span,
            body_span,
            body: Some(Box::new(body_expr)),
            comment_span,
            extras: Vec::new(),
        };
        Ok(AstStmt::CreateAggregationPolicy(Box::new(ast)))
    }

    /// Parse ALTER AGGREGATION POLICY statement.
    ///
    /// Syntax:
    /// ALTER AGGREGATION POLICY [ IF EXISTS ] <name> RENAME TO <new_name>
    /// ALTER AGGREGATION POLICY [ IF EXISTS ] <name> SET BODY -> <expression>
    /// ALTER AGGREGATION POLICY <name> SET TAG <tag_name> = '<tag_value>' [ , ... ]
    /// ALTER AGGREGATION POLICY <name> UNSET TAG <tag_name> [ , ... ]
    /// ALTER AGGREGATION POLICY [ IF EXISTS ] <name> SET COMMENT = '<string_literal>'
    /// ALTER AGGREGATION POLICY [ IF EXISTS ] <name> UNSET COMMENT
    pub(crate) fn try_parse_alter_aggregation_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_aggregation_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_token_id = self.last_token_id();

        // AGGREGATION (Identifier, NOT Keyword!)
        let aggregation_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AGGREGATION".to_string()])?;

        if !matches!(aggregation_tok.kind, TokenKind::Identifier { .. })
            || !aggregation_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("AGGREGATION")
        {
            return Err(ParseError::new(
                aggregation_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AGGREGATION keyword".to_string(),
                },
            ));
        }
        let aggregation_span = aggregation_tok.span;
        let aggregation_token_id = self.last_token_id();

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
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword after peek for IF EXISTS");
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

        // Policy name
        let name_span = self.parse_qualified_name_span()?;

        // Parse action
        let action = self.parse_alter_aggregation_policy_action()?;
        let action_span = action.span;

        // Calculate full statement span
        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        // Build CST node
        let syntax_action = SyntaxAlterAggregationPolicyAction { span: action_span };
        let action_id = self
            .syntax_arena
            .alloc_alter_aggregation_policy_action(syntax_action);

        let syntax_node = SyntaxAlterAggregationPolicy {
            alter_keyword: alter_token_id,
            aggregation_token: aggregation_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            name_span,
            action_id,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_alter_aggregation_policy_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterAggregationPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            aggregation_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span,
            actions: vec![action],
        };
        Ok(AstStmt::AlterAggregationPolicy(Box::new(ast)))
    }

    /// Parse DROP AGGREGATION POLICY statement.
    ///
    /// Syntax:
    /// DROP AGGREGATION POLICY [ IF EXISTS ] <name>
    pub(crate) fn try_parse_drop_aggregation_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_aggregation_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // AGGREGATION (Identifier, NOT Keyword!)
        let aggregation_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AGGREGATION".to_string()])?;

        if !matches!(aggregation_tok.kind, TokenKind::Identifier { .. })
            || !aggregation_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("AGGREGATION")
        {
            return Err(ParseError::new(
                aggregation_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AGGREGATION keyword".to_string(),
                },
            ));
        }
        let aggregation_span = aggregation_tok.span;
        let aggregation_token_id = self.last_token_id();

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
                        "IF keyword available after peek in drop_aggregation_policy IF EXISTS",
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
        let syntax_node = SyntaxDropAggregationPolicy {
            drop_keyword: drop_token_id,
            aggregation_token: aggregation_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            policy_name_span,
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_drop_aggregation_policy(syntax_node);

        // Build AST node
        let ast = AstDropAggregationPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            aggregation_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropAggregationPolicy(Box::new(ast)))
    }

    // Helper methods

    /// Parse ALTER AGGREGATION POLICY action (SET/UNSET/RENAME TO).
    fn parse_alter_aggregation_policy_action(
        &mut self,
    ) -> ParseResult<AstAlterAggregationPolicyAction> {
        let action_tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["RENAME, SET, or UNSET".to_string()],
        )?;

        let action_start = action_tok.span.start;

        let kind = match &action_tok.kind {
            TokenKind::Keyword(Keyword::Rename) => {
                self.advance(); // consume RENAME
                let rename_span = Some(action_tok.span);

                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                    return Err(ParseError::new(
                        to_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TO after RENAME".to_string(),
                        },
                    ));
                }
                let to_span = Some(to_tok.span);

                let new_name_span = self.parse_qualified_name_span()?;

                AstAlterAggregationPolicyActionKind::RenameTo {
                    rename_span,
                    to_span,
                    new_name_span,
                }
            }
            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = Some(action_tok.span);

                // Peek next token to determine what we're setting
                let next_tok = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["BODY, TAG, or COMMENT".to_string()],
                )?;

                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::Body) => {
                        self.advance(); // consume BODY
                        let body_span_kw = Some(next_tok.span);

                        // -> operator
                        let arrow_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["->".to_string()])?;
                        if !matches!(arrow_tok.kind, TokenKind::Operator(Operator::RightArrow)) {
                            return Err(ParseError::new(
                                arrow_tok.span,
                                ParseErrorKind::InvalidStatement {
                                    message: "Expected '->' operator after BODY".to_string(),
                                },
                            ));
                        }
                        let arrow_span = Some(arrow_tok.span);

                        // Parse body expression
                        let body_expr = self.parse_expr().map_err(|_| {
                            ParseError::new(
                                self.current_span(),
                                ParseErrorKind::InvalidExpression {
                                    message: "Expected body expression after '->' operator"
                                        .to_string(),
                                },
                            )
                        })?;
                        let expression_span = body_expr.span();

                        AstAlterAggregationPolicyActionKind::SetBody {
                            set_span,
                            body_span: body_span_kw,
                            arrow_span,
                            expression_span,
                            expression: Some(Box::new(body_expr)),
                        }
                    }
                    TokenKind::Keyword(Keyword::Tag) => {
                        self.advance(); // consume TAG
                        let tag_span = Some(next_tok.span);

                        // Parse tag assignments: tag1 = 'value1', tag2 = 'value2', ...
                        let assignments_start = self.current_span().start;
                        while let Some(tok) = self.peek_non_trivia() {
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }
                            self.advance();
                        }
                        let assignments_end = self.current_span().start;
                        let tags_span = Span {
                            start: assignments_start,
                            end: assignments_end,
                        };

                        AstAlterAggregationPolicyActionKind::SetTag {
                            set_span,
                            tag_span,
                            tags_span,
                        }
                    }
                    TokenKind::Keyword(Keyword::Comment) => {
                        self.advance(); // consume COMMENT
                        let comment_span = Some(next_tok.span);

                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                            Some(eq_tok.span)
                        } else {
                            None
                        };

                        let value_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                        let value_span = value_tok.span;

                        AstAlterAggregationPolicyActionKind::SetComment {
                            set_span,
                            comment_span,
                            eq_span,
                            value_span,
                        }
                    }
                    _ => {
                        return Err(ParseError::new(
                            next_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected BODY, TAG, or COMMENT after SET".to_string(),
                            },
                        ));
                    }
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = Some(action_tok.span);

                // Peek next token
                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["TAG or COMMENT".to_string()])?;

                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::Tag) => {
                        self.advance(); // consume TAG
                        let tag_span = Some(next_tok.span);

                        // Parse tag names: tag1, tag2, ...
                        let tags_start = self.current_span().start;
                        while let Some(tok) = self.peek_non_trivia() {
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }
                            self.advance();
                        }
                        let tags_end = self.current_span().start;
                        let tags_span = Span {
                            start: tags_start,
                            end: tags_end,
                        };

                        AstAlterAggregationPolicyActionKind::UnsetTag {
                            unset_span,
                            tag_span,
                            tags_span,
                        }
                    }
                    TokenKind::Keyword(Keyword::Comment) => {
                        self.advance(); // consume COMMENT
                        let comment_span = Some(next_tok.span);

                        AstAlterAggregationPolicyActionKind::UnsetComment {
                            unset_span,
                            comment_span,
                        }
                    }
                    _ => {
                        return Err(ParseError::new(
                            next_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected TAG or COMMENT after UNSET".to_string(),
                            },
                        ));
                    }
                }
            }
            _ => {
                return Err(ParseError::new(
                    action_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected RENAME, SET, or UNSET".to_string(),
                    },
                ));
            }
        };

        let action_end = self.current_span().start;
        let action_span = Span {
            start: action_start,
            end: action_end,
        };

        Ok(AstAlterAggregationPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None, // Filled by caller
            kind,
        })
    }
}
