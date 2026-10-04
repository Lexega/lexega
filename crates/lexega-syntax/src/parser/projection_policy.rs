// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for PROJECTION POLICY statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] PROJECTION POLICY [IF NOT EXISTS] name AS () RETURNS PROJECTION_CONSTRAINT -> <body>`
//! - `ALTER PROJECTION POLICY [IF EXISTS] name { RENAME TO | SET BODY | SET/UNSET TAG | SET/UNSET COMMENT }`
//! - `DROP PROJECTION POLICY [IF EXISTS] name`
//!
//! Token reference:
//! - PROJECTION is Identifier, NOT Keyword
//! - PROJECTION_CONSTRAINT is single token with underscore
//! - ALLOW and ENFORCEMENT are Identifiers, not Keywords
//! - Body uses arrow operator (->) and is full SQL expression

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterProjectionPolicy, AstAlterProjectionPolicyAction, AstAlterProjectionPolicyActionKind,
    AstCreateProjectionPolicy, AstDropProjectionPolicy,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterProjectionPolicy, SyntaxAlterProjectionPolicyAction, SyntaxCreateProjectionPolicy,
    SyntaxDropProjectionPolicy,
};

impl<'a> Parser<'a> {
    /// Parse CREATE PROJECTION POLICY statement.
    pub(crate) fn try_parse_create_projection_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_projection_policy")?;

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
                    let or_tok = self
                        .advance()
                        .expect_invariant("OR token after peek in create_projection_policy");
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

        // PROJECTION (Identifier, NOT Keyword!)
        let projection_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PROJECTION".to_string()])?;

        if !matches!(projection_tok.kind, TokenKind::Identifier { .. })
            || !projection_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("PROJECTION")
        {
            return Err(ParseError::new(
                projection_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected PROJECTION keyword".to_string(),
                },
            ));
        }
        let projection_span = projection_tok.span;
        let projection_token_id = self.last_token_id();

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
                        .expect_invariant("IF token after peek in create_projection_policy");
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
                                message: "Expected EXISTS after NOT".to_string(),
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

        // AS
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

        // ()
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

        let rparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ')' after '('".to_string(),
                },
            ));
        }
        let rparen_token_id = self.last_token_id();
        let empty_params_span = Span {
            start: lparen_tok.span.start,
            end: rparen_tok.span.end,
        };

        // RETURNS
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

        // PROJECTION_CONSTRAINT (Identifier with underscore)
        let return_type_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["PROJECTION_CONSTRAINT".to_string()],
        )?;
        if !matches!(return_type_tok.kind, TokenKind::Identifier { .. })
            || !return_type_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("PROJECTION_CONSTRAINT")
        {
            return Err(ParseError::new(
                return_type_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected PROJECTION_CONSTRAINT type".to_string(),
                },
            ));
        }
        let return_type_span = return_type_tok.span;

        // -> (Arrow operator)
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
        let arrow_span = arrow_tok.span;
        let arrow_token_id = self.last_token_id();

        // Parse body expression
        // Body can be: PROJECTION_CONSTRAINT(...) function call or CASE expression
        let (body_expr, body_span) = match self.parse_expr() {
            Ok(expr) => {
                let span = expr.span();
                (Some(Box::new(expr)), span)
            }
            Err(_) => {
                // Fallback: capture everything until optional COMMENT or semicolon
                let body_start = self.current_span().start;
                let mut body_end = body_start;

                // Scan tokens until COMMENT or semicolon
                while let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment))
                        || matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                    {
                        break;
                    }
                    body_end = tok.span.end;
                    self.advance();
                }

                let span = Span {
                    start: body_start,
                    end: body_end,
                };
                (None, span)
            }
        };

        // Optional COMMENT = 'string'
        let comment_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let comment_start = tok.span.start;
                self.advance(); // consume COMMENT

                let _eq_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;

                let value_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["comment_string".to_string()])?;

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

        // Calculate statement span
        let stmt_end = comment_span.map(|s| s.end).unwrap_or(body_span.end);

        let stmt_span = Span {
            start: create_span.start,
            end: stmt_end,
        };

        // Build CST node
        let syntax_node = SyntaxCreateProjectionPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            projection_token: projection_token_id,
            policy_keyword: policy_token_id,
            policy_name_span,
            as_keyword: Some(as_token_id),
            lparen_token: Some(lparen_token_id),
            rparen_token: Some(rparen_token_id),
            returns_keyword: Some(returns_token_id),
            return_type_span: Some(return_type_span),
            arrow_token: Some(arrow_token_id),
            body_span,
            comment_span,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_create_projection_policy(syntax_node);

        // Build AST node
        let ast = AstCreateProjectionPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            projection_span,
            policy_span,
            policy_name_span,
            as_span: Some(as_span),
            empty_params_span: Some(empty_params_span),
            returns_span: Some(returns_span),
            return_type_span: Some(return_type_span),
            arrow_span: Some(arrow_span),
            body_span,
            body_expr,
            comment_span,
            extras: Vec::new(),
        };
        Ok(AstStmt::CreateProjectionPolicy(Box::new(ast)))
    }

    /// Parse ALTER PROJECTION POLICY statement.
    pub(crate) fn try_parse_alter_projection_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_projection_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_token_id = self.last_token_id();

        // PROJECTION (Identifier, NOT Keyword!)
        let projection_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PROJECTION".to_string()])?;

        if !matches!(projection_tok.kind, TokenKind::Identifier { .. })
            || !projection_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("PROJECTION")
        {
            return Err(ParseError::new(
                projection_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected PROJECTION keyword".to_string(),
                },
            ));
        }
        let projection_span = projection_tok.span;
        let projection_token_id = self.last_token_id();

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

        // Optional IF EXISTS (statement-level, before policy name)
        // Only valid for: RENAME TO, SET BODY, SET COMMENT, UNSET COMMENT
        let (if_exists_span, if_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF token after peek in alter_projection_policy");
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

        // Parse action (RENAME TO | SET BODY | SET TAG | UNSET TAG | SET COMMENT | UNSET COMMENT)
        let action = self.parse_alter_projection_policy_action()?;
        let action_span = action.span;

        // Calculate statement span
        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        // Build CST node
        let syntax_action = SyntaxAlterProjectionPolicyAction { span: action_span };
        let syntax_action_id = self
            .syntax_arena
            .alloc_alter_projection_policy_action(syntax_action);

        let syntax_node = SyntaxAlterProjectionPolicy {
            alter_keyword: alter_token_id,
            projection_token: projection_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            name_span,
            action_id: syntax_action_id,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_alter_projection_policy_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterProjectionPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            projection_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span,
            action,
        };
        Ok(AstStmt::AlterProjectionPolicy(Box::new(ast)))
    }

    /// Parse ALTER PROJECTION POLICY action.
    fn parse_alter_projection_policy_action(
        &mut self,
    ) -> ParseResult<AstAlterProjectionPolicyAction> {
        let action_start = self.current_span().start;

        let tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["action".to_string()])?;

        let kind = match &tok.kind {
            TokenKind::Keyword(Keyword::Rename) => {
                let rename_tok = self
                    .advance()
                    .expect_invariant("RENAME token after peek in alter_projection_policy_action");
                let rename_span = rename_tok.span;

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
                let to_span = to_tok.span;

                let new_name_span = self.parse_qualified_name_span()?;

                AstAlterProjectionPolicyActionKind::RenameTo {
                    rename_span: Some(rename_span),
                    to_span: Some(to_span),
                    new_name_span,
                }
            }

            TokenKind::Keyword(Keyword::Set) => {
                let set_tok = self
                    .advance()
                    .expect_invariant("SET token after peek in alter_projection_policy_action");
                let set_span = set_tok.span;

                let next_tok = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["BODY | TAG | COMMENT".to_string()],
                )?;

                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::Body) => {
                        let body_tok = self.advance().expect_invariant(
                            "BODY token after peek in alter_projection_policy_action",
                        );
                        let body_span = body_tok.span;

                        // -> (Arrow operator)
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
                        let arrow_span = arrow_tok.span;

                        // Parse body expression
                        let (body_expr, expression_span) = match self.parse_expr() {
                            Ok(expr) => {
                                let span = expr.span();
                                (Some(Box::new(expr)), span)
                            }
                            Err(_) => {
                                // Fallback: capture everything until semicolon/EOF
                                let expr_start = self.current_span().start;
                                let mut expr_end = expr_start;

                                while let Some(tok) = self.peek_non_trivia() {
                                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                                    {
                                        break;
                                    }
                                    expr_end = tok.span.end;
                                    self.advance();
                                }

                                let span = Span {
                                    start: expr_start,
                                    end: expr_end,
                                };
                                (None, span)
                            }
                        };

                        AstAlterProjectionPolicyActionKind::SetBody {
                            set_span: Some(set_span),
                            body_span: Some(body_span),
                            arrow_span: Some(arrow_span),
                            expression_span,
                            body_expr,
                        }
                    }

                    TokenKind::Keyword(Keyword::Tag) => {
                        let tag_tok = self.advance().expect_invariant(
                            "TAG token after peek in alter_projection_policy SET TAG",
                        );
                        let tag_span = tag_tok.span;

                        // Parse tag assignments until we hit something that isn't a tag assignment
                        let assignments_start = self.current_span().start;
                        let mut assignments_end;

                        // Consume at least one tag assignment
                        loop {
                            // Tag name (possibly qualified: db.schema.tag_name)
                            let _tag_name_span = self.parse_qualified_name_span()?;

                            // =
                            let _eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;

                            // Tag value (string)
                            let tag_value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["tag_value".to_string()])?;

                            assignments_end = tag_value_tok.span.end;

                            // Check for comma (more assignments)
                            if let Some(tok) = self.peek_non_trivia() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                                    self.advance(); // consume comma
                                    continue;
                                }
                            }
                            break;
                        }

                        let assignments_span = Span {
                            start: assignments_start,
                            end: assignments_end,
                        };

                        AstAlterProjectionPolicyActionKind::SetTag {
                            set_span: Some(set_span),
                            tag_span: Some(tag_span),
                            assignments_span,
                        }
                    }

                    TokenKind::Keyword(Keyword::Comment) => {
                        let comment_tok = self.advance().expect_invariant(
                            "COMMENT token after peek in alter_projection_policy SET COMMENT",
                        );
                        let comment_span = comment_tok.span;

                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = eq_tok.span;

                        let value_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["comment_string".to_string()])?;
                        let comment_value_span = value_tok.span;

                        AstAlterProjectionPolicyActionKind::SetComment {
                            set_span: Some(set_span),
                            comment_span: Some(comment_span),
                            eq_span: Some(eq_span),
                            comment_value_span,
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
                let unset_tok = self
                    .advance()
                    .expect_invariant("UNSET token after peek in alter_projection_policy_action");
                let unset_span = unset_tok.span;

                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["TAG | COMMENT".to_string()])?;

                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::Tag) => {
                        let tag_tok = self.advance().expect_invariant(
                            "TAG token after peek in alter_projection_policy UNSET TAG",
                        );
                        let tag_span = tag_tok.span;

                        // Parse tag names (comma-separated)
                        let tags_start = self.current_span().start;
                        let mut tags_end;

                        // Consume at least one tag name
                        loop {
                            let tag_name_span = self.parse_qualified_name_span()?;
                            tags_end = tag_name_span.end;

                            // Check for comma (more tags)
                            if let Some(tok) = self.peek_non_trivia() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                                    self.advance(); // consume comma
                                    continue;
                                }
                            }
                            break;
                        }

                        let tags_span = Span {
                            start: tags_start,
                            end: tags_end,
                        };

                        AstAlterProjectionPolicyActionKind::UnsetTag {
                            unset_span: Some(unset_span),
                            tag_span: Some(tag_span),
                            tags_span,
                        }
                    }

                    TokenKind::Keyword(Keyword::Comment) => {
                        let comment_tok = self.advance().expect_invariant(
                            "COMMENT token after peek in alter_projection_policy UNSET COMMENT",
                        );
                        let comment_span = comment_tok.span;

                        AstAlterProjectionPolicyActionKind::UnsetComment {
                            unset_span: Some(unset_span),
                            comment_span: Some(comment_span),
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
                    tok.span,
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

        Ok(AstAlterProjectionPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind,
        })
    }

    /// Parse DROP PROJECTION POLICY statement.
    pub(crate) fn try_parse_drop_projection_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_projection_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // PROJECTION (Identifier, NOT Keyword!)
        let projection_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PROJECTION".to_string()])?;

        if !matches!(projection_tok.kind, TokenKind::Identifier { .. })
            || !projection_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("PROJECTION")
        {
            return Err(ParseError::new(
                projection_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected PROJECTION keyword".to_string(),
                },
            ));
        }
        let projection_span = projection_tok.span;
        let projection_token_id = self.last_token_id();

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
                        "IF keyword available after peek in drop_projection_policy IF EXISTS",
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

        // Policy name
        let policy_name_span = self.parse_qualified_name_span()?;

        // Calculate statement span
        let stmt_span = Span {
            start: drop_span.start,
            end: policy_name_span.end,
        };

        // Build CST node
        let syntax_node = SyntaxDropProjectionPolicy {
            drop_keyword: drop_token_id,
            projection_token: projection_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            policy_name_span,
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_drop_projection_policy(syntax_node);

        // Build AST node
        let ast = AstDropProjectionPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            projection_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropProjectionPolicy(Box::new(ast)))
    }
}
