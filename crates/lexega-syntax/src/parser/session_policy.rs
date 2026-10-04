// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for SESSION POLICY statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] SESSION POLICY [IF NOT EXISTS] name [properties]`
//! - `ALTER SESSION POLICY [IF EXISTS] name { RENAME TO | SET | UNSET }`
//! - `DROP SESSION POLICY [IF EXISTS] name`
//!
//! Token reference:
//! - SESSION is Identifier, NOT Keyword
//! - Property names (SESSION_IDLE_TIMEOUT_MINS, etc.) are Identifiers
//! - Must use lexeme matching with eq_ignore_ascii_case()

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterSessionPolicy, AstAlterSessionPolicyAction, AstAlterSessionPolicyActionKind,
    AstCreateSessionPolicy, AstDropSessionPolicy, AstUnknownClause,
    CreatePolicyProperty as AstCreatePolicyProperty, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterSessionPolicy, SyntaxAlterSessionPolicyAction, SyntaxCreateSessionPolicy,
    SyntaxDropSessionPolicy,
};

struct RoleListSpec {
    span: Span,
    lparen_token: crate::cst::TokenId,
    rparen_token: crate::cst::TokenId,
    /// Individual role name spans
    values: Vec<Span>,
}

impl<'a> Parser<'a> {
    /// Parse CREATE SESSION POLICY statement.
    pub(crate) fn try_parse_create_session_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_session_policy")?;

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
                    let or_tok = self.advance().expect_invariant(
                        "OR keyword available after peek in create_session_policy",
                    );
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

        // SESSION (Identifier, NOT Keyword!)
        let session_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SESSION".to_string()])?;

        if !matches!(session_tok.kind, TokenKind::Identifier { .. })
            || !session_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SESSION")
        {
            return Err(ParseError::new(
                session_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SESSION keyword".to_string(),
                },
            ));
        }
        let session_span = session_tok.span;
        let session_token_id = self.last_token_id();

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
                    let if_tok = self.advance().expect_invariant(
                        "IF keyword available after peek in create_session_policy IF NOT EXISTS",
                    );
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
        let mut properties: Vec<AstCreatePolicyProperty> = Vec::new();
        let mut extras = Vec::new();

        while let Some(tok) = self.peek_non_trivia() {
            // Check if we've reached end of statement
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }

            // Try to parse a property
            let prop_start = tok.span.start;

            match &tok.kind {
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    match lexeme_upper.as_str() {
                        "SESSION_IDLE_TIMEOUT_MINS" | "SESSION_UI_IDLE_TIMEOUT_MINS" => {
                            let name_tok = self
                                .advance()
                                .expect_invariant("property name available after peek");
                            let name_span = name_tok.span;
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["number".to_string()])?;
                            properties.push(AstCreatePolicyProperty {
                                name_span,
                                eq_span: eq_tok.span,
                                value_span: value_tok.span,
                                full_span: Span {
                                    start: prop_start,
                                    end: value_tok.span.end,
                                },
                            });
                        }
                        "ALLOWED_SECONDARY_ROLES" | "BLOCKED_SECONDARY_ROLES" => {
                            let name_tok = self
                                .advance()
                                .expect_invariant("property name available after peek");
                            let name_span = name_tok.span;
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let roles_spec = self.parse_role_list()?;
                            properties.push(AstCreatePolicyProperty {
                                name_span,
                                eq_span: eq_tok.span,
                                value_span: roles_spec.span,
                                full_span: Span {
                                    start: prop_start,
                                    end: roles_spec.span.end,
                                },
                            });
                        }
                        _ => {
                            // Unknown property - defensive design
                            let unknown_tok = self.advance().expect_invariant("unknown property identifier available after peek in create_session_policy");
                            // Consume until next property or semicolon
                            while let Some(tok) = self.peek_non_trivia() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                    break;
                                }
                                if matches!(tok.kind, TokenKind::Identifier { .. }) {
                                    let lex_up = tok.lexeme(self.source).to_uppercase();
                                    if lex_up == "SESSION_IDLE_TIMEOUT_MINS"
                                        || lex_up == "SESSION_UI_IDLE_TIMEOUT_MINS"
                                        || lex_up == "ALLOWED_SECONDARY_ROLES"
                                        || lex_up == "BLOCKED_SECONDARY_ROLES"
                                    {
                                        break;
                                    }
                                }
                                if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                                    break;
                                }
                                self.advance();
                            }
                            let end_pos = self.current_span().start;
                            extras.push(AstUnknownClause {
                                introducer: Some(unknown_tok.span),
                                span: Span {
                                    start: prop_start,
                                    end: end_pos,
                                },
                                kind: UnknownKind::Property,
                                node_id: self.id_gen.next(),
                            });
                        }
                    }
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    let comment_name_tok = self
                        .advance()
                        .expect_invariant("COMMENT keyword available after peek");
                    let name_span = comment_name_tok.span;
                    let eq_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let value_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                    properties.push(AstCreatePolicyProperty {
                        name_span,
                        eq_span: eq_tok.span,
                        value_span: value_tok.span,
                        full_span: Span {
                            start: prop_start,
                            end: value_tok.span.end,
                        },
                    });
                }
                _ => {
                    // Unexpected token
                    break;
                }
            }
        }

        // Calculate full statement span
        let stmt_span = Span {
            start: create_span.start,
            end: properties
                .last()
                .map(|p| p.full_span.end)
                .or(extras.last().map(|e| e.span.end))
                .unwrap_or(policy_name_span.end),
        };

        // Build CST node
        let syntax_node = SyntaxCreateSessionPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            session_keyword: session_token_id,
            policy_keyword: policy_token_id,
            policy_name_span,
            properties: properties.clone(),
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_create_session_policy(syntax_node);

        // Build AST node
        let ast = AstCreateSessionPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            session_span,
            policy_span,
            policy_name_span,
            properties,
            extras,
        };
        Ok(AstStmt::CreateSessionPolicy(Box::new(ast)))
    }

    /// Parse ALTER SESSION POLICY statement.
    pub(crate) fn try_parse_alter_session_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_session_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_token_id = self.last_token_id();

        // SESSION (Identifier, NOT Keyword!)
        let session_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SESSION".to_string()])?;

        if !matches!(session_tok.kind, TokenKind::Identifier { .. })
            || !session_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SESSION")
        {
            return Err(ParseError::new(
                session_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SESSION keyword".to_string(),
                },
            ));
        }
        let session_span = session_tok.span;
        let session_token_id = self.last_token_id();

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
                        "IF keyword available after peek in alter_session_policy IF EXISTS",
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
        let name_span = self.parse_qualified_name_span()?;

        // Parse action(s)
        let actions = self.parse_alter_session_policy_actions()?;
        let action_span = match (actions.first(), actions.last()) {
            (Some(first), Some(last)) => Span {
                start: first.span.start,
                end: last.span.end,
            },
            _ => {
                return Err(ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected ALTER SESSION POLICY action".to_string(),
                    },
                ));
            }
        };

        // Calculate full statement span
        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        // Build CST node
        let syntax_action = SyntaxAlterSessionPolicyAction { span: action_span };
        let action_id = self
            .syntax_arena
            .alloc_alter_session_policy_action(syntax_action);

        let syntax_node = SyntaxAlterSessionPolicy {
            alter_keyword: alter_token_id,
            session_keyword: session_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            name_span,
            action_id,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_alter_session_policy_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterSessionPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            session_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span,
            actions,
        };
        Ok(AstStmt::AlterSessionPolicy(Box::new(ast)))
    }

    /// Parse DROP SESSION POLICY statement.
    pub(crate) fn try_parse_drop_session_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_session_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // SESSION (Identifier, NOT Keyword!)
        let session_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SESSION".to_string()])?;

        if !matches!(session_tok.kind, TokenKind::Identifier { .. })
            || !session_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SESSION")
        {
            return Err(ParseError::new(
                session_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SESSION keyword".to_string(),
                },
            ));
        }
        let session_span = session_tok.span;
        let session_token_id = self.last_token_id();

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
                        "IF keyword available after peek in drop_session_policy IF EXISTS",
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

        // Calculate full statement span
        let stmt_span = Span {
            start: drop_span.start,
            end: policy_name_span.end,
        };

        // Build CST node
        let syntax_node = SyntaxDropSessionPolicy {
            drop_keyword: drop_token_id,
            session_keyword: session_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            policy_name_span,
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_drop_session_policy(syntax_node);

        // Build AST node
        let ast = AstDropSessionPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            session_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropSessionPolicy(Box::new(ast)))
    }

    // Helper methods

    /// Parse ALTER SESSION POLICY action(s) (SET/UNSET/RENAME TO).
    fn parse_alter_session_policy_actions(
        &mut self,
    ) -> ParseResult<Vec<AstAlterSessionPolicyAction>> {
        let action_tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["RENAME, SET, or UNSET".to_string()],
        )?;

        let actions = match &action_tok.kind {
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

                vec![AstAlterSessionPolicyAction {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: action_tok.span.start,
                        end: new_name_span.end,
                    },
                    syntax_id: None,
                    kind: AstAlterSessionPolicyActionKind::RenameTo {
                        rename_span,
                        to_span,
                        new_name_span,
                    },
                }]
            }
            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = Some(action_tok.span);

                // Peek next token to determine what we're setting
                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["property or TAG".to_string()])?;

                match &next_tok.kind {
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
                        let assignments_span = Span {
                            start: assignments_start,
                            end: assignments_end,
                        };

                        vec![AstAlterSessionPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_tok.span.start,
                                end: assignments_span.end,
                            },
                            syntax_id: None,
                            kind: AstAlterSessionPolicyActionKind::SetTag {
                                set_span,
                                tag_span,
                                assignments_span,
                            },
                        }]
                    }
                    _ => self.parse_alter_session_policy_set_actions(set_span, action_tok.span)?,
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = Some(action_tok.span);

                // Peek next token
                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["property or TAG".to_string()])?;

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

                        vec![AstAlterSessionPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_tok.span.start,
                                end: tags_span.end,
                            },
                            syntax_id: None,
                            kind: AstAlterSessionPolicyActionKind::UnsetTag {
                                unset_span,
                                tag_span,
                                tags_span,
                            },
                        }]
                    }
                    _ => {
                        self.parse_alter_session_policy_unset_actions(unset_span, action_tok.span)?
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

        Ok(actions)
    }

    fn parse_alter_session_policy_set_actions(
        &mut self,
        initial_set_span: Option<Span>,
        fallback_start: Span,
    ) -> ParseResult<Vec<AstAlterSessionPolicyAction>> {
        let mut actions = Vec::new();
        let mut set_span_for_next = initial_set_span;

        while let Some(tok) = self.peek_non_trivia() {
            if self.is_alter_session_policy_action_boundary(tok) {
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance();
                continue;
            }

            let set_span = set_span_for_next.take();
            let start = set_span.map(|s| s.start).unwrap_or(tok.span.start);

            let kind = match tok.kind {
                TokenKind::Keyword(Keyword::Comment) => {
                    self.advance();
                    let comment_span = Some(tok.span);
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
                    AstAlterSessionPolicyActionKind::SetComment {
                        set_span,
                        comment_span,
                        eq_span,
                        comment_value_span: value_tok.span,
                    }
                }
                TokenKind::Identifier { .. } => {
                    let property_tok = self.advance().expect_invariant(
                        "identifier token available after peek in SET properties",
                    );
                    let property_span = property_tok.span;
                    let lexeme_upper = property_tok.lexeme(self.source).to_uppercase();

                    let eq_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let eq_span = if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                        Some(eq_tok.span)
                    } else {
                        None
                    };

                    match lexeme_upper.as_str() {
                        "SESSION_IDLE_TIMEOUT_MINS" => {
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["number".to_string()])?;
                            AstAlterSessionPolicyActionKind::SetSessionIdleTimeoutMins {
                                set_span,
                                property_span,
                                eq_span,
                                value_span: value_tok.span,
                            }
                        }
                        "SESSION_UI_IDLE_TIMEOUT_MINS" => {
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["number".to_string()])?;
                            AstAlterSessionPolicyActionKind::SetSessionUiIdleTimeoutMins {
                                set_span,
                                property_span,
                                eq_span,
                                value_span: value_tok.span,
                            }
                        }
                        "ALLOWED_SECONDARY_ROLES" => {
                            let RoleListSpec {
                                span: roles_spec_span,
                                lparen_token,
                                rparen_token,
                                values,
                            } = self.parse_role_list()?;
                            AstAlterSessionPolicyActionKind::SetAllowedSecondaryRoles {
                                set_span,
                                property_span,
                                eq_span,
                                roles_spec_span,
                                lparen_token: Some(lparen_token),
                                rparen_token: Some(rparen_token),
                                values,
                            }
                        }
                        "BLOCKED_SECONDARY_ROLES" => {
                            let RoleListSpec {
                                span: roles_spec_span,
                                lparen_token,
                                rparen_token,
                                values,
                            } = self.parse_role_list()?;
                            AstAlterSessionPolicyActionKind::SetBlockedSecondaryRoles {
                                set_span,
                                property_span,
                                eq_span,
                                roles_spec_span,
                                lparen_token: Some(lparen_token),
                                rparen_token: Some(rparen_token),
                                values,
                            }
                        }
                        _ => {
                            return Err(ParseError::new(
                                property_span,
                                ParseErrorKind::InvalidStatement {
                                    message: format!(
                                        "Unknown SESSION POLICY property: {}",
                                        property_tok.lexeme(self.source)
                                    ),
                                },
                            ));
                        }
                    }
                }
                _ => {
                    return Err(ParseError::new(
                        tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected property name, TAG, or COMMENT after SET"
                                .to_string(),
                        },
                    ));
                }
            };

            let end = match &kind {
                AstAlterSessionPolicyActionKind::SetSessionIdleTimeoutMins {
                    value_span, ..
                }
                | AstAlterSessionPolicyActionKind::SetSessionUiIdleTimeoutMins {
                    value_span, ..
                } => value_span.end,
                AstAlterSessionPolicyActionKind::SetAllowedSecondaryRoles {
                    roles_spec_span,
                    ..
                }
                | AstAlterSessionPolicyActionKind::SetBlockedSecondaryRoles {
                    roles_spec_span,
                    ..
                } => roles_spec_span.end,
                AstAlterSessionPolicyActionKind::SetComment {
                    comment_value_span, ..
                } => comment_value_span.end,
                _ => self.current_span().start,
            };

            actions.push(AstAlterSessionPolicyAction {
                node_id: self.id_gen.next(),
                span: Span { start, end },
                syntax_id: None,
                kind,
            });
        }

        if actions.is_empty() {
            return Err(ParseError::new(
                fallback_start,
                ParseErrorKind::InvalidStatement {
                    message: "Expected property name, TAG, or COMMENT after SET".to_string(),
                },
            ));
        }

        Ok(actions)
    }

    fn parse_alter_session_policy_unset_actions(
        &mut self,
        initial_unset_span: Option<Span>,
        fallback_start: Span,
    ) -> ParseResult<Vec<AstAlterSessionPolicyAction>> {
        let mut actions = Vec::new();
        let mut unset_span_for_next = initial_unset_span;

        while let Some(tok) = self.peek_non_trivia() {
            if self.is_alter_session_policy_action_boundary(tok) {
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance();
                continue;
            }

            let unset_span = unset_span_for_next.take();
            let start = unset_span.map(|s| s.start).unwrap_or(tok.span.start);

            let kind = match tok.kind {
                TokenKind::Keyword(Keyword::Comment) => {
                    self.advance();
                    AstAlterSessionPolicyActionKind::UnsetComment {
                        unset_span,
                        comment_span: Some(tok.span),
                    }
                }
                TokenKind::Identifier { .. } => {
                    let property_tok = self.advance().expect_invariant(
                        "identifier token available after peek in UNSET properties",
                    );
                    let property_span = property_tok.span;
                    let lexeme_upper = property_tok.lexeme(self.source).to_uppercase();

                    match lexeme_upper.as_str() {
                        "SESSION_IDLE_TIMEOUT_MINS" => {
                            AstAlterSessionPolicyActionKind::UnsetSessionIdleTimeoutMins {
                                unset_span,
                                property_span,
                            }
                        }
                        "SESSION_UI_IDLE_TIMEOUT_MINS" => {
                            AstAlterSessionPolicyActionKind::UnsetSessionUiIdleTimeoutMins {
                                unset_span,
                                property_span,
                            }
                        }
                        "ALLOWED_SECONDARY_ROLES" => {
                            AstAlterSessionPolicyActionKind::UnsetAllowedSecondaryRoles {
                                unset_span,
                                property_span,
                            }
                        }
                        "BLOCKED_SECONDARY_ROLES" => {
                            AstAlterSessionPolicyActionKind::UnsetBlockedSecondaryRoles {
                                unset_span,
                                property_span,
                            }
                        }
                        _ => {
                            return Err(ParseError::new(
                                property_span,
                                ParseErrorKind::InvalidStatement {
                                    message: format!(
                                        "Unknown SESSION POLICY property: {}",
                                        property_tok.lexeme(self.source)
                                    ),
                                },
                            ));
                        }
                    }
                }
                _ => {
                    return Err(ParseError::new(
                        tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected property name, TAG, or COMMENT after UNSET"
                                .to_string(),
                        },
                    ));
                }
            };

            let end = match &kind {
                AstAlterSessionPolicyActionKind::UnsetSessionIdleTimeoutMins {
                    property_span,
                    ..
                }
                | AstAlterSessionPolicyActionKind::UnsetSessionUiIdleTimeoutMins {
                    property_span,
                    ..
                }
                | AstAlterSessionPolicyActionKind::UnsetAllowedSecondaryRoles {
                    property_span,
                    ..
                }
                | AstAlterSessionPolicyActionKind::UnsetBlockedSecondaryRoles {
                    property_span,
                    ..
                } => property_span.end,
                AstAlterSessionPolicyActionKind::UnsetComment { comment_span, .. } => comment_span
                    .map(|s| s.end)
                    .unwrap_or(self.current_span().start),
                _ => self.current_span().start,
            };

            actions.push(AstAlterSessionPolicyAction {
                node_id: self.id_gen.next(),
                span: Span { start, end },
                syntax_id: None,
                kind,
            });
        }

        if actions.is_empty() {
            return Err(ParseError::new(
                fallback_start,
                ParseErrorKind::InvalidStatement {
                    message: "Expected property name, TAG, or COMMENT after UNSET".to_string(),
                },
            ));
        }

        Ok(actions)
    }

    fn is_alter_session_policy_action_boundary(&self, tok: &crate::lexer::Token) -> bool {
        matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
            || matches!(
                tok.kind,
                TokenKind::Keyword(
                    Keyword::Alter
                        | Keyword::Create
                        | Keyword::Drop
                        | Keyword::Select
                        | Keyword::Insert
                        | Keyword::Update
                        | Keyword::Delete
                        | Keyword::Merge
                )
            )
    }

    /// Parse role list: ( role1, role2, ... ) or () or ('ALL')
    fn parse_role_list(&mut self) -> ParseResult<RoleListSpec> {
        let lparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '(' for role list".to_string(),
                },
            ));
        }
        let lparen_token = self.last_token_id();
        let start = lparen_tok.span.start;

        // Parse individual role names (string literals or identifiers, comma-separated)
        let mut values = Vec::new();
        let mut expect_value = true;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                break;
            }
            if !expect_value {
                // Expect comma separator
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    expect_value = true;
                    continue;
                }
                break;
            }
            let val_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["role name".to_string()])?;
            values.push(val_tok.span);
            expect_value = false;
        }

        let rparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ')' after role list".to_string(),
                },
            ));
        }
        let rparen_token = self.last_token_id();
        let end = rparen_tok.span.end;

        Ok(RoleListSpec {
            span: Span { start, end },
            lparen_token,
            rparen_token,
            values,
        })
    }
}
