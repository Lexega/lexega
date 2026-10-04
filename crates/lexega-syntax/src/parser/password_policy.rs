// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for PASSWORD POLICY statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] PASSWORD POLICY [IF NOT EXISTS] name [properties]`
//! - `ALTER PASSWORD POLICY [IF EXISTS] name { RENAME TO | SET | UNSET }`
//! - `DROP PASSWORD POLICY [IF EXISTS] name`
//!
//! Token reference:
//! - PASSWORD is Identifier, NOT Keyword
//! - Property names (PASSWORD_MIN_LENGTH, etc.) are Identifiers
//! - Must use lexeme matching with eq_ignore_ascii_case()

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterPasswordPolicy, AstAlterPasswordPolicyAction, AstAlterPasswordPolicyActionKind,
    AstCreatePasswordPolicy, AstDropPasswordPolicy, AstUnknownClause,
    CreatePolicyProperty as AstCreatePolicyProperty, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterPasswordPolicy, SyntaxAlterPasswordPolicyAction, SyntaxCreatePasswordPolicy,
    SyntaxDropPasswordPolicy,
};

impl<'a> Parser<'a> {
    /// Parse CREATE PASSWORD POLICY statement.
    pub(crate) fn try_parse_create_password_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_password_policy")?;

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
                        "OR token available after peek in create_password_policy",
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

        // PASSWORD (Identifier, NOT Keyword!)
        let password_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PASSWORD".to_string()])?;

        if !matches!(password_tok.kind, TokenKind::Identifier { .. })
            || !password_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("PASSWORD")
        {
            return Err(ParseError::new(
                password_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected PASSWORD keyword".to_string(),
                },
            ));
        }
        let password_span = password_tok.span;
        let password_token_id = self.last_token_id();

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
                        "IF token available after peek in create_password_policy",
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
        let mut properties: Vec<AstCreatePolicyProperty> = Vec::new();

        let mut extras: Vec<AstUnknownClause> = Vec::new();

        // Parse properties until we hit semicolon or EOF
        while let Some(tok) = self.peek_non_trivia() {
            let prop_start = tok.span.start;

            match &tok.kind {
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    match lexeme_upper.as_str() {
                        "PASSWORD_MIN_LENGTH"
                        | "PASSWORD_MAX_LENGTH"
                        | "PASSWORD_MIN_UPPER_CASE_CHARS"
                        | "PASSWORD_MIN_LOWER_CASE_CHARS"
                        | "PASSWORD_MIN_NUMERIC_CHARS"
                        | "PASSWORD_MIN_SPECIAL_CHARS"
                        | "PASSWORD_MIN_AGE_DAYS"
                        | "PASSWORD_MAX_AGE_DAYS"
                        | "PASSWORD_MAX_RETRIES"
                        | "PASSWORD_LOCKOUT_TIME_MINS"
                        | "PASSWORD_HISTORY" => {
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
                        _ => {
                            // Unknown property - defensive design
                            let unknown_tok = self.advance().expect_invariant("unknown property token available after peek in create_password_policy");
                            // Consume until next property or semicolon
                            while let Some(tok) = self.peek_non_trivia() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                    break;
                                }
                                if matches!(tok.kind, TokenKind::Identifier { .. }) {
                                    let lex_up = tok.lexeme(self.source).to_uppercase();
                                    if lex_up.starts_with("PASSWORD_") || lex_up == "COMMENT" {
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
        let syntax_node = SyntaxCreatePasswordPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            password_token: password_token_id,
            policy_keyword: policy_token_id,
            policy_name_span,
            properties: properties.clone(),
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_create_password_policy(syntax_node);

        // Build AST node
        let ast = AstCreatePasswordPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            password_span,
            policy_span,
            policy_name_span,
            properties,
            extras,
        };
        Ok(AstStmt::CreatePasswordPolicy(Box::new(ast)))
    }

    /// Parse ALTER PASSWORD POLICY statement.
    pub(crate) fn try_parse_alter_password_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_password_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_token_id = self.last_token_id();

        // PASSWORD (Identifier, NOT Keyword!)
        let password_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PASSWORD".to_string()])?;

        if !matches!(password_tok.kind, TokenKind::Identifier { .. })
            || !password_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("PASSWORD")
        {
            return Err(ParseError::new(
                password_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected PASSWORD keyword".to_string(),
                },
            ));
        }
        let password_span = password_tok.span;
        let password_token_id = self.last_token_id();

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
                        .expect_invariant("IF token available after peek in alter_password_policy");
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

        // Parse actions
        let mut actions: Vec<AstAlterPasswordPolicyAction> = Vec::new();
        let action_start_pos = self.current_span().start;

        // Parse at least one action
        let action = self.parse_alter_password_policy_action()?;
        let first_is_set = action.kind.is_set_property();
        let first_is_unset = action.kind.is_unset_property();
        actions.push(action);

        // For SET/UNSET actions, additional properties may follow without repeating the keyword
        // e.g. ALTER PASSWORD POLICY p SET PASSWORD_MIN_LENGTH = 14 PASSWORD_MAX_LENGTH = 128;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi)
                    | TokenKind::Keyword(Keyword::Set | Keyword::Unset | Keyword::Rename)
            ) {
                break;
            }
            if first_is_set
                && (matches!(tok.kind, TokenKind::Identifier { .. })
                    || matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)))
            {
                let additional = self.parse_set_password_property(None)?;
                actions.push(additional);
            } else if first_is_unset
                && (matches!(tok.kind, TokenKind::Identifier { .. })
                    || matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)))
            {
                let additional = self.parse_unset_password_property(None)?;
                actions.push(additional);
            } else {
                break;
            }
        }

        // Calculate action span (from first action to last)
        let action_span = Span {
            start: action_start_pos,
            end: actions
                .last()
                .map(|a| a.span.end)
                .unwrap_or(action_start_pos),
        };

        // Calculate full statement span
        let stmt_span = Span {
            start: alter_span.start,
            end: actions.last().map(|a| a.span.end).unwrap_or(name_span.end),
        };

        // Build CST action node (minimal - details in AST)
        let action_syntax_node = SyntaxAlterPasswordPolicyAction { span: action_span };
        let action_syntax_id = self
            .syntax_arena
            .alloc_alter_password_policy_action(action_syntax_node);

        // Build CST statement node
        let syntax_node = SyntaxAlterPasswordPolicy {
            alter_keyword: alter_token_id,
            password_token: password_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            name_span,
            action_id: action_syntax_id,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_alter_password_policy_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterPasswordPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            password_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span,
            actions,
        };
        Ok(AstStmt::AlterPasswordPolicy(Box::new(ast)))
    }

    /// Parse DROP PASSWORD POLICY statement.
    pub(crate) fn try_parse_drop_password_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_password_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // PASSWORD (Identifier, NOT Keyword!)
        let password_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PASSWORD".to_string()])?;

        if !matches!(password_tok.kind, TokenKind::Identifier { .. })
            || !password_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("PASSWORD")
        {
            return Err(ParseError::new(
                password_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected PASSWORD keyword".to_string(),
                },
            ));
        }
        let password_span = password_tok.span;
        let password_token_id = self.last_token_id();

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
                        .expect_invariant("IF token available after peek in drop_password_policy");
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
        let syntax_node = SyntaxDropPasswordPolicy {
            drop_keyword: drop_token_id,
            password_token: password_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            policy_name_span,
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_drop_password_policy(syntax_node);

        // Build AST node
        let ast = AstDropPasswordPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            password_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropPasswordPolicy(Box::new(ast)))
    }

    // Helper methods

    /// Parse ALTER PASSWORD POLICY action (SET/UNSET/RENAME TO).
    fn parse_alter_password_policy_action(&mut self) -> ParseResult<AstAlterPasswordPolicyAction> {
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

                AstAlterPasswordPolicyActionKind::RenameTo {
                    rename_span,
                    to_span,
                    new_name_span,
                }
            }
            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = Some(action_tok.span);

                // Check what's being set
                let next_tok = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["property name or TAG".to_string()],
                )?;

                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    // SET TAG
                    self.advance(); // consume TAG
                    let tag_span = Some(next_tok.span);

                    // Parse tag assignments (TAG_NAME = 'value', ...)
                    let tags_start = self.current_span().start;

                    // Consume until we hit something else or run out of tokens
                    let mut tag_end = tags_start;
                    while let Some(tok) = self.peek_non_trivia() {
                        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                            || matches!(tok.kind, TokenKind::Keyword(Keyword::Set))
                            || matches!(tok.kind, TokenKind::Keyword(Keyword::Unset))
                        {
                            break;
                        }
                        tag_end = tok.span.end;
                        self.advance();
                    }

                    let tags_span = Span {
                        start: tags_start,
                        end: tag_end,
                    };

                    AstAlterPasswordPolicyActionKind::SetTag {
                        set_span,
                        tag_span,
                        assignments_span: tags_span,
                    }
                } else {
                    // Delegate to shared SET property parser
                    return self.parse_set_password_property(set_span);
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = Some(action_tok.span);

                let next_tok = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["property name or TAG".to_string()],
                )?;

                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    // UNSET TAG
                    self.advance(); // consume TAG
                    let tag_span = Some(next_tok.span);

                    // Parse tag names
                    let tags_start = self.current_span().start;

                    let mut tag_end = tags_start;
                    while let Some(tok) = self.peek_non_trivia() {
                        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                            || matches!(tok.kind, TokenKind::Keyword(Keyword::Set))
                            || matches!(tok.kind, TokenKind::Keyword(Keyword::Unset))
                        {
                            break;
                        }
                        tag_end = tok.span.end;
                        self.advance();
                    }

                    let tags_span = Span {
                        start: tags_start,
                        end: tag_end,
                    };

                    AstAlterPasswordPolicyActionKind::UnsetTag {
                        unset_span,
                        tag_span,
                        tags_span,
                    }
                } else {
                    // Delegate to shared UNSET property parser
                    return self.parse_unset_password_property(unset_span);
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

        let action_span = Span {
            start: action_start,
            end: self.current_span().start,
        };

        let action = AstAlterPasswordPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind,
        };

        Ok(action)
    }

    /// Parse a SET property (COMMENT or identifier property) for ALTER PASSWORD POLICY.
    /// `set_span` is Some for the first property (has SET keyword), None for continuations.
    fn parse_set_password_property(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterPasswordPolicyAction> {
        let action_start = self.current_span().start;

        let next_tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["property name or COMMENT".to_string()],
        )?;

        let kind = if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            // SET COMMENT = 'value'
            self.advance(); // consume COMMENT
            let comment_keyword_span = Some(next_tok.span);

            let eq_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
            let eq_span = Some(eq_tok.span);

            let value_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["string".to_string()])?;

            AstAlterPasswordPolicyActionKind::SetComment {
                set_span,
                comment_span: comment_keyword_span,
                eq_span,
                comment_value_span: value_tok.span,
            }
        } else if matches!(next_tok.kind, TokenKind::Identifier { .. }) {
            let property_tok = self.advance().expect_invariant(
                "property identifier available after peek in parse_set_password_property",
            );
            let property_span = property_tok.span;
            let property_name = property_tok.lexeme(self.source).to_uppercase();

            let eq_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
            let eq_span = Some(eq_tok.span);

            let value_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
            let value_span = value_tok.span;

            match property_name.as_str() {
                "PASSWORD_MIN_LENGTH" => AstAlterPasswordPolicyActionKind::SetPasswordMinLength {
                    set_span,
                    property_span,
                    eq_span,
                    value_span,
                },
                "PASSWORD_MAX_LENGTH" => AstAlterPasswordPolicyActionKind::SetPasswordMaxLength {
                    set_span,
                    property_span,
                    eq_span,
                    value_span,
                },
                "PASSWORD_MIN_UPPER_CASE_CHARS" => {
                    AstAlterPasswordPolicyActionKind::SetPasswordMinUpperCaseChars {
                        set_span,
                        property_span,
                        eq_span,
                        value_span,
                    }
                }
                "PASSWORD_MIN_LOWER_CASE_CHARS" => {
                    AstAlterPasswordPolicyActionKind::SetPasswordMinLowerCaseChars {
                        set_span,
                        property_span,
                        eq_span,
                        value_span,
                    }
                }
                "PASSWORD_MIN_NUMERIC_CHARS" => {
                    AstAlterPasswordPolicyActionKind::SetPasswordMinNumericChars {
                        set_span,
                        property_span,
                        eq_span,
                        value_span,
                    }
                }
                "PASSWORD_MIN_SPECIAL_CHARS" => {
                    AstAlterPasswordPolicyActionKind::SetPasswordMinSpecialChars {
                        set_span,
                        property_span,
                        eq_span,
                        value_span,
                    }
                }
                "PASSWORD_MIN_AGE_DAYS" => {
                    AstAlterPasswordPolicyActionKind::SetPasswordMinAgeDays {
                        set_span,
                        property_span,
                        eq_span,
                        value_span,
                    }
                }
                "PASSWORD_MAX_AGE_DAYS" => {
                    AstAlterPasswordPolicyActionKind::SetPasswordMaxAgeDays {
                        set_span,
                        property_span,
                        eq_span,
                        value_span,
                    }
                }
                "PASSWORD_MAX_RETRIES" => AstAlterPasswordPolicyActionKind::SetPasswordMaxRetries {
                    set_span,
                    property_span,
                    eq_span,
                    value_span,
                },
                "PASSWORD_LOCKOUT_TIME_MINS" => {
                    AstAlterPasswordPolicyActionKind::SetPasswordLockoutTimeMins {
                        set_span,
                        property_span,
                        eq_span,
                        value_span,
                    }
                }
                "PASSWORD_HISTORY" => AstAlterPasswordPolicyActionKind::SetPasswordHistory {
                    set_span,
                    property_span,
                    eq_span,
                    value_span,
                },
                _ => {
                    return Err(ParseError::new(
                        property_span,
                        ParseErrorKind::InvalidStatement {
                            message: format!("Unknown PASSWORD POLICY property: {}", property_name),
                        },
                    ));
                }
            }
        } else {
            return Err(ParseError::new(
                next_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected property name or COMMENT after SET".to_string(),
                },
            ));
        };

        let action_span = Span {
            start: action_start,
            end: self.current_span().start,
        };

        Ok(AstAlterPasswordPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind,
        })
    }

    /// Parse an UNSET property (COMMENT or identifier property) for ALTER PASSWORD POLICY.
    /// `unset_span` is Some for the first property (has UNSET keyword), None for continuations.
    fn parse_unset_password_property(
        &mut self,
        unset_span: Option<Span>,
    ) -> ParseResult<AstAlterPasswordPolicyAction> {
        let action_start = self.current_span().start;

        let next_tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["property name or COMMENT".to_string()],
        )?;

        let kind = if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            self.advance(); // consume COMMENT
            AstAlterPasswordPolicyActionKind::UnsetComment {
                unset_span,
                comment_span: Some(next_tok.span),
            }
        } else if matches!(next_tok.kind, TokenKind::Identifier { .. }) {
            let property_tok = self.advance().expect_invariant(
                "property identifier available after peek in parse_unset_password_property",
            );
            let property_span = property_tok.span;
            let property_name = property_tok.lexeme(self.source).to_uppercase();

            match property_name.as_str() {
                "PASSWORD_MIN_LENGTH" => AstAlterPasswordPolicyActionKind::UnsetPasswordMinLength {
                    unset_span,
                    property_span,
                },
                "PASSWORD_MAX_LENGTH" => AstAlterPasswordPolicyActionKind::UnsetPasswordMaxLength {
                    unset_span,
                    property_span,
                },
                "PASSWORD_MIN_UPPER_CASE_CHARS" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordMinUpperCaseChars {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_MIN_LOWER_CASE_CHARS" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordMinLowerCaseChars {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_MIN_NUMERIC_CHARS" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordMinNumericChars {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_MIN_SPECIAL_CHARS" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordMinSpecialChars {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_MIN_AGE_DAYS" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordMinAgeDays {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_MAX_AGE_DAYS" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordMaxAgeDays {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_MAX_RETRIES" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordMaxRetries {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_LOCKOUT_TIME_MINS" => {
                    AstAlterPasswordPolicyActionKind::UnsetPasswordLockoutTimeMins {
                        unset_span,
                        property_span,
                    }
                }
                "PASSWORD_HISTORY" => AstAlterPasswordPolicyActionKind::UnsetPasswordHistory {
                    unset_span,
                    property_span,
                },
                _ => {
                    return Err(ParseError::new(
                        property_span,
                        ParseErrorKind::InvalidStatement {
                            message: format!("Unknown PASSWORD POLICY property: {}", property_name),
                        },
                    ));
                }
            }
        } else {
            return Err(ParseError::new(
                next_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected property name or COMMENT after UNSET".to_string(),
                },
            ));
        };

        let action_span = Span {
            start: action_start,
            end: self.current_span().start,
        };

        Ok(AstAlterPasswordPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind,
        })
    }
}
