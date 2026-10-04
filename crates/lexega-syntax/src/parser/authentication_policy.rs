// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for AUTHENTICATION POLICY statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE | OR ALTER] AUTHENTICATION POLICY [IF NOT EXISTS] name [properties]`
//! - ALTER AUTHENTICATION POLICY name RENAME TO new_name
//! - `ALTER AUTHENTICATION POLICY [IF EXISTS] name { SET | UNSET } properties`
//! - `DROP AUTHENTICATION POLICY [IF EXISTS] name`
//!
//! Token reference:
//! - AUTHENTICATION is Identifier, NOT Keyword
//! - Property names (AUTHENTICATION_METHODS, CLIENT_TYPES, etc.) are Identifiers
//! - Must use lexeme matching with eq_ignore_ascii_case()

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterAuthenticationPolicy, AstAlterAuthenticationPolicyAction,
    AstAlterAuthenticationPolicyActionKind, AstCreateAuthenticationPolicy,
    AstDropAuthenticationPolicy, AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterAuthenticationPolicy, SyntaxAlterAuthenticationPolicyAction,
    SyntaxCreateAuthenticationPolicy, SyntaxDropAuthenticationPolicy,
};

impl<'a> Parser<'a> {
    /// Parse CREATE AUTHENTICATION POLICY statement.
    pub(crate) fn try_parse_create_authentication_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_authentication_policy")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let create_token_id = self.last_token_id();

        // Optional OR REPLACE or OR ALTER
        let mut or_replace_span = None;
        let mut or_alter_span = None;
        let mut or_token_id = None;
        let mut replace_token_id = None;
        let mut alter_token_in_create_id = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                let or_tok = self
                    .advance()
                    .expect_invariant("OR keyword available after peek");
                or_token_id = Some(self.last_token_id());

                let next_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["REPLACE or ALTER".to_string()])?;

                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    replace_token_id = Some(self.last_token_id());
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: next_tok.span.end,
                    });
                } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Alter)) {
                    alter_token_in_create_id = Some(self.last_token_id());
                    or_alter_span = Some(Span {
                        start: or_tok.span.start,
                        end: next_tok.span.end,
                    });
                } else {
                    return Err(ParseError::new(
                        next_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected REPLACE or ALTER after OR".to_string(),
                        },
                    ));
                }
            }
        }

        // AUTHENTICATION (Identifier, NOT Keyword!)
        let auth_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AUTHENTICATION".to_string()])?;

        if !matches!(auth_tok.kind, TokenKind::Identifier { .. })
            || !auth_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("AUTHENTICATION")
        {
            return Err(ParseError::new(
                auth_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AUTHENTICATION keyword".to_string(),
                },
            ));
        }
        let authentication_span = auth_tok.span;
        let authentication_token_id = self.last_token_id();

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

        // Optional IF NOT EXISTS (only for CREATE, not CREATE OR ALTER)
        let mut if_not_exists_span = None;
        let mut if_token_id = None;
        let mut not_token_id = None;
        let mut exists_token_id = None;

        if or_alter_span.is_none() {
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword available after peek");
                    if_token_id = Some(self.last_token_id());

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
                    not_token_id = Some(self.last_token_id());

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
                    exists_token_id = Some(self.last_token_id());

                    if_not_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists_tok.span.end,
                    });
                }
            }
        }

        // Policy name
        let policy_name_span = self.parse_qualified_name_span()?;
        let mut authentication_methods_span = None;
        let mut client_types_span = None;
        let mut client_policy_span = None;
        let mut mfa_enrollment_span = None;
        let mut mfa_policy_span = None;
        let mut pat_policy_span = None;
        let mut workload_identity_policy_span = None;
        let mut security_integrations_span = None;
        let mut comment_span = None;
        let mut extras = Vec::new();

        let mut last_prop_end = policy_name_span.end;

        while let Some(tok) = self.peek_non_trivia() {
            // Check if we've reached end of statement
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }

            // Try to parse a property
            let prop_tok = tok; // Already peeked
            let prop_start = prop_tok.span.start;

            match &prop_tok.kind {
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();
                    match lexeme_upper.as_str() {
                        "AUTHENTICATION_METHODS" => {
                            self.advance();
                            let span = self.parse_property_with_paren_list(prop_start)?;
                            authentication_methods_span = Some(span);
                            last_prop_end = span.end;
                        }
                        "CLIENT_TYPES" => {
                            self.advance();
                            let span = self.parse_property_with_paren_list(prop_start)?;
                            client_types_span = Some(span);
                            last_prop_end = span.end;
                        }
                        "CLIENT_POLICY" => {
                            self.advance();
                            let span = self.parse_property_with_nested_parens(prop_start)?;
                            client_policy_span = Some(span);
                            last_prop_end = span.end;
                        }
                        "MFA_ENROLLMENT" => {
                            self.advance();
                            let span = self.parse_simple_property_value(prop_start)?;
                            mfa_enrollment_span = Some(span);
                            last_prop_end = span.end;
                        }
                        "MFA_POLICY" => {
                            self.advance();
                            let span = self.parse_property_with_nested_parens(prop_start)?;
                            mfa_policy_span = Some(span);
                            last_prop_end = span.end;
                        }
                        "PAT_POLICY" => {
                            self.advance();
                            let span = self.parse_property_with_nested_parens(prop_start)?;
                            pat_policy_span = Some(span);
                            last_prop_end = span.end;
                        }
                        "WORKLOAD_IDENTITY_POLICY" => {
                            self.advance();
                            let span = self.parse_property_with_nested_parens(prop_start)?;
                            workload_identity_policy_span = Some(span);
                            last_prop_end = span.end;
                        }
                        "SECURITY_INTEGRATIONS" => {
                            self.advance();
                            let span = self.parse_security_integrations_value(prop_start)?;
                            security_integrations_span = Some(span);
                            last_prop_end = span.end;
                        }
                        _ => {
                            // Unknown property - defensive design
                            let unknown_tok = self
                                .advance()
                                .expect_invariant("unknown property token available after peek");
                            let end_pos = self.consume_unknown_property()?;
                            extras.push(AstUnknownClause {
                                introducer: Some(unknown_tok.span),
                                span: Span {
                                    start: prop_start,
                                    end: end_pos,
                                },
                                kind: UnknownKind::Property,
                                node_id: self.id_gen.next(),
                            });
                            last_prop_end = end_pos;
                        }
                    }
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    self.advance();
                    let span = self.parse_simple_property_value(prop_start)?;
                    comment_span = Some(span);
                    last_prop_end = span.end;
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
            end: last_prop_end,
        };

        // Build CST node
        let syntax_node = SyntaxCreateAuthenticationPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            alter_keyword_in_create: alter_token_in_create_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            authentication_token: authentication_token_id,
            policy_keyword: policy_token_id,
            policy_name_span,
            authentication_methods_span,
            client_types_span,
            client_policy_span,
            mfa_enrollment_span,
            mfa_policy_span,
            pat_policy_span,
            workload_identity_policy_span,
            security_integrations_span,
            comment_span,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_create_authentication_policy(syntax_node);

        // Build AST node
        let ast = AstCreateAuthenticationPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            or_alter_span,
            if_not_exists_span,
            authentication_span,
            policy_span,
            policy_name_span,
            authentication_methods_span,
            client_types_span,
            client_policy_span,
            mfa_enrollment_span,
            mfa_policy_span,
            pat_policy_span,
            workload_identity_policy_span,
            security_integrations_span,
            comment_span,
            extras,
        };
        Ok(AstStmt::CreateAuthenticationPolicy(Box::new(ast)))
    }

    /// Parse ALTER AUTHENTICATION POLICY statement.
    pub(crate) fn try_parse_alter_authentication_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_authentication_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_token_id = self.last_token_id();

        // AUTHENTICATION (Identifier, NOT Keyword!)
        let auth_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AUTHENTICATION".to_string()])?;

        if !matches!(auth_tok.kind, TokenKind::Identifier { .. })
            || !auth_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("AUTHENTICATION")
        {
            return Err(ParseError::new(
                auth_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AUTHENTICATION keyword".to_string(),
                },
            ));
        }
        let authentication_span = auth_tok.span;
        let authentication_token_id = self.last_token_id();

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

        // Check for IF EXISTS or policy name
        // Note: RENAME TO does NOT support IF EXISTS per Snowflake docs
        let mut if_exists_span = None;
        let mut if_token_id = None;
        let mut exists_token_id = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword available after peek in ALTER");
                if_token_id = Some(self.last_token_id());

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
                exists_token_id = Some(self.last_token_id());

                if_exists_span = Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                });
            }
        }

        // Policy name
        let name_span = self.parse_qualified_name_span()?;

        // Parse action
        let action = self.parse_alter_authentication_policy_action()?;
        let action_span = action.span;

        // Calculate full statement span
        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        // Build CST node
        let syntax_action = SyntaxAlterAuthenticationPolicyAction { span: action_span };
        let action_id = self
            .syntax_arena
            .alloc_alter_authentication_policy_action(syntax_action);

        let syntax_node = SyntaxAlterAuthenticationPolicy {
            alter_keyword: alter_token_id,
            authentication_token: authentication_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            name_span,
            action_id,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_alter_authentication_policy_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterAuthenticationPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            authentication_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span,
            action,
        };
        Ok(AstStmt::AlterAuthenticationPolicy(Box::new(ast)))
    }

    /// Parse DROP AUTHENTICATION POLICY statement.
    pub(crate) fn try_parse_drop_authentication_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_authentication_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // AUTHENTICATION (Identifier, NOT Keyword!)
        let auth_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AUTHENTICATION".to_string()])?;

        if !matches!(auth_tok.kind, TokenKind::Identifier { .. })
            || !auth_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("AUTHENTICATION")
        {
            return Err(ParseError::new(
                auth_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AUTHENTICATION keyword".to_string(),
                },
            ));
        }
        let authentication_span = auth_tok.span;
        let authentication_token_id = self.last_token_id();

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
        let mut if_exists_span = None;
        let mut if_token_id = None;
        let mut exists_token_id = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword available after peek in DROP");
                if_token_id = Some(self.last_token_id());

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
                exists_token_id = Some(self.last_token_id());

                if_exists_span = Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                });
            }
        }

        // Policy name
        let policy_name_span = self.parse_qualified_name_span()?;

        // Calculate full statement span
        let stmt_span = Span {
            start: drop_span.start,
            end: policy_name_span.end,
        };

        // Build CST node
        let syntax_node = SyntaxDropAuthenticationPolicy {
            drop_keyword: drop_token_id,
            authentication_token: authentication_token_id,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            policy_name_span,
            span: stmt_span,
        };

        let syntax_id = self
            .syntax_arena
            .alloc_drop_authentication_policy(syntax_node);

        // Build AST node
        let ast = AstDropAuthenticationPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            authentication_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropAuthenticationPolicy(Box::new(ast)))
    }

    // ========================================================================
    // Helper methods for AUTHENTICATION POLICY parsing
    // ========================================================================

    /// Parse ALTER AUTHENTICATION POLICY action (SET/UNSET/RENAME TO).
    fn parse_alter_authentication_policy_action(
        &mut self,
    ) -> ParseResult<AstAlterAuthenticationPolicyAction> {
        let action_tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["RENAME, SET, or UNSET".to_string()],
        )?;

        let action_start = action_tok.span.start;

        let kind = match action_tok.kind {
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

                AstAlterAuthenticationPolicyActionKind::RenameTo {
                    rename_span,
                    to_span,
                    new_name_span,
                }
            }
            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = Some(action_tok.span);

                self.parse_authentication_policy_set_action(set_span)?
            }
            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = Some(action_tok.span);

                self.parse_authentication_policy_unset_action(unset_span)?
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

        // Calculate action span
        let action_end = match &kind {
            AstAlterAuthenticationPolicyActionKind::RenameTo { new_name_span, .. } => {
                new_name_span.end
            }
            AstAlterAuthenticationPolicyActionKind::SetAuthenticationMethods {
                value_span, ..
            } => value_span.end,
            AstAlterAuthenticationPolicyActionKind::SetClientTypes { value_span, .. } => {
                value_span.end
            }
            AstAlterAuthenticationPolicyActionKind::SetClientPolicy { value_span, .. } => {
                value_span.end
            }
            AstAlterAuthenticationPolicyActionKind::SetMfaEnrollment { value_span, .. } => {
                value_span.end
            }
            AstAlterAuthenticationPolicyActionKind::SetMfaPolicy { value_span, .. } => {
                value_span.end
            }
            AstAlterAuthenticationPolicyActionKind::SetPatPolicy { value_span, .. } => {
                value_span.end
            }
            AstAlterAuthenticationPolicyActionKind::SetWorkloadIdentityPolicy {
                value_span,
                ..
            } => value_span.end,
            AstAlterAuthenticationPolicyActionKind::SetSecurityIntegrations {
                value_span, ..
            } => value_span.end,
            AstAlterAuthenticationPolicyActionKind::SetComment { value_span, .. } => value_span.end,
            AstAlterAuthenticationPolicyActionKind::UnsetAuthenticationMethods {
                property_span,
                ..
            } => property_span.end,
            AstAlterAuthenticationPolicyActionKind::UnsetClientTypes { property_span, .. } => {
                property_span.end
            }
            AstAlterAuthenticationPolicyActionKind::UnsetClientPolicy { property_span, .. } => {
                property_span.end
            }
            AstAlterAuthenticationPolicyActionKind::UnsetMfaEnrollment {
                property_span, ..
            } => property_span.end,
            AstAlterAuthenticationPolicyActionKind::UnsetMfaPolicy { property_span, .. } => {
                property_span.end
            }
            AstAlterAuthenticationPolicyActionKind::UnsetPatPolicy { property_span, .. } => {
                property_span.end
            }
            AstAlterAuthenticationPolicyActionKind::UnsetWorkloadIdentityPolicy {
                property_span,
                ..
            } => property_span.end,
            AstAlterAuthenticationPolicyActionKind::UnsetSecurityIntegrations {
                property_span,
                ..
            } => property_span.end,
            AstAlterAuthenticationPolicyActionKind::UnsetComment { property_span, .. } => {
                property_span.map(|s| s.end).unwrap_or(action_start)
            }
        };

        Ok(AstAlterAuthenticationPolicyAction {
            node_id: self.id_gen.next(),
            span: Span {
                start: action_start,
                end: action_end,
            },
            syntax_id: None,
            kind,
        })
    }

    /// Parse SET action for ALTER AUTHENTICATION POLICY.
    fn parse_authentication_policy_set_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterAuthenticationPolicyActionKind> {
        let prop_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["property name".to_string()])?;
        #[allow(unused_variables)]
        let prop_start = prop_tok.span.start;

        match &prop_tok.kind {
            TokenKind::Identifier { .. } => {
                let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();
                match lexeme_upper.as_str() {
                    "AUTHENTICATION_METHODS" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_span = self.parse_paren_list_span()?;
                        Ok(
                            AstAlterAuthenticationPolicyActionKind::SetAuthenticationMethods {
                                set_span,
                                property_span,
                                eq_span,
                                value_span,
                            },
                        )
                    }
                    "CLIENT_TYPES" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_span = self.parse_paren_list_span()?;
                        Ok(AstAlterAuthenticationPolicyActionKind::SetClientTypes {
                            set_span,
                            property_span,
                            eq_span,
                            value_span,
                        })
                    }
                    "CLIENT_POLICY" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_span = self.parse_nested_paren_span()?;
                        Ok(AstAlterAuthenticationPolicyActionKind::SetClientPolicy {
                            set_span,
                            property_span,
                            eq_span,
                            value_span,
                        })
                    }
                    "MFA_ENROLLMENT" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                        let value_span = value_tok.span;
                        Ok(AstAlterAuthenticationPolicyActionKind::SetMfaEnrollment {
                            set_span,
                            property_span,
                            eq_span,
                            value_span,
                        })
                    }
                    "MFA_POLICY" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_span = self.parse_nested_paren_span()?;
                        Ok(AstAlterAuthenticationPolicyActionKind::SetMfaPolicy {
                            set_span,
                            property_span,
                            eq_span,
                            value_span,
                        })
                    }
                    "PAT_POLICY" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_span = self.parse_nested_paren_span()?;
                        Ok(AstAlterAuthenticationPolicyActionKind::SetPatPolicy {
                            set_span,
                            property_span,
                            eq_span,
                            value_span,
                        })
                    }
                    "WORKLOAD_IDENTITY_POLICY" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_span = self.parse_nested_paren_span()?;
                        Ok(
                            AstAlterAuthenticationPolicyActionKind::SetWorkloadIdentityPolicy {
                                set_span,
                                property_span,
                                eq_span,
                                value_span,
                            },
                        )
                    }
                    "SECURITY_INTEGRATIONS" => {
                        self.advance();
                        let property_span = prop_tok.span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = Some(eq_tok.span);
                        let value_span = self.parse_security_integrations_value_span()?;
                        Ok(
                            AstAlterAuthenticationPolicyActionKind::SetSecurityIntegrations {
                                set_span,
                                property_span,
                                eq_span,
                                value_span,
                            },
                        )
                    }
                    _ => Err(ParseError::new(
                        prop_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Unknown SET property: {}",
                                prop_tok.lexeme(self.source)
                            ),
                        },
                    )),
                }
            }
            TokenKind::Keyword(Keyword::Comment) => {
                self.advance();
                let property_span = Some(prop_tok.span);
                let eq_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                let eq_span = Some(eq_tok.span);
                let value_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                let value_span = value_tok.span;
                Ok(AstAlterAuthenticationPolicyActionKind::SetComment {
                    set_span,
                    property_span,
                    eq_span,
                    value_span,
                })
            }
            _ => Err(ParseError::new(
                prop_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected property name after SET".to_string(),
                },
            )),
        }
    }

    /// Parse UNSET action for ALTER AUTHENTICATION POLICY.
    fn parse_authentication_policy_unset_action(
        &mut self,
        unset_span: Option<Span>,
    ) -> ParseResult<AstAlterAuthenticationPolicyActionKind> {
        let prop_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["property name".to_string()])?;

        match &prop_tok.kind {
            TokenKind::Identifier { .. } => {
                let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();
                self.advance();
                let property_span = prop_tok.span;

                match lexeme_upper.as_str() {
                    "AUTHENTICATION_METHODS" => Ok(
                        AstAlterAuthenticationPolicyActionKind::UnsetAuthenticationMethods {
                            unset_span,
                            property_span,
                        },
                    ),
                    "CLIENT_TYPES" => {
                        Ok(AstAlterAuthenticationPolicyActionKind::UnsetClientTypes {
                            unset_span,
                            property_span,
                        })
                    }
                    "CLIENT_POLICY" => {
                        Ok(AstAlterAuthenticationPolicyActionKind::UnsetClientPolicy {
                            unset_span,
                            property_span,
                        })
                    }
                    "MFA_ENROLLMENT" => {
                        Ok(AstAlterAuthenticationPolicyActionKind::UnsetMfaEnrollment {
                            unset_span,
                            property_span,
                        })
                    }
                    "MFA_POLICY" => Ok(AstAlterAuthenticationPolicyActionKind::UnsetMfaPolicy {
                        unset_span,
                        property_span,
                    }),
                    "PAT_POLICY" => Ok(AstAlterAuthenticationPolicyActionKind::UnsetPatPolicy {
                        unset_span,
                        property_span,
                    }),
                    "WORKLOAD_IDENTITY_POLICY" => Ok(
                        AstAlterAuthenticationPolicyActionKind::UnsetWorkloadIdentityPolicy {
                            unset_span,
                            property_span,
                        },
                    ),
                    "SECURITY_INTEGRATIONS" => Ok(
                        AstAlterAuthenticationPolicyActionKind::UnsetSecurityIntegrations {
                            unset_span,
                            property_span,
                        },
                    ),
                    _ => Err(ParseError::new(
                        prop_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Unknown UNSET property: {}",
                                prop_tok.lexeme(self.source)
                            ),
                        },
                    )),
                }
            }
            TokenKind::Keyword(Keyword::Comment) => {
                self.advance();
                let property_span = Some(prop_tok.span);
                Ok(AstAlterAuthenticationPolicyActionKind::UnsetComment {
                    unset_span,
                    property_span,
                })
            }
            _ => Err(ParseError::new(
                prop_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected property name after UNSET".to_string(),
                },
            )),
        }
    }

    // ========================================================================
    // Property value parsing helpers
    // ========================================================================

    /// Parse = (value, value, ...) and return full span from prop_start
    fn parse_property_with_paren_list(&mut self, prop_start: u32) -> ParseResult<Span> {
        let _eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        let end_span = self.parse_paren_list_span()?;
        Ok(Span {
            start: prop_start,
            end: end_span.end,
        })
    }

    /// Parse = (nested structure with balanced parens)
    fn parse_property_with_nested_parens(&mut self, prop_start: u32) -> ParseResult<Span> {
        let _eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        let end_span = self.parse_nested_paren_span()?;
        Ok(Span {
            start: prop_start,
            end: end_span.end,
        })
    }

    /// Parse = simple_value (identifier or string literal)
    fn parse_simple_property_value(&mut self, prop_start: u32) -> ParseResult<Span> {
        let _eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        let value_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
        Ok(Span {
            start: prop_start,
            end: value_tok.span.end,
        })
    }

    /// Parse SECURITY_INTEGRATIONS value: = (list) | = all | = none
    fn parse_security_integrations_value(&mut self, prop_start: u32) -> ParseResult<Span> {
        let _eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        let value_span = self.parse_security_integrations_value_span()?;
        Ok(Span {
            start: prop_start,
            end: value_span.end,
        })
    }

    /// Parse the value portion of SECURITY_INTEGRATIONS: (list) | all | none
    fn parse_security_integrations_value_span(&mut self) -> ParseResult<Span> {
        let next_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["value or (".to_string()])?;

        if matches!(next_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            self.parse_paren_list_span()
        } else {
            // ALL or NONE (or other identifier)
            let value_tok = self
                .advance()
                .expect_invariant("SECURITY_INTEGRATIONS value token available after peek");
            Ok(value_tok.span)
        }
    }

    /// Parse balanced parentheses and return span of the entire group
    fn parse_paren_list_span(&mut self) -> ParseResult<Span> {
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected (".to_string(),
                },
            ));
        }
        let start = lparen.span.start;

        let mut depth = 1;
        let mut end = lparen.span.end;

        while depth > 0 {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
            end = tok.span.end;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                _ => {}
            }
        }

        Ok(Span { start, end })
    }

    /// Parse nested parentheses (like CLIENT_POLICY or MFA_POLICY)
    fn parse_nested_paren_span(&mut self) -> ParseResult<Span> {
        // Same as parse_paren_list_span but handles nested content
        self.parse_paren_list_span()
    }

    /// Consume unknown property until next known property or semicolon
    fn consume_unknown_property(&mut self) -> ParseResult<u32> {
        let known_props = [
            "AUTHENTICATION_METHODS",
            "CLIENT_TYPES",
            "CLIENT_POLICY",
            "MFA_ENROLLMENT",
            "MFA_POLICY",
            "PAT_POLICY",
            "WORKLOAD_IDENTITY_POLICY",
            "SECURITY_INTEGRATIONS",
        ];

        let mut last_end = self.current_span().start;

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lex_up = tok.lexeme(self.source).to_uppercase();
                if known_props.contains(&lex_up.as_str()) {
                    break;
                }
            }
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                break;
            }
            let consumed = self
                .advance()
                .expect_invariant("unknown property content token available after peek");
            last_end = consumed.span.end;
        }

        Ok(last_end)
    }
}
