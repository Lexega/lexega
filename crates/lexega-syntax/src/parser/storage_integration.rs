// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for STORAGE INTEGRATION statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] STORAGE INTEGRATION [IF NOT EXISTS] name [properties]`
//! - `ALTER [STORAGE] INTEGRATION [IF EXISTS] name { SET | UNSET | SET TAG | UNSET TAG }`
//! - `DROP [STORAGE] INTEGRATION [IF EXISTS] name`
//!
//! Token reference:
//! - STORAGE is Keyword::Storage
//! - INTEGRATION is Keyword::Integration
//! - Property names (TYPE, STORAGE_PROVIDER, etc.) are Identifiers
//! - Must use lexeme matching with eq_ignore_ascii_case()

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterStorageIntegration, AstAlterStorageIntegrationAction,
    AstAlterStorageIntegrationActionKind, AstCreateStorageIntegration, AstDropStorageIntegration,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterStorageIntegration, SyntaxAlterStorageIntegrationAction,
    SyntaxCreateStorageIntegration, SyntaxDropStorageIntegration,
};

impl<'a> Parser<'a> {
    /// Parse CREATE STORAGE INTEGRATION statement.
    pub(crate) fn try_parse_create_storage_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_storage_integration")?;

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
                        .expect_invariant("OR keyword consumed after match");
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

        // STORAGE (Keyword)
        let storage_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["STORAGE".to_string()])?;
        if !matches!(storage_tok.kind, TokenKind::Keyword(Keyword::Storage)) {
            return Err(ParseError::new(
                storage_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected STORAGE keyword".to_string(),
                },
            ));
        }
        let storage_span = storage_tok.span;
        let storage_token_id = self.last_token_id();

        // INTEGRATION (Keyword)
        let integration_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INTEGRATION".to_string()])?;
        if !matches!(
            integration_tok.kind,
            TokenKind::Keyword(Keyword::Integration)
        ) {
            return Err(ParseError::new(
                integration_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected INTEGRATION keyword".to_string(),
                },
            ));
        }
        let integration_span = integration_tok.span;
        let integration_token_id = self.last_token_id();

        // Optional IF NOT EXISTS
        let (if_not_exists_span, if_token_id, not_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword consumed after match");
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

        // Integration name
        let integration_name_span = self.parse_qualified_name_span()?;
        let mut type_span: Option<Span> = None;
        let mut storage_provider_span: Option<Span> = None;
        let mut enabled_span: Option<Span> = None;
        let mut storage_allowed_locations_span: Option<Span> = None;
        let mut storage_blocked_locations_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut storage_aws_role_arn_span: Option<Span> = None;
        let mut storage_aws_external_id_span: Option<Span> = None;
        let mut storage_aws_object_acl_span: Option<Span> = None;
        let mut azure_tenant_id_span: Option<Span> = None;
        let mut use_privatelink_endpoint_span: Option<Span> = None;
        let mut last_property_end = integration_name_span.end;

        // Parse properties until we hit semicolon or EOF
        while let Some(tok) = self.peek_non_trivia() {
            let prop_start = tok.span.start;

            match &tok.kind {
                TokenKind::Identifier { .. } | TokenKind::Keyword(_) => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    match lexeme_upper.as_str() {
                        "TYPE" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after TYPE".to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            type_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "STORAGE_PROVIDER" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after STORAGE_PROVIDER".to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            storage_provider_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "ENABLED" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after ENABLED".to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            enabled_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "STORAGE_ALLOWED_LOCATIONS" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after STORAGE_ALLOWED_LOCATIONS"
                                            .to_string(),
                                    },
                                ));
                            }
                            // Value is a parenthesized list - consume until closing paren
                            let value_start = self.current_span().start;
                            let mut paren_depth = 0;
                            let mut value_end = value_start;
                            loop {
                                if let Some(val_tok) = self.advance() {
                                    value_end = val_tok.span.end;
                                    if matches!(
                                        val_tok.kind,
                                        TokenKind::Punctuation(Punctuation::LParen)
                                    ) {
                                        paren_depth += 1;
                                    } else if matches!(
                                        val_tok.kind,
                                        TokenKind::Punctuation(Punctuation::RParen)
                                    ) {
                                        paren_depth -= 1;
                                        if paren_depth == 0 {
                                            break;
                                        }
                                    }
                                } else {
                                    return Err(ParseError::new(
                                        Span {
                                            start: value_start,
                                            end: value_end,
                                        },
                                        ParseErrorKind::InvalidStatement {
                                            message: "Unclosed STORAGE_ALLOWED_LOCATIONS list"
                                                .to_string(),
                                        },
                                    ));
                                }
                            }
                            storage_allowed_locations_span = Some(Span {
                                start: prop_start,
                                end: value_end,
                            });
                            last_property_end = value_end;
                        }
                        "STORAGE_BLOCKED_LOCATIONS" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after STORAGE_BLOCKED_LOCATIONS"
                                            .to_string(),
                                    },
                                ));
                            }
                            // Value is a parenthesized list - consume until closing paren
                            let value_start = self.current_span().start;
                            let mut paren_depth = 0;
                            let mut value_end = value_start;
                            loop {
                                if let Some(val_tok) = self.advance() {
                                    value_end = val_tok.span.end;
                                    if matches!(
                                        val_tok.kind,
                                        TokenKind::Punctuation(Punctuation::LParen)
                                    ) {
                                        paren_depth += 1;
                                    } else if matches!(
                                        val_tok.kind,
                                        TokenKind::Punctuation(Punctuation::RParen)
                                    ) {
                                        paren_depth -= 1;
                                        if paren_depth == 0 {
                                            break;
                                        }
                                    }
                                } else {
                                    return Err(ParseError::new(
                                        Span {
                                            start: value_start,
                                            end: value_end,
                                        },
                                        ParseErrorKind::InvalidStatement {
                                            message: "Unclosed STORAGE_BLOCKED_LOCATIONS list"
                                                .to_string(),
                                        },
                                    ));
                                }
                            }
                            storage_blocked_locations_span = Some(Span {
                                start: prop_start,
                                end: value_end,
                            });
                            last_property_end = value_end;
                        }
                        "COMMENT" => {
                            self.advance(); // consume property name
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
                                .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                            comment_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "STORAGE_AWS_ROLE_ARN" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after STORAGE_AWS_ROLE_ARN"
                                            .to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                            storage_aws_role_arn_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "STORAGE_AWS_EXTERNAL_ID" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after STORAGE_AWS_EXTERNAL_ID"
                                            .to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                            storage_aws_external_id_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "STORAGE_AWS_OBJECT_ACL" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after STORAGE_AWS_OBJECT_ACL"
                                            .to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                            storage_aws_object_acl_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "AZURE_TENANT_ID" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after AZURE_TENANT_ID".to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                            azure_tenant_id_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        "USE_PRIVATELINK_ENDPOINT" => {
                            self.advance(); // consume property name
                            let eq_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                return Err(ParseError::new(
                                    eq_tok.span,
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected = after USE_PRIVATELINK_ENDPOINT"
                                            .to_string(),
                                    },
                                ));
                            }
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            use_privatelink_endpoint_span = Some(Span {
                                start: prop_start,
                                end: value_tok.span.end,
                            });
                            last_property_end = value_tok.span.end;
                        }
                        _ => break, // Unknown property, stop parsing
                    }
                }
                _ => break, // Non-identifier, end of properties
            }
        }

        // Calculate statement span (CREATE to last property end)
        let stmt_span = Span {
            start: create_span.start,
            end: last_property_end,
        };

        // Build CST node
        let syntax_node = SyntaxCreateStorageIntegration {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            storage_keyword: storage_token_id,
            integration_keyword: integration_token_id,
            integration_name_span,
            type_span,
            storage_provider_span,
            enabled_span,
            storage_allowed_locations_span,
            storage_blocked_locations_span,
            comment_span,
            storage_aws_role_arn_span,
            storage_aws_external_id_span,
            storage_aws_object_acl_span,
            azure_tenant_id_span,
            use_privatelink_endpoint_span,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_create_storage_integration(syntax_node);

        // Build AST node
        let ast = AstCreateStorageIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            storage_span,
            integration_span,
            integration_name_span,
            type_span,
            storage_provider_span,
            enabled_span,
            storage_allowed_locations_span,
            storage_blocked_locations_span,
            comment_span,
            storage_aws_role_arn_span,
            storage_aws_external_id_span,
            storage_aws_object_acl_span,
            azure_tenant_id_span,
            use_privatelink_endpoint_span,
        };
        Ok(AstStmt::CreateStorageIntegration(Box::new(ast)))
    }

    /// Parse ALTER STORAGE INTEGRATION statement.
    pub(crate) fn try_parse_alter_storage_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_storage_integration")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_token_id = self.last_token_id();

        // Optional STORAGE keyword
        let (storage_span, storage_token_id) = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Storage)) {
                let storage_tok = self
                    .advance()
                    .expect_invariant("STORAGE keyword consumed after match in ALTER");
                (Some(storage_tok.span), Some(self.last_token_id()))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // INTEGRATION (Keyword)
        let integration_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INTEGRATION".to_string()])?;
        if !matches!(
            integration_tok.kind,
            TokenKind::Keyword(Keyword::Integration)
        ) {
            return Err(ParseError::new(
                integration_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected INTEGRATION keyword".to_string(),
                },
            ));
        }
        let integration_span = integration_tok.span;
        let integration_token_id = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword consumed after match in ALTER IF EXISTS");
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

        // Integration name
        let name_span = self.parse_qualified_name_span()?;

        // Parse actions (SET/UNSET properties, SET TAG, UNSET TAG)
        let action_start = self.current_span().start;
        let mut actions: Vec<AstAlterStorageIntegrationAction> = Vec::new();

        // Peek at action keyword
        let action_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["SET or UNSET".to_string()])?;

        match &action_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = action_tok.span;

                // Peek at what comes after SET
                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["property or TAG".to_string()])?;

                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    // SET TAG
                    let tag_tok = self
                        .advance()
                        .expect_invariant("TAG keyword consumed after match");
                    let tag_span = tag_tok.span;

                    // Consume tag assignments until we hit semicolon or EOF
                    let tags_start = self.current_span().start;
                    let mut tags_end = tags_start;
                    while let Some(tok) = self.peek_non_trivia() {
                        if matches!(
                            tok.kind,
                            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                        ) {
                            break;
                        }
                        let consumed_tok = self
                            .advance()
                            .expect_invariant("tag assignment token consumed after peek in loop");
                        tags_end = consumed_tok.span.end;
                    }

                    let action_span = Span {
                        start: set_span.start,
                        end: tags_end,
                    };

                    let action = AstAlterStorageIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: action_span,
                        syntax_id: None,
                        kind: AstAlterStorageIntegrationActionKind::SetTag {
                            set_span: Some(set_span),
                            tag_span,
                            tags_value_span: Span {
                                start: tags_start,
                                end: tags_end,
                            },
                        },
                    };
                    actions.push(action);
                } else if matches!(next_tok.kind, TokenKind::Identifier { .. }) {
                    // SET property
                    let prop_tok = self
                        .advance()
                        .expect_invariant("property identifier consumed after match");
                    let property_span = prop_tok.span;
                    let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();

                    let eq_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let eq_span = if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                        Some(eq_tok.span)
                    } else {
                        return Err(ParseError::new(
                            eq_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: format!(
                                    "Expected = after {}",
                                    prop_tok.lexeme(self.source)
                                ),
                            },
                        ));
                    };

                    // Parse value (can be simple value or parenthesized list)
                    let value_start = self.current_span().start;
                    let mut value_end = value_start;

                    // Check if value is a parenthesized list
                    if let Some(val_tok) = self.peek_non_trivia() {
                        if matches!(val_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                            // Parenthesized list - consume until closing paren
                            let mut paren_depth = 0;
                            loop {
                                if let Some(tok) = self.advance() {
                                    value_end = tok.span.end;
                                    if matches!(
                                        tok.kind,
                                        TokenKind::Punctuation(Punctuation::LParen)
                                    ) {
                                        paren_depth += 1;
                                    } else if matches!(
                                        tok.kind,
                                        TokenKind::Punctuation(Punctuation::RParen)
                                    ) {
                                        paren_depth -= 1;
                                        if paren_depth == 0 {
                                            break;
                                        }
                                    }
                                } else {
                                    return Err(ParseError::new(
                                        Span {
                                            start: value_start,
                                            end: value_end,
                                        },
                                        ParseErrorKind::InvalidStatement {
                                            message: "Unclosed parenthesized list".to_string(),
                                        },
                                    ));
                                }
                            }
                        } else {
                            // Simple value
                            let value_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            value_end = value_tok.span.end;
                        }
                    }

                    let value_span = Span {
                        start: value_start,
                        end: value_end,
                    };

                    let action_span = Span {
                        start: set_span.start,
                        end: value_end,
                    };

                    // Determine action kind based on property name
                    let kind = match lexeme_upper.as_str() {
                        "ENABLED" => AstAlterStorageIntegrationActionKind::SetEnabled {
                            set_span: Some(set_span),
                            property_span,
                            eq_span,
                            value_span,
                        },
                        "STORAGE_ALLOWED_LOCATIONS" => {
                            AstAlterStorageIntegrationActionKind::SetStorageAllowedLocations {
                                set_span: Some(set_span),
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "STORAGE_BLOCKED_LOCATIONS" => {
                            AstAlterStorageIntegrationActionKind::SetStorageBlockedLocations {
                                set_span: Some(set_span),
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "STORAGE_AWS_ROLE_ARN" => {
                            AstAlterStorageIntegrationActionKind::SetAwsRoleArn {
                                set_span: Some(set_span),
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "STORAGE_AWS_EXTERNAL_ID" => {
                            AstAlterStorageIntegrationActionKind::SetAwsExternalId {
                                set_span: Some(set_span),
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "STORAGE_AWS_OBJECT_ACL" => {
                            AstAlterStorageIntegrationActionKind::SetAwsObjectAcl {
                                set_span: Some(set_span),
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "AZURE_TENANT_ID" => {
                            AstAlterStorageIntegrationActionKind::SetAzureTenantId {
                                set_span: Some(set_span),
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "USE_PRIVATELINK_ENDPOINT" => {
                            AstAlterStorageIntegrationActionKind::SetUsePrivatelinkEndpoint {
                                set_span: Some(set_span),
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "COMMENT" => AstAlterStorageIntegrationActionKind::SetComment {
                            set_span: Some(set_span),
                            comment_span: property_span,
                            eq_span,
                            value_span,
                        },
                        _ => {
                            return Err(ParseError::new(
                                property_span,
                                ParseErrorKind::InvalidStatement {
                                    message: format!(
                                        "Unknown property: {}",
                                        prop_tok.lexeme(self.source)
                                    ),
                                },
                            ));
                        }
                    };

                    let action = AstAlterStorageIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: action_span,
                        syntax_id: None,
                        kind,
                    };
                    actions.push(action);
                } else {
                    return Err(ParseError::new(
                        next_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected property name or TAG after SET".to_string(),
                        },
                    ));
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = action_tok.span;

                // Peek at what comes after UNSET
                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["property or TAG".to_string()])?;

                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    // UNSET TAG
                    let tag_tok = self
                        .advance()
                        .expect_invariant("TAG keyword consumed after match");
                    let tag_span = tag_tok.span;

                    // Consume tag names until we hit semicolon or EOF
                    let tags_start = self.current_span().start;
                    let mut tags_end = tags_start;
                    while let Some(tok) = self.peek_non_trivia() {
                        if matches!(
                            tok.kind,
                            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                        ) {
                            break;
                        }
                        let consumed_tok = self
                            .advance()
                            .expect_invariant("tag name token consumed after peek in loop");
                        tags_end = consumed_tok.span.end;
                    }

                    let action_span = Span {
                        start: unset_span.start,
                        end: tags_end,
                    };

                    let action = AstAlterStorageIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: action_span,
                        syntax_id: None,
                        kind: AstAlterStorageIntegrationActionKind::UnsetTag {
                            unset_span: Some(unset_span),
                            tag_span,
                            tag_names_span: Span {
                                start: tags_start,
                                end: tags_end,
                            },
                        },
                    };
                    actions.push(action);
                } else if matches!(next_tok.kind, TokenKind::Identifier { .. }) {
                    // UNSET property
                    let prop_tok = self
                        .advance()
                        .expect_invariant("property identifier consumed after match");
                    let property_span = prop_tok.span;
                    let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();

                    let action_span = Span {
                        start: unset_span.start,
                        end: property_span.end,
                    };

                    // Determine action kind based on property name
                    let kind = match lexeme_upper.as_str() {
                        "ENABLED" => AstAlterStorageIntegrationActionKind::UnsetEnabled {
                            unset_span: Some(unset_span),
                            property_span,
                        },
                        "STORAGE_BLOCKED_LOCATIONS" => {
                            AstAlterStorageIntegrationActionKind::UnsetStorageBlockedLocations {
                                unset_span: Some(unset_span),
                                property_span,
                            }
                        }
                        "COMMENT" => AstAlterStorageIntegrationActionKind::UnsetComment {
                            unset_span: Some(unset_span),
                            comment_span: property_span,
                        },
                        _ => {
                            return Err(ParseError::new(
                                property_span,
                                ParseErrorKind::InvalidStatement {
                                    message: format!(
                                        "Unknown or non-unset-able property: {}",
                                        prop_tok.lexeme(self.source)
                                    ),
                                },
                            ));
                        }
                    };

                    let action = AstAlterStorageIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: action_span,
                        syntax_id: None,
                        kind,
                    };
                    actions.push(action);
                } else {
                    return Err(ParseError::new(
                        next_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected property name or TAG after UNSET".to_string(),
                        },
                    ));
                }
            }
            _ => {
                return Err(ParseError::new(
                    action_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected SET or UNSET".to_string(),
                    },
                ));
            }
        }

        // Calculate action span and statement span
        let action_span = Span {
            start: action_start,
            end: actions.last().map(|a| a.span.end).unwrap_or(name_span.end),
        };

        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        // Build CST node (minimal - actions stored in AST)
        let syntax_action = SyntaxAlterStorageIntegrationAction { span: action_span };
        let syntax_action_id = self
            .syntax_arena
            .alloc_alter_storage_integration_action(syntax_action);

        let syntax_node = SyntaxAlterStorageIntegration {
            alter_keyword: alter_token_id,
            storage_keyword: storage_token_id,
            integration_keyword: integration_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            name_span,
            action_id: syntax_action_id,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_alter_storage_integration_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterStorageIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            storage_span,
            integration_span,
            if_exists_span,
            name_span,
            action_span,
            actions,
        };
        Ok(AstStmt::AlterStorageIntegration(Box::new(ast)))
    }

    /// Parse DROP STORAGE INTEGRATION statement.
    pub(crate) fn try_parse_drop_storage_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_storage_integration")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // Optional STORAGE keyword
        let (storage_span, storage_token_id) = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Storage)) {
                let storage_tok = self
                    .advance()
                    .expect_invariant("STORAGE keyword consumed after match in DROP");
                (Some(storage_tok.span), Some(self.last_token_id()))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // INTEGRATION (Keyword)
        let integration_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INTEGRATION".to_string()])?;
        if !matches!(
            integration_tok.kind,
            TokenKind::Keyword(Keyword::Integration)
        ) {
            return Err(ParseError::new(
                integration_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected INTEGRATION keyword".to_string(),
                },
            ));
        }
        let integration_span = integration_tok.span;
        let integration_token_id = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword consumed after match in DROP IF EXISTS");
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

        // Integration name
        let integration_name_span = self.parse_qualified_name_span()?;

        // Calculate statement span
        let stmt_span = Span {
            start: drop_span.start,
            end: integration_name_span.end,
        };

        // Build CST node
        let syntax_node = SyntaxDropStorageIntegration {
            drop_keyword: drop_token_id,
            storage_keyword: storage_token_id,
            integration_keyword: integration_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            integration_name_span,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_drop_storage_integration(syntax_node);

        // Build AST node
        let ast = AstDropStorageIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            storage_span,
            integration_span,
            if_exists_span,
            integration_name_span,
        };
        Ok(AstStmt::DropStorageIntegration(Box::new(ast)))
    }
}
