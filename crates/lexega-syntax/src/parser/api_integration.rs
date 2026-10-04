// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for API INTEGRATION statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] API INTEGRATION [IF NOT EXISTS] name <properties>`
//! - `ALTER [API] INTEGRATION [IF EXISTS] name { SET | UNSET } <actions>`
//! - `DROP [API] INTEGRATION [IF EXISTS] name`
//!
//! Token reference:
//! - "API" is Identifier, NOT Keyword
//! - Property names (API_PROVIDER, etc.) are Identifiers
//! - COMMENT is Keyword(Comment), TAG is Keyword(Tag)
//! - Must use lexeme matching with eq_ignore_ascii_case()

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterApiIntegration, AstAlterApiIntegrationAction, AstAlterApiIntegrationActionKind,
    AstCreateApiIntegration, AstDropApiIntegration, AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterApiIntegration, SyntaxAlterApiIntegrationAction, SyntaxCreateApiIntegration,
    SyntaxDropApiIntegration,
};

impl<'a> Parser<'a> {
    /// Parse CREATE API INTEGRATION statement
    pub(crate) fn try_parse_create_api_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_api_integration")?;

        // CREATE keyword
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let create_keyword = self.last_token_id();
        let start = create_span.start;

        // Optional: OR REPLACE
        let (or_keyword, replace_keyword, or_replace_span) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(&tok.kind, TokenKind::Keyword(Keyword::Or)) {
                    let or_tok = self
                        .advance()
                        .expect_invariant("OR keyword in CREATE API INTEGRATION");
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
                        Some(or_token_id),
                        Some(replace_token_id),
                        Some(or_replace_span),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        // API keyword (Identifier, NOT Keyword!)
        let api_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["API".to_string()])?;
        if !matches!(api_tok.kind, TokenKind::Identifier { .. })
            || !api_tok.lexeme(self.source).eq_ignore_ascii_case("API")
        {
            return Err(ParseError::new(
                api_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected 'API' keyword (as Identifier)".to_string(),
                },
            ));
        }
        let api_span = api_tok.span;
        let api_token = self.last_token_id();

        // INTEGRATION keyword
        self.expect_keyword(Keyword::Integration)?;
        let integration_span = self.current_span();
        let integration_keyword = self.last_token_id();

        // Optional: IF NOT EXISTS
        let (if_keyword, not_keyword, exists_keyword, if_not_exists_span) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword in CREATE API INTEGRATION IF NOT EXISTS");
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
                        Some(if_token_id),
                        Some(not_token_id),
                        Some(exists_token_id),
                        Some(if_not_exists_span),
                    )
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            };

        // Integration name
        let integration_name_span = self.parse_qualified_name_span()?;
        let mut end = integration_name_span.end;

        // Initialize all property spans
        let mut api_provider_span: Option<Span> = None;
        let mut api_aws_role_arn_span: Option<Span> = None;
        let mut azure_tenant_id_span: Option<Span> = None;
        let mut azure_ad_application_id_span: Option<Span> = None;
        let mut google_audience_span: Option<Span> = None;
        let mut api_allowed_prefixes_span: Option<Span> = None;
        let mut api_blocked_prefixes_span: Option<Span> = None;
        let mut api_key_span: Option<Span> = None;
        let mut enabled_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut allowed_authentication_secrets_span: Option<Span> = None;
        let mut api_user_authentication_span: Option<Span> = None;
        let mut tls_trusted_certificates_span: Option<Span> = None;
        let mut use_privatelink_endpoint_span: Option<Span> = None;
        let mut extras: Vec<AstUnknownClause> = Vec::new();

        // Parse properties until semicolon or EOF
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                &tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }

            let prop_start = tok.span.start;

            match &tok.kind {
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    match lexeme_upper.as_str() {
                        "API_PROVIDER" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            api_provider_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "API_AWS_ROLE_ARN" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            api_aws_role_arn_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "AZURE_TENANT_ID" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            azure_tenant_id_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "AZURE_AD_APPLICATION_ID" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            azure_ad_application_id_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "GOOGLE_AUDIENCE" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            google_audience_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "API_ALLOWED_PREFIXES"
                        | "API_BLOCKED_PREFIXES"
                        | "ALLOWED_AUTHENTICATION_SECRETS"
                        | "TLS_TRUSTED_CERTIFICATES" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;

                            // Parse list: (val, val, ...) or single value
                            if let Some(lparen_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &lparen_tok.kind,
                                    TokenKind::Punctuation(Punctuation::LParen)
                                ) {
                                    self.advance();
                                    let mut paren_depth = 1;
                                    while paren_depth > 0 {
                                        if let Some(t) = self.advance() {
                                            end = t.span.end;
                                            if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::LParen)
                                            ) {
                                                paren_depth += 1;
                                            } else if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::RParen)
                                            ) {
                                                paren_depth -= 1;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                } else {
                                    let val = self.advance().ok_or_eof(
                                        self.current_span(),
                                        vec!["value".to_string()],
                                    )?;
                                    end = val.span.end;
                                }
                            }

                            let prop_span = Span {
                                start: prop_start,
                                end,
                            };
                            match lexeme_upper.as_str() {
                                "API_ALLOWED_PREFIXES" => {
                                    api_allowed_prefixes_span = Some(prop_span)
                                }
                                "API_BLOCKED_PREFIXES" => {
                                    api_blocked_prefixes_span = Some(prop_span)
                                }
                                "ALLOWED_AUTHENTICATION_SECRETS" => {
                                    allowed_authentication_secrets_span = Some(prop_span)
                                }
                                "TLS_TRUSTED_CERTIFICATES" => {
                                    tls_trusted_certificates_span = Some(prop_span)
                                }
                                _ => {}
                            }
                        }
                        "API_KEY" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            api_key_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "ENABLED" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            enabled_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "API_USER_AUTHENTICATION" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            api_user_authentication_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "USE_PRIVATELINK_ENDPOINT" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            end = val.span.end;
                            use_privatelink_endpoint_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        _ => {
                            // Unknown property - defensive design
                            self.advance();
                            if let Some(eq_tok) = self.peek_non_trivia() {
                                if matches!(&eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                    self.advance();
                                    if let Some(val) = self.advance() {
                                        end = val.span.end;
                                    }
                                    extras.push(AstUnknownClause {
                                        introducer: Some(Span {
                                            start: prop_start,
                                            end: tok.span.end,
                                        }),
                                        span: Span {
                                            start: prop_start,
                                            end,
                                        },
                                        kind: UnknownKind::Property,
                                        node_id: self.id_gen.next(),
                                    });
                                }
                            }
                        }
                    }
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    self.advance();
                    let _eq = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let val = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                    end = val.span.end;
                    comment_span = Some(Span {
                        start: prop_start,
                        end,
                    });
                }
                _ => {
                    break;
                }
            }
        }

        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = SyntaxCreateApiIntegration {
            create_keyword,
            or_keyword,
            replace_keyword,
            if_keyword,
            not_keyword,
            exists_keyword,
            api_token,
            integration_keyword,
            integration_name_span,
            api_provider_span,
            api_aws_role_arn_span,
            api_allowed_prefixes_span,
            api_blocked_prefixes_span,
            api_key_span,
            enabled_span,
            comment_span,
            azure_tenant_id_span,
            azure_ad_application_id_span,
            google_audience_span,
            allowed_authentication_secrets_span,
            api_user_authentication_span,
            tls_trusted_certificates_span,
            use_privatelink_endpoint_span,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_create_api_integration(syntax_node);

        // Build AST node
        let ast = AstCreateApiIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            api_span,
            integration_span,
            integration_name_span,
            api_provider_span,
            api_aws_role_arn_span,
            azure_tenant_id_span,
            azure_ad_application_id_span,
            google_audience_span,
            api_allowed_prefixes_span,
            api_blocked_prefixes_span,
            api_key_span,
            enabled_span,
            comment_span,
            allowed_authentication_secrets_span,
            api_user_authentication_span,
            tls_trusted_certificates_span,
            use_privatelink_endpoint_span,
            extras,
        };
        Ok(AstStmt::CreateApiIntegration(Box::new(ast)))
    }

    /// Parse ALTER API INTEGRATION statement
    pub(crate) fn try_parse_alter_api_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_api_integration")?;

        // ALTER keyword
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_keyword = self.last_token_id();
        let start = alter_tok.span.start;

        // Optional: API keyword (can be omitted)
        let api_token = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("API")
            {
                self.advance();
                Some(self.last_token_id())
            } else {
                None
            }
        } else {
            None
        };

        // INTEGRATION keyword
        self.expect_keyword(Keyword::Integration)?;
        let integration_keyword = self.last_token_id();

        // Optional: IF EXISTS
        let (if_keyword, exists_keyword) = if let Some(tok) = self.peek_non_trivia() {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance();
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
                (Some(if_token_id), Some(exists_token_id))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Integration name
        let name_span = self.parse_qualified_name_span()?;

        // Parse actions (SET/UNSET)
        let mut actions = Vec::new();

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                &tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }

            let action_start = tok.span.start;

            match &tok.kind {
                TokenKind::Keyword(Keyword::Set) => {
                    let set_tok = self
                        .advance()
                        .expect_invariant("SET keyword in ALTER API INTEGRATION");
                    let set_span = set_tok.span;

                    // Parse property name
                    let prop_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["property name".to_string()])?;
                    let property_span = prop_tok.span;

                    if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        // SET TAG is special: comma-separated tag_name = value
                        let tag_span = property_span;
                        let tags_start = self
                            .peek_non_trivia()
                            .map(|t| t.span.start)
                            .unwrap_or(tag_span.end);
                        let mut action_end;

                        loop {
                            let _tag_name_span = self.parse_qualified_name_span()?;
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            action_end = val.span.end;

                            if let Some(comma_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &comma_tok.kind,
                                    TokenKind::Punctuation(Punctuation::Comma)
                                ) {
                                    self.advance();
                                    continue;
                                }
                            }
                            break;
                        }

                        let tags_span = Span {
                            start: tags_start,
                            end: action_end,
                        };
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        actions.push(AstAlterApiIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            syntax_id: None,
                            kind: AstAlterApiIntegrationActionKind::SetTag {
                                set_span: Some(set_span),
                                tag_span: Some(tag_span),
                                tags_span,
                            },
                        });
                    } else if let TokenKind::Identifier { .. } = prop_tok.kind {
                        let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();

                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = eq_tok.span;

                        // Handle list values for some properties
                        let value_start;
                        let value_end;
                        if matches!(
                            lexeme_upper.as_str(),
                            "API_ALLOWED_PREFIXES"
                                | "API_BLOCKED_PREFIXES"
                                | "ALLOWED_AUTHENTICATION_SECRETS"
                        ) {
                            // Parse list: (val, val, ...) or single value
                            if let Some(lparen_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &lparen_tok.kind,
                                    TokenKind::Punctuation(Punctuation::LParen)
                                ) {
                                    let lparen = self.advance().expect_invariant(
                                        "left paren for list value in ALTER API INTEGRATION SET",
                                    );
                                    value_start = lparen.span.start;
                                    let mut paren_depth = 1;
                                    let mut last_end = lparen.span.end;
                                    while paren_depth > 0 {
                                        if let Some(t) = self.advance() {
                                            last_end = t.span.end;
                                            if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::LParen)
                                            ) {
                                                paren_depth += 1;
                                            } else if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::RParen)
                                            ) {
                                                paren_depth -= 1;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                    value_end = last_end;
                                } else {
                                    let val = self.advance().ok_or_eof(
                                        self.current_span(),
                                        vec!["value".to_string()],
                                    )?;
                                    value_start = val.span.start;
                                    value_end = val.span.end;
                                }
                            } else {
                                let val = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                                value_start = val.span.start;
                                value_end = val.span.end;
                            }
                        } else {
                            let val_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            value_start = val_tok.span.start;
                            value_end = val_tok.span.end;
                        }

                        let value_span = Span {
                            start: value_start,
                            end: value_end,
                        };
                        let action_end = value_end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };

                        let kind = match lexeme_upper.as_str() {
                            "API_AWS_ROLE_ARN" => {
                                AstAlterApiIntegrationActionKind::SetApiAwsRoleArn {
                                    set_span: Some(set_span),
                                    property_span,
                                    eq_span: Some(eq_span),
                                    value_span,
                                }
                            }
                            "API_KEY" => AstAlterApiIntegrationActionKind::SetApiKey {
                                set_span: Some(set_span),
                                property_span,
                                eq_span: Some(eq_span),
                                value_span,
                            },
                            "ENABLED" => AstAlterApiIntegrationActionKind::SetEnabled {
                                set_span: Some(set_span),
                                property_span,
                                eq_span: Some(eq_span),
                                value_span,
                            },
                            "API_ALLOWED_PREFIXES" => {
                                AstAlterApiIntegrationActionKind::SetApiAllowedPrefixes {
                                    set_span: Some(set_span),
                                    property_span,
                                    eq_span: Some(eq_span),
                                    value_span,
                                }
                            }
                            "API_BLOCKED_PREFIXES" => {
                                AstAlterApiIntegrationActionKind::SetApiBlockedPrefixes {
                                    set_span: Some(set_span),
                                    property_span,
                                    eq_span: Some(eq_span),
                                    value_span,
                                }
                            }
                            "AZURE_AD_APPLICATION_ID" => {
                                AstAlterApiIntegrationActionKind::SetAzureAdApplicationId {
                                    set_span: Some(set_span),
                                    property_span,
                                    eq_span: Some(eq_span),
                                    value_span,
                                }
                            }
                            "ALLOWED_AUTHENTICATION_SECRETS" => {
                                AstAlterApiIntegrationActionKind::SetAllowedAuthenticationSecrets {
                                    set_span: Some(set_span),
                                    property_span,
                                    eq_span: Some(eq_span),
                                    value_span,
                                }
                            }
                            _ => {
                                // Property outside the recognized set: record it
                                // structurally as SetOther — never guess a specific
                                // known property (e.g. API_KEY), which would forge a
                                // credential-change finding.
                                AstAlterApiIntegrationActionKind::SetOther {
                                    set_span: Some(set_span),
                                    property_span,
                                    eq_span: Some(eq_span),
                                    value_span,
                                }
                            }
                        };

                        actions.push(AstAlterApiIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            syntax_id: None,
                            kind,
                        });
                    } else if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                        let comment_span = property_span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let eq_span = eq_tok.span;
                        let val_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                        let value_span = val_tok.span;
                        let action_end = value_span.end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };

                        actions.push(AstAlterApiIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            syntax_id: None,
                            kind: AstAlterApiIntegrationActionKind::SetComment {
                                set_span: Some(set_span),
                                comment_span,
                                eq_span: Some(eq_span),
                                value_span,
                            },
                        });
                    }
                }
                TokenKind::Keyword(Keyword::Unset) => {
                    let unset_tok = self
                        .advance()
                        .expect_invariant("UNSET keyword in ALTER API INTEGRATION");
                    let unset_span = unset_tok.span;

                    let prop_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["property name".to_string()])?;
                    let property_span = prop_tok.span;

                    if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        // UNSET TAG is special: comma-separated tag names
                        let tag_span = property_span;
                        let tags_start = self
                            .peek_non_trivia()
                            .map(|t| t.span.start)
                            .unwrap_or(tag_span.end);
                        let mut action_end;

                        loop {
                            let tag_name_span = self.parse_qualified_name_span()?;
                            action_end = tag_name_span.end;

                            if let Some(comma_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &comma_tok.kind,
                                    TokenKind::Punctuation(Punctuation::Comma)
                                ) {
                                    self.advance();
                                    continue;
                                }
                            }
                            break;
                        }

                        let tags_span = Span {
                            start: tags_start,
                            end: action_end,
                        };
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        actions.push(AstAlterApiIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            syntax_id: None,
                            kind: AstAlterApiIntegrationActionKind::UnsetTag {
                                unset_span: Some(unset_span),
                                tag_span: Some(tag_span),
                                tags_span,
                            },
                        });
                    } else if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                        let comment_span = property_span;
                        let action_end = comment_span.end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };

                        actions.push(AstAlterApiIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            syntax_id: None,
                            kind: AstAlterApiIntegrationActionKind::UnsetComment {
                                unset_span: Some(unset_span),
                                comment_span,
                            },
                        });
                    } else if let TokenKind::Identifier { .. } = prop_tok.kind {
                        let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();
                        let action_end = property_span.end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };

                        let kind = match lexeme_upper.as_str() {
                            "API_KEY" => AstAlterApiIntegrationActionKind::UnsetApiKey {
                                unset_span: Some(unset_span),
                                property_span,
                            },
                            "ENABLED" => AstAlterApiIntegrationActionKind::UnsetEnabled {
                                unset_span: Some(unset_span),
                                property_span,
                            },
                            "API_BLOCKED_PREFIXES" => {
                                AstAlterApiIntegrationActionKind::UnsetApiBlockedPrefixes {
                                    unset_span: Some(unset_span),
                                    property_span,
                                }
                            }
                            _ => {
                                // Unknown property - use first known variant
                                AstAlterApiIntegrationActionKind::UnsetApiKey {
                                    unset_span: Some(unset_span),
                                    property_span,
                                }
                            }
                        };

                        actions.push(AstAlterApiIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            syntax_id: None,
                            kind,
                        });
                    }
                }
                _ => break,
            }
        }

        let action_span = if let (Some(first), Some(last)) = (actions.first(), actions.last()) {
            Span {
                start: first.span.start,
                end: last.span.end,
            }
        } else {
            name_span
        };

        let end = action_span.end;
        let stmt_span = Span { start, end };

        // Build CST nodes for each action
        let action_ids: Vec<_> = actions
            .iter()
            .map(|action| {
                let syntax_action = SyntaxAlterApiIntegrationAction { span: action.span };
                self.syntax_arena
                    .alloc_alter_api_integration_action(syntax_action)
            })
            .collect();

        // Use first action_id for syntax node (simplified)
        let action_id = action_ids.first().copied().ok_or_else(|| {
            ParseError::new(
                stmt_span,
                ParseErrorKind::InvalidStatement {
                    message: "ALTER API INTEGRATION requires at least one action".to_string(),
                },
            )
        })?;

        // Build CST node
        let syntax_node = SyntaxAlterApiIntegration {
            alter_keyword,
            api_token: api_token.unwrap_or(alter_keyword), // Use alter_keyword as fallback
            integration_keyword,
            if_keyword,
            exists_keyword,
            name_span,
            action_id,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_alter_api_integration_stmt(syntax_node);

        // Compute keyword spans
        let alter_span = alter_tok.span;
        let api_span = api_token.and_then(|_| self.tokens.first().map(|t| t.span)); // Approximate
        let integration_span = name_span; // Will be refined
        let if_exists_span = if if_keyword.is_some() {
            Some(name_span)
        } else {
            None
        };

        // Build AST node
        let ast = AstAlterApiIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            api_span,
            integration_span,
            if_exists_span,
            name_span,
            action_span,
            actions,
        };
        Ok(AstStmt::AlterApiIntegration(Box::new(ast)))
    }

    /// Parse DROP API INTEGRATION statement
    pub(crate) fn try_parse_drop_api_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_api_integration")?;

        // DROP keyword
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_keyword = self.last_token_id();
        let start = drop_tok.span.start;

        // Optional: API keyword
        let api_token = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("API")
            {
                self.advance();
                Some(self.last_token_id())
            } else {
                None
            }
        } else {
            None
        };

        // INTEGRATION keyword
        self.expect_keyword(Keyword::Integration)?;
        let integration_keyword = self.last_token_id();

        // Optional: IF EXISTS
        let (if_keyword, exists_keyword) = if let Some(tok) = self.peek_non_trivia() {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance();
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
                (Some(if_token_id), Some(exists_token_id))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Integration name
        let integration_name_span = self.parse_qualified_name_span()?;
        let end = integration_name_span.end;

        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = SyntaxDropApiIntegration {
            drop_keyword,
            api_token,
            integration_keyword,
            if_keyword,
            exists_keyword,
            integration_name_span,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_drop_api_integration(syntax_node);

        // Compute keyword spans
        let drop_span = drop_tok.span;
        let api_span = api_token.and_then(|_| self.tokens.first().map(|t| t.span)); // Approximate
        let integration_span = integration_name_span; // Will be refined
        let if_exists_span = if if_keyword.is_some() {
            Some(integration_name_span)
        } else {
            None
        };

        // Build AST node
        let ast = AstDropApiIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            api_span,
            integration_span,
            if_exists_span,
            integration_name_span,
        };
        Ok(AstStmt::DropApiIntegration(Box::new(ast)))
    }
}
