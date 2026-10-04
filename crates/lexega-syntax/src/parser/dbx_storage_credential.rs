// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Databricks Unity Catalog `CREATE/ALTER/DROP [STORAGE | SERVICE] CREDENTIAL` statements.
//!
//! Syntax:
//!   `CREATE [STORAGE | SERVICE] CREDENTIAL [IF NOT EXISTS] credential_name [COMMENT comment]`
//!   `ALTER [STORAGE | SERVICE] CREDENTIAL credential_name { RENAME TO new_name | [SET] OWNER TO principal }`
//!   `DROP [STORAGE | SERVICE] CREDENTIAL [IF EXISTS] credential_name`
//!
//! Token reference (--debug-tokens --dialect databricks):
//!   CREATE     → Keyword(Create)
//!   ALTER      → Keyword(Alter)
//!   DROP       → Keyword(Drop)
//!   STORAGE    → Keyword(Storage)
//!   SERVICE    → Identifier (NOT Keyword)
//!   CREDENTIAL → Identifier (NOT Keyword — singular, not Credentials)
//!   IF         → Keyword(If)
//!   NOT        → Keyword(Not)
//!   EXISTS     → Keyword(Exists)
//!   COMMENT    → Keyword(Comment)
//!   RENAME     → Keyword(Rename)
//!   TO         → Keyword(To)
//!   SET        → Keyword(Set)
//!   OWNER      → Keyword(Owner)

use crate::ast::types::{
    AlterStorageCredentialAction, AstAlterStorageCredential, AstCreateStorageCredential,
    AstDropStorageCredential, AstStmt, AstStorageCredentialProvider,
    AstStorageCredentialProviderVariant, CredentialKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::create_stage::unquote_sql_string;

impl<'a> Parser<'a> {
    /// Parse `CREATE [STORAGE | SERVICE] CREDENTIAL [IF NOT EXISTS] name [COMMENT '...']`
    ///
    /// Called from `try_parse_stmt()` after dispatcher identifies CREATE [STORAGE|SERVICE] CREDENTIAL.
    /// Position: at CREATE token (idx reset to saved_idx pointing to CREATE).
    pub(crate) fn try_parse_create_storage_credential(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_storage_credential")?;
        let start = self.current_span().start;

        // CREATE
        let _create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;

        // Determine credential kind: STORAGE | SERVICE | bare
        let credential_kind = self.parse_credential_kind_qualifier()?;

        // CREDENTIAL (Identifier, NOT Keyword)
        let cred_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREDENTIAL".to_string()])?;
        if !cred_kw_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CREDENTIAL")
        {
            return Err(ParseError::new(
                cred_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CREDENTIAL, found '{}'",
                        cred_kw_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Optional IF NOT EXISTS
        let if_not_exists = self.parse_optional_if_not_exists()?.is_some();

        // Credential name (required — possibly backtick-quoted, possibly qualified)
        let credential_name_span = self.parse_qualified_name_span()?;
        let mut end = credential_name_span.end;

        // Optional WITH keyword preceding the provider clause.
        self.consume_optional_with_keyword();

        // Optional provider clause (AWS_IAM_ROLE / AZURE_* / DATABRICKS_GCP_* /
        // CLOUDFLARE_API_TOKEN). When present, the provider's last argument
        // extends the statement span.
        let provider = self.try_parse_storage_credential_provider()?;
        if let Some(p) = provider.as_ref() {
            end = provider_span_end(p).unwrap_or(end);
        }

        // Optional COMMENT
        let mut comment_keyword_span = None;
        let mut comment_value_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let comment_kw = self.advance().unwrap();
                comment_keyword_span = Some(comment_kw.span);

                let comment_val = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
                comment_value_span = Some(comment_val.span);
                end = comment_val.span.end;
            }
        }

        let span = Span { start, end };

        let ast = AstCreateStorageCredential {
            node_id: self.id_gen.next(),
            span,
            credential_kind,
            if_not_exists,
            credential_name_span,
            provider,
            comment_keyword_span,
            comment_value_span,
        };
        Ok(AstStmt::CreateStorageCredential(Box::new(ast)))
    }

    /// Parse `ALTER [STORAGE | SERVICE] CREDENTIAL name { RENAME TO new_name | [SET] OWNER TO principal }`
    ///
    /// Called from `try_parse_stmt()` after dispatcher identifies ALTER [STORAGE|SERVICE] CREDENTIAL.
    /// Position: at ALTER token (idx reset to saved_idx pointing to ALTER).
    pub(crate) fn try_parse_alter_storage_credential(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_storage_credential")?;
        let start = self.current_span().start;

        // ALTER
        let _alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;

        // Determine credential kind: STORAGE | SERVICE | bare
        let credential_kind = self.parse_credential_kind_qualifier()?;

        // CREDENTIAL (Identifier, NOT Keyword)
        let cred_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREDENTIAL".to_string()])?;
        if !cred_kw_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CREDENTIAL")
        {
            return Err(ParseError::new(
                cred_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CREDENTIAL, found '{}'",
                        cred_kw_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Credential name (required)
        let credential_name_span = self.parse_qualified_name_span()?;

        // Parse action: RENAME TO | [SET] OWNER TO | provider clause
        let action = self.parse_alter_credential_action()?;
        let end = match &action {
            AlterStorageCredentialAction::RenameTo { new_name_span, .. } => new_name_span.end,
            AlterStorageCredentialAction::OwnerTo {
                owner_name_span, ..
            } => owner_name_span.end,
            AlterStorageCredentialAction::SetProvider { end_span, .. } => end_span.end,
        };

        let span = Span { start, end };

        let ast = AstAlterStorageCredential {
            node_id: self.id_gen.next(),
            span,
            credential_kind,
            credential_name_span,
            action,
        };
        Ok(AstStmt::AlterStorageCredential(Box::new(ast)))
    }

    /// Parse `DROP [STORAGE | SERVICE] CREDENTIAL [IF EXISTS] name`
    ///
    /// Called from `try_parse_stmt()` after dispatcher identifies DROP [STORAGE|SERVICE] CREDENTIAL.
    /// Position: at DROP token (idx reset to saved_idx pointing to DROP).
    pub(crate) fn try_parse_drop_storage_credential(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_storage_credential")?;
        let start = self.current_span().start;

        // DROP
        let _drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;

        // Determine credential kind: STORAGE | SERVICE | bare
        let credential_kind = self.parse_credential_kind_qualifier()?;

        // CREDENTIAL (Identifier, NOT Keyword)
        let cred_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREDENTIAL".to_string()])?;
        if !cred_kw_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CREDENTIAL")
        {
            return Err(ParseError::new(
                cred_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CREDENTIAL, found '{}'",
                        cred_kw_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Optional IF EXISTS
        let if_exists = self.parse_optional_if_exists()?.is_some();

        // Credential name (required)
        let credential_name_span = self.parse_qualified_name_span()?;
        let end = credential_name_span.end;

        let span = Span { start, end };

        let ast = AstDropStorageCredential {
            node_id: self.id_gen.next(),
            span,
            credential_kind,
            if_exists,
            credential_name_span,
        };
        Ok(AstStmt::DropStorageCredential(Box::new(ast)))
    }

    // ─── Helpers ────────────────────────────────────────────────────────────────

    /// Parse the optional STORAGE | SERVICE qualifier before CREDENTIAL.
    /// Returns `CredentialKind::Storage`, `CredentialKind::Service`, or `CredentialKind::Bare`.
    /// Consumes the qualifier token if present; leaves cursor at CREDENTIAL.
    fn parse_credential_kind_qualifier(&mut self) -> ParseResult<CredentialKind> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Storage)) {
                self.advance(); // consume STORAGE
                return Ok(CredentialKind::Storage);
            }
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("SERVICE")
            {
                self.advance(); // consume SERVICE
                return Ok(CredentialKind::Service);
            }
        }
        Ok(CredentialKind::Bare)
    }

    /// Parse the action clause of an ALTER CREDENTIAL statement.
    /// Expects: RENAME TO new_name | [SET] OWNER TO principal
    fn parse_alter_credential_action(&mut self) -> ParseResult<AlterStorageCredentialAction> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected RENAME TO or OWNER TO after credential name".to_string(),
                },
            )
        })?;

        if matches!(tok.kind, TokenKind::Keyword(Keyword::Rename)) {
            // RENAME TO new_name
            let rename_tok = self.advance().unwrap();
            let rename_span = rename_tok.span;

            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TO after RENAME, found '{}'",
                            to_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let to_span = to_tok.span;

            let new_name_span = self.parse_qualified_name_span()?;

            Ok(AlterStorageCredentialAction::RenameTo {
                rename_span,
                to_span,
                new_name_span,
            })
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
            // SET OWNER TO principal
            let set_tok = self.advance().unwrap();
            let set_span = Some(set_tok.span);

            let owner_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["OWNER".to_string()])?;
            if !matches!(owner_tok.kind, TokenKind::Keyword(Keyword::Owner)) {
                return Err(ParseError::new(
                    owner_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected OWNER after SET, found '{}'",
                            owner_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let owner_span = owner_tok.span;

            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TO after OWNER, found '{}'",
                            to_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let to_span = to_tok.span;

            let owner_name_span = self.parse_qualified_name_span()?;

            Ok(AlterStorageCredentialAction::OwnerTo {
                set_span,
                owner_span,
                to_span,
                owner_name_span,
            })
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Owner)) {
            // OWNER TO principal (without SET)
            let owner_tok = self.advance().unwrap();
            let owner_span = owner_tok.span;

            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TO after OWNER, found '{}'",
                            to_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let to_span = to_tok.span;

            let owner_name_span = self.parse_qualified_name_span()?;

            Ok(AlterStorageCredentialAction::OwnerTo {
                set_span: None,
                owner_span,
                to_span,
                owner_name_span,
            })
        } else {
            // Optional WITH preceding the provider clause.
            self.consume_optional_with_keyword();
            // Try to recognize a provider keyword (AWS_IAM_ROLE etc.).
            // If we recognize one, this is a SetProvider action.
            if let Some(provider) = self.try_parse_storage_credential_provider()? {
                let end_span = provider_span_end_as_span(&provider).unwrap_or(tok.span);
                return Ok(AlterStorageCredentialAction::SetProvider { end_span, provider });
            }
            Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected RENAME TO, [SET] OWNER TO, or a provider clause, found '{}'",
                        tok.lexeme(self.source)
                    ),
                },
            ))
        }
    }

    /// Consume an optional `WITH` keyword token (Databricks SQL allows
    /// the provider clause to be introduced with or without it).
    fn consume_optional_with_keyword(&mut self) {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                self.advance();
            }
        }
    }

    /// Try to parse a provider clause if the next non-trivia token is a
    /// recognized provider keyword. Returns `None` when the next token
    /// isn't a recognized provider — caller continues with whatever
    /// optional tail follows.
    fn try_parse_storage_credential_provider(
        &mut self,
    ) -> ParseResult<Option<AstStorageCredentialProvider>> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok(None),
        };
        let lex = tok.lexeme(self.source);
        if lex.eq_ignore_ascii_case("AWS_IAM_ROLE") {
            Ok(Some(self.parse_aws_iam_role_provider()?))
        } else if lex.eq_ignore_ascii_case("AZURE_MANAGED_IDENTITY") {
            Ok(Some(self.parse_azure_managed_identity_provider()?))
        } else if lex.eq_ignore_ascii_case("AZURE_SERVICE_PRINCIPAL") {
            Ok(Some(self.parse_azure_service_principal_provider()?))
        } else if lex.eq_ignore_ascii_case("DATABRICKS_GCP_SERVICE_ACCOUNT") {
            Ok(Some(self.parse_databricks_gcp_service_account_provider()?))
        } else if lex.eq_ignore_ascii_case("CLOUDFLARE_API_TOKEN") {
            Ok(Some(self.parse_cloudflare_api_token_provider()?))
        } else {
            Ok(None)
        }
    }

    fn parse_aws_iam_role_provider(&mut self) -> ParseResult<AstStorageCredentialProvider> {
        let kw = self
            .advance()
            .expect_invariant("AWS_IAM_ROLE keyword consumed after lexeme match");
        let keyword_span = kw.span;
        // Optional opening paren — accept either positional or paren-wrapped form.
        let in_parens = self.consume_optional_lparen();
        let (role_arn_span, role_arn_text) = self.parse_provider_arg("role_arn")?;
        if in_parens {
            self.consume_optional_rparen();
        }
        let mut all_literal_values = Vec::new();
        if let Some(t) = role_arn_text.as_ref() {
            all_literal_values.push(t.clone());
        }
        Ok(AstStorageCredentialProvider {
            variant: AstStorageCredentialProviderVariant::AwsIamRole {
                keyword_span,
                role_arn_span,
                role_arn_text,
            },
            all_literal_values,
        })
    }

    fn parse_azure_managed_identity_provider(
        &mut self,
    ) -> ParseResult<AstStorageCredentialProvider> {
        let kw = self
            .advance()
            .expect_invariant("AZURE_MANAGED_IDENTITY keyword consumed after lexeme match");
        let keyword_span = kw.span;
        let in_parens = self.consume_optional_lparen();
        let (managed_identity_id_span, managed_identity_id_text) =
            self.parse_provider_arg("managed_identity_id")?;

        // Optional `, ACCESS_CONNECTOR_ID '<value>'`
        let mut access_connector_id_span = None;
        let mut access_connector_id_text = None;
        if self.consume_optional_comma() {
            // Expect ACCESS_CONNECTOR_ID identifier.
            if let Some(t) = self.peek_non_trivia() {
                if t.lexeme(self.source)
                    .eq_ignore_ascii_case("ACCESS_CONNECTOR_ID")
                {
                    self.advance(); // consume ACCESS_CONNECTOR_ID
                    let (s, txt) = self.parse_provider_arg("access_connector_id")?;
                    access_connector_id_span = Some(s);
                    access_connector_id_text = txt;
                }
            }
        }
        if in_parens {
            self.consume_optional_rparen();
        }

        let mut all_literal_values = Vec::new();
        if let Some(t) = managed_identity_id_text.as_ref() {
            all_literal_values.push(t.clone());
        }
        if let Some(t) = access_connector_id_text.as_ref() {
            all_literal_values.push(t.clone());
        }

        Ok(AstStorageCredentialProvider {
            variant: AstStorageCredentialProviderVariant::AzureManagedIdentity {
                keyword_span,
                managed_identity_id_span,
                managed_identity_id_text,
                access_connector_id_span,
                access_connector_id_text,
            },
            all_literal_values,
        })
    }

    fn parse_azure_service_principal_provider(
        &mut self,
    ) -> ParseResult<AstStorageCredentialProvider> {
        let kw = self
            .advance()
            .expect_invariant("AZURE_SERVICE_PRINCIPAL keyword consumed after lexeme match");
        let keyword_span = kw.span;
        let in_parens = self.consume_optional_lparen();
        let (directory_id_span, directory_id_text) = self.parse_provider_arg("directory_id")?;
        self.consume_optional_comma();
        let (application_id_span, application_id_text) =
            self.parse_provider_arg("application_id")?;
        self.consume_optional_comma();
        let (client_secret_span, client_secret_text) = self.parse_provider_arg("client_secret")?;
        if in_parens {
            self.consume_optional_rparen();
        }

        let mut all_literal_values = Vec::new();
        for t in [
            directory_id_text.as_ref(),
            application_id_text.as_ref(),
            client_secret_text.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            all_literal_values.push(t.clone());
        }

        Ok(AstStorageCredentialProvider {
            variant: AstStorageCredentialProviderVariant::AzureServicePrincipal {
                keyword_span,
                directory_id_span,
                directory_id_text,
                application_id_span,
                application_id_text,
                client_secret_span,
                client_secret_text,
            },
            all_literal_values,
        })
    }

    fn parse_databricks_gcp_service_account_provider(
        &mut self,
    ) -> ParseResult<AstStorageCredentialProvider> {
        let kw = self
            .advance()
            .expect_invariant("DATABRICKS_GCP_SERVICE_ACCOUNT keyword consumed after lexeme match");
        let keyword_span = kw.span;
        // The DATABRICKS_GCP_SERVICE_ACCOUNT provider takes no arguments.
        // Defensive: if a stray `()` follows, swallow it.
        if self.consume_optional_lparen() {
            self.consume_optional_rparen();
        }
        Ok(AstStorageCredentialProvider {
            variant: AstStorageCredentialProviderVariant::DatabricksGcpServiceAccount {
                keyword_span,
            },
            all_literal_values: Vec::new(),
        })
    }

    fn parse_cloudflare_api_token_provider(&mut self) -> ParseResult<AstStorageCredentialProvider> {
        let kw = self
            .advance()
            .expect_invariant("CLOUDFLARE_API_TOKEN keyword consumed after lexeme match");
        let keyword_span = kw.span;
        let in_parens = self.consume_optional_lparen();
        let (account_id_span, account_id_text) = self.parse_provider_arg("account_id")?;
        self.consume_optional_comma();
        let (access_key_id_span, access_key_id_text) = self.parse_provider_arg("access_key_id")?;
        self.consume_optional_comma();
        let (secret_access_key_span, secret_access_key_text) =
            self.parse_provider_arg("secret_access_key")?;
        if in_parens {
            self.consume_optional_rparen();
        }

        let mut all_literal_values = Vec::new();
        for t in [
            account_id_text.as_ref(),
            access_key_id_text.as_ref(),
            secret_access_key_text.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            all_literal_values.push(t.clone());
        }

        Ok(AstStorageCredentialProvider {
            variant: AstStorageCredentialProviderVariant::CloudflareApiToken {
                keyword_span,
                account_id_span,
                account_id_text,
                access_key_id_span,
                access_key_id_text,
                secret_access_key_span,
                secret_access_key_text,
            },
            all_literal_values,
        })
    }

    /// Parse one provider argument. Accepts a string literal (returning
    /// the unquoted text) or any non-string token (advancing past it
    /// and returning `None` for the text — parameterized values land
    /// here).
    fn parse_provider_arg(&mut self, label: &str) -> ParseResult<(Span, Option<String>)> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected {} value", label),
                },
            )
        })?;
        let span = tok.span;
        if matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) {
            let consumed = self
                .advance()
                .expect_invariant("string literal consumed after kind match");
            let text = unquote_sql_string(consumed.lexeme(self.source));
            Ok((span, Some(text)))
        } else {
            // Parameter / identifier / numeric — accept and advance.
            self.advance();
            Ok((span, None))
        }
    }

    fn consume_optional_lparen(&mut self) -> bool {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                self.advance();
                return true;
            }
        }
        false
    }

    fn consume_optional_rparen(&mut self) -> bool {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                self.advance();
                return true;
            }
        }
        false
    }

    fn consume_optional_comma(&mut self) -> bool {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance();
                return true;
            }
        }
        false
    }
}

/// Returns the source byte offset where the provider's last meaningful
/// span ends. Used to extend the enclosing statement's span past the
/// provider arguments.
fn provider_span_end(provider: &AstStorageCredentialProvider) -> Option<u32> {
    use AstStorageCredentialProviderVariant as V;
    let span = match &provider.variant {
        V::AwsIamRole { role_arn_span, .. } => *role_arn_span,
        V::AzureManagedIdentity {
            managed_identity_id_span,
            access_connector_id_span,
            ..
        } => access_connector_id_span.unwrap_or(*managed_identity_id_span),
        V::AzureServicePrincipal {
            client_secret_span, ..
        } => *client_secret_span,
        V::DatabricksGcpServiceAccount { keyword_span } => *keyword_span,
        V::CloudflareApiToken {
            secret_access_key_span,
            ..
        } => *secret_access_key_span,
        V::Unparsed { body_span, .. } => return body_span.map(|s| s.end),
    };
    Some(span.end)
}

/// Same as [`provider_span_end`] but returns a `Span` whose `end` is the
/// provider's last arg end and `start` is the provider keyword span's
/// start (used to populate `AlterStorageCredentialAction::SetProvider`'s
/// `end_span` slot, which the enclosing statement consults for its
/// span).
fn provider_span_end_as_span(provider: &AstStorageCredentialProvider) -> Option<Span> {
    use AstStorageCredentialProviderVariant as V;
    let (start, end) = match &provider.variant {
        V::AwsIamRole {
            keyword_span,
            role_arn_span,
            ..
        } => (keyword_span.start, role_arn_span.end),
        V::AzureManagedIdentity {
            keyword_span,
            managed_identity_id_span,
            access_connector_id_span,
            ..
        } => (
            keyword_span.start,
            access_connector_id_span
                .map(|s| s.end)
                .unwrap_or(managed_identity_id_span.end),
        ),
        V::AzureServicePrincipal {
            keyword_span,
            client_secret_span,
            ..
        } => (keyword_span.start, client_secret_span.end),
        V::DatabricksGcpServiceAccount { keyword_span } => (keyword_span.start, keyword_span.end),
        V::CloudflareApiToken {
            keyword_span,
            secret_access_key_span,
            ..
        } => (keyword_span.start, secret_access_key_span.end),
        V::Unparsed {
            keyword_span,
            body_span,
        } => {
            let s = keyword_span.map(|s| s.start).unwrap_or(0);
            let e = body_span.map(|b| b.end).unwrap_or(s);
            (s, e)
        }
    };
    Some(Span { start, end })
}
