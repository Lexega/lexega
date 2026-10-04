// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for Snowflake account-level ALTER constructs that don't share
//! a parent object surface with other dialects:
//!
//!   - `ALTER SHARE [IF EXISTS] <name> { ADD | REMOVE | SET } ACCOUNTS = …`
//!   - `ALTER SHARE [IF EXISTS] <name> { SET | UNSET } <property> …`
//!   - `ALTER SECURITY INTEGRATION [IF EXISTS] <name> { SET | UNSET | RENAME TO } …`
//!   - `ALTER REPLICATION GROUP [IF EXISTS] <name> …`
//!   - `ALTER FAILOVER GROUP [IF EXISTS] <name> …`
//!
//! Each parser produces a typed AST node with a closed action enum that
//! covers the principal SQL action (ADD ACCOUNTS, REMOVE ACCOUNTS, SET …,
//! REMOVE … FROM ALLOWED_DATABASES, etc.). Unrecognized inner shapes
//! route to the `Unknown(AstUnknownClause)` variant so the parser never
//! falls back to OpaqueContent for these constructs.

use crate::ast::types::{
    AstAlterAlert, AstAlterAlertAction, AstAlterAlertActionKind, AstAlterApplication,
    AstAlterApplicationPackage, AstAlterComputePool, AstAlterCortexSearchService,
    AstAlterDatashare, AstAlterDatashareAction, AstAlterDatashareActionKind, AstAlterFailoverGroup,
    AstAlterGitRepository, AstAlterImageRepository, AstAlterListing, AstAlterNetworkRule,
    AstAlterNetworkRuleAction, AstAlterNetworkRuleActionKind, AstAlterNotebook,
    AstAlterReplicationGroup, AstAlterResourceMonitor, AstAlterSecret, AstAlterSecretAction,
    AstAlterSecretActionKind, AstAlterSecurityIntegration, AstAlterSecurityIntegrationAction,
    AstAlterSecurityIntegrationActionKind, AstAlterSemanticView, AstAlterService, AstAlterShare,
    AstAlterShareAction, AstAlterShareActionKind, AstAlterStreamlit, AstApplicationAction,
    AstComputePoolAction, AstCortexSearchServiceAction, AstCreateAccount, AstCreateAlert,
    AstCreateApplication, AstCreateApplicationPackage, AstCreateComputePool,
    AstCreateCortexSearchService, AstCreateDatashare, AstCreateGitRepository,
    AstCreateImageRepository, AstCreateListing, AstCreateManagedAccount, AstCreateNetworkRule,
    AstCreateNotebook, AstCreateReplicationFailoverGroup, AstCreateResourceMonitor,
    AstCreateSecret, AstCreateSecurityIntegration, AstCreateSemanticView, AstCreateService,
    AstCreateShare, AstCreateStreamlit, AstDatashareObjectKind, AstGitRepositoryAction,
    AstImageRepositoryAction, AstListingAction, AstNotebookAction,
    AstReplicationFailoverGroupAction, AstReplicationFailoverGroupActionKind,
    AstResourceMonitorTrigger, AstSemanticViewAction, AstSemanticViewTable, AstServiceAction,
    AstStageFileCommand, AstStageFileCommandKind, AstStmt, AstStreamlitAction, AstUnknownClause,
    UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Punctuation, Span, Token, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `CREATE [OR REPLACE] SHARE [IF NOT EXISTS] <name> [COMMENT = '<text>']`.
    pub(crate) fn try_parse_create_share(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_share")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let share_span = expect_identifier_lexeme(self, "SHARE")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Optional COMMENT = '<text>'
        let mut comment_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let com_start = tok.span.start;
                self.advance(); // COMMENT
                let _ = parse_optional_eq(self);
                let val_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
                let com_end = val_tok.span.end;
                comment_span = Some(Span {
                    start: com_start,
                    end: com_end,
                });
                end = com_end;
            }
        }

        let ast = AstCreateShare {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            share_span,
            if_not_exists_span,
            name_span,
            comment_span,
        };
        Ok(AstStmt::CreateShare(Box::new(ast)))
    }

    /// Parse `ALTER SHARE [IF EXISTS] <name> <action>`.
    pub(crate) fn try_parse_alter_share(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_share")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let share_span = expect_identifier_lexeme(self, "SHARE")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let action = parse_alter_share_action(self)?;

        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let ast = AstAlterShare {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            share_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterShare(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] DATASHARE [IF NOT EXISTS] <name>
    ///   [SET PUBLICACCESSIBLE [=] TRUE|FALSE]` (Amazon Redshift).
    pub(crate) fn try_parse_create_datashare(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_datashare")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let datashare_span = expect_identifier_lexeme(self, "DATASHARE")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Optional `SET PUBLICACCESSIBLE [=] TRUE|FALSE` on the CREATE form.
        let mut publicly_accessible: Option<bool> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
                let saved = self.idx;
                self.advance(); // SET
                let is_public = self
                    .peek_non_trivia()
                    .map(|t| {
                        matches!(t.kind, TokenKind::Identifier { .. })
                            && t.lexeme(self.source)
                                .eq_ignore_ascii_case("PUBLICACCESSIBLE")
                    })
                    .unwrap_or(false);
                if is_public {
                    self.advance(); // PUBLICACCESSIBLE
                    let _ = parse_optional_eq(self);
                    if let Some(v) = self.peek_non_trivia() {
                        if let Some((val, sp)) = bool_literal(v, self.source) {
                            self.advance();
                            publicly_accessible = Some(val);
                            end = sp.end;
                        }
                    }
                } else {
                    // Not PUBLICACCESSIBLE — restore (forward-compat).
                    self.idx = saved;
                }
            }
        }

        let ast = AstCreateDatashare {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            datashare_span,
            if_not_exists_span,
            name_span,
            publicly_accessible,
        };
        Ok(AstStmt::CreateDatashare(Box::new(ast)))
    }

    /// Parse `ALTER DATASHARE <name> <action>` (Amazon Redshift).
    pub(crate) fn try_parse_alter_datashare(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_datashare")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let datashare_span = expect_identifier_lexeme(self, "DATASHARE")?;
        let name_span = self.parse_qualified_name_span()?;
        let action = parse_alter_datashare_action(self)?;

        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };
        let ast = AstAlterDatashare {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            datashare_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterDatashare(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] SECURITY INTEGRATION [IF NOT EXISTS] <name>
    ///   TYPE = <type> ENABLED = … <type_specific_props> [COMMENT = '<text>']`.
    pub(crate) fn try_parse_create_security_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_security_integration")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let security_span = expect_identifier_lexeme(self, "SECURITY")?;
        let integration_span =
            expect_keyword_or_identifier(self, Keyword::Integration, "INTEGRATION")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let mut type_span: Option<Span> = None;
        let mut type_value_span: Option<Span> = None;
        let mut enabled_span: Option<Span> = None;
        let mut enabled_value_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut properties_start: Option<u32> = None;
        let mut properties_end: u32 = end;

        // Walk properties until ; / EOF (shared with ALTER … SET). TYPE /
        // ENABLED / COMMENT are additionally promoted to dedicated spans;
        // everything else extends the catch-all properties_span.
        let properties = walk_object_properties(self);
        for prop in &properties {
            let name_upper = self
                .source
                .get(prop.name_span.start as usize..prop.name_span.end as usize)
                .unwrap_or("")
                .to_ascii_uppercase();
            let prop_end = prop.value_span.map(|v| v.end).unwrap_or(prop.name_span.end);
            let prop_span = Span {
                start: prop.name_span.start,
                end: prop_end,
            };
            match (name_upper.as_str(), prop.value_span) {
                ("TYPE", Some(val_span)) => {
                    type_span = Some(prop_span);
                    type_value_span = Some(val_span);
                }
                ("ENABLED", Some(val_span)) => {
                    enabled_span = Some(prop_span);
                    enabled_value_span = Some(val_span);
                }
                ("COMMENT", Some(_)) => {
                    comment_span = Some(prop_span);
                }
                _ => {
                    // Other property (or value-less keyword) — extend the
                    // catch-all span.
                    if properties_start.is_none() {
                        properties_start = Some(prop_span.start);
                    }
                    properties_end = prop_end;
                }
            }
            end = prop_end;
        }

        let properties_span = properties_start.map(|start| Span {
            start,
            end: properties_end,
        });

        let ast = AstCreateSecurityIntegration {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            if_not_exists_span,
            security_span,
            integration_span,
            name_span,
            properties,
            type_span,
            type_value_span,
            enabled_span,
            enabled_value_span,
            comment_span,
            properties_span,
        };
        Ok(AstStmt::CreateSecurityIntegration(Box::new(ast)))
    }

    /// Parse `ALTER SECURITY INTEGRATION [IF EXISTS] <name> <action>`.
    pub(crate) fn try_parse_alter_security_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_security_integration")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let security_span = expect_identifier_lexeme(self, "SECURITY")?;
        let integration_span =
            expect_keyword_or_identifier(self, Keyword::Integration, "INTEGRATION")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let action = parse_alter_security_integration_action(self)?;

        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let ast = AstAlterSecurityIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            security_span,
            integration_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterSecurityIntegration(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] SECRET [IF NOT EXISTS] <name>
    ///   TYPE = <type> <type_specific_props> [COMMENT = '<text>']`.
    pub(crate) fn try_parse_create_secret(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_secret")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let secret_span = expect_identifier_lexeme(self, "SECRET")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let mut type_value_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;

        let properties = walk_object_properties(self);
        for prop in &properties {
            let name_upper = self
                .source
                .get(prop.name_span.start as usize..prop.name_span.end as usize)
                .unwrap_or("")
                .to_ascii_uppercase();
            let prop_end = prop.value_span.map(|v| v.end).unwrap_or(prop.name_span.end);
            match (name_upper.as_str(), prop.value_span) {
                ("TYPE", Some(val_span)) => type_value_span = Some(val_span),
                ("COMMENT", Some(_)) => {
                    comment_span = Some(Span {
                        start: prop.name_span.start,
                        end: prop_end,
                    });
                }
                _ => {}
            }
            end = prop_end;
        }

        let ast = AstCreateSecret {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            secret_span,
            if_not_exists_span,
            name_span,
            properties,
            type_value_span,
            comment_span,
        };
        Ok(AstStmt::CreateSecret(Box::new(ast)))
    }

    /// Parse `ALTER SECRET [IF EXISTS] <name> { SET <props> | UNSET <prop> [, …] }`.
    pub(crate) fn try_parse_alter_secret(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_secret")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let secret_span = expect_identifier_lexeme(self, "SECRET")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let action_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["SET or UNSET".to_string()])?;
        let action_start = action_tok.span.start;

        let action = match action_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                let set_tok = self.advance().expect_invariant("SET in alter secret");
                let set_span = set_tok.span;
                let properties = walk_object_properties(self);
                let end = properties
                    .last()
                    .map(|p| p.value_span.map(|v| v.end).unwrap_or(p.name_span.end))
                    .unwrap_or(set_span.end);
                AstAlterSecretAction {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: action_start,
                        end,
                    },
                    kind: AstAlterSecretActionKind::Set {
                        set_span,
                        properties,
                    },
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                let unset_tok = self.advance().expect_invariant("UNSET in alter secret");
                let unset_span = unset_tok.span;
                let mut property_name_spans: Vec<Span> = Vec::new();
                let mut end = unset_span.end;
                while let Some(tok) = self.peek_non_trivia() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                    ) {
                        break;
                    }
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                        self.advance();
                        continue;
                    }
                    let name_tok = self
                        .advance()
                        .expect_invariant("UNSET property name consumed after peek");
                    property_name_spans.push(name_tok.span);
                    end = name_tok.span.end;
                }
                AstAlterSecretAction {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: action_start,
                        end,
                    },
                    kind: AstAlterSecretActionKind::Unset {
                        unset_span,
                        property_name_spans,
                    },
                }
            }
            _ => {
                return Err(ParseError::new(
                    action_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected SET or UNSET after secret name".to_string(),
                    },
                ));
            }
        };

        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let ast = AstAlterSecret {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            secret_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterSecret(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] NETWORK RULE [IF NOT EXISTS] <name>
    ///   TYPE = <type> VALUE_LIST = (…) MODE = <mode> [COMMENT = '<text>']`.
    pub(crate) fn try_parse_create_network_rule(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_network_rule")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let network_span = expect_identifier_lexeme(self, "NETWORK")?;
        let rule_span = expect_identifier_lexeme(self, "RULE")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let mut type_value_span: Option<Span> = None;
        let mut mode_value_span: Option<Span> = None;
        let mut value_list_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;

        let properties = walk_object_properties(self);
        for prop in &properties {
            let name_upper = self
                .source
                .get(prop.name_span.start as usize..prop.name_span.end as usize)
                .unwrap_or("")
                .to_ascii_uppercase();
            let prop_end = prop.value_span.map(|v| v.end).unwrap_or(prop.name_span.end);
            match (name_upper.as_str(), prop.value_span) {
                ("TYPE", Some(val_span)) => type_value_span = Some(val_span),
                ("MODE", Some(val_span)) => mode_value_span = Some(val_span),
                ("VALUE_LIST", Some(val_span)) => value_list_span = Some(val_span),
                ("COMMENT", Some(_)) => {
                    comment_span = Some(Span {
                        start: prop.name_span.start,
                        end: prop_end,
                    });
                }
                _ => {}
            }
            end = prop_end;
        }

        let ast = AstCreateNetworkRule {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            network_span,
            rule_span,
            if_not_exists_span,
            name_span,
            properties,
            type_value_span,
            mode_value_span,
            value_list_span,
            comment_span,
        };
        Ok(AstStmt::CreateNetworkRule(Box::new(ast)))
    }

    /// Parse `ALTER NETWORK RULE [IF EXISTS] <name> { SET <props> | UNSET <prop> [, …] }`.
    pub(crate) fn try_parse_alter_network_rule(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_network_rule")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let network_span = expect_identifier_lexeme(self, "NETWORK")?;
        let rule_span = expect_identifier_lexeme(self, "RULE")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let action_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["SET or UNSET".to_string()])?;
        let action_start = action_tok.span.start;

        let action = match action_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                let set_tok = self.advance().expect_invariant("SET in alter network rule");
                let set_span = set_tok.span;
                let properties = walk_object_properties(self);
                let end = properties
                    .last()
                    .map(|p| p.value_span.map(|v| v.end).unwrap_or(p.name_span.end))
                    .unwrap_or(set_span.end);
                AstAlterNetworkRuleAction {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: action_start,
                        end,
                    },
                    kind: AstAlterNetworkRuleActionKind::Set {
                        set_span,
                        properties,
                    },
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                let unset_tok = self
                    .advance()
                    .expect_invariant("UNSET in alter network rule");
                let unset_span = unset_tok.span;
                let mut property_name_spans: Vec<Span> = Vec::new();
                let mut end = unset_span.end;
                while let Some(tok) = self.peek_non_trivia() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                    ) {
                        break;
                    }
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                        self.advance();
                        continue;
                    }
                    let name_tok = self
                        .advance()
                        .expect_invariant("UNSET property name consumed after peek");
                    property_name_spans.push(name_tok.span);
                    end = name_tok.span.end;
                }
                AstAlterNetworkRuleAction {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: action_start,
                        end,
                    },
                    kind: AstAlterNetworkRuleActionKind::Unset {
                        unset_span,
                        property_name_spans,
                    },
                }
            }
            _ => {
                return Err(ParseError::new(
                    action_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected SET or UNSET after network rule name".to_string(),
                    },
                ));
            }
        };

        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let ast = AstAlterNetworkRule {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            network_span,
            rule_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterNetworkRule(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] RESOURCE MONITOR [IF NOT EXISTS] <name>
    ///   [WITH] <props> [TRIGGERS ON <pct> PERCENT DO <action> ...]`.
    pub(crate) fn try_parse_create_resource_monitor(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_resource_monitor")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let resource_span = expect_identifier_lexeme(self, "RESOURCE")?;
        let monitor_span = expect_identifier_lexeme(self, "MONITOR")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Optional WITH keyword introduces the property bag.
        let with_span = match self.peek_non_trivia() {
            Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("WITH") => {
                let tok = self.advance().expect_invariant("WITH consumed after peek");
                end = tok.span.end;
                Some(tok.span)
            }
            _ => None,
        };

        let properties = walk_object_properties_until(self, Some("TRIGGERS"));
        let (credit_quota_span, frequency_value_span, notify_users_span) =
            resource_monitor_slots(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let triggers = self.parse_resource_monitor_triggers();
        if let Some(last) = triggers.last() {
            end = last.span.end;
        }

        let ast = AstCreateResourceMonitor {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            resource_span,
            monitor_span,
            if_not_exists_span,
            name_span,
            with_span,
            properties,
            credit_quota_span,
            frequency_value_span,
            notify_users_span,
            triggers,
        };
        Ok(AstStmt::CreateResourceMonitor(Box::new(ast)))
    }

    /// Parse `ALTER RESOURCE MONITOR [IF EXISTS] <name> SET <props>
    ///   [TRIGGERS ON <pct> PERCENT DO <action> ...]`.
    pub(crate) fn try_parse_alter_resource_monitor(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_resource_monitor")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let resource_span = expect_identifier_lexeme(self, "RESOURCE")?;
        let monitor_span = expect_identifier_lexeme(self, "MONITOR")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let set_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
        if !matches!(set_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            return Err(ParseError::new(
                set_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET after resource monitor name".to_string(),
                },
            ));
        }
        let set_span = set_tok.span;
        let mut end = set_span.end;

        let properties = walk_object_properties_until(self, Some("TRIGGERS"));
        let (credit_quota_span, frequency_value_span, notify_users_span) =
            resource_monitor_slots(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let triggers_present = matches!(
            self.peek_non_trivia(),
            Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("TRIGGERS")
        );
        let triggers = self.parse_resource_monitor_triggers();
        if let Some(last) = triggers.last() {
            end = last.span.end;
        }

        let ast = AstAlterResourceMonitor {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end,
            },
            alter_span,
            resource_span,
            monitor_span,
            if_exists_span,
            name_span,
            set_span,
            properties,
            credit_quota_span,
            frequency_value_span,
            notify_users_span,
            triggers,
            triggers_present,
        };
        Ok(AstStmt::AlterResourceMonitor(Box::new(ast)))
    }

    /// Parse `CREATE COMPUTE POOL [IF NOT EXISTS] <name> <props>`.
    pub(crate) fn try_parse_create_compute_pool(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_compute_pool")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let or_replace_span = self.parse_optional_or_replace()?;
        let compute_span = expect_identifier_lexeme(self, "COMPUTE")?;
        let pool_span = expect_identifier_lexeme(self, "POOL")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties(self);
        let (instance_family_span, auto_resume_span, min_nodes_span, max_nodes_span) =
            compute_pool_slots(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateComputePool {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            compute_span,
            pool_span,
            if_not_exists_span,
            name_span,
            properties,
            instance_family_span,
            auto_resume_span,
            min_nodes_span,
            max_nodes_span,
        };
        Ok(AstStmt::CreateComputePool(Box::new(ast)))
    }

    /// Parse `ALTER COMPUTE POOL [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | SUSPEND | RESUME | STOP ALL }`.
    pub(crate) fn try_parse_alter_compute_pool(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_compute_pool")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let compute_span = expect_identifier_lexeme(self, "COMPUTE")?;
        let pool_span = expect_identifier_lexeme(self, "POOL")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        let mut properties = Vec::new();
        let mut instance_family_span = None;
        let mut auto_resume_span = None;

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            properties = walk_object_properties(self);
            let (ifam, ar, _mn, _mx) = compute_pool_slots(self, &properties);
            instance_family_span = ifam;
            auto_resume_span = ar;
            if let Some(last) = properties.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstComputePoolAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let unset_props = walk_object_properties(self);
            if let Some(last) = unset_props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstComputePoolAction::Unset
        } else if action_lex == "SUSPEND" {
            let t = self
                .advance()
                .expect_invariant("SUSPEND consumed after peek");
            end = t.span.end;
            AstComputePoolAction::Suspend
        } else if action_lex == "RESUME" {
            let t = self
                .advance()
                .expect_invariant("RESUME consumed after peek");
            end = t.span.end;
            AstComputePoolAction::Resume
        } else if action_lex == "STOP" {
            let t = self.advance().expect_invariant("STOP consumed after peek");
            end = t.span.end;
            // Optional ALL.
            if matches!(
                self.peek_non_trivia(),
                Some(tk) if tk.lexeme(self.source).eq_ignore_ascii_case("ALL")
            ) {
                let all = self.advance().expect_invariant("ALL consumed after peek");
                end = all.span.end;
            }
            AstComputePoolAction::StopAll
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message:
                        "Expected SET, UNSET, SUSPEND, RESUME, or STOP ALL after compute pool name"
                            .to_string(),
                },
            ));
        };

        let ast = AstAlterComputePool {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end,
            },
            alter_span,
            compute_span,
            pool_span,
            if_exists_span,
            name_span,
            action,
            properties,
            instance_family_span,
            auto_resume_span,
        };
        Ok(AstStmt::AlterComputePool(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] GIT REPOSITORY [IF NOT EXISTS] <name> <props>`.
    pub(crate) fn try_parse_create_git_repository(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_git_repository")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let or_replace_span = self.parse_optional_or_replace()?;
        let git_span = expect_identifier_lexeme(self, "GIT")?;
        let repository_span = expect_identifier_lexeme(self, "REPOSITORY")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties(self);
        let (api_integration_span, origin_span, git_credentials_span) =
            git_repository_slots(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateGitRepository {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            git_span,
            repository_span,
            if_not_exists_span,
            name_span,
            properties,
            api_integration_span,
            origin_span,
            git_credentials_span,
        };
        Ok(AstStmt::CreateGitRepository(Box::new(ast)))
    }

    /// Parse `ALTER GIT REPOSITORY [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | FETCH }`.
    pub(crate) fn try_parse_alter_git_repository(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_git_repository")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let git_span = expect_identifier_lexeme(self, "GIT")?;
        let repository_span = expect_identifier_lexeme(self, "REPOSITORY")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        let mut properties = Vec::new();
        let mut api_integration_span = None;
        let mut git_credentials_span = None;

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            properties = walk_object_properties(self);
            let (api, _origin, creds) = git_repository_slots(self, &properties);
            api_integration_span = api;
            git_credentials_span = creds;
            if let Some(last) = properties.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstGitRepositoryAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let unset_props = walk_object_properties(self);
            if let Some(last) = unset_props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstGitRepositoryAction::Unset
        } else if action_lex == "FETCH" {
            let t = self.advance().expect_invariant("FETCH consumed after peek");
            end = t.span.end;
            AstGitRepositoryAction::Fetch
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET, UNSET, or FETCH after git repository name".to_string(),
                },
            ));
        };

        let ast = AstAlterGitRepository {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end,
            },
            alter_span,
            git_span,
            repository_span,
            if_exists_span,
            name_span,
            action,
            properties,
            api_integration_span,
            git_credentials_span,
        };
        Ok(AstStmt::AlterGitRepository(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] IMAGE REPOSITORY [IF NOT EXISTS] <name>
    ///   [COMMENT = '<text>'] [[WITH] TAG (...)]`.
    pub(crate) fn try_parse_create_image_repository(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_image_repository")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let or_replace_span = self.parse_optional_or_replace()?;
        let image_span = expect_identifier_lexeme(self, "IMAGE")?;
        let repository_span = expect_identifier_lexeme(self, "REPOSITORY")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // COMMENT / TAG are recorded for span coverage only.
        let properties = walk_object_properties(self);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateImageRepository {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            image_span,
            repository_span,
            if_not_exists_span,
            name_span,
            properties,
        };
        Ok(AstStmt::CreateImageRepository(Box::new(ast)))
    }

    /// Parse `ALTER IMAGE REPOSITORY [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> }`.
    pub(crate) fn try_parse_alter_image_repository(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_image_repository")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let image_span = expect_identifier_lexeme(self, "IMAGE")?;
        let repository_span = expect_identifier_lexeme(self, "REPOSITORY")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        let mut properties = Vec::new();

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            properties = walk_object_properties(self);
            if let Some(last) = properties.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstImageRepositoryAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let unset_props = walk_object_properties(self);
            if let Some(last) = unset_props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstImageRepositoryAction::Unset
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET after image repository name".to_string(),
                },
            ));
        };

        let ast = AstAlterImageRepository {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end,
            },
            alter_span,
            image_span,
            repository_span,
            if_exists_span,
            name_span,
            action,
            properties,
        };
        Ok(AstStmt::AlterImageRepository(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] STREAMLIT [IF NOT EXISTS] <name>
    ///   ROOT_LOCATION = '<path>' MAIN_FILE = '<file>' [<more props>]`.
    pub(crate) fn try_parse_create_streamlit(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_streamlit")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let or_replace_span = self.parse_optional_or_replace()?;
        let streamlit_span = expect_identifier_lexeme(self, "STREAMLIT")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties(self);
        let external_access_integrations_span =
            external_access_integrations_slot(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateStreamlit {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            streamlit_span,
            if_not_exists_span,
            name_span,
            properties,
            external_access_integrations_span,
        };
        Ok(AstStmt::CreateStreamlit(Box::new(ast)))
    }

    /// Parse `ALTER STREAMLIT [IF EXISTS] <name> { SET <props> | UNSET <props> }`.
    pub(crate) fn try_parse_alter_streamlit(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_streamlit")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let streamlit_span = expect_identifier_lexeme(self, "STREAMLIT")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        let mut properties = Vec::new();
        let mut external_access_integrations_span = None;

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            properties = walk_object_properties(self);
            external_access_integrations_span =
                external_access_integrations_slot(self, &properties);
            if let Some(last) = properties.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstStreamlitAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let unset_props = walk_object_properties(self);
            if let Some(last) = unset_props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstStreamlitAction::Unset
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET after streamlit name".to_string(),
                },
            ));
        };

        let ast = AstAlterStreamlit {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end,
            },
            alter_span,
            streamlit_span,
            if_exists_span,
            name_span,
            action,
            properties,
            external_access_integrations_span,
        };
        Ok(AstStmt::AlterStreamlit(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] SERVICE [IF NOT EXISTS] <name>
    ///   IN COMPUTE POOL <pool> { FROM SPECIFICATION <body> | FROM @<stage> … }
    ///   [<props>]` (Snowpark Container Services).
    pub(crate) fn try_parse_create_service(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_service")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let or_replace_span = self.parse_optional_or_replace()?;
        let service_span = expect_identifier_lexeme(self, "SERVICE")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Optional `IN COMPUTE POOL <pool>` (mandatory in Snowflake; the parser
        // is permissive and records it when present).
        let mut compute_pool_span = None;
        if self
            .peek_non_trivia()
            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("IN"))
        {
            self.advance().expect_invariant("IN consumed after peek");
            expect_identifier_lexeme(self, "COMPUTE")?;
            expect_identifier_lexeme(self, "POOL")?;
            let pool_name = self.parse_qualified_name_span()?;
            end = pool_name.end;
            compute_pool_span = Some(pool_name);
        }

        // Optional `FROM …` clause (inline `$$`/string spec body, or `@stage`).
        if self
            .peek_non_trivia()
            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("FROM"))
        {
            end = self.parse_service_from_clause()?;
        }

        // Trailing property bag. In the `FROM @stage SPECIFICATION_FILE=…` form
        // the stage path + SPECIFICATION_FILE property are consumed here too.
        let properties = walk_object_properties(self);
        let external_access_integrations_span =
            external_access_integrations_slot(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateService {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            service_span,
            if_not_exists_span,
            name_span,
            compute_pool_span,
            properties,
            external_access_integrations_span,
        };
        Ok(AstStmt::CreateService(Box::new(ast)))
    }

    /// Parse the `FROM …` clause of CREATE SERVICE. Consumes the FROM keyword
    /// and, for the inline `SPECIFICATION[_TEMPLATE]` form, the spec body — a
    /// `$$…$$` dollar-quoted block (re-using `parse_dollar_block_body`, which
    /// scans opaquely to the matching closer since the body is YAML, not SQL)
    /// or a `'…'` string. For the `FROM @<stage> SPECIFICATION_FILE = …` form
    /// only FROM is consumed; the stage path + property are left for the
    /// trailing property walk. Returns the end offset consumed.
    fn parse_service_from_clause(&mut self) -> ParseResult<u32> {
        let from_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;
        let mut end = from_tok.span.end;
        let next_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        if next_lex == "SPECIFICATION" || next_lex == "SPECIFICATION_TEMPLATE" {
            let spec_kw = self
                .advance()
                .expect_invariant("SPECIFICATION consumed after peek");
            end = spec_kw.span.end;
            let body_is_dollar = self
                .peek_non_trivia()
                .map(|t| crate::parser::core::is_dollar_quote_tag(t.lexeme(self.source)))
                .unwrap_or(false);
            let body_is_string = self
                .peek_non_trivia()
                .map(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::String)))
                .unwrap_or(false);
            if body_is_dollar {
                let opener = self
                    .advance()
                    .expect_invariant("dollar opener consumed after peek");
                let open_lo = opener.span.start as usize;
                let open_hi = opener.span.end as usize;
                let body_content_start = opener.span.end;
                let parsed = crate::parser::scripting::parse_dollar_block_body(
                    self,
                    open_lo,
                    open_hi,
                    body_content_start,
                );
                end = parsed.delimiter_end;
            } else if body_is_string {
                let s = self
                    .advance()
                    .expect_invariant("spec string consumed after peek");
                end = s.span.end;
            }
        }
        // else: `FROM @stage …` — leave the stage path for the property walk.
        Ok(end)
    }

    /// Parse `ALTER SERVICE [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | RESUME | SUSPEND }`.
    pub(crate) fn try_parse_alter_service(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_service")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let service_span = expect_identifier_lexeme(self, "SERVICE")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        let mut properties = Vec::new();
        let mut external_access_integrations_span = None;

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            properties = walk_object_properties(self);
            external_access_integrations_span =
                external_access_integrations_slot(self, &properties);
            if let Some(last) = properties.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstServiceAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let unset_props = walk_object_properties(self);
            if let Some(last) = unset_props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstServiceAction::Unset
        } else if action_lex == "RESUME" {
            let t = self
                .advance()
                .expect_invariant("RESUME consumed after peek");
            end = t.span.end;
            AstServiceAction::Resume
        } else if action_lex == "SUSPEND" {
            let t = self
                .advance()
                .expect_invariant("SUSPEND consumed after peek");
            end = t.span.end;
            AstServiceAction::Suspend
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET, UNSET, RESUME, or SUSPEND after service name"
                        .to_string(),
                },
            ));
        };

        let ast = AstAlterService {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end,
            },
            alter_span,
            service_span,
            if_exists_span,
            name_span,
            action,
            properties,
            external_access_integrations_span,
        };
        Ok(AstStmt::AlterService(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] NOTEBOOK [IF NOT EXISTS] <name>
    ///   [FROM '<path>'] [MAIN_FILE = '<file>'] [<more props>]`. The optional
    /// `FROM '<path>'` clause has no `$$` body, so it is absorbed by the
    /// property walk (no dedicated FROM handler needed).
    pub(crate) fn try_parse_create_notebook(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_notebook")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let or_replace_span = self.parse_optional_or_replace()?;
        let notebook_span = expect_identifier_lexeme(self, "NOTEBOOK")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties(self);
        let external_access_integrations_span =
            external_access_integrations_slot(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateNotebook {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            notebook_span,
            if_not_exists_span,
            name_span,
            properties,
            external_access_integrations_span,
        };
        Ok(AstStmt::CreateNotebook(Box::new(ast)))
    }

    /// Parse `ALTER NOTEBOOK [IF EXISTS] <name> { SET <props> | UNSET <props> }`.
    pub(crate) fn try_parse_alter_notebook(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_notebook")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let notebook_span = expect_identifier_lexeme(self, "NOTEBOOK")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        let mut properties = Vec::new();
        let mut external_access_integrations_span = None;

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            properties = walk_object_properties(self);
            external_access_integrations_span =
                external_access_integrations_slot(self, &properties);
            if let Some(last) = properties.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstNotebookAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let unset_props = walk_object_properties(self);
            if let Some(last) = unset_props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstNotebookAction::Unset
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET after notebook name".to_string(),
                },
            ));
        };

        let ast = AstAlterNotebook {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end,
            },
            alter_span,
            notebook_span,
            if_exists_span,
            name_span,
            action,
            properties,
            external_access_integrations_span,
        };
        Ok(AstStmt::AlterNotebook(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] SEMANTIC VIEW [IF NOT EXISTS] <name>
    ///   TABLES (...) [RELATIONSHIPS (...)] [FACTS (...)] [DIMENSIONS (...)]
    ///   [METRICS (...)] [trailing properties]`.
    ///
    /// The TABLES block is decomposed into the base-table access surface; the
    /// other model blocks are captured as opaque balanced-paren spans (presence
    /// is the recognition signal). Trailing properties (COMMENT, WITH
    /// EXTENSION, …) carry no governance signal and are absorbed to the
    /// statement terminator.
    pub(crate) fn try_parse_create_semantic_view(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_semantic_view")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace_span = self.parse_optional_or_replace()?;
        expect_identifier_lexeme(self, "SEMANTIC")?;
        expect_keyword_or_identifier(self, Keyword::View, "VIEW")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let mut tables = Vec::new();
        let mut relationships_span = None;
        let mut facts_span = None;
        let mut dimensions_span = None;
        let mut metrics_span = None;

        // Recognized model blocks, in any order.
        while let Some(lex) = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
        {
            match lex.as_str() {
                "TABLES" => {
                    self.advance()
                        .expect_invariant("TABLES consumed after peek");
                    let (parsed, block_end) = self.parse_semantic_view_tables()?;
                    tables = parsed;
                    end = block_end;
                }
                "RELATIONSHIPS" => {
                    self.advance()
                        .expect_invariant("RELATIONSHIPS consumed after peek");
                    if let Some(span) = self.consume_semantic_view_block()? {
                        end = span.end;
                        relationships_span = Some(span);
                    }
                }
                "FACTS" => {
                    self.advance().expect_invariant("FACTS consumed after peek");
                    if let Some(span) = self.consume_semantic_view_block()? {
                        end = span.end;
                        facts_span = Some(span);
                    }
                }
                "DIMENSIONS" => {
                    self.advance()
                        .expect_invariant("DIMENSIONS consumed after peek");
                    if let Some(span) = self.consume_semantic_view_block()? {
                        end = span.end;
                        dimensions_span = Some(span);
                    }
                }
                "METRICS" => {
                    self.advance()
                        .expect_invariant("METRICS consumed after peek");
                    if let Some(span) = self.consume_semantic_view_block()? {
                        end = span.end;
                        metrics_span = Some(span);
                    }
                }
                _ => break,
            }
        }

        // Trailing properties (COMMENT = '…', [WITH] EXTENSION (…)) carry no
        // governance signal — absorb opaquely to the statement terminator.
        let tail_end = skip_to_statement_terminator(self);
        if tail_end > end {
            end = tail_end;
        }

        let ast = AstCreateSemanticView {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            if_not_exists_span,
            name_span,
            tables,
            relationships_span,
            facts_span,
            dimensions_span,
            metrics_span,
        };
        Ok(AstStmt::CreateSemanticView(Box::new(ast)))
    }

    /// Parse a `TABLES (...)` block into the base-table access surface. The
    /// caller has consumed the `TABLES` keyword. Returns the entries and the
    /// end offset of the block's closing paren. Each entry is
    /// `<logical_alias> [AS <physical_table>] [trailing per-entry clauses]`;
    /// the physical table is the access surface (the alias itself when no AS).
    fn parse_semantic_view_tables(&mut self) -> ParseResult<(Vec<AstSemanticViewTable>, u32)> {
        let open = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(open.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                open.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ( after TABLES".to_string(),
                },
            ));
        }
        let mut end = open.span.end;
        let mut tables = Vec::new();
        // Paren depth inside the TABLES block; entry separators are commas at
        // depth 1, the block closes at the depth-1 `)`.
        let mut depth: u32 = 1;

        'entries: loop {
            // Entry start: stop on EOF or the block's closing paren.
            if self.peek_non_trivia().is_none() {
                break;
            }
            let is_close = matches!(
                self.peek_non_trivia(),
                Some(tok) if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen))
            );
            if is_close {
                let close = self
                    .advance()
                    .expect_invariant("RParen consumed after peek");
                end = close.span.end;
                break;
            }

            // <logical_alias> [AS <physical_table>]
            let alias_span = self.parse_qualified_name_span()?;
            let mut physical_span = alias_span;
            let is_as = self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("AS"))
                .unwrap_or(false);
            if is_as {
                self.advance().expect_invariant("AS consumed after peek");
                physical_span = self.parse_qualified_name_span()?;
            }
            end = physical_span.end;
            tables.push(AstSemanticViewTable {
                alias_span,
                physical_span,
            });

            // Skip the entry's trailing clauses (PRIMARY KEY, UNIQUE, WITH
            // SYNONYMS, COMMENT, …) to the next entry boundary or block close.
            loop {
                let (is_lparen, is_rparen, is_comma) = match self.peek_non_trivia() {
                    None => break 'entries,
                    Some(tok) => (
                        matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)),
                        matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)),
                        matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)),
                    ),
                };
                if is_comma && depth == 1 {
                    self.advance().expect_invariant(", consumed in entry skip");
                    continue 'entries;
                }
                if is_rparen {
                    let t = self.advance().expect_invariant(") consumed in entry skip");
                    end = t.span.end;
                    if depth == 1 {
                        break 'entries; // closed the TABLES block
                    }
                    depth -= 1;
                    continue;
                }
                if is_lparen {
                    depth += 1;
                }
                let t = self
                    .advance()
                    .expect_invariant("token consumed in entry skip");
                end = t.span.end;
            }
        }

        Ok((tables, end))
    }

    /// Consume an optional `(...)` block after a recognized model-block keyword
    /// (RELATIONSHIPS / FACTS / DIMENSIONS / METRICS), capturing it as one
    /// opaque balanced-paren span. Returns None when no `(` follows.
    fn consume_semantic_view_block(&mut self) -> ParseResult<Option<Span>> {
        let is_open = matches!(
            self.peek_non_trivia(),
            Some(tok) if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen))
        );
        if !is_open {
            return Ok(None);
        }
        Ok(Some(self.consume_balanced_parens()?))
    }

    /// Parse `ALTER SEMANTIC VIEW [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | RENAME TO <name> }`.
    pub(crate) fn try_parse_alter_semantic_view(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_semantic_view")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        expect_identifier_lexeme(self, "SEMANTIC")?;
        expect_keyword_or_identifier(self, Keyword::View, "VIEW")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            let props = walk_object_properties(self);
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstSemanticViewAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let props = walk_object_properties(self);
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstSemanticViewAction::Unset
        } else if action_lex == "RENAME" {
            self.advance()
                .expect_invariant("RENAME consumed after peek");
            // Optional TO.
            let is_to = self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("TO"))
                .unwrap_or(false);
            if is_to {
                self.advance().expect_invariant("TO consumed after peek");
            }
            let new_name = self.parse_qualified_name_span()?;
            end = new_name.end;
            AstSemanticViewAction::Rename
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET, UNSET, or RENAME after semantic view name".to_string(),
                },
            ));
        };

        let ast = AstAlterSemanticView {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterSemanticView(Box::new(ast)))
    }

    /// Parse `CREATE [OR REPLACE] CORTEX SEARCH SERVICE [IF NOT EXISTS] <name>
    ///   ON <col> [ATTRIBUTES ...] WAREHOUSE = ... TARGET_LAG = ...
    ///   [EMBEDDING_MODEL = ...] [COMMENT = ...] AS <query>`.
    ///
    /// The ON/ATTRIBUTES clauses and the property values are absorbed by the
    /// property walk (stopping at AS); the governable EMBEDDING_MODEL value is
    /// pulled out by name. The `AS <query>` body is consumed (captured as an
    /// opaque span) so the inner SELECT is not fragmented into a standalone
    /// statement.
    pub(crate) fn try_parse_create_cortex_search_service(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_cortex_search_service")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace_span = self.parse_optional_or_replace()?;
        expect_identifier_lexeme(self, "CORTEX")?;
        expect_identifier_lexeme(self, "SEARCH")?;
        expect_identifier_lexeme(self, "SERVICE")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties_until(self, Some("AS"));
        let embedding_model_span = embedding_model_slot(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        // `AS <query>` body — consume so the inner SELECT is not fragmented.
        let mut source_query_span = None;
        let is_as = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("AS"))
            .unwrap_or(false);
        if is_as {
            self.advance().expect_invariant("AS consumed after peek");
            let body_start = self.peek_non_trivia().map(|t| t.span.start).unwrap_or(end);
            let body_end = skip_to_statement_terminator(self);
            if body_end > body_start {
                source_query_span = Some(Span {
                    start: body_start,
                    end: body_end,
                });
            }
            end = end.max(body_end);
        }

        let ast = AstCreateCortexSearchService {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            if_not_exists_span,
            name_span,
            embedding_model_span,
            source_query_span,
        };
        Ok(AstStmt::CreateCortexSearchService(Box::new(ast)))
    }

    /// Parse `ALTER CORTEX SEARCH SERVICE [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | RESUME | SUSPEND }`.
    pub(crate) fn try_parse_alter_cortex_search_service(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_cortex_search_service")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        expect_identifier_lexeme(self, "CORTEX")?;
        expect_identifier_lexeme(self, "SEARCH")?;
        expect_identifier_lexeme(self, "SERVICE")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below (the fallthrough
        // returns an error), so no initializer is needed.
        let mut end;
        let mut embedding_model_span = None;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            let props = walk_object_properties(self);
            embedding_model_span = embedding_model_slot(self, &props);
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstCortexSearchServiceAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let props = walk_object_properties(self);
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstCortexSearchServiceAction::Unset
        } else if action_lex == "RESUME" {
            let t = self
                .advance()
                .expect_invariant("RESUME consumed after peek");
            end = t.span.end;
            AstCortexSearchServiceAction::Resume
        } else if action_lex == "SUSPEND" {
            let t = self
                .advance()
                .expect_invariant("SUSPEND consumed after peek");
            end = t.span.end;
            AstCortexSearchServiceAction::Suspend
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message:
                        "Expected SET, UNSET, RESUME, or SUSPEND after cortex search service name"
                            .to_string(),
                },
            ));
        };

        let ast = AstAlterCortexSearchService {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            if_exists_span,
            name_span,
            action,
            embedding_model_span,
        };
        Ok(AstStmt::AlterCortexSearchService(Box::new(ast)))
    }

    /// Parse `CREATE APPLICATION <name>
    ///   [FROM { APPLICATION PACKAGE <pkg> | LISTING <listing> }]
    ///   [USING '<path>'] [DEBUG_MODE = ...] [COMMENT = ...]` (Native Apps).
    pub(crate) fn try_parse_create_application(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_application")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace_span = self.parse_optional_or_replace()?;
        expect_identifier_lexeme(self, "APPLICATION")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // FROM { APPLICATION PACKAGE <pkg> | LISTING <listing> }
        let mut from_listing = false;
        let mut source_name_span = None;
        let is_from = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("FROM"))
            .unwrap_or(false);
        if is_from {
            self.advance().expect_invariant("FROM consumed after peek");
            let next_lex = self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).to_ascii_uppercase())
                .unwrap_or_default();
            if next_lex == "APPLICATION" {
                self.advance()
                    .expect_invariant("APPLICATION consumed after peek");
                let is_pkg = self
                    .peek_non_trivia()
                    .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("PACKAGE"))
                    .unwrap_or(false);
                if is_pkg {
                    self.advance()
                        .expect_invariant("PACKAGE consumed after peek");
                }
                let n = self.parse_qualified_name_span()?;
                end = n.end;
                source_name_span = Some(n);
            } else if next_lex == "LISTING" {
                self.advance()
                    .expect_invariant("LISTING consumed after peek");
                from_listing = true;
                let n = self.parse_qualified_name_span()?;
                end = n.end;
                source_name_span = Some(n);
            }
            // else: unknown FROM target — leave for the property walk
        }

        let properties = walk_object_properties(self);
        let debug_mode_span = property_value_by_name(self, &properties, "DEBUG_MODE");
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateApplication {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            if_not_exists_span,
            name_span,
            from_listing,
            source_name_span,
            debug_mode_span,
        };
        Ok(AstStmt::CreateApplication(Box::new(ast)))
    }

    /// Parse `ALTER APPLICATION [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | UPGRADE ... | ... }` (Native Apps).
    pub(crate) fn try_parse_alter_application(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_application")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        expect_identifier_lexeme(self, "APPLICATION")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        let (action, debug_mode_span, end) = self.parse_application_alter_tail("DEBUG_MODE");

        let ast = AstAlterApplication {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            if_exists_span,
            name_span,
            action,
            debug_mode_span,
        };
        Ok(AstStmt::AlterApplication(Box::new(ast)))
    }

    /// Parse `CREATE APPLICATION PACKAGE [IF NOT EXISTS] <name>
    ///   [COMMENT = ...] [DISTRIBUTION = ...] ...` (Native Apps).
    pub(crate) fn try_parse_create_application_package(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_application_package")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace_span = self.parse_optional_or_replace()?;
        expect_identifier_lexeme(self, "APPLICATION")?;
        expect_identifier_lexeme(self, "PACKAGE")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties(self);
        let distribution_span = property_value_by_name(self, &properties, "DISTRIBUTION");
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateApplicationPackage {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            if_not_exists_span,
            name_span,
            distribution_span,
        };
        Ok(AstStmt::CreateApplicationPackage(Box::new(ast)))
    }

    /// Parse `ALTER APPLICATION PACKAGE [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | ADD VERSION ... | ... }` (Native Apps).
    pub(crate) fn try_parse_alter_application_package(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_application_package")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        expect_identifier_lexeme(self, "APPLICATION")?;
        expect_identifier_lexeme(self, "PACKAGE")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        let (action, distribution_span, end) = self.parse_application_alter_tail("DISTRIBUTION");

        let ast = AstAlterApplicationPackage {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            if_exists_span,
            name_span,
            action,
            distribution_span,
        };
        Ok(AstStmt::AlterApplicationPackage(Box::new(ast)))
    }

    /// Parse the action tail of an ALTER APPLICATION[ PACKAGE]: returns the
    /// action, the value span of the named property (SET only), and the end
    /// offset. Unknown forms (UPGRADE, ADD VERSION, …) are consumed to the
    /// statement terminator as `Other` so they are recognized, not fragmented.
    fn parse_application_alter_tail(
        &mut self,
        value_prop_name: &str,
    ) -> (AstApplicationAction, Option<Span>, u32) {
        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            let mut end = set_tok.span.end;
            let props = walk_object_properties(self);
            let value = property_value_by_name(self, &props, value_prop_name);
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            (AstApplicationAction::Set, value, end)
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            let mut end = unset_tok.span.end;
            let props = walk_object_properties(self);
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            (AstApplicationAction::Unset, None, end)
        } else {
            // UPGRADE / ADD VERSION / SET DEFAULT RELEASE DIRECTIVE / … —
            // consume to the terminator; recognized as the alter family.
            let end = skip_to_statement_terminator(self);
            (AstApplicationAction::Other, None, end)
        }
    }

    /// Parse `CREATE [OR REPLACE] [EXTERNAL] LISTING [IF NOT EXISTS] <name>
    ///   [{SHARE <share> | APPLICATION PACKAGE <pkg>}] [AS <manifest>]
    ///   [PUBLISH = ...] [REVIEW = ...] [COMMENT = ...]` (Snowflake Marketplace).
    ///
    /// Reachable both from the bare `CREATE LISTING` dispatch and the
    /// `CREATE EXTERNAL <obj>` disambiguation; handles the optional EXTERNAL
    /// modifier itself.
    pub(crate) fn try_parse_create_listing(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_listing")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace_span = self.parse_optional_or_replace()?;
        let is_external = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("EXTERNAL"))
            .unwrap_or(false);
        if is_external {
            self.advance()
                .expect_invariant("EXTERNAL consumed after peek");
        }
        expect_identifier_lexeme(self, "LISTING")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Optional shared object: SHARE <share> | APPLICATION PACKAGE <pkg>.
        let mut shared_object_span = None;
        let next_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();
        if next_lex == "SHARE" {
            self.advance().expect_invariant("SHARE consumed after peek");
            let n = self.parse_qualified_name_span()?;
            end = n.end;
            shared_object_span = Some(n);
        } else if next_lex == "APPLICATION" {
            self.advance()
                .expect_invariant("APPLICATION consumed after peek");
            let is_pkg = self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("PACKAGE"))
                .unwrap_or(false);
            if is_pkg {
                self.advance()
                    .expect_invariant("PACKAGE consumed after peek");
            }
            let n = self.parse_qualified_name_span()?;
            end = n.end;
            shared_object_span = Some(n);
        }

        // Optional AS <manifest> ('…' or $$…$$) — consumed so a $$ YAML body
        // does not fragment.
        end = self.consume_as_manifest(end);

        // Property bag: PUBLISH / REVIEW / COMMENT.
        let properties = walk_object_properties(self);
        let publish_span = property_value_by_name(self, &properties, "PUBLISH");
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateListing {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            if_not_exists_span,
            name_span,
            is_external,
            shared_object_span,
            publish_span,
        };
        Ok(AstStmt::CreateListing(Box::new(ast)))
    }

    /// Parse `ALTER LISTING [IF EXISTS] <name>
    ///   { SET <props> | UNSET <props> | PUBLISH | UNPUBLISH | AS <manifest> | ... }`.
    pub(crate) fn try_parse_alter_listing(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_listing")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        expect_identifier_lexeme(self, "LISTING")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;
        // `end` is assigned by every action branch below.
        let mut end;
        let mut publish_span = None;

        let action_lex = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_ascii_uppercase())
            .unwrap_or_default();

        let action = if action_lex == "SET" {
            let set_tok = self.advance().expect_invariant("SET consumed after peek");
            end = set_tok.span.end;
            let props = walk_object_properties(self);
            publish_span = property_value_by_name(self, &props, "PUBLISH");
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstListingAction::Set
        } else if action_lex == "UNSET" {
            let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
            end = unset_tok.span.end;
            let props = walk_object_properties(self);
            if let Some(last) = props.last() {
                end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
            }
            AstListingAction::Unset
        } else {
            // PUBLISH / UNPUBLISH / RENAME / AS <manifest> / … — consume an
            // optional AS manifest body (so a $$ body does not fragment), then
            // any remainder to the terminator.
            end = self.consume_as_manifest(name_span.end);
            let tail = skip_to_statement_terminator(self);
            end = end.max(tail);
            AstListingAction::Other
        };

        let ast = AstAlterListing {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            if_exists_span,
            name_span,
            action,
            publish_span,
        };
        Ok(AstStmt::AlterListing(Box::new(ast)))
    }

    /// If the next non-trivia token is `AS`, consume it and the following
    /// manifest body (`$$…$$` dollar block or `'…'` string), returning the end
    /// offset. Returns `current_end` unchanged when there is no AS clause.
    fn consume_as_manifest(&mut self, current_end: u32) -> u32 {
        let is_as = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("AS"))
            .unwrap_or(false);
        if !is_as {
            return current_end;
        }
        self.advance().expect_invariant("AS consumed after peek");
        let body_is_dollar = self
            .peek_non_trivia()
            .map(|t| crate::parser::core::is_dollar_quote_tag(t.lexeme(self.source)))
            .unwrap_or(false);
        let body_is_string = self
            .peek_non_trivia()
            .map(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::String)))
            .unwrap_or(false);
        if body_is_dollar {
            let opener = self
                .advance()
                .expect_invariant("dollar opener consumed after peek");
            let open_lo = opener.span.start as usize;
            let open_hi = opener.span.end as usize;
            let body_content_start = opener.span.end;
            let parsed = crate::parser::scripting::parse_dollar_block_body(
                self,
                open_lo,
                open_hi,
                body_content_start,
            );
            parsed.delimiter_end
        } else if body_is_string {
            let s = self
                .advance()
                .expect_invariant("manifest string consumed after peek");
            s.span.end
        } else {
            current_end
        }
    }

    /// Parse `CREATE MANAGED ACCOUNT <name> ADMIN_NAME = ... ADMIN_PASSWORD = ...
    ///   TYPE = READER [COMMENT = '...']` (Snowflake reader account).
    ///
    /// The credential properties are consumed by the property walk but only the
    /// TYPE value is extracted; the admin password is never captured.
    pub(crate) fn try_parse_create_managed_account(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_managed_account")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace_span = self.parse_optional_or_replace()?;
        expect_identifier_lexeme(self, "MANAGED")?;
        expect_identifier_lexeme(self, "ACCOUNT")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties(self);
        let account_type_span = property_value_by_name(self, &properties, "TYPE");
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateManagedAccount {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            if_not_exists_span,
            name_span,
            account_type_span,
        };
        Ok(AstStmt::CreateManagedAccount(Box::new(ast)))
    }

    /// Parse `CREATE ACCOUNT <name> ADMIN_NAME = ... { ADMIN_PASSWORD | … }
    ///   EDITION = ... [...]` (Snowflake org-level account provisioning).
    ///
    /// Recognition only; the credential properties are consumed but never
    /// captured.
    pub(crate) fn try_parse_create_account(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_account")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace_span = self.parse_optional_or_replace()?;
        expect_identifier_lexeme(self, "ACCOUNT")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties(self);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let ast = AstCreateAccount {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace_span,
            if_not_exists_span,
            name_span,
        };
        Ok(AstStmt::CreateAccount(Box::new(ast)))
    }

    /// Parse a Snowflake client file command: `PUT file://<local> @<stage>`,
    /// `GET @<stage> file://<local>`, `REMOVE @<stage>` (RM), `LIST @<stage>`
    /// (LS). The caller has verified the leading verb. The verb determines the
    /// operation; the `@<stage>` reference is captured (the first contiguous
    /// run of tokens beginning with `@`); the remainder is consumed to the
    /// terminator.
    pub(crate) fn try_parse_stage_file_command(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("stage_file_command")?;

        let verb_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PUT/GET/REMOVE/LIST".to_string()])?;
        let start = verb_tok.span.start;
        let mut end = verb_tok.span.end;
        let kind = match verb_tok.lexeme(self.source).to_ascii_uppercase().as_str() {
            "PUT" => AstStageFileCommandKind::Put,
            "GET" => AstStageFileCommandKind::Get,
            "REMOVE" | "RM" => AstStageFileCommandKind::Remove,
            "LIST" | "LS" => AstStageFileCommandKind::List,
            _ => {
                return Err(ParseError::new(
                    verb_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected PUT, GET, REMOVE, or LIST".to_string(),
                    },
                ));
            }
        };

        // Consume the rest of the statement, capturing the `@<stage>` reference
        // (the first run of tokens beginning with `@`, extended while adjacent).
        let mut stage_ref_span: Option<Span> = None;
        loop {
            let (is_terminator, tok_start, tok_end, starts_with_at) = match self.peek_non_trivia() {
                None => break,
                Some(tok) => (
                    matches!(
                        tok.kind,
                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                    ),
                    tok.span.start,
                    tok.span.end,
                    tok.lexeme(self.source).starts_with('@'),
                ),
            };
            if is_terminator {
                break;
            }
            match stage_ref_span {
                None if starts_with_at => {
                    stage_ref_span = Some(Span {
                        start: tok_start,
                        end: tok_end,
                    });
                }
                Some(sp) if sp.end == tok_start => {
                    // Adjacent (no whitespace) — extend the stage path.
                    stage_ref_span = Some(Span {
                        start: sp.start,
                        end: tok_end,
                    });
                }
                _ => {}
            }
            end = tok_end;
            self.advance()
                .expect_invariant("token consumed in stage file command");
        }

        let ast = AstStageFileCommand {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            kind,
            stage_ref_span,
        };
        Ok(AstStmt::StageFileCommand(Box::new(ast)))
    }

    /// Parse the `TRIGGERS ON <pct> PERCENT DO <action> [...]` clause.
    /// Returns empty when the next token is not `TRIGGERS`.
    fn parse_resource_monitor_triggers(&mut self) -> Vec<AstResourceMonitorTrigger> {
        let is_triggers = matches!(
            self.peek_non_trivia(),
            Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("TRIGGERS")
        );
        if !is_triggers {
            return Vec::new();
        }
        self.advance()
            .expect_invariant("TRIGGERS consumed after peek");

        let mut triggers = Vec::new();
        loop {
            // Tolerate a repeated `TRIGGERS` keyword introducing the next
            // clause (some authors write `TRIGGERS ON … TRIGGERS ON …`).
            if matches!(
                self.peek_non_trivia(),
                Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("TRIGGERS")
            ) {
                self.advance()
                    .expect_invariant("TRIGGERS consumed after peek");
                continue;
            }
            let is_on = matches!(
                self.peek_non_trivia(),
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::On))
                    || tok.lexeme(self.source).eq_ignore_ascii_case("ON")
            );
            if !is_on {
                break;
            }
            let on_tok = self.advance().expect_invariant("ON consumed after peek");
            let on_span = on_tok.span;
            let Some(threshold_tok) = self.advance() else {
                break;
            };
            let threshold_span = threshold_tok.span;
            let Some(percent_tok) = self.advance() else {
                break;
            };
            let percent_span = percent_tok.span;
            let Some(do_tok) = self.advance() else {
                break;
            };
            let do_span = do_tok.span;
            let Some(action_tok) = self.advance() else {
                break;
            };
            let action_span = action_tok.span;
            triggers.push(AstResourceMonitorTrigger {
                node_id: self.id_gen.next(),
                span: Span {
                    start: on_span.start,
                    end: action_span.end,
                },
                on_span,
                threshold_span,
                percent_span,
                do_span,
                action_span,
            });
        }
        triggers
    }

    /// Parse `CREATE [OR REPLACE] ALERT [IF NOT EXISTS] <name>
    ///   [WAREHOUSE = <wh>] SCHEDULE = '<sched>' [COMMENT = '<text>']
    ///   IF (EXISTS ( <query> )) THEN <action>`.
    ///
    /// The condition and action SQL are recursively consumed so they are
    /// recognized as part of the alert rather than fragmenting into
    /// mis-analyzed standalone statements (mirrors CREATE TASK's body).
    pub(crate) fn try_parse_create_alert(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_alert")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let alert_span = expect_identifier_lexeme(self, "ALERT")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let properties = walk_object_properties_until(self, Some("IF"));
        let (warehouse_span, schedule_span, comment_span) = alert_property_slots(self, &properties);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        // IF ( EXISTS ( <query> ) )
        let mut if_span: Option<Span> = None;
        let mut condition_span: Option<Span> = None;
        if matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::If))
        ) {
            let if_tok = self.advance().expect_invariant("IF consumed after peek");
            if_span = Some(if_tok.span);
            end = if_tok.span.end;
            if matches!(
                self.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen))
            ) {
                let cspan = self.consume_balanced_parens()?;
                condition_span = Some(cspan);
                end = cspan.end;
            }
        }

        // THEN <action_statement>
        let mut then_span: Option<Span> = None;
        let mut action: Option<Result<Box<AstStmt>, Span>> = None;
        if matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Then))
        ) {
            let then_tok = self.advance().expect_invariant("THEN consumed after peek");
            then_span = Some(then_tok.span);
            // `end` is set by both match arms below.
            match self.parse_statement() {
                Ok(stmt) => {
                    end = stmt.span().end;
                    action = Some(Ok(Box::new(stmt)));
                }
                Err(_) => {
                    let body_start = self.current_span().start;
                    let body_end = skip_to_statement_terminator(self);
                    action = Some(Err(Span {
                        start: body_start,
                        end: body_end,
                    }));
                    end = body_end;
                }
            }
        }

        let ast = AstCreateAlert {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            alert_span,
            if_not_exists_span,
            name_span,
            properties,
            warehouse_span,
            schedule_span,
            comment_span,
            if_span,
            condition_span,
            then_span,
            action,
        };
        Ok(AstStmt::CreateAlert(Box::new(ast)))
    }

    /// Parse `ALTER ALERT [IF EXISTS] <name>
    ///   { RESUME | SUSPEND | SET <props> | UNSET <props>
    ///   | MODIFY CONDITION EXISTS (…) | MODIFY ACTION <statement> }`.
    pub(crate) fn try_parse_alter_alert(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_alert")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let alert_span = expect_identifier_lexeme(self, "ALERT")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let action_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["alert action".to_string()])?;
        let action_start = action_tok.span.start;

        let kind = if action_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("RESUME")
        {
            let t = self
                .advance()
                .expect_invariant("RESUME consumed after lexeme check");
            AstAlterAlertActionKind::Resume {
                resume_span: t.span,
            }
        } else if action_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("SUSPEND")
        {
            let t = self
                .advance()
                .expect_invariant("SUSPEND consumed after lexeme check");
            AstAlterAlertActionKind::Suspend {
                suspend_span: t.span,
            }
        } else if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            let set_tok = self.advance().expect_invariant("SET consumed after match");
            let set_span = set_tok.span;
            let properties = walk_object_properties_until(self, None);
            AstAlterAlertActionKind::Set {
                set_span,
                properties,
            }
        } else if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Unset)) {
            let unset_tok = self
                .advance()
                .expect_invariant("UNSET consumed after match");
            let unset_span = unset_tok.span;
            let mut property_name_spans: Vec<Span> = Vec::new();
            while let Some(tok) = self.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                ) {
                    break;
                }
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    continue;
                }
                let name_tok = self
                    .advance()
                    .expect_invariant("UNSET property name consumed after peek");
                property_name_spans.push(name_tok.span);
            }
            AstAlterAlertActionKind::Unset {
                unset_span,
                property_name_spans,
            }
        } else if action_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("MODIFY")
        {
            let modify_tok = self
                .advance()
                .expect_invariant("MODIFY consumed after lexeme check");
            let modify_span = modify_tok.span;
            let sub = self
                .peek_non_trivia()
                .ok_or_eof(self.current_span(), vec!["CONDITION or ACTION".to_string()])?;
            if sub.lexeme(self.source).eq_ignore_ascii_case("CONDITION") {
                self.advance()
                    .expect_invariant("CONDITION consumed after peek");
                let cstart = self
                    .peek_non_trivia()
                    .map(|t| t.span.start)
                    .unwrap_or(modify_span.end);
                let cend = skip_to_statement_terminator(self);
                AstAlterAlertActionKind::ModifyCondition {
                    modify_span,
                    condition_span: Span {
                        start: cstart,
                        end: cend,
                    },
                }
            } else if sub.lexeme(self.source).eq_ignore_ascii_case("ACTION") {
                self.advance()
                    .expect_invariant("ACTION consumed after peek");
                let body_start = self
                    .peek_non_trivia()
                    .map(|t| t.span.start)
                    .unwrap_or(modify_span.end);
                let (body, body_end) = match self.parse_statement() {
                    Ok(stmt) => {
                        let e = stmt.span().end;
                        (Ok(Box::new(stmt)), e)
                    }
                    Err(_) => {
                        let e = skip_to_statement_terminator(self);
                        (
                            Err(Span {
                                start: body_start,
                                end: e,
                            }),
                            e,
                        )
                    }
                };
                AstAlterAlertActionKind::ModifyAction {
                    modify_span,
                    action_span: Span {
                        start: body_start,
                        end: body_end,
                    },
                    body,
                }
            } else {
                return Err(ParseError::new(
                    sub.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected CONDITION or ACTION after MODIFY in ALTER ALERT"
                            .to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                action_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected RESUME, SUSPEND, SET, UNSET, or MODIFY in ALTER ALERT"
                        .to_string(),
                },
            ));
        };

        let action_end = match &kind {
            AstAlterAlertActionKind::Resume { resume_span } => resume_span.end,
            AstAlterAlertActionKind::Suspend { suspend_span } => suspend_span.end,
            AstAlterAlertActionKind::Set {
                properties,
                set_span,
            } => properties
                .last()
                .map(|p| p.value_span.map(|v| v.end).unwrap_or(p.name_span.end))
                .unwrap_or(set_span.end),
            AstAlterAlertActionKind::Unset {
                property_name_spans,
                unset_span,
            } => property_name_spans
                .last()
                .map(|s| s.end)
                .unwrap_or(unset_span.end),
            AstAlterAlertActionKind::ModifyCondition { condition_span, .. } => condition_span.end,
            AstAlterAlertActionKind::ModifyAction { action_span, .. } => action_span.end,
        };

        let action = AstAlterAlertAction {
            node_id: self.id_gen.next(),
            span: Span {
                start: action_start,
                end: action_end,
            },
            kind,
        };

        let ast = AstAlterAlert {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end: action.span.end,
            },
            alter_span,
            alert_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterAlert(Box::new(ast)))
    }

    /// Parse `CREATE {REPLICATION|FAILOVER} GROUP [IF NOT EXISTS] <name> …`.
    /// One entry for both group types; the group-type identifier is read
    /// here and carried on the AST.
    pub(crate) fn try_parse_create_replication_failover_group(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_replication_failover_group")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let or_replace_span = self.parse_optional_or_replace()?;

        // REPLICATION or FAILOVER (Identifier)
        let group_type_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["REPLICATION or FAILOVER".to_string()],
        )?;
        let group_type_span = group_type_tok.span;
        let group_keyword_span = expect_keyword_or_identifier(self, Keyword::Group, "GROUP")?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let mut replica_source_span: Option<Span> = None;
        let mut object_types_span: Option<Span> = None;
        let mut allowed_databases_span: Option<Span> = None;
        let mut allowed_shares_span: Option<Span> = None;
        let mut allowed_accounts_span: Option<Span> = None;
        let mut replication_schedule_span: Option<Span> = None;

        // Secondary form: AS REPLICA OF <source>
        if matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::As))
        ) {
            self.advance().expect_invariant("AS consumed after peek");
            // REPLICA
            if let Some(t) = self.peek_non_trivia() {
                if t.lexeme(self.source).eq_ignore_ascii_case("REPLICA") {
                    self.advance()
                        .expect_invariant("REPLICA consumed after peek");
                }
            }
            // OF
            if let Some(t) = self.peek_non_trivia() {
                if matches!(t.kind, TokenKind::Keyword(Keyword::Of))
                    || t.lexeme(self.source).eq_ignore_ascii_case("OF")
                {
                    self.advance().expect_invariant("OF consumed after peek");
                }
            }
            let src = self.parse_qualified_name_span()?;
            replica_source_span = Some(src);
            end = src.end;
        } else {
            // Primary form: scan known `NAME = <list>` properties.
            while let Some(tok) = self.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                ) {
                    break;
                }
                let lex = tok.lexeme(self.source).to_ascii_uppercase();
                // Value-less / non-egress clauses we consume but don't track.
                if lex == "IGNORE" || lex == "WITH" || lex == "TAG" {
                    let t = self
                        .advance()
                        .expect_invariant("clause token consumed after peek");
                    end = t.span.end;
                    continue;
                }
                if is_repl_group_property(&lex) && self.repl_group_name_is_assignment() {
                    self.advance()
                        .expect_invariant("property name consumed after peek");
                    self.advance().expect_invariant("= consumed after peek");
                    let value_span = self.scan_repl_group_value();
                    end = value_span.end;
                    match lex.as_str() {
                        "OBJECT_TYPES" => object_types_span = Some(value_span),
                        "ALLOWED_DATABASES" => allowed_databases_span = Some(value_span),
                        "ALLOWED_SHARES" => allowed_shares_span = Some(value_span),
                        "ALLOWED_ACCOUNTS" => allowed_accounts_span = Some(value_span),
                        "REPLICATION_SCHEDULE" => replication_schedule_span = Some(value_span),
                        _ => {}
                    }
                } else {
                    let t = self.advance().expect_invariant("token consumed after peek");
                    end = t.span.end;
                }
            }
        }

        let ast = AstCreateReplicationFailoverGroup {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end,
            },
            create_span,
            or_replace_span,
            group_type_span,
            group_keyword_span,
            if_not_exists_span,
            name_span,
            replica_source_span,
            object_types_span,
            allowed_databases_span,
            allowed_shares_span,
            allowed_accounts_span,
            replication_schedule_span,
        };
        Ok(AstStmt::CreateReplicationFailoverGroup(Box::new(ast)))
    }

    /// Scan a replication/failover-group property value (comma-separated list
    /// or quoted string). The value ends at the next known property name
    /// followed by `=`, a value-less clause keyword (IGNORE / WITH / AS), or
    /// the statement terminator. Cursor starts at the first value token.
    fn scan_repl_group_value(&mut self) -> Span {
        let start = self
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(self.current_span().start);
        let mut end = start;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let lex = tok.lexeme(self.source).to_ascii_uppercase();
            if lex == "IGNORE"
                || lex == "WITH"
                || matches!(tok.kind, TokenKind::Keyword(Keyword::As))
            {
                break;
            }
            if is_repl_group_property(&lex) && self.repl_group_name_is_assignment() {
                break;
            }
            let t = self
                .advance()
                .expect_invariant("value token consumed after peek");
            end = t.span.end;
        }
        Span { start, end }
    }

    /// True when the currently-peeked token (a candidate property name) is
    /// immediately followed by `=`. Saves and restores the cursor.
    fn repl_group_name_is_assignment(&mut self) -> bool {
        let saved = self.idx;
        if self.advance().is_none() {
            self.idx = saved;
            return false;
        }
        let is_eq = matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq))
        );
        self.idx = saved;
        is_eq
    }

    /// Parse `ALTER REPLICATION GROUP [IF EXISTS] <name> <action>`.
    pub(crate) fn try_parse_alter_replication_group(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_replication_group")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let replication_span = expect_identifier_lexeme(self, "REPLICATION")?;
        let group_span = expect_keyword_or_identifier(self, Keyword::Group, "GROUP")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let action = parse_replication_failover_group_action(self)?;

        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let ast = AstAlterReplicationGroup {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            replication_span,
            group_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterReplicationGroup(Box::new(ast)))
    }

    /// Parse `ALTER FAILOVER GROUP [IF EXISTS] <name> <action>`.
    pub(crate) fn try_parse_alter_failover_group(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_failover_group")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let failover_span = expect_identifier_lexeme(self, "FAILOVER")?;
        let group_span = expect_keyword_or_identifier(self, Keyword::Group, "GROUP")?;
        let if_exists_span = parse_optional_if_exists(self)?;
        let name_span = self.parse_qualified_name_span()?;

        let action = parse_replication_failover_group_action(self)?;

        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let ast = AstAlterFailoverGroup {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            failover_span,
            group_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterFailoverGroup(Box::new(ast)))
    }
}

// ─── ALTER SHARE action ───

/// Return `(value, span)` when `tok` is a boolean literal (TRUE/FALSE).
fn bool_literal(tok: &Token, source: &str) -> Option<(bool, Span)> {
    if matches!(tok.kind, TokenKind::Literal(LiteralKind::Boolean)) {
        Some((tok.lexeme(source).eq_ignore_ascii_case("TRUE"), tok.span))
    } else {
        None
    }
}

fn parse_alter_datashare_action(parser: &mut Parser<'_>) -> ParseResult<AstAlterDatashareAction> {
    let tok = parser.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            parser.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected ADD / REMOVE / SET after datashare name".to_string(),
            },
        )
    })?;
    let action_start = tok.span.start;
    let lexeme_upper = tok.lexeme(parser.source).to_ascii_uppercase();

    match lexeme_upper.as_str() {
        "ADD" => parse_datashare_add_remove(parser, true, action_start),
        "REMOVE" => parse_datashare_add_remove(parser, false, action_start),
        "SET" => parse_datashare_set(parser, action_start),
        _ => {
            let end = consume_until_semi_or_eof(parser, action_start);
            let body_span = Span {
                start: action_start,
                end,
            };
            Ok(AstAlterDatashareAction {
                node_id: parser.id_gen.next(),
                span: body_span,
                kind: AstAlterDatashareActionKind::Unknown(AstUnknownClause {
                    node_id: parser.id_gen.next(),
                    introducer: None,
                    span: body_span,
                    kind: UnknownKind::AlterAction,
                }),
            })
        }
    }
}

fn parse_datashare_add_remove(
    parser: &mut Parser<'_>,
    is_add: bool,
    action_start: u32,
) -> ParseResult<AstAlterDatashareAction> {
    let op_tok = parser
        .advance()
        .expect_invariant("ADD/REMOVE consumed after lexeme check");
    let op_span = op_tok.span;

    // Object kind: TABLE (Keyword or lexeme) | SCHEMA (lexeme).
    let kind_tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec!["TABLE or SCHEMA".to_string()])?;
    let object_kind_span = kind_tok.span;
    let object_kind = if matches!(kind_tok.kind, TokenKind::Keyword(Keyword::Table))
        || kind_tok.lexeme(parser.source).eq_ignore_ascii_case("TABLE")
    {
        AstDatashareObjectKind::Table
    } else if kind_tok
        .lexeme(parser.source)
        .eq_ignore_ascii_case("SCHEMA")
    {
        AstDatashareObjectKind::Schema
    } else {
        return Err(ParseError::new(
            kind_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected TABLE or SCHEMA after ADD/REMOVE".to_string(),
            },
        ));
    };

    let name_span = parser.parse_qualified_name_span()?;
    let end = consume_until_semi_or_eof(parser, name_span.end);
    let span = Span {
        start: action_start,
        end,
    };
    let kind = if is_add {
        AstAlterDatashareActionKind::AddObject {
            add_span: op_span,
            object_kind,
            object_kind_span,
            name_span,
        }
    } else {
        AstAlterDatashareActionKind::RemoveObject {
            remove_span: op_span,
            object_kind,
            object_kind_span,
            name_span,
        }
    };
    Ok(AstAlterDatashareAction {
        node_id: parser.id_gen.next(),
        span,
        kind,
    })
}

fn parse_datashare_set(
    parser: &mut Parser<'_>,
    action_start: u32,
) -> ParseResult<AstAlterDatashareAction> {
    let set_tok = parser
        .advance()
        .expect_invariant("SET consumed after lexeme check");
    let set_span = set_tok.span;

    // Generic SET fallback used when the property/value shape is unrecognized.
    let generic = |parser: &mut Parser<'_>, from: u32| {
        let end = consume_until_semi_or_eof(parser, from);
        AstAlterDatashareAction {
            node_id: parser.id_gen.next(),
            span: Span {
                start: action_start,
                end,
            },
            kind: AstAlterDatashareActionKind::SetProperty {
                set_span,
                properties_span: Span {
                    start: set_span.end,
                    end,
                },
            },
        }
    };

    let prop = match parser.peek_non_trivia() {
        Some(p) => p,
        None => return Ok(generic(parser, set_span.end)),
    };
    let prop_upper = prop.lexeme(parser.source).to_ascii_uppercase();
    let is_typed = matches!(prop.kind, TokenKind::Identifier { .. })
        && (prop_upper == "PUBLICACCESSIBLE" || prop_upper == "INCLUDENEW");
    if !is_typed {
        let prop_start = prop.span.start;
        return Ok(generic(parser, prop_start));
    }
    let property_span = prop.span;
    parser.advance(); // property
    let _eq = parse_optional_eq(parser);

    let (value, value_span) = match parser
        .peek_non_trivia()
        .and_then(|v| bool_literal(v, parser.source))
    {
        Some((b, sp)) => {
            parser.advance();
            (b, sp)
        }
        None => return Ok(generic(parser, set_span.end)),
    };

    if prop_upper == "PUBLICACCESSIBLE" {
        let end = consume_until_semi_or_eof(parser, value_span.end);
        return Ok(AstAlterDatashareAction {
            node_id: parser.id_gen.next(),
            span: Span {
                start: action_start,
                end,
            },
            kind: AstAlterDatashareActionKind::SetPublicAccessible {
                set_span,
                property_span,
                value_span,
                value,
            },
        });
    }

    // INCLUDENEW [=] TRUE|FALSE FOR SCHEMA <schema>
    let mut schema_span: Option<Span> = None;
    if let Some(for_tok) = parser.peek_non_trivia() {
        if matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
            parser.advance(); // FOR
            if let Some(s) = parser.peek_non_trivia() {
                if matches!(s.kind, TokenKind::Identifier { .. })
                    && s.lexeme(parser.source).eq_ignore_ascii_case("SCHEMA")
                {
                    parser.advance(); // SCHEMA
                    if let Ok(sp) = parser.parse_qualified_name_span() {
                        schema_span = Some(sp);
                    }
                }
            }
        }
    }
    let span_end = schema_span.map(|s| s.end).unwrap_or(value_span.end);
    let end = consume_until_semi_or_eof(parser, span_end);
    Ok(AstAlterDatashareAction {
        node_id: parser.id_gen.next(),
        span: Span {
            start: action_start,
            end,
        },
        kind: AstAlterDatashareActionKind::SetIncludeNew {
            set_span,
            property_span,
            value_span,
            value,
            schema_span,
        },
    })
}

fn parse_alter_share_action(parser: &mut Parser<'_>) -> ParseResult<AstAlterShareAction> {
    let tok = parser.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            parser.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected ADD / REMOVE / SET / UNSET after share name".to_string(),
            },
        )
    })?;
    let action_start = tok.span.start;
    let lexeme_upper = tok.lexeme(parser.source).to_ascii_uppercase();

    match lexeme_upper.as_str() {
        "ADD" => parse_share_add_or_remove_set_accounts(parser, AddRemoveSet::Add, action_start),
        "REMOVE" => {
            parse_share_add_or_remove_set_accounts(parser, AddRemoveSet::Remove, action_start)
        }
        "SET" => {
            // SET ACCOUNTS = … OR SET <property> = <value> …
            let saved = parser.idx;
            let set_tok = parser
                .advance()
                .expect_invariant("SET consumed after lexeme check");
            let set_span = set_tok.span;
            if let Some(next) = parser.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Identifier { .. })
                    && next.lexeme(parser.source).eq_ignore_ascii_case("ACCOUNTS")
                {
                    let accounts_tok = parser
                        .advance()
                        .expect_invariant("ACCOUNTS consumed after lexeme check");
                    let accounts_span = accounts_tok.span;
                    let _eq_span = parse_optional_eq(parser);
                    let list_start = parser
                        .peek_non_trivia()
                        .map(|t| t.span.start)
                        .unwrap_or(accounts_span.end);
                    let list_end = consume_until_semi_or_eof(parser, list_start);
                    let account_list_span = Span {
                        start: list_start,
                        end: list_end,
                    };
                    let kind = AstAlterShareActionKind::SetAccounts {
                        set_span,
                        accounts_span,
                        account_list_span,
                    };
                    return Ok(AstAlterShareAction {
                        node_id: parser.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end: list_end,
                        },
                        kind,
                    });
                }
            }
            // Generic SET <property> = <value> …
            let prop_start = parser
                .peek_non_trivia()
                .map(|t| t.span.start)
                .unwrap_or(set_span.end);
            let end = consume_until_semi_or_eof(parser, prop_start);
            // If body is empty (immediate semi), parser idx didn't move past
            // SET — preserve set_span as the span end.
            let _ = saved;
            let properties_span = Span {
                start: set_span.end,
                end,
            };
            Ok(AstAlterShareAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstAlterShareActionKind::Set {
                    set_span,
                    properties_span,
                },
            })
        }
        "UNSET" => {
            let unset_tok = parser
                .advance()
                .expect_invariant("UNSET consumed after lexeme check");
            let unset_span = unset_tok.span;
            let end = consume_until_semi_or_eof(parser, unset_span.end);
            let properties_span = Span {
                start: unset_span.end,
                end,
            };
            Ok(AstAlterShareAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstAlterShareActionKind::Unset {
                    unset_span,
                    properties_span,
                },
            })
        }
        _ => {
            // Unknown action — consume body for forward-compat.
            let end = consume_until_semi_or_eof(parser, action_start);
            let body_span = Span {
                start: action_start,
                end,
            };
            Ok(AstAlterShareAction {
                node_id: parser.id_gen.next(),
                span: body_span,
                kind: AstAlterShareActionKind::Unknown(AstUnknownClause {
                    node_id: parser.id_gen.next(),
                    introducer: None,
                    span: body_span,
                    kind: UnknownKind::AlterAction,
                }),
            })
        }
    }
}

enum AddRemoveSet {
    Add,
    Remove,
}

fn parse_share_add_or_remove_set_accounts(
    parser: &mut Parser<'_>,
    op: AddRemoveSet,
    action_start: u32,
) -> ParseResult<AstAlterShareAction> {
    let op_tok = parser
        .advance()
        .expect_invariant("ADD/REMOVE consumed after lexeme check");
    let op_span = op_tok.span;
    let next = parser.peek_non_trivia();
    let is_accounts = next
        .map(|t| {
            matches!(t.kind, TokenKind::Identifier { .. })
                && t.lexeme(parser.source).eq_ignore_ascii_case("ACCOUNTS")
        })
        .unwrap_or(false);

    if is_accounts {
        let accounts_tok = parser
            .advance()
            .expect_invariant("ACCOUNTS consumed after lexeme check");
        let accounts_span = accounts_tok.span;
        let _eq_span = parse_optional_eq(parser);
        let list_start = parser
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(accounts_span.end);
        let list_end = consume_until_semi_or_eof(parser, list_start);
        let account_list_span = Span {
            start: list_start,
            end: list_end,
        };
        let kind = match op {
            AddRemoveSet::Add => AstAlterShareActionKind::AddAccounts {
                add_span: op_span,
                accounts_span,
                account_list_span,
            },
            AddRemoveSet::Remove => AstAlterShareActionKind::RemoveAccounts {
                remove_span: op_span,
                accounts_span,
                account_list_span,
            },
        };
        return Ok(AstAlterShareAction {
            node_id: parser.id_gen.next(),
            span: Span {
                start: action_start,
                end: list_end,
            },
            kind,
        });
    }

    // Unknown ADD/REMOVE shape — preserve as Unknown.
    let end = consume_until_semi_or_eof(parser, op_span.end);
    let body_span = Span {
        start: action_start,
        end,
    };
    Ok(AstAlterShareAction {
        node_id: parser.id_gen.next(),
        span: body_span,
        kind: AstAlterShareActionKind::Unknown(AstUnknownClause {
            node_id: parser.id_gen.next(),
            introducer: None,
            span: body_span,
            kind: UnknownKind::AlterAction,
        }),
    })
}

// ─── ALTER SECURITY INTEGRATION action ───

fn parse_alter_security_integration_action(
    parser: &mut Parser<'_>,
) -> ParseResult<AstAlterSecurityIntegrationAction> {
    let tok = parser.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            parser.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected SET / UNSET / RENAME after integration name".to_string(),
            },
        )
    })?;
    let action_start = tok.span.start;

    match tok.kind {
        TokenKind::Keyword(Keyword::Set) => {
            let set_tok = parser
                .advance()
                .expect_invariant("SET in alter security integration");
            let set_span = set_tok.span;
            let properties = walk_object_properties(parser);
            let end = properties
                .last()
                .map(|p| p.value_span.map(|v| v.end).unwrap_or(p.name_span.end))
                .unwrap_or(set_span.end);
            let properties_span = Span {
                start: set_span.end,
                end,
            };
            Ok(AstAlterSecurityIntegrationAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstAlterSecurityIntegrationActionKind::Set {
                    set_span,
                    properties_span,
                    properties,
                },
            })
        }
        TokenKind::Keyword(Keyword::Unset) => {
            let unset_tok = parser
                .advance()
                .expect_invariant("UNSET in alter security integration");
            let unset_span = unset_tok.span;
            let mut property_name_spans: Vec<Span> = Vec::new();
            let mut end = unset_span.end;
            while let Some(tok) = parser.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                ) {
                    break;
                }
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    parser.advance();
                    continue;
                }
                let name_tok = parser
                    .advance()
                    .expect_invariant("UNSET property name consumed after peek");
                property_name_spans.push(name_tok.span);
                end = name_tok.span.end;
            }
            let properties_span = Span {
                start: unset_span.end,
                end,
            };
            Ok(AstAlterSecurityIntegrationAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstAlterSecurityIntegrationActionKind::Unset {
                    unset_span,
                    properties_span,
                    property_name_spans,
                },
            })
        }
        _ if tok.lexeme(parser.source).eq_ignore_ascii_case("RENAME") => {
            let rename_tok = parser
                .advance()
                .expect_invariant("RENAME in alter security integration");
            let rename_span = rename_tok.span;
            let to_tok = parser
                .advance()
                .ok_or_eof(parser.current_span(), vec!["TO".to_string()])?;
            let to_span = to_tok.span;
            let new_name_span = parser.parse_qualified_name_span()?;
            Ok(AstAlterSecurityIntegrationAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end: new_name_span.end,
                },
                kind: AstAlterSecurityIntegrationActionKind::Rename {
                    rename_span,
                    to_span,
                    new_name_span,
                },
            })
        }
        _ => {
            let end = consume_until_semi_or_eof(parser, action_start);
            let body_span = Span {
                start: action_start,
                end,
            };
            Ok(AstAlterSecurityIntegrationAction {
                node_id: parser.id_gen.next(),
                span: body_span,
                kind: AstAlterSecurityIntegrationActionKind::Unknown(AstUnknownClause {
                    node_id: parser.id_gen.next(),
                    introducer: None,
                    span: body_span,
                    kind: UnknownKind::AlterAction,
                }),
            })
        }
    }
}

// ─── ALTER REPLICATION GROUP / ALTER FAILOVER GROUP action ───

fn parse_replication_failover_group_action(
    parser: &mut Parser<'_>,
) -> ParseResult<AstReplicationFailoverGroupAction> {
    let tok = parser.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            parser.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected SET / UNSET / ADD / REMOVE / MOVE after group name".to_string(),
            },
        )
    })?;
    let action_start = tok.span.start;
    let lexeme_upper = tok.lexeme(parser.source).to_ascii_uppercase();

    match lexeme_upper.as_str() {
        "SET" => {
            let set_tok = parser
                .advance()
                .expect_invariant("SET in replication/failover group");
            let set_span = set_tok.span;
            let end = consume_until_semi_or_eof(parser, set_span.end);
            Ok(AstReplicationFailoverGroupAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstReplicationFailoverGroupActionKind::Set {
                    set_span,
                    properties_span: Span {
                        start: set_span.end,
                        end,
                    },
                },
            })
        }
        "UNSET" => {
            let unset_tok = parser
                .advance()
                .expect_invariant("UNSET in replication/failover group");
            let unset_span = unset_tok.span;
            let end = consume_until_semi_or_eof(parser, unset_span.end);
            Ok(AstReplicationFailoverGroupAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstReplicationFailoverGroupActionKind::Unset {
                    unset_span,
                    properties_span: Span {
                        start: unset_span.end,
                        end,
                    },
                },
            })
        }
        "ADD" => parse_add_to_or_remove_from(parser, AddRemove::Add, action_start),
        "REMOVE" => parse_add_to_or_remove_from(parser, AddRemove::Remove, action_start),
        "MOVE" => {
            let move_tok = parser
                .advance()
                .expect_invariant("MOVE in replication/failover group");
            let move_span = move_tok.span;
            let end = consume_until_semi_or_eof(parser, move_span.end);
            Ok(AstReplicationFailoverGroupAction {
                node_id: parser.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstReplicationFailoverGroupActionKind::Move {
                    move_span,
                    body_span: Span {
                        start: move_span.end,
                        end,
                    },
                },
            })
        }
        _ => {
            let end = consume_until_semi_or_eof(parser, action_start);
            let body_span = Span {
                start: action_start,
                end,
            };
            Ok(AstReplicationFailoverGroupAction {
                node_id: parser.id_gen.next(),
                span: body_span,
                kind: AstReplicationFailoverGroupActionKind::Unknown(AstUnknownClause {
                    node_id: parser.id_gen.next(),
                    introducer: None,
                    span: body_span,
                    kind: UnknownKind::AlterAction,
                }),
            })
        }
    }
}

enum AddRemove {
    Add,
    Remove,
}

fn parse_add_to_or_remove_from(
    parser: &mut Parser<'_>,
    op: AddRemove,
    action_start: u32,
) -> ParseResult<AstReplicationFailoverGroupAction> {
    let op_tok = parser
        .advance()
        .expect_invariant("ADD/REMOVE consumed after lexeme check");
    let op_span = op_tok.span;

    // Collect <list> tokens up to TO/FROM
    let list_start = parser
        .peek_non_trivia()
        .map(|t| t.span.start)
        .unwrap_or(op_span.end);
    let mut list_end = op_span.end;
    let mut sep_span: Option<Span> = None;
    let sep_match: &[&str] = match op {
        AddRemove::Add => &["TO"],
        AddRemove::Remove => &["FROM"],
    };
    while let Some(next) = parser.peek_non_trivia() {
        if matches!(
            next.kind,
            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
        ) {
            break;
        }
        let lex = next.lexeme(parser.source);
        if sep_match.iter().any(|s| lex.eq_ignore_ascii_case(s)) {
            let sep_tok = parser
                .advance()
                .expect_invariant("separator consumed after lexeme check");
            sep_span = Some(sep_tok.span);
            break;
        }
        list_end = next.span.end;
        parser.advance();
    }
    let list_span = Span {
        start: list_start,
        end: list_end,
    };

    let target_start = parser
        .peek_non_trivia()
        .map(|t| t.span.start)
        .unwrap_or(list_end);
    let target_end = consume_until_semi_or_eof(parser, target_start);
    let target_span = Span {
        start: target_start,
        end: target_end,
    };

    let separator_span = sep_span.unwrap_or(Span {
        start: list_end,
        end: list_end,
    });

    let kind = match op {
        AddRemove::Add => AstReplicationFailoverGroupActionKind::AddTo {
            add_span: op_span,
            list_span,
            to_span: separator_span,
            target_span,
        },
        AddRemove::Remove => AstReplicationFailoverGroupActionKind::RemoveFrom {
            remove_span: op_span,
            list_span,
            from_span: separator_span,
            target_span,
        },
    };

    Ok(AstReplicationFailoverGroupAction {
        node_id: parser.id_gen.next(),
        span: Span {
            start: action_start,
            end: target_end,
        },
        kind,
    })
}

// ─── helpers ───

fn parse_optional_if_exists(parser: &mut Parser<'_>) -> ParseResult<Option<Span>> {
    let starts_with_if = matches!(
        parser.peek_non_trivia(),
        Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::If))
    );
    if !starts_with_if {
        return Ok(None);
    }
    let if_tok = parser.advance().expect_invariant("IF consumed after match");
    let exists_tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec!["EXISTS".to_string()])?;
    if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
        return Err(ParseError::new(
            exists_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected EXISTS after IF".to_string(),
            },
        ));
    }
    Ok(Some(Span {
        start: if_tok.span.start,
        end: exists_tok.span.end,
    }))
}

/// Walk `<name> [= <value>]` properties until `;` / EOF, collecting
/// typed name/value span pairs. Shared by CREATE SECURITY INTEGRATION
/// and ALTER SECURITY INTEGRATION … SET. Stray commas between
/// properties are skipped; a value runs until the next token that looks
/// like a property name followed by `=` (see [`is_likely_property_name`]).
pub(crate) fn walk_object_properties(
    parser: &mut Parser<'_>,
) -> Vec<crate::ast::AstObjectProperty> {
    walk_object_properties_until(parser, None)
}

/// Walk `<name> [= <value>]` properties. When `stop_lexeme` is `Some`, the
/// walk terminates (without consuming) at the first non-trivia token whose
/// lexeme matches it — both at a property boundary and mid-value-scan. Used
/// by families with a trailing non-property clause (RESOURCE MONITOR's
/// `TRIGGERS`).
fn walk_object_properties_until(
    parser: &mut Parser<'_>,
    stop_lexeme: Option<&str>,
) -> Vec<crate::ast::AstObjectProperty> {
    let at_stop = |tok: &crate::lexer::Token, parser: &Parser<'_>| -> bool {
        let Some(stop) = stop_lexeme else {
            return false;
        };
        matches!(
            tok.kind,
            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
        ) && tok.lexeme(parser.source).eq_ignore_ascii_case(stop)
    };
    let mut properties = Vec::new();
    while let Some(tok) = parser.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
        ) {
            break;
        }
        if at_stop(tok, parser) {
            break;
        }
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
            parser.advance();
            continue;
        }
        let name_tok = parser
            .advance()
            .expect_invariant("property name consumed after peek");
        let name_span = name_tok.span;

        // No '=' — value-less keyword; record name-only and continue.
        if parse_optional_eq(parser).is_none() {
            properties.push(crate::ast::AstObjectProperty {
                name_span,
                value_span: None,
            });
            continue;
        }

        // Value: scan tokens until the next non-trivia token is either a
        // likely property name followed by '=' or ; / EOF / stop lexeme.
        let value_start = parser
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(name_span.end);
        let mut value_end = value_start;
        while let Some(next) = parser.peek_non_trivia() {
            if matches!(
                next.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            if at_stop(next, parser) {
                break;
            }
            let next_lex = next.lexeme(parser.source).to_ascii_uppercase();
            let next_idx_saved = parser.idx;
            parser.advance();
            let consumed = next.span.end;
            let following_is_eq = matches!(
                parser.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq))
            );
            if following_is_eq && is_likely_property_name(next, parser.source, &next_lex) {
                // Roll back — leave the property-name token for the next iteration.
                parser.idx = next_idx_saved;
                break;
            }
            value_end = consumed;
        }
        let value_span = Span {
            start: value_start,
            end: value_end,
        };
        // Record credential value spans so they are masked out of output.
        let name_upper = parser
            .source
            .get(name_span.start as usize..name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        if crate::parser::core::is_credential_value_property(&name_upper) {
            parser.redaction_spans.push(value_span);
        }
        // A rendered placeholder is not a statically-known value — record
        // the property with no value span (redaction above still applies).
        let value_span = if parser.span_overlaps_placeholder(value_span) {
            None
        } else {
            Some(value_span)
        };
        properties.push(crate::ast::AstObjectProperty {
            name_span,
            value_span,
        });
    }
    properties
}

/// Pull the `CREDIT_QUOTA` / `FREQUENCY` / `NOTIFY_USERS` value spans out of a
/// resource-monitor property bag. Returns `(credit_quota, frequency,
/// notify_users)` value spans.
fn resource_monitor_slots(
    parser: &Parser<'_>,
    properties: &[crate::ast::AstObjectProperty],
) -> (Option<Span>, Option<Span>, Option<Span>) {
    let mut credit_quota = None;
    let mut frequency = None;
    let mut notify_users = None;
    for prop in properties {
        let name_upper = parser
            .source
            .get(prop.name_span.start as usize..prop.name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        match (name_upper.as_str(), prop.value_span) {
            ("CREDIT_QUOTA", Some(v)) => credit_quota = Some(v),
            ("FREQUENCY", Some(v)) => frequency = Some(v),
            ("NOTIFY_USERS", Some(v)) => notify_users = Some(v),
            _ => {}
        }
    }
    (credit_quota, frequency, notify_users)
}

/// Pull `INSTANCE_FAMILY` / `AUTO_RESUME` / `MIN_NODES` / `MAX_NODES` value
/// spans out of a compute-pool property bag.
fn compute_pool_slots(
    parser: &Parser<'_>,
    properties: &[crate::ast::AstObjectProperty],
) -> (Option<Span>, Option<Span>, Option<Span>, Option<Span>) {
    let mut instance_family = None;
    let mut auto_resume = None;
    let mut min_nodes = None;
    let mut max_nodes = None;
    for prop in properties {
        let name_upper = parser
            .source
            .get(prop.name_span.start as usize..prop.name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        match (name_upper.as_str(), prop.value_span) {
            ("INSTANCE_FAMILY", Some(v)) => instance_family = Some(v),
            ("AUTO_RESUME", Some(v)) => auto_resume = Some(v),
            ("MIN_NODES", Some(v)) => min_nodes = Some(v),
            ("MAX_NODES", Some(v)) => max_nodes = Some(v),
            _ => {}
        }
    }
    (instance_family, auto_resume, min_nodes, max_nodes)
}

/// Pull `API_INTEGRATION` / `ORIGIN` / `GIT_CREDENTIALS` value spans out of a
/// git-repository property bag.
fn git_repository_slots(
    parser: &Parser<'_>,
    properties: &[crate::ast::AstObjectProperty],
) -> (Option<Span>, Option<Span>, Option<Span>) {
    let mut api_integration = None;
    let mut origin = None;
    let mut git_credentials = None;
    for prop in properties {
        let name_upper = parser
            .source
            .get(prop.name_span.start as usize..prop.name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        match (name_upper.as_str(), prop.value_span) {
            ("API_INTEGRATION", Some(v)) => api_integration = Some(v),
            ("ORIGIN", Some(v)) => origin = Some(v),
            ("GIT_CREDENTIALS", Some(v)) => git_credentials = Some(v),
            _ => {}
        }
    }
    (api_integration, origin, git_credentials)
}

/// Pull the `EXTERNAL_ACCESS_INTEGRATIONS` value span out of a property bag —
/// the network-egress recognition surface shared by STREAMLIT and SERVICE.
/// Returns the value span when the clause is present; its presence is the
/// signal, not its contents.
fn external_access_integrations_slot(
    parser: &Parser<'_>,
    properties: &[crate::ast::AstObjectProperty],
) -> Option<Span> {
    for prop in properties {
        let name_upper = parser
            .source
            .get(prop.name_span.start as usize..prop.name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        if name_upper == "EXTERNAL_ACCESS_INTEGRATIONS" {
            return prop.value_span;
        }
    }
    None
}

/// Pull the `EMBEDDING_MODEL = '<model>'` value span out of a property bag.
fn embedding_model_slot(
    parser: &Parser<'_>,
    properties: &[crate::ast::AstObjectProperty],
) -> Option<Span> {
    for prop in properties {
        let name_upper = parser
            .source
            .get(prop.name_span.start as usize..prop.name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        if name_upper == "EMBEDDING_MODEL" {
            return prop.value_span;
        }
    }
    None
}

/// Pull a named property's value span out of a property bag. `name` must be
/// upper-case.
fn property_value_by_name(
    parser: &Parser<'_>,
    properties: &[crate::ast::AstObjectProperty],
    name: &str,
) -> Option<Span> {
    for prop in properties {
        let name_upper = parser
            .source
            .get(prop.name_span.start as usize..prop.name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        if name_upper == name {
            return prop.value_span;
        }
    }
    None
}

/// Pull the `WAREHOUSE` / `SCHEDULE` / `COMMENT` value spans out of an
/// alert property bag. Returns `(warehouse, schedule, comment)`.
fn alert_property_slots(
    parser: &Parser<'_>,
    properties: &[crate::ast::AstObjectProperty],
) -> (Option<Span>, Option<Span>, Option<Span>) {
    let mut warehouse = None;
    let mut schedule = None;
    let mut comment = None;
    for prop in properties {
        let name_upper = parser
            .source
            .get(prop.name_span.start as usize..prop.name_span.end as usize)
            .unwrap_or("")
            .to_ascii_uppercase();
        match (name_upper.as_str(), prop.value_span) {
            ("WAREHOUSE", Some(v)) => warehouse = Some(v),
            ("SCHEDULE", Some(v)) => schedule = Some(v),
            ("COMMENT", Some(v)) => comment = Some(v),
            _ => {}
        }
    }
    (warehouse, schedule, comment)
}

/// Advance to (but do not consume) the statement terminator (`;` or EOF),
/// returning the end position of the last consumed token. Used to capture
/// an unparseable alert action body or a MODIFY CONDITION span.
fn skip_to_statement_terminator(parser: &mut Parser<'_>) -> u32 {
    let mut end = parser.current_span().end;
    while let Some(tok) = parser.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
        ) {
            break;
        }
        let t = parser
            .advance()
            .expect_invariant("token consumed in skip_to_statement_terminator");
        end = t.span.end;
    }
    end
}

/// Known `NAME = <list>` property names in CREATE REPLICATION / FAILOVER
/// GROUP. Used as value-scan boundaries by the targeted scanner.
fn is_repl_group_property(upper_lexeme: &str) -> bool {
    matches!(
        upper_lexeme,
        "OBJECT_TYPES"
            | "ALLOWED_DATABASES"
            | "ALLOWED_EXTERNAL_VOLUMES"
            | "ALLOWED_SHARES"
            | "ALLOWED_INTEGRATION_TYPES"
            | "ALLOWED_ACCOUNTS"
            | "REPLICATION_SCHEDULE"
            | "OPTIMIZED_REFRESH"
            | "ERROR_INTEGRATION"
    )
}

fn parse_optional_eq(parser: &mut Parser<'_>) -> Option<Span> {
    let next = parser.peek_non_trivia()?;
    if matches!(next.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        let tok = parser.advance().expect_invariant("= consumed after match");
        Some(tok.span)
    } else {
        None
    }
}

fn expect_identifier_lexeme(parser: &mut Parser<'_>, expected: &str) -> ParseResult<Span> {
    let tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec![expected.to_string()])?;
    let is_ident = matches!(tok.kind, TokenKind::Identifier { .. });
    if !is_ident || !tok.lexeme(parser.source).eq_ignore_ascii_case(expected) {
        return Err(ParseError::new(
            tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected {} keyword", expected),
            },
        ));
    }
    Ok(tok.span)
}

/// Accept either the typed Keyword variant or an Identifier with the
/// matching lexeme. Used for words like INTEGRATION that the lexer may
/// classify either way depending on context.
fn expect_keyword_or_identifier(
    parser: &mut Parser<'_>,
    keyword: Keyword,
    label: &str,
) -> ParseResult<Span> {
    let tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec![label.to_string()])?;
    let matched = match tok.kind {
        TokenKind::Keyword(k) if k == keyword => true,
        TokenKind::Identifier { .. } => tok.lexeme(parser.source).eq_ignore_ascii_case(label),
        _ => false,
    };
    if !matched {
        return Err(ParseError::new(
            tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected {} keyword", label),
            },
        ));
    }
    Ok(tok.span)
}

/// Heuristic: returns `true` when `tok` looks like a Snowflake property
/// keyword (unquoted identifier whose uppercase lexeme is all-caps with
/// underscores — e.g. `OAUTH_CLIENT`, `STORAGE_AWS_ROLE_ARN`,
/// `OAUTH_REFRESH_TOKEN_VALIDITY`). Used by the security-integration
/// property scanner to recognise property boundaries when there's no
/// comma separator (Snowflake's CREATE SECURITY INTEGRATION uses
/// whitespace between `KEY = VALUE` pairs, not commas).
fn is_likely_property_name(tok: &crate::lexer::Token, source: &str, upper_lex: &str) -> bool {
    // Identifiers AND keywords qualify: property names like COMMENT /
    // TYPE / ENABLED lex as keywords. The caller additionally requires
    // the following token to be `=`, so a keyword mid-value (rare)
    // can't be misread as a property name unless followed by `=`.
    if !matches!(
        tok.kind,
        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
    ) {
        return false;
    }
    let lex = tok.lexeme(source);
    if !lex.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    // Reject TRUE/FALSE which are unquoted identifiers used as property
    // values for ENABLED = TRUE, OAUTH_ISSUE_REFRESH_TOKENS = TRUE, etc.
    if upper_lex == "TRUE" || upper_lex == "FALSE" || upper_lex == "NULL" {
        return false;
    }
    // Property names are uppercase by convention in Snowflake docs.
    // Lowercase identifiers are typically values (provider names like
    // `aws_api_gateway`).
    lex.chars().all(|c| !c.is_ascii_lowercase())
}

/// Consume non-trivia tokens until the next semicolon / EOF, returning
/// the end offset (or `start` if nothing was consumed). Used by the
/// generic SET/UNSET/MOVE/Unknown bodies that don't enumerate every
/// Snowflake property in the AST.
fn consume_until_semi_or_eof(parser: &mut Parser<'_>, start: u32) -> u32 {
    let mut end = start;
    while let Some(tok) = parser.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
        ) {
            break;
        }
        end = tok.span.end;
        parser.advance();
    }
    end
}
