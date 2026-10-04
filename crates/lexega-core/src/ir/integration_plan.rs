// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE | ALTER | DROP [<KIND>] INTEGRATION`
//! statements. Covers the **API**, **Storage**,
//! **External-Access**, and **Notification** kinds.
//!
//! Mirrors the policy_plan layout: top-level kind-agnostic fields
//! (rename / tag / comment) plus a closed `IntegrationPlanVariant`
//! enum carrying per-kind structural fields.

use crate::ast::{
    AstAlterApiIntegration, AstAlterApiIntegrationActionKind, AstAlterExternalAccessIntegration,
    AstAlterExternalAccessIntegrationActionKind, AstAlterNotificationIntegration,
    AstAlterNotificationIntegrationActionKind, AstAlterSecurityIntegration,
    AstAlterSecurityIntegrationActionKind, AstAlterStorageIntegration,
    AstAlterStorageIntegrationActionKind, AstCreateApiIntegration,
    AstCreateExternalAccessIntegration, AstCreateNotificationIntegration,
    AstCreateSecurityIntegration, AstCreateStorageIntegration, AstDrop, AstDropApiIntegration,
    AstDropExternalAccessIntegration, AstDropNotificationIntegration, AstDropStorageIntegration,
    AstObjectProperty, NodeId,
};
use crate::ir::policy_plan::PolicyCommentAction;
use crate::ir::span_extract::extract_integer_literal_value;
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

/// Source-string-free carrier for one integration DDL statement.
#[derive(Debug, Clone)]
pub struct IntegrationPlan {
    pub action: IntegrationAction,
    pub integration_kind: IntegrationKindIr,
    pub name_span: Span,
    /// `ALTER … RENAME TO <new_name>` action — populated only for the
    /// `ExternalAccess` variant today (other integration kinds have no
    /// rename surface in their typed AST).
    pub renamed_to_name_span: Option<Span>,
    pub if_not_exists: bool,
    pub if_exists: bool,
    pub or_replace: bool,
    pub set_tag_action_spans: Vec<Span>,
    pub unset_tag_action_spans: Vec<Span>,
    pub comment: PolicyCommentAction,
    pub variant: IntegrationPlanVariant,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrationAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrationKindIr {
    Api,
    Storage,
    ExternalAccess,
    Notification,
    Security,
}

#[derive(Debug, Clone)]
pub enum IntegrationPlanVariant {
    Api(ApiIntegrationShape),
    Storage(StorageIntegrationShape),
    ExternalAccess(ExternalAccessIntegrationShape),
    Notification(NotificationIntegrationShape),
    Security(SecurityIntegrationShape),
    DropOnly,
}

/// Security-integration structured payload (OAuth / SAML2 / SCIM /
/// EXTERNAL_OAUTH providers). The TYPE discriminator and property
/// name/value pairs are recognition primitives — which types or
/// property values weaken authentication is YAML policy.
#[derive(Debug, Clone, Default)]
pub struct SecurityIntegrationShape {
    /// `TYPE = <value>` (upper-cased), e.g. `OAUTH`, `SAML2`, `SCIM`.
    pub integration_type: Option<String>,
    /// CREATE-time `ENABLED = TRUE | FALSE`. `None` = clause absent.
    pub enabled_on_create: Option<bool>,
    pub had_set_enabled_to_true: bool,
    pub had_set_enabled_to_false: bool,
    /// `UNSET ENABLED` observed.
    pub had_unset_enabled: bool,
    /// Property name/value pairs from CREATE bodies and `ALTER … SET`
    /// (names upper-cased; TYPE / ENABLED / COMMENT excluded — they
    /// have dedicated slots).
    pub set_properties: Vec<SecurityIntegrationPropertyIr>,
    /// `ALTER … UNSET` property names (upper-cased; ENABLED excluded).
    pub unset_properties: Vec<String>,
    /// `RENAME TO <new_name>` observed.
    pub had_rename: bool,
}

/// One `<name> = <value>` pair in a security-integration body.
#[derive(Debug, Clone)]
pub struct SecurityIntegrationPropertyIr {
    /// Upper-cased property name as written.
    pub name: String,
    /// Raw value text (trimmed); `None` for value-less keywords.
    pub value: Option<String>,
}

/// Notification-integration structured payload. Today the SNW-NOTIFINTG-*
/// rules predicate only on statement kind, so the shape is intentionally
/// narrow — typed flags for `ENABLED`, plus action flags from ALTER.
/// Future SNW-NOTIFINTG-* rules can promote provider-specific fields
/// (`AWS_SNS_TOPIC_ARN`, `WEBHOOK_URL`, …) to typed slots without
/// changing this struct's shape.
#[derive(Debug, Clone, Default)]
pub struct NotificationIntegrationShape {
    /// CREATE-time `ENABLED = TRUE | FALSE`. `None` = clause absent.
    pub enabled_on_create: Option<bool>,
    /// `ALTER … SET ENABLED = TRUE` action observed.
    pub had_set_enabled_to_true: bool,
    /// `ALTER … SET ENABLED = FALSE` action observed.
    pub had_set_enabled_to_false: bool,
    /// `ALTER … RENAME TO …` action observed.
    pub had_rename: bool,
}

/// API-integration structured payload. CREATE-time presence flags plus
/// ALTER action flags drive the SNW-API-INTG-* rules.
#[derive(Debug, Clone, Default)]
pub struct ApiIntegrationShape {
    pub enabled_on_create: Option<bool>,
    pub has_api_key_on_create: bool,
    pub has_allowed_prefixes_on_create: bool,
    pub has_blocked_prefixes_on_create: bool,
    pub had_set_enabled_to_true: bool,
    pub had_set_enabled_to_false: bool,
    pub had_set_api_key: bool,
    pub had_unset_api_key: bool,
    pub had_set_aws_role: bool,
    pub had_set_azure_ad_application_id: bool,
    pub had_set_allowed_prefixes: bool,
    pub had_set_blocked_prefixes: bool,
}

/// Storage-integration structured payload.
#[derive(Debug, Clone, Default)]
pub struct StorageIntegrationShape {
    pub enabled_on_create: Option<bool>,
    pub had_set_enabled_to_true: bool,
    pub had_set_enabled_to_false: bool,
    pub had_set_aws_role: bool,
    pub had_set_azure_tenant: bool,
    pub had_set_allowed_locations: bool,
    pub had_set_blocked_locations: bool,
}

/// External-access-integration structured payload. Drives SNW-EXTACC-*
/// rules. Mirrors the API/Storage shape pattern: CREATE-time presence
/// flags plus ALTER action flags.
#[derive(Debug, Clone, Default)]
pub struct ExternalAccessIntegrationShape {
    /// CREATE-time `ENABLED = TRUE | FALSE`. `None` = clause absent
    /// (Snowflake default is `TRUE`); `Some(false)` = explicitly
    /// disabled at creation.
    pub enabled_on_create: Option<bool>,

    // ── ALTER action flags ───────────────────────────────────────────
    pub had_set_enabled_to_true: bool,
    pub had_set_enabled_to_false: bool,
    pub had_unset_enabled: bool,

    /// `SET ALLOWED_NETWORK_RULES = (rule_a, rule_b)` — non-empty list
    /// (additive intent; drives `SNW-EXTACC-NETRULE-ADD`).
    pub had_set_allowed_network_rules_nonempty: bool,
    /// `SET ALLOWED_NETWORK_RULES = (...)` (any form) — drives
    /// `SNW-EXTACC-NETRULES-CHG`.
    pub had_set_allowed_network_rules: bool,
    /// `UNSET ALLOWED_NETWORK_RULES` — drives
    /// `SNW-EXTACC-NETRULE-RMV`.
    pub had_unset_allowed_network_rules: bool,

    /// `SET ALLOWED_API_AUTHENTICATION_INTEGRATIONS = (...)` — drives
    /// `SNW-EXTACC-HOSTS-CHG`.
    pub had_set_allowed_api_authentication_integrations: bool,
    pub had_unset_allowed_api_authentication_integrations: bool,

    /// `SET ALLOWED_AUTHENTICATION_SECRETS = (...)` — drives
    /// `SNW-EXTACC-SECRETS-CHG`.
    pub had_set_allowed_authentication_secrets: bool,
    /// `UNSET ALLOWED_AUTHENTICATION_SECRETS` — drives
    /// `SNW-EXTACC-SECRET-RMV`.
    pub had_unset_allowed_authentication_secrets: bool,

    /// `RENAME TO <new_name>` — drives `SNW-EXTACC-NAME-CHG`.
    pub had_rename: bool,
}

// ─────────────────────────────────────────────────────────────────────
// API Integration
// ─────────────────────────────────────────────────────────────────────

pub fn lower_create_api_integration_to_integration_plan(
    p: &AstCreateApiIntegration,
    source: &str,
) -> IntegrationPlan {
    let enabled_on_create = p.enabled_span.map(|sp| read_enabled_bool(sp, source));
    let shape = ApiIntegrationShape {
        enabled_on_create,
        has_api_key_on_create: p.api_key_span.is_some(),
        has_allowed_prefixes_on_create: p.api_allowed_prefixes_span.is_some(),
        has_blocked_prefixes_on_create: p.api_blocked_prefixes_span.is_some(),
        ..ApiIntegrationShape::default()
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    IntegrationPlan {
        action: IntegrationAction::Create,
        integration_kind: IntegrationKindIr::Api,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: IntegrationPlanVariant::Api(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_alter_api_integration_to_integration_plan(
    p: &AstAlterApiIntegration,
    source: &str,
) -> IntegrationPlan {
    use AstAlterApiIntegrationActionKind as A;
    let mut shape = ApiIntegrationShape::default();
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    for action in &p.actions {
        match &action.kind {
            A::SetEnabled { value_span, .. } => {
                if read_enabled_bool(*value_span, source) {
                    shape.had_set_enabled_to_true = true;
                } else {
                    shape.had_set_enabled_to_false = true;
                }
            }
            A::UnsetEnabled { .. } => {
                // No SNW-API-INTG-* rule predicates on UNSET ENABLED today.
            }
            A::SetApiKey { .. } => shape.had_set_api_key = true,
            A::UnsetApiKey { .. } => shape.had_unset_api_key = true,
            A::SetApiAwsRoleArn { .. } => shape.had_set_aws_role = true,
            A::SetAzureAdApplicationId { .. } => shape.had_set_azure_ad_application_id = true,
            A::SetApiAllowedPrefixes { .. } => shape.had_set_allowed_prefixes = true,
            A::SetApiBlockedPrefixes { .. } => shape.had_set_blocked_prefixes = true,
            A::UnsetApiBlockedPrefixes { .. } => {
                // Tracked but no rule consumes today.
            }
            A::SetAllowedAuthenticationSecrets { .. } => {
                // No rule consumer today.
            }
            A::SetOther { .. } => {
                // Property outside the recognized set: intentionally maps to no
                // shape flag. Mapping it to a specific action (e.g.
                // had_set_api_key) would forge that finding on an unknown
                // property.
            }
            A::SetComment { value_span, .. } => {
                comment = PolicyCommentAction::Set {
                    value_span: *value_span,
                };
            }
            A::UnsetComment { .. } => comment = PolicyCommentAction::Unset,
            A::SetTag { tags_span, .. } => set_tag_action_spans.push(*tags_span),
            A::UnsetTag { tags_span, .. } => unset_tag_action_spans.push(*tags_span),
        }
    }

    IntegrationPlan {
        action: IntegrationAction::Alter,
        integration_kind: IntegrationKindIr::Api,
        name_span: p.name_span,
        renamed_to_name_span: None,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: IntegrationPlanVariant::Api(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_drop_api_integration_to_integration_plan(
    p: &AstDropApiIntegration,
) -> IntegrationPlan {
    IntegrationPlan {
        action: IntegrationAction::Drop,
        integration_kind: IntegrationKindIr::Api,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: IntegrationPlanVariant::DropOnly,
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Storage Integration
// ─────────────────────────────────────────────────────────────────────

pub fn lower_create_storage_integration_to_integration_plan(
    p: &AstCreateStorageIntegration,
    source: &str,
) -> IntegrationPlan {
    let enabled_on_create = p.enabled_span.map(|sp| read_enabled_bool(sp, source));
    let shape = StorageIntegrationShape {
        enabled_on_create,
        ..StorageIntegrationShape::default()
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    IntegrationPlan {
        action: IntegrationAction::Create,
        integration_kind: IntegrationKindIr::Storage,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: IntegrationPlanVariant::Storage(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_alter_storage_integration_to_integration_plan(
    p: &AstAlterStorageIntegration,
    source: &str,
) -> IntegrationPlan {
    use AstAlterStorageIntegrationActionKind as A;
    let mut shape = StorageIntegrationShape::default();
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    for action in &p.actions {
        match &action.kind {
            A::SetEnabled { value_span, .. } => {
                if read_enabled_bool(*value_span, source) {
                    shape.had_set_enabled_to_true = true;
                } else {
                    shape.had_set_enabled_to_false = true;
                }
            }
            A::UnsetEnabled { .. } => {}
            A::SetStorageAllowedLocations { .. } => shape.had_set_allowed_locations = true,
            A::SetStorageBlockedLocations { .. } => shape.had_set_blocked_locations = true,
            A::UnsetStorageBlockedLocations { .. } => {}
            A::SetAwsRoleArn { .. } => shape.had_set_aws_role = true,
            A::SetAwsExternalId { .. } => {} // No rule consumer today.
            A::SetAwsObjectAcl { .. } => {}  // No rule consumer today.
            A::SetAzureTenantId { .. } => shape.had_set_azure_tenant = true,
            A::SetUsePrivatelinkEndpoint { .. } => {}
            A::SetComment { value_span, .. } => {
                comment = PolicyCommentAction::Set {
                    value_span: *value_span,
                };
            }
            A::UnsetComment { .. } => comment = PolicyCommentAction::Unset,
            A::SetTag {
                tags_value_span, ..
            } => set_tag_action_spans.push(*tags_value_span),
            A::UnsetTag { tag_names_span, .. } => unset_tag_action_spans.push(*tag_names_span),
        }
    }

    IntegrationPlan {
        action: IntegrationAction::Alter,
        integration_kind: IntegrationKindIr::Storage,
        name_span: p.name_span,
        renamed_to_name_span: None,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: IntegrationPlanVariant::Storage(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_drop_storage_integration_to_integration_plan(
    p: &AstDropStorageIntegration,
) -> IntegrationPlan {
    IntegrationPlan {
        action: IntegrationAction::Drop,
        integration_kind: IntegrationKindIr::Storage,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: IntegrationPlanVariant::DropOnly,
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// External Access Integration
// ─────────────────────────────────────────────────────────────────────

pub fn lower_create_external_access_integration_to_integration_plan(
    p: &AstCreateExternalAccessIntegration,
    source: &str,
) -> IntegrationPlan {
    let enabled_on_create = p.enabled_span.map(|sp| read_enabled_bool(sp, source));
    let shape = ExternalAccessIntegrationShape {
        enabled_on_create,
        ..ExternalAccessIntegrationShape::default()
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    IntegrationPlan {
        action: IntegrationAction::Create,
        integration_kind: IntegrationKindIr::ExternalAccess,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: IntegrationPlanVariant::ExternalAccess(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_alter_external_access_integration_to_integration_plan(
    p: &AstAlterExternalAccessIntegration,
    source: &str,
) -> IntegrationPlan {
    use AstAlterExternalAccessIntegrationActionKind as A;
    let mut shape = ExternalAccessIntegrationShape::default();
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;
    let mut renamed_to_name_span: Option<Span> = None;

    for action in &p.actions {
        match &action.kind {
            A::SetEnabled { value_span, .. } => {
                if read_enabled_bool(*value_span, source) {
                    shape.had_set_enabled_to_true = true;
                } else {
                    shape.had_set_enabled_to_false = true;
                }
            }
            A::UnsetEnabled { .. } => {
                // UNSET ENABLED reverts to default (TRUE) — treat as enable
                // from a customer-visible standpoint.
                shape.had_unset_enabled = true;
            }
            A::SetAllowedNetworkRules { value_span, .. } => {
                shape.had_set_allowed_network_rules = true;
                if has_non_paren_content_span(*value_span, source) {
                    shape.had_set_allowed_network_rules_nonempty = true;
                }
            }
            A::UnsetAllowedNetworkRules { .. } => {
                shape.had_unset_allowed_network_rules = true;
            }
            A::SetAllowedApiAuthenticationIntegrations { .. } => {
                shape.had_set_allowed_api_authentication_integrations = true;
            }
            A::UnsetAllowedApiAuthenticationIntegrations { .. } => {
                shape.had_unset_allowed_api_authentication_integrations = true;
            }
            A::SetAllowedAuthenticationSecrets { .. } => {
                shape.had_set_allowed_authentication_secrets = true;
            }
            A::UnsetAllowedAuthenticationSecrets { .. } => {
                shape.had_unset_allowed_authentication_secrets = true;
            }
            A::SetComment { value_span, .. } => {
                comment = PolicyCommentAction::Set {
                    value_span: *value_span,
                };
            }
            A::UnsetComment { .. } => comment = PolicyCommentAction::Unset,
            A::SetTag { tags_span, .. } => set_tag_action_spans.push(*tags_span),
            A::UnsetTag { tags_span, .. } => unset_tag_action_spans.push(*tags_span),
            A::Rename { new_name_span, .. } => {
                shape.had_rename = true;
                renamed_to_name_span = Some(*new_name_span);
            }
        }
    }

    IntegrationPlan {
        action: IntegrationAction::Alter,
        integration_kind: IntegrationKindIr::ExternalAccess,
        name_span: p.name_span,
        renamed_to_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: IntegrationPlanVariant::ExternalAccess(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_drop_external_access_integration_to_integration_plan(
    p: &AstDropExternalAccessIntegration,
) -> IntegrationPlan {
    IntegrationPlan {
        action: IntegrationAction::Drop,
        integration_kind: IntegrationKindIr::ExternalAccess,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: IntegrationPlanVariant::DropOnly,
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Notification Integration
// ─────────────────────────────────────────────────────────────────────
//
// Drives SNW-NOTIFINTG-NEW (CREATE) and SNW-NOTIFINTG-CHG (ALTER).
// Predicates on statement kind only today; the shape carries
// enable / rename action flags for forward rule-extensibility.

pub fn lower_create_notification_integration_to_integration_plan(
    p: &AstCreateNotificationIntegration,
    source: &str,
) -> IntegrationPlan {
    let enabled_on_create = p.enabled_span.map(|sp| read_enabled_bool(sp, source));
    let shape = NotificationIntegrationShape {
        enabled_on_create,
        ..NotificationIntegrationShape::default()
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    IntegrationPlan {
        action: IntegrationAction::Create,
        integration_kind: IntegrationKindIr::Notification,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: IntegrationPlanVariant::Notification(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_alter_notification_integration_to_integration_plan(
    p: &AstAlterNotificationIntegration,
    source: &str,
) -> IntegrationPlan {
    use AstAlterNotificationIntegrationActionKind as A;
    let mut shape = NotificationIntegrationShape::default();
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;
    let mut renamed_to_name_span: Option<Span> = None;

    for action in &p.actions {
        match &action.kind {
            A::SetEnabled { value_span, .. } => {
                if read_enabled_bool(*value_span, source) {
                    shape.had_set_enabled_to_true = true;
                } else {
                    shape.had_set_enabled_to_false = true;
                }
            }
            A::UnsetEnabled { .. } => {
                // No SNW-NOTIFINTG-* rule predicates on UNSET ENABLED today.
            }
            A::SetComment { value_span, .. } => {
                comment = PolicyCommentAction::Set {
                    value_span: *value_span,
                };
            }
            A::UnsetComment { .. } => comment = PolicyCommentAction::Unset,
            A::SetTag { tags_span, .. } => set_tag_action_spans.push(*tags_span),
            A::UnsetTag { tags_span, .. } => unset_tag_action_spans.push(*tags_span),
            A::Rename { new_name_span, .. } => {
                shape.had_rename = true;
                renamed_to_name_span = Some(*new_name_span);
            }
            A::SetOther { .. } | A::UnsetOther { .. } => {
                // Forward-compat property setters; no rule consumer today.
            }
        }
    }

    IntegrationPlan {
        action: IntegrationAction::Alter,
        integration_kind: IntegrationKindIr::Notification,
        name_span: p.name_span,
        renamed_to_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: IntegrationPlanVariant::Notification(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_drop_notification_integration_to_integration_plan(
    p: &AstDropNotificationIntegration,
) -> IntegrationPlan {
    IntegrationPlan {
        action: IntegrationAction::Drop,
        integration_kind: IntegrationKindIr::Notification,
        name_span: p.integration_name_span,
        renamed_to_name_span: None,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: IntegrationPlanVariant::DropOnly,
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Security Integration
// ─────────────────────────────────────────────────────────────────────

pub fn lower_create_security_integration_to_integration_plan(
    p: &AstCreateSecurityIntegration,
    source: &str,
) -> IntegrationPlan {
    let integration_type = p
        .type_value_span
        .and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().to_ascii_uppercase());
    let enabled_on_create = p.enabled_value_span.map(|sp| read_enabled_bool(sp, source));
    let shape = SecurityIntegrationShape {
        integration_type,
        enabled_on_create,
        set_properties: security_property_pairs(&p.properties, source),
        ..SecurityIntegrationShape::default()
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    IntegrationPlan {
        action: IntegrationAction::Create,
        integration_kind: IntegrationKindIr::Security,
        name_span: p.name_span,
        renamed_to_name_span: None,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: IntegrationPlanVariant::Security(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

pub fn lower_alter_security_integration_to_integration_plan(
    p: &AstAlterSecurityIntegration,
    source: &str,
) -> IntegrationPlan {
    use AstAlterSecurityIntegrationActionKind as A;
    let mut shape = SecurityIntegrationShape::default();
    let mut renamed_to_name_span: Option<Span> = None;

    match &p.action.kind {
        A::Set { properties, .. } => {
            for prop in properties {
                let name = slice_span(source, prop.name_span)
                    .unwrap_or("")
                    .trim()
                    .to_ascii_uppercase();
                if name == "ENABLED" {
                    if let Some(value_span) = prop.value_span {
                        if read_enabled_bool(value_span, source) {
                            shape.had_set_enabled_to_true = true;
                        } else {
                            shape.had_set_enabled_to_false = true;
                        }
                        continue;
                    }
                }
                shape.set_properties.push(SecurityIntegrationPropertyIr {
                    name,
                    value: prop
                        .value_span
                        .and_then(|sp| slice_span(source, sp))
                        .map(|t| t.trim().to_string()),
                });
            }
        }
        A::Unset {
            property_name_spans,
            ..
        } => {
            for span in property_name_spans {
                let name = slice_span(source, *span)
                    .unwrap_or("")
                    .trim()
                    .to_ascii_uppercase();
                if name == "ENABLED" {
                    shape.had_unset_enabled = true;
                } else {
                    shape.unset_properties.push(name);
                }
            }
        }
        A::Rename { new_name_span, .. } => {
            shape.had_rename = true;
            renamed_to_name_span = Some(*new_name_span);
        }
        A::Unknown(_) => {}
    }

    IntegrationPlan {
        action: IntegrationAction::Alter,
        integration_kind: IntegrationKindIr::Security,
        name_span: p.name_span,
        renamed_to_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: IntegrationPlanVariant::Security(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is SECURITY INTEGRATION
/// (no typed drop AST exists for this kind). The caller gates on the
/// object type.
pub fn lower_drop_security_integration_to_integration_plan(s: &AstDrop) -> IntegrationPlan {
    IntegrationPlan {
        action: IntegrationAction::Drop,
        integration_kind: IntegrationKindIr::Security,
        name_span: s.target_name_span.unwrap_or(s.span),
        renamed_to_name_span: None,
        if_not_exists: false,
        if_exists: s.if_exists_span.is_some(),
        or_replace: false,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: IntegrationPlanVariant::DropOnly,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Resolve CREATE-body property pairs, excluding the three names that
/// have dedicated typed slots (TYPE / ENABLED / COMMENT).
fn security_property_pairs(
    properties: &[AstObjectProperty],
    source: &str,
) -> Vec<SecurityIntegrationPropertyIr> {
    properties
        .iter()
        .filter_map(|prop| {
            let name = slice_span(source, prop.name_span)?
                .trim()
                .to_ascii_uppercase();
            if matches!(name.as_str(), "TYPE" | "ENABLED" | "COMMENT") {
                return None;
            }
            Some(SecurityIntegrationPropertyIr {
                name,
                value: prop
                    .value_span
                    .and_then(|sp| slice_span(source, sp))
                    .map(|t| t.trim().to_string()),
            })
        })
        .collect()
}

/// Returns `true` if the parenthesized value span (e.g. `(a, b)` or
/// `()`) contains at least one identifier-bearing character — i.e. any
/// content beyond parens / whitespace / commas. Drives the
/// `had_set_allowed_network_rules_nonempty` bit used by
/// `SNW-EXTACC-NETRULE-ADD`.
pub(crate) fn has_non_paren_content_span(span: Span, source: &str) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    text.chars()
        .any(|c| !c.is_whitespace() && c != '(' && c != ')' && c != ',')
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

/// Read an `ENABLED = TRUE | FALSE` value span. Span may cover the
/// full clause (`ENABLED = TRUE`) or just the value side; tokenize and
/// pick the first TRUE/FALSE keyword. Defaults to `true` if neither is
/// found (matching Snowflake's ENABLED default).
pub(crate) fn read_enabled_bool(span: Span, source: &str) -> bool {
    use crate::lexer::{tokenize, Keyword, LiteralKind, TokenKind};
    let text = match slice_span(source, span) {
        Some(t) => t,
        None => return true,
    };
    let lex_result = tokenize(text);
    for token in &lex_result.tokens {
        match token.kind {
            // The Lexega lexer surfaces `TRUE` / `FALSE` as
            // `Literal(Boolean)` (see `LiteralKind::Boolean`), not as
            // bare keywords — gate on the lexeme content.
            TokenKind::Literal(LiteralKind::Boolean) => {
                let lexeme = &text[token.span.start as usize..token.span.end as usize];
                return lexeme.eq_ignore_ascii_case("true");
            }
            // Defensive: some tokenization paths still emit the
            // standalone keywords. Keep the explicit cases so the
            // helper stays robust if either source surfaces.
            TokenKind::Keyword(Keyword::True) => return true,
            TokenKind::Keyword(Keyword::False) => return false,
            _ => {}
        }
    }
    true
}

/// Convenience for callers that expect a `u32` (mirrors policy_plan
/// pattern, kept here for symmetry).
#[allow(dead_code)] // reserved for future integration-property lowering
pub(crate) fn read_int_u32(span: Span, source: &str) -> Option<u32> {
    extract_integer_literal_value(span, source).map(|v| v as u32)
}
