// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Integration DDL facts: CREATE / ALTER / DROP `[<KIND>] INTEGRATION`
//! statements. Covers the API, Storage, ExternalAccess, and Notification kinds.
//!
//! Top-level `IntegrationFacts` carries the kind discriminator, action,
//! target, and lifecycle changes (tags, comment); per-kind variants carry
//! the structural fields specific to each integration type.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::catalog::CatalogTag;
use super::ddl::DdlAction;
use super::identity::{IdentName, ObjectRef};
use super::policy::PolicyCommentChange;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct IntegrationFacts {
    pub kind: IntegrationKind,
    pub action: DdlAction,
    pub target: ObjectRef,
    pub variant: IntegrationVariantFacts,

    /// `ALTER … RENAME TO …` action (rare for integrations; reserved
    /// for forward compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_to: Option<IdentName>,

    /// `SET TAG <key> = '<value>' [, …]` actions on this statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_tags: Vec<CatalogTag>,

    /// `UNSET TAG <key> [, …]` action keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_tags: Vec<IdentName>,

    /// Comment lifecycle (`Unchanged` / `Set { text }` / `Unset`).
    #[serde(default)]
    pub comment: PolicyCommentChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "IntegrationType"))]
pub enum IntegrationKind {
    Api,
    Storage,
    ExternalAccess,
    Notification,
    Security,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntegrationVariantFacts {
    Api(ApiIntegrationVariantFacts),
    Storage(StorageIntegrationVariantFacts),
    ExternalAccess(ExternalAccessIntegrationVariantFacts),
    Notification(NotificationIntegrationVariantFacts),
    Security(SecurityIntegrationVariantFacts),
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ApiIntegrationVariantFacts {
    /// CREATE-time `ENABLED = TRUE | FALSE`. Omitted when the clause
    /// is absent (Snowflake default is `TRUE`); `false` when
    /// explicitly disabled at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_on_create: Option<bool>,
    /// CREATE-time `API_KEY = '…'` clause present.
    #[serde(default)]
    pub has_api_key_on_create: bool,
    /// CREATE-time `API_ALLOWED_PREFIXES = (…)` clause present.
    #[serde(default)]
    pub has_allowed_prefixes_on_create: bool,
    /// CREATE-time `API_BLOCKED_PREFIXES = (…)` clause present.
    #[serde(default)]
    pub has_blocked_prefixes_on_create: bool,

    // ── ALTER action flags ───────────────────────────────────────────
    #[serde(default)]
    pub had_set_enabled_to_true: bool,
    #[serde(default)]
    pub had_set_enabled_to_false: bool,
    #[serde(default)]
    pub had_set_api_key: bool,
    #[serde(default)]
    pub had_unset_api_key: bool,
    #[serde(default)]
    pub had_set_aws_role: bool,
    #[serde(default)]
    pub had_set_azure_ad_application_id: bool,
    #[serde(default)]
    pub had_set_allowed_prefixes: bool,
    #[serde(default)]
    pub had_set_blocked_prefixes: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StorageIntegrationVariantFacts {
    /// CREATE-time `ENABLED = TRUE | FALSE`. Omitted when the clause
    /// is absent (Snowflake default is `TRUE`); `false` when
    /// explicitly disabled at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_on_create: Option<bool>,

    // ── ALTER action flags ───────────────────────────────────────────
    #[serde(default)]
    pub had_set_enabled_to_true: bool,
    #[serde(default)]
    pub had_set_enabled_to_false: bool,
    #[serde(default)]
    pub had_set_aws_role: bool,
    #[serde(default)]
    pub had_set_azure_tenant: bool,
    #[serde(default)]
    pub had_set_allowed_locations: bool,
    #[serde(default)]
    pub had_set_blocked_locations: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ExternalAccessIntegrationVariantFacts {
    /// CREATE-time `ENABLED = TRUE | FALSE`. Omitted when the clause
    /// is absent (Snowflake default is `TRUE`); `false` when
    /// explicitly disabled at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_on_create: Option<bool>,

    // ── ALTER action flags ───────────────────────────────────────────
    #[serde(default)]
    pub had_set_enabled_to_true: bool,
    #[serde(default)]
    pub had_set_enabled_to_false: bool,
    /// `UNSET ENABLED` — reverts to the default enabled state.
    #[serde(default)]
    pub had_unset_enabled: bool,

    /// `SET ALLOWED_NETWORK_RULES = (...)` action (any form).
    #[serde(default)]
    pub had_set_allowed_network_rules: bool,
    /// `SET ALLOWED_NETWORK_RULES = (rule, …)` with at least one element.
    #[serde(default)]
    pub had_set_allowed_network_rules_nonempty: bool,
    /// `UNSET ALLOWED_NETWORK_RULES` action.
    #[serde(default)]
    pub had_unset_allowed_network_rules: bool,

    /// `SET ALLOWED_API_AUTHENTICATION_INTEGRATIONS = (...)` action.
    #[serde(default)]
    pub had_set_allowed_api_authentication_integrations: bool,
    #[serde(default)]
    pub had_unset_allowed_api_authentication_integrations: bool,

    /// `SET ALLOWED_AUTHENTICATION_SECRETS = (...)` action.
    #[serde(default)]
    pub had_set_allowed_authentication_secrets: bool,
    /// `UNSET ALLOWED_AUTHENTICATION_SECRETS` action.
    #[serde(default)]
    pub had_unset_allowed_authentication_secrets: bool,

    /// `RENAME TO <new_name>` action.
    #[serde(default)]
    pub had_rename: bool,
}

/// Security-integration (OAuth / SAML2 / SCIM / EXTERNAL_OAUTH provider)
/// statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SecurityIntegrationVariantFacts {
    /// `TYPE = <value>` (upper-cased), e.g. `OAUTH`, `SAML2`, `SCIM`,
    /// `EXTERNAL_OAUTH`. Absent when the statement does not state a type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_type: Option<String>,
    /// CREATE-time `ENABLED = TRUE | FALSE`. Omitted when the clause
    /// is absent; `false` when explicitly disabled at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_on_create: Option<bool>,

    // ── ALTER action flags ───────────────────────────────────────────
    #[serde(default)]
    pub had_set_enabled_to_true: bool,
    #[serde(default)]
    pub had_set_enabled_to_false: bool,
    /// `UNSET ENABLED` — reverts to the default enabled state.
    #[serde(default)]
    pub had_unset_enabled: bool,

    /// Property name/value pairs written by the statement (CREATE body
    /// or `ALTER … SET`), in declaration order. Names are upper-cased;
    /// TYPE / ENABLED / COMMENT appear in their dedicated fields instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_properties: Vec<SecurityIntegrationProperty>,
    /// Property names removed by `ALTER … UNSET` (upper-cased).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_properties: Vec<IdentName>,

    /// `RENAME TO <new_name>` action.
    #[serde(default)]
    pub had_rename: bool,
}

/// One `<name> = <value>` property written by a security-integration
/// statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SecurityIntegrationProperty {
    /// Upper-cased property name as written, e.g. `SAML2_FORCE_AUTHN`.
    pub name: IdentName,
    /// Raw value text as written (trimmed); absent for value-less
    /// keywords. Credential-bearing properties' values
    /// (`OAUTH_CLIENT_SECRET`, …) are masked in the facts copies
    /// attached to reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The value with any surrounding quotes stripped and upper-cased,
    /// for case- and quote-insensitive matching (`'Enable'`, `enable`,
    /// and `ENABLE` all normalize to `ENABLE`). Absent for value-less
    /// keywords. Match rule predicates against this; `value` keeps the
    /// verbatim spelling. Masked for credential-bearing properties, like
    /// `value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_normalized: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct NotificationIntegrationVariantFacts {
    /// CREATE-time `ENABLED = TRUE | FALSE`. Omitted when the clause
    /// is absent (Snowflake default is `TRUE`); `false` when
    /// explicitly disabled at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_on_create: Option<bool>,
    /// `ALTER … SET ENABLED = TRUE` action observed.
    #[serde(default)]
    pub had_set_enabled_to_true: bool,
    /// `ALTER … SET ENABLED = FALSE` action observed.
    #[serde(default)]
    pub had_set_enabled_to_false: bool,
    /// `ALTER … RENAME TO <new_name>` action observed.
    #[serde(default)]
    pub had_rename: bool,
}
