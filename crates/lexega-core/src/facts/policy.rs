// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Policy DDL facts: which policy kind, what action, body semantics, and
//! per-policy-kind structured payload.
//!
//! `body_semantics` captures the analytic shape (`AllowAll` /
//! `MaskingPassthrough` / `Conditional` etc.); `variant` carries the
//! kind-specific configuration (network rules, password length minimums,
//! authentication methods, …).

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::catalog::CatalogTag;
use super::ddl::DdlAction;
use super::expr::Expr;
use super::identity::{IdentName, ObjectRef};
use super::literal::DataType;
use super::query::PredicateEvent;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PolicyFacts {
    pub kind: PolicyKind,
    pub action: DdlAction,
    pub target: ObjectRef,
    pub body_semantics: PolicyBodySemantics,
    pub variant: PolicyVariantFacts,

    /// `ALTER … RENAME TO <new_name>` action. Omitted for CREATE /
    /// DROP / ALTER without RENAME.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_to: Option<IdentName>,

    /// `SET TAG <key> = '<value>' [, …]` actions on this statement. For
    /// CREATE this is the inline tag list; for ALTER this is each
    /// `SET TAG` action's contributions in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_tags: Vec<CatalogTag>,

    /// `UNSET TAG <key> [, …]` actions on ALTER statements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_tags: Vec<IdentName>,

    /// Comment lifecycle for this statement. `Unchanged` for CREATE
    /// without a `COMMENT = '…'` clause and ALTER without any
    /// `SET/UNSET COMMENT` action; `Set(text)` for CREATE-with-comment
    /// or `ALTER … SET COMMENT = '…'`; `Unset` for `ALTER … UNSET
    /// COMMENT`.
    #[serde(default)]
    pub comment: PolicyCommentChange,
}

/// Lifecycle of the `COMMENT` field on a policy DDL statement. Captures
/// CREATE-time and ALTER-time changes uniformly so rules can distinguish
/// "comment unchanged" from "comment removed".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyCommentChange {
    /// CREATE without a `COMMENT = '…'` clause, or ALTER without any
    /// `SET/UNSET COMMENT` action.
    #[default]
    Unchanged,
    /// CREATE-with-comment or `ALTER … SET COMMENT = '<text>'`.
    Set { text: String },
    /// `ALTER … UNSET COMMENT`.
    Unset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PolicyType"))]
pub enum PolicyKind {
    Masking,
    RowAccess,
    Network,
    Session,
    Password,
    Aggregation,
    Projection,
    Authentication,
    JoinPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyBodySemantics {
    /// Body is `TRUE` / always-pass / passthrough predicate.
    AllowAll,
    /// Body is `FALSE` / always-deny.
    DenyAll,
    /// Non-trivial conditional body.
    Conditional { conditions: Vec<PredicateEvent> },
    /// Masking policy returns the input column unchanged.
    MaskingPassthrough,
    /// Body semantics could not be analyzed.
    Opaque { reason: PolicyBodyOpaqueReason },
    /// `DROP` statement — no body to analyze.
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PolicyBodyOpaqueReason {
    UnparsedExpression,
    DialectSpecificFunction,
    UnresolvedCatalogReference,
    CrossDatabaseReference,
    /// Body references a procedural variable / parameter.
    ProceduralReference,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyVariantFacts {
    Masking(MaskingPolicyFacts),
    RowAccess(RowAccessPolicyFacts),
    Network(NetworkPolicyFacts),
    Session(SessionPolicyFacts),
    Password(PasswordPolicyFacts),
    Aggregation(AggregationPolicyFacts),
    Projection(ProjectionPolicyFacts),
    JoinPolicy(JoinPolicyFacts),
    Authentication(AuthenticationPolicyFacts),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MaskingPolicyFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PolicyArgument>,
    pub return_type: DataType,
    /// `EXEMPT_OTHER_POLICIES = TRUE` clause present on CREATE — the
    /// masking policy bypasses other policies on the same column.
    #[serde(default)]
    pub exempt_other_policies: bool,
    /// Masking body expression. Present for `CREATE MASKING POLICY` and
    /// for `ALTER MASKING POLICY … SET BODY -> …`. Absent for ALTER
    /// actions that don't carry a body (rename / tag / comment) and for DROP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Expr>,
    /// All expressions the body can yield on any code path, after fanning
    /// out CASE branches and stripping no-op casts. Empty when `body` is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_terminal_returns: Vec<Expr>,
    /// For each value the masking body can return, whether that value is one
    /// of the policy's input arguments returned unchanged. Aligned by position
    /// with `body_terminal_returns`. A policy whose every return is an
    /// unchanged input applies no masking.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_terminal_flows: Vec<MaskTerminalFlow>,
}

/// Whether a value a masking policy can return exposes one of the policy's
/// input arguments unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MaskTerminalFlow {
    /// Returns the input argument at `arg_position` unchanged: the original
    /// value is exposed without masking.
    Identity { arg_position: u32 },
    /// Returns a transformed value, a constant, or some other value rather
    /// than an unchanged input argument.
    Altered,
}

impl Default for MaskingPolicyFacts {
    fn default() -> Self {
        Self {
            arguments: Vec::new(),
            return_type: DataType {
                kind: super::literal::DataTypeKind::Other(IdentName::new("")),
                precision: None,
                scale: None,
                length: None,
                element_type: None,
                key_type: None,
                fields: Vec::new(),
                timezone: None,
                raw: String::new(),
            },
            exempt_other_policies: false,
            body: None,
            body_terminal_returns: Vec::new(),
            body_terminal_flows: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct RowAccessPolicyFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PolicyArgument>,
    /// Expected `BOOLEAN`.
    pub return_type: DataType,
    /// Row access filter expression. Present for `CREATE ROW ACCESS POLICY`
    /// (Snowflake body / BigQuery `FILTER USING (...)`) and for `ALTER …
    /// SET BODY -> …`. Absent for ALTER actions without a body and for DROP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Expr>,
    /// All expressions the body can yield on any code path, after fanning
    /// out CASE branches and stripping no-op casts. Empty when `body` is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_terminal_returns: Vec<Expr>,
    /// PostgreSQL `CREATE/ALTER POLICY ... USING (<expr>)` boolean
    /// read-filter. Omitted for Snowflake/BigQuery row-access policies
    /// (those carry the predicate in `body`) and for PG ALTER actions
    /// without a USING clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub using_predicate: Option<PolicyPredicate>,
    /// PostgreSQL `CREATE/ALTER POLICY ... WITH CHECK (<expr>)` boolean
    /// write-filter. Omitted for non-PG dialects and for PG statements
    /// without a `WITH CHECK` clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_predicate: Option<PolicyPredicate>,
    /// PostgreSQL `AS PERMISSIVE | RESTRICTIVE` modifier. Omitted for
    /// non-PG dialects and for PG statements that omit the clause
    /// (the implicit default is `PERMISSIVE`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissiveness: Option<PgPolicyPermissiveness>,
    /// PostgreSQL `FOR { ALL | SELECT | INSERT | UPDATE | DELETE }`
    /// modifier. Omitted for non-PG dialects and for PG statements
    /// that omit the clause (the implicit default is `ALL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<PgPolicyCommand>,
}

impl Default for RowAccessPolicyFacts {
    fn default() -> Self {
        Self {
            arguments: Vec::new(),
            return_type: DataType {
                kind: super::literal::DataTypeKind::Other(IdentName::new("")),
                precision: None,
                scale: None,
                length: None,
                element_type: None,
                key_type: None,
                fields: Vec::new(),
                timezone: None,
                raw: String::new(),
            },
            body: None,
            body_terminal_returns: Vec::new(),
            using_predicate: None,
            check_predicate: None,
            permissiveness: None,
            command: None,
        }
    }
}

/// A boolean policy predicate (PostgreSQL `USING` or `WITH CHECK` clause).
/// Carries the parsed expression tree and the body semantics classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PolicyPredicate {
    /// Parsed predicate expression as a public structural `Expr` tree.
    pub body: Expr,
    /// Body semantics classification. `AllowAll` for provable tautologies
    /// (`true`, `1=1`, …); other arms describe the remaining predicate shapes.
    pub body_semantics: PolicyBodySemantics,
    /// Set of expressions this predicate can yield on any code path
    /// after fanning out CASE branches and stripping no-op casts.
    /// Empty when the predicate body could not be reduced to terminal
    /// returns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_terminal_returns: Vec<Expr>,
}

/// PostgreSQL `CREATE POLICY ... AS PERMISSIVE | RESTRICTIVE` modifier.
/// `Permissive` policies combine disjunctively (OR) with peers; `Restrictive`
/// policies combine conjunctively (AND). PostgreSQL defaults to `Permissive`
/// when the clause is omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PostgresPolicyMode"))]
pub enum PgPolicyPermissiveness {
    Permissive,
    Restrictive,
}

/// PostgreSQL `CREATE POLICY ... FOR { ALL | SELECT | INSERT | UPDATE | DELETE }`
/// modifier. Each command has distinct evaluation semantics for `USING`
/// and `WITH CHECK`. `All` is the implicit default when the clause is omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PostgresPolicyCommand"))]
pub enum PgPolicyCommand {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct NetworkPolicyFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ip_lists: Vec<IpListEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_ip_lists: Vec<IpListEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_network_rules: Vec<ObjectRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_network_rules: Vec<ObjectRef>,
    /// One entry per property clause written in the statement —
    /// `ALLOWED_IP_LIST` / `BLOCKED_IP_LIST` /
    /// `ALLOWED_NETWORK_RULE_LIST` / `BLOCKED_NETWORK_RULE_LIST` /
    /// `COMMENT` — regardless of value count. An empty
    /// `ALLOWED_IP_LIST = ()` still emits a property entry. The actual
    /// IP / rule values live on `allowed_ip_lists` /
    /// `blocked_network_rules` / etc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<NetworkPolicyProperty>,
    /// `ALTER … SET (…)` action — wholesale list replacement.
    #[serde(default)]
    pub had_set_action: bool,
    /// `ALTER … ADD <list>` action — additive change.
    #[serde(default)]
    pub had_add_action: bool,
    /// `ALTER … REMOVE <list>` action.
    #[serde(default)]
    pub had_remove_action: bool,
}

/// One property-clause occurrence in a network-policy CREATE /
/// ALTER. Match with
/// `properties: { exists: { kind: allowed_ip_list } }` to detect a
/// specific property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct NetworkPolicyProperty {
    pub kind: NetworkPolicyPropertyKind,
}

/// Typed kind of property clause that appeared in a network-policy
/// CREATE / ALTER. One entry is pushed onto
/// [`NetworkPolicyFacts::properties`] for every property the statement
/// syntactically specified — regardless of whether the value list was
/// non-empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyPropertyKind {
    AllowedIpList,
    BlockedIpList,
    AllowedNetworkRules,
    BlockedNetworkRules,
    Comment,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct IpListEntry {
    pub raw: String,
    pub cidr_prefix: Option<u32>,
    pub is_private_range: Option<bool>,
    /// `0.0.0.0/0` — accepts all traffic.
    pub is_zero_route: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SessionPolicyFacts {
    pub session_idle_timeout_mins: Option<u32>,
    pub session_ui_idle_timeout_mins: Option<u32>,
    /// Fields that the ALTER statement explicitly `UNSET`s (vs simply
    /// not modifying). Empty for CREATE and DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_fields: Vec<SessionPolicyField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionPolicyField {
    SessionIdleTimeoutMins,
    SessionUiIdleTimeoutMins,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PasswordPolicyFacts {
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    pub min_upper_case_chars: Option<u32>,
    pub min_lower_case_chars: Option<u32>,
    pub min_numeric_chars: Option<u32>,
    pub min_special_chars: Option<u32>,
    pub min_age_days: Option<u32>,
    pub max_age_days: Option<u32>,
    pub max_retries: Option<u32>,
    pub lockout_time_mins: Option<u32>,
    pub history: Option<u32>,
    /// Fields that the ALTER statement explicitly `UNSET`s (vs simply
    /// not modifying). Empty for CREATE and DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_fields: Vec<PasswordPolicyField>,
    /// Character classes required by the policy (`PASSWORD_MIN_*_CHARS > 0`).
    /// One entry per character class whose minimum is greater than zero.
    /// Empty for ALTER and DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub complexity_classes: Vec<PasswordPolicyComplexityClass>,
}

/// Character-class buckets gating password complexity. One entry
/// per `PASSWORD_MIN_*_CHARS` property whose value is > 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PasswordCharacterClass"))]
pub enum PasswordPolicyComplexityClass {
    Upper,
    Lower,
    Numeric,
    Special,
}

/// Password-policy field identifiers that can be `UNSET` in an
/// ALTER PASSWORD POLICY statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PasswordPolicyField {
    MinLength,
    MaxLength,
    MinUpperCaseChars,
    MinLowerCaseChars,
    MinNumericChars,
    MinSpecialChars,
    MinAgeDays,
    MaxAgeDays,
    MaxRetries,
    LockoutTimeMins,
    History,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AggregationPolicyFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PolicyArgument>,
    /// Smallest `MIN_GROUP_SIZE` literal observed in the policy body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_group_size: Option<u32>,
    /// Body uses (or branches via CASE to) `NO_AGGREGATION_CONSTRAINT()`.
    #[serde(default)]
    pub has_no_aggregation_constraint: bool,
    /// Body is a `CASE WHEN … THEN … ELSE … END` expression.
    #[serde(default)]
    pub has_conditional_body: bool,
    /// `ALTER … SET BODY -> …` action present.
    #[serde(default)]
    pub had_body_change: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ProjectionPolicyFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PolicyArgument>,
    /// Body uses (or branches via CASE to) `PROJECTION_CONSTRAINT(ALLOW => TRUE)`.
    #[serde(default)]
    pub has_allow_list: bool,
    /// Body specifies `ENFORCEMENT => 'NULLIFY'` or `'NONE'` — neither
    /// hard-blocks the query (`NULLIFY` substitutes NULL, `NONE`
    /// performs no action), so both classify as enforcement disabled.
    #[serde(default)]
    pub has_enforcement_disabled: bool,
    /// Body specifies `ENFORCEMENT => …` with a value other than the
    /// recognized disabled sentinels (`NULLIFY` / `NONE`).
    #[serde(default)]
    pub has_enforcement_enabled: bool,
    /// Body is a `CASE WHEN … THEN … ELSE … END` expression.
    #[serde(default)]
    pub has_conditional_body: bool,
    /// `ALTER … SET BODY -> …` action present.
    #[serde(default)]
    pub had_body_change: bool,
}

/// Snowflake JOIN POLICY recognition facts. A join policy's body calls
/// `JOIN_CONSTRAINT(JOIN_REQUIRED => <bool>)`: `TRUE` requires a join
/// predicate, `FALSE` permits unrestricted joins.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct JoinPolicyFacts {
    /// Body uses (or branches via CASE to) `JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE)`.
    #[serde(default)]
    pub has_join_required: bool,
    /// Body uses (or branches to) `JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE)`
    /// — the policy imposes no join restriction.
    #[serde(default)]
    pub has_join_not_required: bool,
    /// Body is a `CASE WHEN … THEN … ELSE … END` expression.
    #[serde(default)]
    pub has_conditional_body: bool,
    /// `ALTER … SET BODY -> …` action present.
    #[serde(default)]
    pub had_body_change: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AuthenticationPolicyFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication_methods: Vec<AuthMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mfa_authentication_methods: Vec<AuthMethod>,
    #[serde(default)]
    pub mfa_enrollment: MfaEnrollmentLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_types: Vec<ClientType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_integrations: Vec<ObjectRef>,

    /// CREATE-time: whether MFA is required, computed from
    /// `MFA_ENROLLMENT = REQUIRED` or `MFA_POLICY = REQUIRED`.
    #[serde(default)]
    pub mfa_required: bool,
    /// ALTER: SET / UNSET AUTHENTICATION_METHODS action present.
    #[serde(default)]
    pub had_methods_change: bool,
    /// ALTER: SET / UNSET MFA_ENROLLMENT or MFA_POLICY action present.
    #[serde(default)]
    pub had_mfa_change: bool,
    /// ALTER: SET / UNSET CLIENT_TYPES action present.
    #[serde(default)]
    pub had_client_types_change: bool,
    /// ALTER: SET / UNSET SECURITY_INTEGRATIONS action present.
    #[serde(default)]
    pub had_security_integrations_change: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Saml,
    Oauth,
    KeyPair,
    ProgrammaticAccessToken,
    All,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "MultiFactorAuthLevel"))]
pub enum MfaEnrollmentLevel {
    #[default]
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    SnowflakeUi,
    Drivers,
    SnowSql,
    All,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PolicyArgument {
    pub name: IdentName,
    pub data_type: DataType,
}
