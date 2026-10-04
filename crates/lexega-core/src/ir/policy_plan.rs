// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE | ALTER | DROP <…> POLICY` statements.
//!
//! Source-string-free typed projection of the AST consumed by
//! `derive_facts_from_policy_plan` to build a public
//! `StatementFacts.policy` carrier.
//!
//! Each policy kind (`Password`, `Masking`, `RowAccess`, `Network`,
//! `Session`, `Aggregation`, `Projection`, `Authentication`, …) is a
//! [`PolicyPlanVariant`] with its own lowering functions.
//! The dispatch in [`crate::Engine::analyze_ddl_facts`] wires
//! the AST variant directly to its lowering function — no fallback
//! arm projects an "Unimplemented" plan, matching the structural
//! invariant that every dispatched plan has a facts projection.

use crate::ast::{
    AlterPgPolicyAction, AstAlterAggregationPolicy, AstAlterAggregationPolicyActionKind,
    AstAlterAuthenticationPolicy, AstAlterAuthenticationPolicyActionKind, AstAlterJoinPolicy,
    AstAlterJoinPolicyActionKind, AstAlterMaskingPolicy, AstAlterMaskingPolicyActionKind,
    AstAlterNetworkPolicy, AstAlterNetworkPolicyActionKind, AstAlterPasswordPolicy,
    AstAlterPasswordPolicyActionKind, AstAlterPgPolicy, AstAlterProjectionPolicy,
    AstAlterProjectionPolicyActionKind, AstAlterRowAccessPolicy, AstAlterRowAccessPolicyActionKind,
    AstAlterSessionPolicy, AstAlterSessionPolicyActionKind, AstCreateAggregationPolicy,
    AstCreateAuthenticationPolicy, AstCreateJoinPolicy, AstCreateMaskingPolicy,
    AstCreateNetworkPolicy, AstCreatePasswordPolicy, AstCreatePgPolicy, AstCreateProjectionPolicy,
    AstCreateRowAccessPolicy, AstCreateSessionPolicy, AstDropAggregationPolicy,
    AstDropAuthenticationPolicy, AstDropJoinPolicy, AstDropMaskingPolicy, AstDropNetworkPolicy,
    AstDropPasswordPolicy, AstDropPgPolicy, AstDropProjectionPolicy, AstDropRowAccessPolicy,
    AstDropSessionPolicy, AstExpr, AstFunctionArg, AstNetworkPolicyPropertyKind,
    CreatePolicyProperty, NodeId, PgCascadeRestrict, PgPolicyCommand as AstPgPolicyCommand,
    PgPolicyPermissiveness as AstPgPolicyPermissiveness,
};
use crate::ir::span_extract::{extract_integer_literal_value, extract_string_literal_value};
use crate::lexer::token::Span;

/// Source-string-free carrier for one CREATE / ALTER / DROP `<…>
/// POLICY` statement. Generic across policy kinds via
/// [`PolicyPlanVariant`]; the kind-agnostic action / lifecycle fields
/// (rename, tag, comment) live on this struct so rules can predicate
/// on them uniformly across policy kinds.
#[derive(Debug, Clone)]
pub struct PolicyPlan {
    pub action: PolicyAction,
    pub policy_kind: PolicyKindIr,
    /// Span of the policy name identifier (CREATE / ALTER / DROP all
    /// carry one).
    pub policy_name_span: Span,
    /// `IF NOT EXISTS` (CREATE only).
    pub if_not_exists: bool,
    /// `IF EXISTS` (ALTER / DROP only).
    pub if_exists: bool,
    /// `OR REPLACE` (CREATE only).
    pub or_replace: bool,

    /// `ALTER … RENAME TO <new_name>` — span of the new name. `None`
    /// for CREATE / DROP / ALTER without RENAME.
    pub renamed_to_span: Option<Span>,

    /// `SET TAG <key>=<value> [, …]` actions on this statement. For
    /// CREATE this is empty (CREATE PASSWORD POLICY does not support
    /// inline tags in Snowflake); for ALTER each entry's span covers
    /// the `<key>=<value>` pair list of one `SET TAG` action.
    pub set_tag_action_spans: Vec<Span>,

    /// `UNSET TAG <key> [, …]` action spans on ALTER statements. Each
    /// entry's span covers the comma-separated key list.
    pub unset_tag_action_spans: Vec<Span>,

    /// Comment-action lifecycle.
    pub comment: PolicyCommentAction,

    /// Per-policy-kind structured payload.
    pub variant: PolicyPlanVariant,

    pub node_id: NodeId,
    pub span: Span,
}

/// Top-level statement action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyAction {
    Create,
    Alter,
    Drop,
}

/// IR-side mirror of [`crate::facts::PolicyKind`]. Closed enum — every
/// supported policy kind has exactly one variant. Adding a new policy
/// kind (e.g., a future `JoinPolicy`) requires extending both this
/// enum and [`crate::facts::PolicyKind`] together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyKindIr {
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

/// Comment-clause lifecycle on a policy DDL statement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PolicyCommentAction {
    /// CREATE without a `COMMENT = '…'` clause, or ALTER without any
    /// `SET/UNSET COMMENT` action.
    #[default]
    Unchanged,
    /// CREATE-with-comment or `ALTER … SET COMMENT = '…'`. Carries the
    /// span of the value side (string-literal text inclusive of
    /// quotes); the projection slices and unquotes.
    Set { value_span: Span },
    /// `ALTER … UNSET COMMENT`.
    Unset,
}

/// Per-policy-kind structured payload. One variant per policy kind —
/// no fallback / opaque arm. New policy kinds add new variants.
#[derive(Debug, Clone)]
pub enum PolicyPlanVariant {
    Password(PasswordPolicyShape),
    Session(SessionPolicyShape),
    Network(NetworkPolicyShape),
    Authentication(AuthenticationPolicyShape),
    Aggregation(AggregationPolicyShape),
    Projection(ProjectionPolicyShape),
    JoinPolicy(JoinPolicyShape),
    Masking(MaskingPolicyShape),
    RowAccess(RowAccessPolicyShape),
    /// Sentinel for a DROP statement: no per-kind body to project.
    /// The kind discriminator on [`PolicyPlan::policy_kind`] disambiguates
    /// which empty per-kind facts variant fact extraction produces. The
    /// `cascade` flag carries `DROP POLICY ... CASCADE`-style modifiers
    /// from dialects that accept them (PostgreSQL today); other dialects
    /// set `cascade: false`. The `on_table` span carries the
    /// `ON <table>` target reference from `DROP POLICY name ON table`
    /// (PostgreSQL grammar; Snowflake / BigQuery `DROP ROW ACCESS
    /// POLICY` has no ON-clause and leaves this `None`). The PG vs
    /// Snowflake/BigQuery routing decision lives at the
    /// `analyze_ddl_facts` dispatch site via
    /// [`crate::facts::extract::PolicyDialectOrigin`] — not in this
    /// field.
    DropOnly {
        cascade: bool,
        on_table: Option<Span>,
    },
}

/// Password-policy structured payload. Each `Option<u32>` slot is
/// populated when the AST carries a corresponding property (CREATE) or
/// SET action (ALTER). UNSET actions feed `unset_fields` instead.
///
/// Last-writer-wins for repeated SET actions in a single ALTER; this
/// matches Snowflake's source-order semantics.
#[derive(Debug, Clone, Default)]
pub struct PasswordPolicyShape {
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
    pub unset_fields: Vec<PasswordPolicyFieldIr>,
}

/// IR-side mirror of [`crate::facts::PasswordPolicyField`]. One arm
/// per `Set*` / `Unset*` action in
/// [`AstAlterPasswordPolicyActionKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordPolicyFieldIr {
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

// ─────────────────────────────────────────────────────────────────────
// CREATE PASSWORD POLICY → PolicyPlan
// ─────────────────────────────────────────────────────────────────────

/// Lower a typed [`AstCreatePasswordPolicy`] into a [`PolicyPlan`].
///
/// CREATE PASSWORD POLICY carries property values inline as
/// `Vec<CreatePolicyProperty>`; the projection scans the list for
/// each known property name (case-insensitive) and parses the value
/// span as an integer literal (per the password-policy grammar all
/// non-COMMENT properties are integers).
pub fn lower_create_password_policy_to_policy_plan(
    p: &AstCreatePasswordPolicy,
    source: &str,
) -> PolicyPlan {
    let shape = PasswordPolicyShape {
        min_length: pwd_int(&p.properties, "PASSWORD_MIN_LENGTH", source),
        max_length: pwd_int(&p.properties, "PASSWORD_MAX_LENGTH", source),
        min_upper_case_chars: pwd_int(&p.properties, "PASSWORD_MIN_UPPER_CASE_CHARS", source),
        min_lower_case_chars: pwd_int(&p.properties, "PASSWORD_MIN_LOWER_CASE_CHARS", source),
        min_numeric_chars: pwd_int(&p.properties, "PASSWORD_MIN_NUMERIC_CHARS", source),
        min_special_chars: pwd_int(&p.properties, "PASSWORD_MIN_SPECIAL_CHARS", source),
        min_age_days: pwd_int(&p.properties, "PASSWORD_MIN_AGE_DAYS", source),
        max_age_days: pwd_int(&p.properties, "PASSWORD_MAX_AGE_DAYS", source),
        max_retries: pwd_int(&p.properties, "PASSWORD_MAX_RETRIES", source),
        lockout_time_mins: pwd_int(&p.properties, "PASSWORD_LOCKOUT_TIME_MINS", source),
        history: pwd_int(&p.properties, "PASSWORD_HISTORY", source),
        unset_fields: Vec::new(),
    };

    let comment = match find_property_value_span(&p.properties, "COMMENT", source) {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };

    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::Password,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Password(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// ALTER PASSWORD POLICY → PolicyPlan
// ─────────────────────────────────────────────────────────────────────

/// Lower a typed [`AstAlterPasswordPolicy`] into a [`PolicyPlan`].
///
/// Walks the action list in source order. Each `Set*` action assigns
/// the corresponding `Option<u32>` slot via `extract_integer_literal_value`
/// (last-writer-wins for repeated SETs). Each `Unset*` action pushes
/// the corresponding [`PasswordPolicyFieldIr`] onto `unset_fields`.
/// `RenameTo`, `SetTag`, `UnsetTag`, `SetComment`, `UnsetComment` flow
/// to the kind-agnostic top-level fields on [`PolicyPlan`].
pub fn lower_alter_password_policy_to_policy_plan(
    p: &AstAlterPasswordPolicy,
    source: &str,
) -> PolicyPlan {
    let mut shape = PasswordPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    for action in &p.actions {
        apply_alter_password_action(
            &action.kind,
            source,
            &mut shape,
            &mut renamed_to_span,
            &mut set_tag_action_spans,
            &mut unset_tag_action_spans,
            &mut comment,
        );
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::Password,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::Password(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

fn apply_alter_password_action(
    kind: &AstAlterPasswordPolicyActionKind,
    source: &str,
    shape: &mut PasswordPolicyShape,
    renamed_to_span: &mut Option<Span>,
    set_tag_action_spans: &mut Vec<Span>,
    unset_tag_action_spans: &mut Vec<Span>,
    comment: &mut PolicyCommentAction,
) {
    use AstAlterPasswordPolicyActionKind as A;

    let parse_int = |span: Span| -> Option<u32> {
        extract_integer_literal_value(span, source).map(|v| v as u32)
    };

    match kind {
        A::RenameTo { new_name_span, .. } => {
            *renamed_to_span = Some(*new_name_span);
        }

        // SET PASSWORD_*
        A::SetPasswordMinLength { value_span, .. } => shape.min_length = parse_int(*value_span),
        A::SetPasswordMaxLength { value_span, .. } => shape.max_length = parse_int(*value_span),
        A::SetPasswordMinUpperCaseChars { value_span, .. } => {
            shape.min_upper_case_chars = parse_int(*value_span);
        }
        A::SetPasswordMinLowerCaseChars { value_span, .. } => {
            shape.min_lower_case_chars = parse_int(*value_span);
        }
        A::SetPasswordMinNumericChars { value_span, .. } => {
            shape.min_numeric_chars = parse_int(*value_span);
        }
        A::SetPasswordMinSpecialChars { value_span, .. } => {
            shape.min_special_chars = parse_int(*value_span);
        }
        A::SetPasswordMinAgeDays { value_span, .. } => shape.min_age_days = parse_int(*value_span),
        A::SetPasswordMaxAgeDays { value_span, .. } => shape.max_age_days = parse_int(*value_span),
        A::SetPasswordMaxRetries { value_span, .. } => shape.max_retries = parse_int(*value_span),
        A::SetPasswordLockoutTimeMins { value_span, .. } => {
            shape.lockout_time_mins = parse_int(*value_span);
        }
        A::SetPasswordHistory { value_span, .. } => shape.history = parse_int(*value_span),

        // UNSET PASSWORD_*
        A::UnsetPasswordMinLength { .. } => {
            shape.unset_fields.push(PasswordPolicyFieldIr::MinLength);
        }
        A::UnsetPasswordMaxLength { .. } => {
            shape.unset_fields.push(PasswordPolicyFieldIr::MaxLength);
        }
        A::UnsetPasswordMinUpperCaseChars { .. } => shape
            .unset_fields
            .push(PasswordPolicyFieldIr::MinUpperCaseChars),
        A::UnsetPasswordMinLowerCaseChars { .. } => shape
            .unset_fields
            .push(PasswordPolicyFieldIr::MinLowerCaseChars),
        A::UnsetPasswordMinNumericChars { .. } => shape
            .unset_fields
            .push(PasswordPolicyFieldIr::MinNumericChars),
        A::UnsetPasswordMinSpecialChars { .. } => shape
            .unset_fields
            .push(PasswordPolicyFieldIr::MinSpecialChars),
        A::UnsetPasswordMinAgeDays { .. } => {
            shape.unset_fields.push(PasswordPolicyFieldIr::MinAgeDays);
        }
        A::UnsetPasswordMaxAgeDays { .. } => {
            shape.unset_fields.push(PasswordPolicyFieldIr::MaxAgeDays);
        }
        A::UnsetPasswordMaxRetries { .. } => {
            shape.unset_fields.push(PasswordPolicyFieldIr::MaxRetries);
        }
        A::UnsetPasswordLockoutTimeMins { .. } => shape
            .unset_fields
            .push(PasswordPolicyFieldIr::LockoutTimeMins),
        A::UnsetPasswordHistory { .. } => {
            shape.unset_fields.push(PasswordPolicyFieldIr::History);
        }

        // Tag / comment lifecycle (kind-agnostic — flows up).
        A::SetTag {
            assignments_span, ..
        } => set_tag_action_spans.push(*assignments_span),
        A::UnsetTag { tags_span, .. } => unset_tag_action_spans.push(*tags_span),
        A::SetComment {
            comment_value_span, ..
        } => {
            *comment = PolicyCommentAction::Set {
                value_span: *comment_value_span,
            };
        }
        A::UnsetComment { .. } => {
            *comment = PolicyCommentAction::Unset;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// DROP PASSWORD POLICY → PolicyPlan
// ─────────────────────────────────────────────────────────────────────

/// Lower a typed [`AstDropPasswordPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_password_policy_to_policy_plan(p: &AstDropPasswordPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::Password,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Session policy lowering.
// ─────────────────────────────────────────────────────────────────────

/// Session-policy structured payload. Mirrors the Snowflake CREATE /
/// ALTER SESSION POLICY surface: two integer timeouts plus the two
/// secondary-role list flags (presence-only — the public schema does
/// not yet expose individual role names).
#[derive(Debug, Clone, Default)]
pub struct SessionPolicyShape {
    pub session_idle_timeout_mins: Option<u32>,
    pub session_ui_idle_timeout_mins: Option<u32>,
    /// Whether `ALLOWED_SECONDARY_ROLES = (...)` was set.
    pub has_allowed_secondary_roles: bool,
    /// Whether `BLOCKED_SECONDARY_ROLES = (...)` was set.
    pub has_blocked_secondary_roles: bool,
    pub unset_fields: Vec<SessionPolicyFieldIr>,
}

/// IR-side mirror of [`crate::facts::SessionPolicyField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionPolicyFieldIr {
    SessionIdleTimeoutMins,
    SessionUiIdleTimeoutMins,
    AllowedSecondaryRoles,
    BlockedSecondaryRoles,
}

/// Lower a typed [`AstCreateSessionPolicy`] into a [`PolicyPlan`].
pub fn lower_create_session_policy_to_policy_plan(
    p: &AstCreateSessionPolicy,
    source: &str,
) -> PolicyPlan {
    let shape = SessionPolicyShape {
        session_idle_timeout_mins: pwd_int(&p.properties, "SESSION_IDLE_TIMEOUT_MINS", source),
        session_ui_idle_timeout_mins: pwd_int(
            &p.properties,
            "SESSION_UI_IDLE_TIMEOUT_MINS",
            source,
        ),
        has_allowed_secondary_roles: find_property_value_span(
            &p.properties,
            "ALLOWED_SECONDARY_ROLES",
            source,
        )
        .is_some(),
        has_blocked_secondary_roles: find_property_value_span(
            &p.properties,
            "BLOCKED_SECONDARY_ROLES",
            source,
        )
        .is_some(),
        unset_fields: Vec::new(),
    };

    let comment = match find_property_value_span(&p.properties, "COMMENT", source) {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };

    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::Session,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Session(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterSessionPolicy`] into a [`PolicyPlan`].
pub fn lower_alter_session_policy_to_policy_plan(
    p: &AstAlterSessionPolicy,
    source: &str,
) -> PolicyPlan {
    use AstAlterSessionPolicyActionKind as A;

    let mut shape = SessionPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    let parse_int = |span: Span| -> Option<u32> {
        extract_integer_literal_value(span, source).map(|v| v as u32)
    };

    for action in &p.actions {
        match &action.kind {
            A::RenameTo { new_name_span, .. } => {
                renamed_to_span = Some(*new_name_span);
            }
            A::SetSessionIdleTimeoutMins { value_span, .. } => {
                shape.session_idle_timeout_mins = parse_int(*value_span);
            }
            A::SetSessionUiIdleTimeoutMins { value_span, .. } => {
                shape.session_ui_idle_timeout_mins = parse_int(*value_span);
            }
            A::SetAllowedSecondaryRoles { .. } => {
                shape.has_allowed_secondary_roles = true;
            }
            A::SetBlockedSecondaryRoles { .. } => {
                shape.has_blocked_secondary_roles = true;
            }
            A::UnsetSessionIdleTimeoutMins { .. } => {
                shape
                    .unset_fields
                    .push(SessionPolicyFieldIr::SessionIdleTimeoutMins);
            }
            A::UnsetSessionUiIdleTimeoutMins { .. } => {
                shape
                    .unset_fields
                    .push(SessionPolicyFieldIr::SessionUiIdleTimeoutMins);
            }
            A::UnsetAllowedSecondaryRoles { .. } => {
                shape
                    .unset_fields
                    .push(SessionPolicyFieldIr::AllowedSecondaryRoles);
            }
            A::UnsetBlockedSecondaryRoles { .. } => {
                shape
                    .unset_fields
                    .push(SessionPolicyFieldIr::BlockedSecondaryRoles);
            }
            A::SetTag {
                assignments_span, ..
            } => set_tag_action_spans.push(*assignments_span),
            A::UnsetTag { tags_span, .. } => unset_tag_action_spans.push(*tags_span),
            A::SetComment {
                comment_value_span, ..
            } => {
                comment = PolicyCommentAction::Set {
                    value_span: *comment_value_span,
                };
            }
            A::UnsetComment { .. } => {
                comment = PolicyCommentAction::Unset;
            }
        }
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::Session,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::Session(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropSessionPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_session_policy_to_policy_plan(p: &AstDropSessionPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::Session,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Property-list helpers (CREATE-time path).
// ─────────────────────────────────────────────────────────────────────

fn pwd_int(props: &[CreatePolicyProperty], name: &str, source: &str) -> Option<u32> {
    let span = find_property_value_span(props, name, source)?;
    extract_integer_literal_value(span, source).map(|v| v as u32)
}

/// Returns the value_span of the first property whose name matches
/// `name` (case-insensitive).
fn find_property_value_span(
    properties: &[CreatePolicyProperty],
    name: &str,
    source: &str,
) -> Option<Span> {
    for p in properties {
        let prop_name = crate::ir::utils::slice_span(source, p.name_span)?;
        if prop_name.trim().eq_ignore_ascii_case(name) {
            return Some(p.value_span);
        }
    }
    None
}

/// Extract a comment string (quotes stripped, `''` escapes folded)
/// from a [`PolicyCommentAction::Set`] value span. Public to the IR /
/// facts modules; used by `derive_facts_from_policy_plan` to build the
/// public `PolicyCommentChange::Set` payload.
pub fn comment_text_from_value_span(value_span: Span, source: &str) -> Option<String> {
    extract_string_literal_value(value_span, source)
}

/// Extract the value side of a `NAME = VALUE` clause where the AST
/// span covers the full clause. The parser-side structural split on
/// `=` is lossless; this is the inverse projection retrieving the
/// already-parsed value. Used by lowering for AUTHENTICATION POLICY
/// enum-shaped properties (`MFA_ENROLLMENT`, `MFA_POLICY`,
/// `PAT_POLICY`, `WORKLOAD_IDENTITY_POLICY`) until the AST surfaces
/// per-property value spans separately.
fn value_after_eq(span: Span, source: &str) -> Option<&str> {
    crate::ir::utils::slice_span(source, span)
        .and_then(|text| text.split_once('=').map(|(_, value)| value.trim()))
}

// ─────────────────────────────────────────────────────────────────────
// Network policy lowering.
// ─────────────────────────────────────────────────────────────────────

/// Network-policy structured payload. Each list field is a Vec of value
/// spans pointing into the source; fact extraction slices and projects
/// them into public `IpListEntry` / `ObjectRef` Vecs. The action flags
/// (mutually exclusive across an ALTER's single `action` field) drive
/// the `SNW-NETPOL-{SET,ADD,RMV}` rules.
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicyShape {
    pub allowed_ip_value_spans: Vec<Span>,
    pub blocked_ip_value_spans: Vec<Span>,
    pub allowed_rule_value_spans: Vec<Span>,
    pub blocked_rule_value_spans: Vec<Span>,
    /// Property clauses that syntactically appeared in the statement
    /// — one entry per property kind, in source order. Drives `*-CFG`
    /// rules with presence-based semantics: a `BLOCKED_IP_LIST = ()`
    /// empty clause still emits a `BlockedIpList` entry here even
    /// though `blocked_ip_value_spans` is empty. Mirrors
    /// `NetworkPolicyFacts.properties` post-projection.
    pub properties: Vec<NetworkPolicyPropertyKindIr>,
    pub had_set_action: bool,
    pub had_add_action: bool,
    pub had_remove_action: bool,
}

/// IR-local typed enum for network-policy property kinds. Mirrors
/// [`crate::facts::policy::NetworkPolicyPropertyKind`] one-to-one;
/// fact extraction copies values across the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkPolicyPropertyKindIr {
    AllowedIpList,
    BlockedIpList,
    AllowedNetworkRules,
    BlockedNetworkRules,
    Comment,
}

/// Lower a typed [`AstCreateNetworkPolicy`] into a [`PolicyPlan`].
pub fn lower_create_network_policy_to_policy_plan(
    p: &AstCreateNetworkPolicy,
    _source: &str,
) -> PolicyPlan {
    let mut shape = NetworkPolicyShape::default();
    let mut comment_value_span: Option<Span> = None;

    for property in &p.properties {
        absorb_network_property(&property.kind, &mut shape, &mut comment_value_span);
    }

    let comment = match comment_value_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };

    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::Network,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Network(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterNetworkPolicy`] into a [`PolicyPlan`].
pub fn lower_alter_network_policy_to_policy_plan(
    p: &AstAlterNetworkPolicy,
    _source: &str,
) -> PolicyPlan {
    use AstAlterNetworkPolicyActionKind as A;

    let mut shape = NetworkPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;
    let mut comment_value_span: Option<Span> = None;

    match &p.action.kind {
        A::Set { properties, .. } => {
            shape.had_set_action = true;
            for property in properties {
                absorb_network_property(&property.kind, &mut shape, &mut comment_value_span);
            }
        }
        A::Add { property, .. } => {
            shape.had_add_action = true;
            absorb_network_property(&property.kind, &mut shape, &mut comment_value_span);
        }
        A::Remove { property, .. } => {
            shape.had_remove_action = true;
            absorb_network_property(&property.kind, &mut shape, &mut comment_value_span);
        }
        A::RenameTo { new_name_span, .. } => {
            renamed_to_span = Some(*new_name_span);
        }
        A::SetTag {
            assignments_span, ..
        } => set_tag_action_spans.push(*assignments_span),
        A::UnsetTag { names_span, .. } => unset_tag_action_spans.push(*names_span),
        A::UnsetComment { .. } => {
            comment = PolicyCommentAction::Unset;
        }
    }

    if let Some(value_span) = comment_value_span {
        comment = PolicyCommentAction::Set { value_span };
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::Network,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::Network(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropNetworkPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_network_policy_to_policy_plan(p: &AstDropNetworkPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::Network,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

fn absorb_network_property(
    kind: &AstNetworkPolicyPropertyKind,
    shape: &mut NetworkPolicyShape,
    comment_value_span: &mut Option<Span>,
) {
    use AstNetworkPolicyPropertyKind as P;
    match kind {
        P::AllowedIpList { values, .. } => {
            shape
                .properties
                .push(NetworkPolicyPropertyKindIr::AllowedIpList);
            shape.allowed_ip_value_spans.extend(values.iter());
        }
        P::BlockedIpList { values, .. } => {
            shape
                .properties
                .push(NetworkPolicyPropertyKindIr::BlockedIpList);
            shape.blocked_ip_value_spans.extend(values.iter());
        }
        P::AllowedNetworkRuleList { rules, .. } => {
            shape
                .properties
                .push(NetworkPolicyPropertyKindIr::AllowedNetworkRules);
            shape.allowed_rule_value_spans.extend(rules.iter());
        }
        P::BlockedNetworkRuleList { rules, .. } => {
            shape
                .properties
                .push(NetworkPolicyPropertyKindIr::BlockedNetworkRules);
            shape.blocked_rule_value_spans.extend(rules.iter());
        }
        P::Comment { comment_span, .. } => {
            shape.properties.push(NetworkPolicyPropertyKindIr::Comment);
            *comment_value_span = Some(*comment_span);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Authentication policy lowering.
// ─────────────────────────────────────────────────────────────────────

/// Authentication-policy structured payload. CREATE-time field
/// `mfa_required` answers "is MFA enforced?" (computed from
/// MFA_ENROLLMENT='REQUIRED' or MFA_POLICY='REQUIRED'). The per-property
/// change flags drive the SNW-AUTHPOL-{METHODS,MFA,CLIENT,SECINTG}-CHG
/// rules on ALTER.
#[derive(Debug, Clone, Default)]
pub struct AuthenticationPolicyShape {
    pub mfa_required: bool,
    pub had_methods_change: bool,
    pub had_mfa_change: bool,
    pub had_client_types_change: bool,
    pub had_security_integrations_change: bool,
}

/// Lower a typed [`AstCreateAuthenticationPolicy`] into a [`PolicyPlan`].
pub fn lower_create_authentication_policy_to_policy_plan(
    p: &AstCreateAuthenticationPolicy,
    source: &str,
) -> PolicyPlan {
    // The AST property spans cover the full `NAME = VALUE` clause (the
    // parser does not yet expose value-only spans for these enum-shaped
    // properties; see `parse_simple_property_value` in the
    // authentication-policy parser). Project the value side by
    // splitting on `=` — a lossless inverse of the parser's structural
    // split, not a text heuristic against unstructured input.
    // Comparing the full clause text against `"REQUIRED"` would
    // always report `mfa_enrollment_required = false`.
    let mfa_enrollment_required = p
        .mfa_enrollment_span
        .and_then(|sp| value_after_eq(sp, source))
        .map(|v| v.eq_ignore_ascii_case("REQUIRED"))
        .unwrap_or(false);
    let mfa_policy_required = p
        .mfa_policy_span
        .and_then(|sp| value_after_eq(sp, source))
        .map(|v| v.eq_ignore_ascii_case("REQUIRED"))
        .unwrap_or(false);
    let shape = AuthenticationPolicyShape {
        mfa_required: mfa_enrollment_required || mfa_policy_required,
        ..AuthenticationPolicyShape::default()
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::Authentication,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Authentication(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterAuthenticationPolicy`] into a [`PolicyPlan`].
pub fn lower_alter_authentication_policy_to_policy_plan(
    p: &AstAlterAuthenticationPolicy,
    _source: &str,
) -> PolicyPlan {
    use AstAlterAuthenticationPolicyActionKind as A;

    let mut shape = AuthenticationPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut comment = PolicyCommentAction::Unchanged;

    match &p.action.kind {
        A::RenameTo { new_name_span, .. } => {
            renamed_to_span = Some(*new_name_span);
        }
        A::SetAuthenticationMethods { .. } | A::UnsetAuthenticationMethods { .. } => {
            shape.had_methods_change = true;
        }
        A::SetMfaEnrollment { .. }
        | A::UnsetMfaEnrollment { .. }
        | A::SetMfaPolicy { .. }
        | A::UnsetMfaPolicy { .. } => {
            shape.had_mfa_change = true;
        }
        A::SetClientTypes { .. } | A::UnsetClientTypes { .. } => {
            shape.had_client_types_change = true;
        }
        A::SetSecurityIntegrations { .. } | A::UnsetSecurityIntegrations { .. } => {
            shape.had_security_integrations_change = true;
        }
        A::SetClientPolicy { .. }
        | A::UnsetClientPolicy { .. }
        | A::SetPatPolicy { .. }
        | A::UnsetPatPolicy { .. }
        | A::SetWorkloadIdentityPolicy { .. }
        | A::UnsetWorkloadIdentityPolicy { .. } => {
            // No specific rule today; the
            // `kind: alter_authentication_policy` predicate on
            // `SNW-AUTHPOL-CHG` matches regardless of which property changed.
        }
        A::SetComment { value_span, .. } => {
            comment = PolicyCommentAction::Set {
                value_span: *value_span,
            };
        }
        A::UnsetComment { .. } => {
            comment = PolicyCommentAction::Unset;
        }
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::Authentication,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Authentication(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropAuthenticationPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_authentication_policy_to_policy_plan(
    p: &AstDropAuthenticationPolicy,
) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::Authentication,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Aggregation policy lowering (body-expression analysis).
// ─────────────────────────────────────────────────────────────────────

/// Aggregation-policy structured payload. Body analysis populates the
/// three boolean shape signals plus the smallest `MIN_GROUP_SIZE`
/// literal observed; ALTER tracks `had_body_change` separately for
/// the SNW-AGGPOL-NOCONST-CHG predicate.
#[derive(Debug, Clone, Default)]
pub struct AggregationPolicyShape {
    pub min_group_size: Option<u32>,
    pub has_no_aggregation_constraint: bool,
    pub has_conditional_body: bool,
    pub had_body_change: bool,
}

/// Lower a typed [`AstCreateAggregationPolicy`] into a [`PolicyPlan`].
pub fn lower_create_aggregation_policy_to_policy_plan(
    p: &AstCreateAggregationPolicy,
    source: &str,
) -> PolicyPlan {
    let mut shape = AggregationPolicyShape::default();
    if let Some(body) = p.body.as_deref() {
        analyze_aggregation_body(body, source, &mut shape);
    }
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::Aggregation,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Aggregation(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterAggregationPolicy`] into a [`PolicyPlan`].
pub fn lower_alter_aggregation_policy_to_policy_plan(
    p: &AstAlterAggregationPolicy,
    source: &str,
) -> PolicyPlan {
    use AstAlterAggregationPolicyActionKind as A;
    let mut shape = AggregationPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    for action in &p.actions {
        match &action.kind {
            A::RenameTo { new_name_span, .. } => renamed_to_span = Some(*new_name_span),
            A::SetBody { expression, .. } => {
                shape.had_body_change = true;
                if let Some(expr) = expression.as_deref() {
                    analyze_aggregation_body(expr, source, &mut shape);
                }
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

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::Aggregation,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::Aggregation(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropAggregationPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_aggregation_policy_to_policy_plan(p: &AstDropAggregationPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::Aggregation,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: false,
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

/// Walk an aggregation-policy body expression. Populates
/// `has_no_aggregation_constraint` / `has_conditional_body` /
/// `min_group_size` based on the expression shape.
///
/// Body forms:
/// - bare `NO_AGGREGATION_CONSTRAINT` ident or `NO_AGGREGATION_CONSTRAINT()` function call
/// - `AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => N)` function call
/// - `MIN_GROUP_SIZE = N` binary op
/// - `CASE WHEN … THEN … ELSE … END` — recursively analyzed into branches
fn analyze_aggregation_body(expr: &AstExpr, source: &str, shape: &mut AggregationPolicyShape) {
    match expr {
        AstExpr::Ident { column_ref, .. } => {
            if let Some(text) = crate::ir::utils::slice_span(source, column_ref.name.span) {
                if text.eq_ignore_ascii_case("NO_AGGREGATION_CONSTRAINT") {
                    shape.has_no_aggregation_constraint = true;
                }
            }
        }
        AstExpr::FunctionCall {
            func_name, args, ..
        } => {
            if let Some(name_text) = crate::ir::utils::slice_span(source, func_name.span) {
                let name_trim = name_text.trim();
                if name_trim.eq_ignore_ascii_case("NO_AGGREGATION_CONSTRAINT") {
                    shape.has_no_aggregation_constraint = true;
                } else if name_trim.eq_ignore_ascii_case("AGGREGATION_CONSTRAINT") {
                    for arg in args {
                        if let AstFunctionArg::Named { name, value, .. } = &**arg {
                            let arg_name = crate::ir::utils::slice_span(source, name.span)
                                .map(|s| s.trim())
                                .unwrap_or("");
                            if arg_name.eq_ignore_ascii_case("MIN_GROUP_SIZE") {
                                if let Some(n) = literal_u32(value, source) {
                                    shape.min_group_size = Some(n);
                                }
                            }
                        }
                    }
                }
            }
        }
        AstExpr::BinaryOp { left, right, .. } => {
            // Match `MIN_GROUP_SIZE = N` shape.
            if let AstExpr::Ident { column_ref, .. } = left.as_ref() {
                if crate::ir::utils::slice_span(source, column_ref.name.span)
                    .map(|s| s.eq_ignore_ascii_case("MIN_GROUP_SIZE"))
                    .unwrap_or(false)
                {
                    if let Some(n) = literal_u32(right, source) {
                        shape.min_group_size = Some(n);
                    }
                }
            }
        }
        AstExpr::Case {
            whens, else_expr, ..
        } => {
            shape.has_conditional_body = true;
            for when in whens {
                analyze_aggregation_body(&when.result, source, shape);
            }
            if let Some(else_expr) = else_expr {
                analyze_aggregation_body(else_expr, source, shape);
            }
        }
        _ => {}
    }
}

fn literal_u32(expr: &AstExpr, source: &str) -> Option<u32> {
    if let AstExpr::Literal { literal, .. } = expr {
        let span = literal.span();
        return extract_integer_literal_value(span, source).map(|v| v as u32);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// Projection policy lowering (body-expression analysis).
// ─────────────────────────────────────────────────────────────────────

/// Projection-policy structured payload. Body analysis recognizes the
/// `PROJECTION_CONSTRAINT(ALLOW => …, ENFORCEMENT => …)` shape and the
/// `CASE`-branched conditional shape.
#[derive(Debug, Clone, Default)]
pub struct ProjectionPolicyShape {
    pub has_allow_list: bool,
    pub has_enforcement_disabled: bool,
    pub has_enforcement_enabled: bool,
    pub has_conditional_body: bool,
    pub had_body_change: bool,
}

/// Lower a typed [`AstCreateProjectionPolicy`] into a [`PolicyPlan`].
pub fn lower_create_projection_policy_to_policy_plan(
    p: &AstCreateProjectionPolicy,
    source: &str,
) -> PolicyPlan {
    let mut shape = ProjectionPolicyShape::default();
    if let Some(body) = p.body_expr.as_deref() {
        analyze_projection_body(body, source, &mut shape);
    }
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::Projection,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Projection(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterProjectionPolicy`] into a [`PolicyPlan`].
pub fn lower_alter_projection_policy_to_policy_plan(
    p: &AstAlterProjectionPolicy,
    source: &str,
) -> PolicyPlan {
    use AstAlterProjectionPolicyActionKind as A;
    let mut shape = ProjectionPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    match &p.action.kind {
        A::RenameTo { new_name_span, .. } => renamed_to_span = Some(*new_name_span),
        A::SetBody { body_expr, .. } => {
            shape.had_body_change = true;
            if let Some(expr) = body_expr.as_deref() {
                analyze_projection_body(expr, source, &mut shape);
            }
        }
        A::SetComment {
            comment_value_span, ..
        } => {
            comment = PolicyCommentAction::Set {
                value_span: *comment_value_span,
            };
        }
        A::UnsetComment { .. } => comment = PolicyCommentAction::Unset,
        A::SetTag {
            assignments_span, ..
        } => set_tag_action_spans.push(*assignments_span),
        A::UnsetTag { tags_span, .. } => unset_tag_action_spans.push(*tags_span),
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::Projection,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::Projection(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropProjectionPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_projection_policy_to_policy_plan(p: &AstDropProjectionPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::Projection,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: false,
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

/// Walk a projection-policy body expression. Recognizes
/// `PROJECTION_CONSTRAINT(ALLOW => true|false, ENFORCEMENT => 'NULLIFY'|…)`
/// and `CASE WHEN … THEN … ELSE … END`.
fn analyze_projection_body(expr: &AstExpr, source: &str, shape: &mut ProjectionPolicyShape) {
    match expr {
        AstExpr::FunctionCall {
            func_name, args, ..
        } => {
            if let Some(name_text) = crate::ir::utils::slice_span(source, func_name.span) {
                if name_text
                    .trim()
                    .eq_ignore_ascii_case("PROJECTION_CONSTRAINT")
                {
                    for arg in args {
                        if let AstFunctionArg::Named { name, value, .. } = &**arg {
                            let arg_name = crate::ir::utils::slice_span(source, name.span)
                                .map(|s| s.trim())
                                .unwrap_or("");
                            if arg_name.eq_ignore_ascii_case("ALLOW") {
                                if literal_bool(value, source) == Some(true) {
                                    shape.has_allow_list = true;
                                }
                            } else if arg_name.eq_ignore_ascii_case("ENFORCEMENT") {
                                if let Some(text) = literal_string(value, source) {
                                    // `NULLIFY` substitutes NULL; `NONE`
                                    // performs no action — neither hard-blocks,
                                    // so both classify as enforcement-disabled
                                    // for SNW-PROJPOL-ENFORCE-OFF governance.
                                    let t = text.trim();
                                    if t.eq_ignore_ascii_case("NULLIFY")
                                        || t.eq_ignore_ascii_case("NONE")
                                    {
                                        shape.has_enforcement_disabled = true;
                                    } else {
                                        shape.has_enforcement_enabled = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        AstExpr::Case {
            whens, else_expr, ..
        } => {
            shape.has_conditional_body = true;
            for when in whens {
                analyze_projection_body(&when.result, source, shape);
            }
            if let Some(else_expr) = else_expr {
                analyze_projection_body(else_expr, source, shape);
            }
        }
        _ => {}
    }
}

fn literal_bool(expr: &AstExpr, source: &str) -> Option<bool> {
    if let AstExpr::Literal { literal, .. } = expr {
        let raw = crate::ir::utils::slice_span(source, literal.span())?
            .trim()
            .to_ascii_uppercase();
        return match raw.as_str() {
            "TRUE" => Some(true),
            "FALSE" => Some(false),
            _ => None,
        };
    }
    None
}

fn literal_string(expr: &AstExpr, source: &str) -> Option<String> {
    if let AstExpr::Literal { literal, .. } = expr {
        return extract_string_literal_value(literal.span(), source);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// Join policy lowering (body-expression analysis). Ninth policy kind.
// ─────────────────────────────────────────────────────────────────────

/// Join-policy structured payload. Body analysis recognizes the
/// `JOIN_CONSTRAINT(JOIN_REQUIRED => true|false)` shape and the
/// `CASE`-branched conditional shape. A `JOIN_REQUIRED => FALSE` body
/// imposes no join restriction (permissive); `TRUE` requires a join
/// predicate. Which is acceptable is YAML policy.
#[derive(Debug, Clone, Default)]
pub struct JoinPolicyShape {
    /// Body uses (or branches to) `JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE)`.
    pub has_join_required: bool,
    /// Body uses (or branches to) `JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE)`
    /// — the policy permits unrestricted joins.
    pub has_join_not_required: bool,
    pub has_conditional_body: bool,
    pub had_body_change: bool,
}

/// Lower a typed [`AstCreateJoinPolicy`] into a [`PolicyPlan`].
pub fn lower_create_join_policy_to_policy_plan(
    p: &AstCreateJoinPolicy,
    source: &str,
) -> PolicyPlan {
    let mut shape = JoinPolicyShape::default();
    if let Some(body) = p.body_expr.as_deref() {
        analyze_join_body(body, source, &mut shape);
    }
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::JoinPolicy,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::JoinPolicy(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterJoinPolicy`] into a [`PolicyPlan`].
pub fn lower_alter_join_policy_to_policy_plan(p: &AstAlterJoinPolicy, source: &str) -> PolicyPlan {
    use AstAlterJoinPolicyActionKind as A;
    let mut shape = JoinPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    match &p.action.kind {
        A::RenameTo { new_name_span } => renamed_to_span = Some(*new_name_span),
        A::SetBody { body_expr, .. } => {
            shape.had_body_change = true;
            if let Some(expr) = body_expr.as_deref() {
                analyze_join_body(expr, source, &mut shape);
            }
        }
        A::SetComment { comment_value_span } => {
            comment = PolicyCommentAction::Set {
                value_span: *comment_value_span,
            };
        }
        A::UnsetComment => comment = PolicyCommentAction::Unset,
        A::SetTag { assignments_span } => set_tag_action_spans.push(*assignments_span),
        A::UnsetTag { tags_span } => unset_tag_action_spans.push(*tags_span),
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::JoinPolicy,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::JoinPolicy(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropJoinPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_join_policy_to_policy_plan(p: &AstDropJoinPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::JoinPolicy,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

/// Walk a join-policy body expression. Recognizes
/// `JOIN_CONSTRAINT(JOIN_REQUIRED => true|false)` and the CASE-branched
/// conditional shape.
fn analyze_join_body(expr: &AstExpr, source: &str, shape: &mut JoinPolicyShape) {
    match expr {
        AstExpr::FunctionCall {
            func_name, args, ..
        } => {
            if let Some(name_text) = crate::ir::utils::slice_span(source, func_name.span) {
                if name_text.trim().eq_ignore_ascii_case("JOIN_CONSTRAINT") {
                    for arg in args {
                        if let AstFunctionArg::Named { name, value, .. } = &**arg {
                            let arg_name = crate::ir::utils::slice_span(source, name.span)
                                .map(|s| s.trim())
                                .unwrap_or("");
                            if arg_name.eq_ignore_ascii_case("JOIN_REQUIRED") {
                                match literal_bool(value, source) {
                                    Some(true) => shape.has_join_required = true,
                                    Some(false) => shape.has_join_not_required = true,
                                    None => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        AstExpr::Case {
            whens, else_expr, ..
        } => {
            shape.has_conditional_body = true;
            for when in whens {
                analyze_join_body(&when.result, source, shape);
            }
            if let Some(else_expr) = else_expr {
                analyze_join_body(else_expr, source, shape);
            }
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────
// Masking policy lowering (CREATE / ALTER / DROP).
// ─────────────────────────────────────────────────────────────────────

/// IR-side mirror of one parameter in a `CREATE MASKING POLICY`
/// signature. Carries the spans of the name and type; identifier
/// normalization and type projection happen at the facts boundary.
#[derive(Debug, Clone)]
pub struct MaskingArgumentIr {
    pub name_span: Span,
    pub type_span: Span,
}

/// Masking-policy structured payload. Carries the parsed body
/// expression and the parameter list so the facts boundary can project
/// a typed public `Expr` tree + terminal-return fan-out. CREATE
/// populates `body` and `arguments`; ALTER populates `body` only when
/// a `SET BODY` action is present; DROP carries `PolicyPlanVariant::DropOnly`
/// instead of this shape.
#[derive(Debug, Clone, Default)]
pub struct MaskingPolicyShape {
    pub exempt_other_policies: bool,
    /// Parsed body expression. `Some` for CREATE and for ALTER with a
    /// `SET BODY` action; `None` for ALTER actions that don't carry a
    /// body. The projection-side public type is `Option<Expr>`.
    pub body: Option<Box<AstExpr>>,
    /// Policy signature parameters in source order. Populated only for
    /// CREATE (ALTER cannot restate the signature for MASKING POLICY).
    pub arguments: Vec<MaskingArgumentIr>,
}

/// Lower a typed [`AstCreateMaskingPolicy`] into a [`PolicyPlan`].
pub fn lower_create_masking_policy_to_policy_plan(
    p: &AstCreateMaskingPolicy,
    _source: &str,
) -> PolicyPlan {
    let arguments = p
        .parameters
        .iter()
        .map(|param| MaskingArgumentIr {
            name_span: param.name_span,
            type_span: param.type_span,
        })
        .collect();
    let shape = MaskingPolicyShape {
        exempt_other_policies: p.exempt_other_policies_value.unwrap_or(false),
        body: Some(p.body.clone()),
        arguments,
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::Masking,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::Masking(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterMaskingPolicy`] into a [`PolicyPlan`].
///
/// ALTER MASKING POLICY carries a single action (unlike ALTER PASSWORD
/// POLICY which carries a list). The action drives the relevant
/// kind-agnostic field (rename / set_tags / unset_tags / comment) or
/// the kind-specific `body` slot.
pub fn lower_alter_masking_policy_to_policy_plan(
    p: &AstAlterMaskingPolicy,
    _source: &str,
) -> PolicyPlan {
    use AstAlterMaskingPolicyActionKind as A;

    let mut shape = MaskingPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    match &p.action.kind {
        A::RenameTo { new_name_span, .. } => {
            renamed_to_span = Some(*new_name_span);
        }
        A::SetBody { body, .. } => {
            shape.body = Some(body.clone());
        }
        A::SetTag {
            assignments_span, ..
        } => {
            set_tag_action_spans.push(*assignments_span);
        }
        A::UnsetTag { tags_span, .. } => {
            unset_tag_action_spans.push(*tags_span);
        }
        A::SetComment {
            comment_value_span, ..
        } => {
            comment = PolicyCommentAction::Set {
                value_span: *comment_value_span,
            };
        }
        A::UnsetComment { .. } => {
            comment = PolicyCommentAction::Unset;
        }
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::Masking,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::Masking(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropMaskingPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_masking_policy_to_policy_plan(p: &AstDropMaskingPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::Masking,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: false,
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Row-access policy lowering (CREATE / ALTER / DROP).
// ─────────────────────────────────────────────────────────────────────

/// IR-side mirror of one parameter in a `CREATE ROW ACCESS POLICY`
/// signature (Snowflake `AS (<name> <type>, …)`). BigQuery row-access
/// policies have no signature and produce an empty argument list.
#[derive(Debug, Clone)]
pub struct RowAccessArgumentIr {
    pub name_span: Span,
    pub type_span: Span,
}

/// Row-access-policy structured payload. Mirrors [`MaskingPolicyShape`]:
/// carries the parsed boolean predicate body and the parameter list so
/// the facts boundary can project a typed public `Expr` tree + terminal-
/// return fan-out. CREATE populates `body` (from Snowflake `body` or
/// BigQuery `filter_expr`) and `arguments`; ALTER populates `body` only
/// when a `SET BODY` action is present; DROP uses
/// [`PolicyPlanVariant::DropOnly`].
///
/// PostgreSQL `CREATE/ALTER POLICY` does not produce a single `body`;
/// it carries an optional `USING` read filter and an optional `WITH
/// CHECK` write filter, plus dialect-specific permissiveness and command
/// modifiers. The fields below are `None` on Snowflake/BigQuery row-
/// access policies and populated on PG-lowered statements.
#[derive(Debug, Clone, Default)]
pub struct RowAccessPolicyShape {
    pub body: Option<Box<AstExpr>>,
    pub arguments: Vec<RowAccessArgumentIr>,
    /// PG `USING (<expr>)` boolean read-filter predicate.
    pub using: Option<Box<AstExpr>>,
    /// PG `WITH CHECK (<expr>)` boolean write-filter predicate.
    pub check: Option<Box<AstExpr>>,
    /// PG `AS PERMISSIVE | RESTRICTIVE` modifier — surfaced only when
    /// the SQL contained the clause.
    pub permissiveness: Option<PgPolicyPermissivenessIr>,
    /// PG `FOR { ALL | SELECT | INSERT | UPDATE | DELETE }` modifier —
    /// surfaced only when the SQL contained the clause.
    pub command: Option<PgPolicyCommandIr>,
    /// `ON <table>` target reference from PostgreSQL `CREATE/ALTER
    /// POLICY name ON table` grammar. `None` for Snowflake / BigQuery
    /// row-access policies, whose CREATE statement carries no target
    /// (those policies are attached separately via `ALTER TABLE ... ADD
    /// ROW ACCESS POLICY`). This is data, not a dialect discriminator
    /// — PG vs Snowflake/BigQuery routing lives at the
    /// `analyze_ddl_facts` dispatch site via
    /// [`crate::facts::extract::PolicyDialectOrigin`].
    pub on_table_span: Option<Span>,
}

/// IR-side mirror of [`crate::facts::PgPolicyPermissiveness`](crate::facts::policy::PgPolicyPermissiveness). Closed
/// enum; adding a new permissiveness variant requires extending both
/// this enum and the public facts type together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PgPolicyPermissivenessIr {
    Permissive,
    Restrictive,
}

/// IR-side mirror of [`crate::facts::PgPolicyCommand`](crate::facts::policy::PgPolicyCommand). Closed enum;
/// adding a new command variant requires extending both this enum and
/// the public facts type together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PgPolicyCommandIr {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

/// Lower a typed [`AstCreateRowAccessPolicy`] into a [`PolicyPlan`].
///
/// Snowflake `body` and BigQuery `filter_expr` are the same semantic
/// surface (the boolean predicate); the lowering picks whichever the
/// AST populated for this dialect.
pub fn lower_create_row_access_policy_to_policy_plan(
    p: &AstCreateRowAccessPolicy,
    _source: &str,
) -> PolicyPlan {
    let arguments = p
        .parameters
        .iter()
        .map(|param| RowAccessArgumentIr {
            name_span: param.name_span,
            type_span: param.type_span,
        })
        .collect();
    let body = p.body.clone().or_else(|| p.filter_expr.clone());
    let shape = RowAccessPolicyShape {
        body,
        arguments,
        ..RowAccessPolicyShape::default()
    };
    let comment = match p.comment_span {
        Some(value_span) => PolicyCommentAction::Set { value_span },
        None => PolicyCommentAction::Unchanged,
    };
    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::RowAccess,
        policy_name_span: p.policy_name_span,
        if_not_exists: p.if_not_exists_span.is_some(),
        if_exists: false,
        or_replace: p.or_replace_span.is_some(),
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment,
        variant: PolicyPlanVariant::RowAccess(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterRowAccessPolicy`] into a [`PolicyPlan`].
///
/// ALTER ROW ACCESS POLICY carries a single action (same shape as
/// ALTER MASKING POLICY). The action drives the relevant kind-agnostic
/// field (rename / set_tags / unset_tags / comment) or the kind-specific
/// `body` slot.
pub fn lower_alter_row_access_policy_to_policy_plan(
    p: &AstAlterRowAccessPolicy,
    _source: &str,
) -> PolicyPlan {
    use AstAlterRowAccessPolicyActionKind as A;

    let mut shape = RowAccessPolicyShape::default();
    let mut renamed_to_span: Option<Span> = None;
    let mut set_tag_action_spans: Vec<Span> = Vec::new();
    let mut unset_tag_action_spans: Vec<Span> = Vec::new();
    let mut comment = PolicyCommentAction::Unchanged;

    match &p.action.kind {
        A::RenameTo { new_name_span, .. } => {
            renamed_to_span = Some(*new_name_span);
        }
        A::SetBody { body, .. } => {
            shape.body = Some(body.clone());
        }
        A::SetTag {
            assignments_span, ..
        } => {
            set_tag_action_spans.push(*assignments_span);
        }
        A::UnsetTag { tags_span, .. } => {
            unset_tag_action_spans.push(*tags_span);
        }
        A::SetComment {
            comment_value_span, ..
        } => {
            comment = PolicyCommentAction::Set {
                value_span: *comment_value_span,
            };
        }
        A::UnsetComment { .. } => {
            comment = PolicyCommentAction::Unset;
        }
    }

    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::RowAccess,
        policy_name_span: p.name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans,
        unset_tag_action_spans,
        comment,
        variant: PolicyPlanVariant::RowAccess(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropRowAccessPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_row_access_policy_to_policy_plan(p: &AstDropRowAccessPolicy) -> PolicyPlan {
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::RowAccess,
        policy_name_span: p.policy_name_span,
        if_not_exists: false,
        if_exists: p.if_exists_span.is_some(),
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade: false,
            on_table: None,
        },
        node_id: p.node_id,
        span: p.span,
    }
}

// ─────────────────────────────────────────────────────────────────────
// PostgreSQL CREATE / ALTER / DROP POLICY lowering.
//
// PG row-level-security policies share the `RowAccess` policy kind with
// Snowflake / BigQuery row-access policies but carry a different
// predicate surface (USING + WITH CHECK, plus PERMISSIVE / RESTRICTIVE
// and FOR command modifiers). The lowering populates the PG-specific
// fields on `RowAccessPolicyShape`.
// ─────────────────────────────────────────────────────────────────────

fn project_pg_permissiveness(p: AstPgPolicyPermissiveness) -> PgPolicyPermissivenessIr {
    match p {
        AstPgPolicyPermissiveness::Permissive => PgPolicyPermissivenessIr::Permissive,
        AstPgPolicyPermissiveness::Restrictive => PgPolicyPermissivenessIr::Restrictive,
    }
}

fn project_pg_command(c: AstPgPolicyCommand) -> PgPolicyCommandIr {
    match c {
        AstPgPolicyCommand::All => PgPolicyCommandIr::All,
        AstPgPolicyCommand::Select => PgPolicyCommandIr::Select,
        AstPgPolicyCommand::Insert => PgPolicyCommandIr::Insert,
        AstPgPolicyCommand::Update => PgPolicyCommandIr::Update,
        AstPgPolicyCommand::Delete => PgPolicyCommandIr::Delete,
    }
}

/// Lower a typed [`AstCreatePgPolicy`] into a [`PolicyPlan`].
pub fn lower_create_pg_policy_to_policy_plan(p: &AstCreatePgPolicy, _source: &str) -> PolicyPlan {
    let permissiveness = p
        .permissiveness
        .as_ref()
        .map(|(v, _)| project_pg_permissiveness(*v));
    let command = p.command.as_ref().map(|(v, _)| project_pg_command(*v));
    let shape = RowAccessPolicyShape {
        body: None,
        arguments: Vec::new(),
        using: p.using_expr.clone(),
        check: p.check_expr.clone(),
        permissiveness,
        command,
        on_table_span: Some(p.table_name),
    };
    PolicyPlan {
        action: PolicyAction::Create,
        policy_kind: PolicyKindIr::RowAccess,
        policy_name_span: p.policy_name,
        if_not_exists: false,
        if_exists: false,
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::RowAccess(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstAlterPgPolicy`] into a [`PolicyPlan`].
///
/// ALTER POLICY carries exactly one action: either `RENAME TO new_name`
/// (sets `renamed_to_span`) or `Modify` (sets the per-kind body slots
/// from any USING / WITH CHECK clauses present).
pub fn lower_alter_pg_policy_to_policy_plan(p: &AstAlterPgPolicy, _source: &str) -> PolicyPlan {
    let mut shape = RowAccessPolicyShape {
        on_table_span: Some(p.table_name),
        ..RowAccessPolicyShape::default()
    };
    let mut renamed_to_span: Option<Span> = None;
    match &p.action {
        AlterPgPolicyAction::Rename { new_name, .. } => {
            renamed_to_span = Some(*new_name);
        }
        AlterPgPolicyAction::Modify {
            using_expr,
            check_expr,
            ..
        } => {
            shape.using = using_expr.clone();
            shape.check = check_expr.clone();
        }
    }
    PolicyPlan {
        action: PolicyAction::Alter,
        policy_kind: PolicyKindIr::RowAccess,
        policy_name_span: p.policy_name,
        if_not_exists: false,
        if_exists: false,
        or_replace: false,
        renamed_to_span,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::RowAccess(shape),
        node_id: p.node_id,
        span: p.span,
    }
}

/// Lower a typed [`AstDropPgPolicy`] into a [`PolicyPlan`].
pub fn lower_drop_pg_policy_to_policy_plan(p: &AstDropPgPolicy) -> PolicyPlan {
    let cascade = matches!(p.cascade_restrict, Some(PgCascadeRestrict::Cascade));
    PolicyPlan {
        action: PolicyAction::Drop,
        policy_kind: PolicyKindIr::RowAccess,
        policy_name_span: p.policy_name,
        if_not_exists: false,
        if_exists: p.if_exists,
        or_replace: false,
        renamed_to_span: None,
        set_tag_action_spans: Vec::new(),
        unset_tag_action_spans: Vec::new(),
        comment: PolicyCommentAction::Unchanged,
        variant: PolicyPlanVariant::DropOnly {
            cascade,
            on_table: Some(p.table_name),
        },
        node_id: p.node_id,
        span: p.span,
    }
}
