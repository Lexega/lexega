// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for principal-policy *attachment* statements.
//!
//! Populated on [`crate::facts::StatementFacts::policy_attachment`] when the
//! statement is `ALTER USER … { SET | UNSET } AUTHENTICATION POLICY …` or
//! `ALTER ACCOUNT { SET | UNSET } AUTHENTICATION POLICY …`. Projected from
//! [`crate::ir::policy_attachment_plan::PolicyAttachmentPlan`] via
//! `derive_facts_from_policy_attachment_plan`.
//!
//! Predicate examples:
//! ```yaml
//! triggers:
//!   all_of:
//!     - policy_attachment.verb: set
//!     - policy_attachment.target_kind: authentication_policy
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::identity::{IdentName, TableRef};

/// Facts for a policy-attachment statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PolicyAttachmentFacts {
    /// Verb performed by the statement (Set / Unset).
    pub verb: PolicyAttachmentVerb,
    /// Principal scope kind (User / Account).
    pub principal_kind: PolicyAttachmentPrincipalKind,
    /// User name when `principal_kind = user`. Omitted for `account`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_name: Option<IdentName>,
    /// Target object kind being attached/detached.
    pub target_kind: PolicyAttachmentTargetKind,
    /// Policy reference (Set form). Omitted for Unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<TableRef>,
}

/// Verb performed by an attachment statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PolicyAttachmentVerb {
    /// `SET <target> = <name>` — bind the target to the principal.
    Set,
    /// `UNSET <target>` — unbind the target from the principal.
    Unset,
}

/// Principal scope of a policy-attachment statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PolicyAttachmentPrincipalType"))]
pub enum PolicyAttachmentPrincipalKind {
    /// `ALTER USER <name> …`.
    User,
    /// `ALTER ACCOUNT …`.
    Account,
}

/// Target object kind for a policy-attachment statement. Today only
/// `AUTHENTICATION POLICY` is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PolicyAttachmentTargetType"))]
pub enum PolicyAttachmentTargetKind {
    AuthenticationPolicy,
}
