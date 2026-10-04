// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `CREATE`/`ALTER SECURITY POLICY`
//! statements.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_security_policy`].
//! Projected from
//! [`crate::ir::security_policy_plan::MssqlSecurityPolicyPlan`] via
//! `derive_facts_from_security_policy_plan`.
//!
//! A security policy is SQL Server's row-level-security control. Three
//! recognition primitives are surfaced: the verb, the policy `state`, and
//! whether filter / block predicates are present. Which combination is
//! dangerous is a YAML verdict — notably, a policy left `off` (or created with
//! no `STATE`, which SQL Server defaults to off) enforces nothing, and turning
//! an existing policy off removes active row protection.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_security_policy
//!     - mssql_security_policy.action: alter
//!     - mssql_security_policy.state: off
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// The security-policy verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecurityPolicyAction {
    /// `CREATE SECURITY POLICY`.
    Create,
    /// `ALTER SECURITY POLICY`.
    Alter,
}

/// The `WITH (STATE = …)` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    /// `STATE = ON` — the policy is active.
    On,
    /// `STATE = OFF` — the policy is inactive (enforces nothing).
    Off,
    /// No `STATE` clause was given. On `CREATE`, SQL Server defaults to off.
    Unset,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlSecurityPolicyFacts {
    /// Whether the policy is being created or altered.
    pub action: SecurityPolicyAction,
    /// The policy's `STATE`. `off` (or `unset` on create) means it enforces
    /// nothing.
    pub state: PolicyState,
    /// A `FILTER PREDICATE` (controls which rows reads can see) is bound.
    pub has_filter_predicate: bool,
    /// A `BLOCK PREDICATE` (restricts which rows writes may touch) is bound.
    pub has_block_predicate: bool,
}
