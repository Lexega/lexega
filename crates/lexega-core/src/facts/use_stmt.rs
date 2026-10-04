// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for `USE` session-context statements.
//!
//! Populated on [`crate::facts::StatementFacts::use_stmt`] when the
//! statement is `USE { ROLE | DATABASE | CATALOG | SCHEMA |
//! WAREHOUSE | SECONDARY ROLES } …`. Projected from
//! [`crate::ir::use_plan::UsePlan`] via `derive_facts_from_use_plan`.
//!
//! Predicate examples:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: use
//!     - use_stmt.kind: role
//!     - use_stmt.target.normalized:
//!         in: [ACCOUNTADMIN, SECURITYADMIN]
//! ```
//!
//! `target` carries the first dotted component of the object span
//! with the standard dialect-aware identifier normalization applied
//! (UPPERCASE on Snowflake / BigQuery / MySQL / MSSQL; lowercase on
//! PostgreSQL / Databricks). Predicates portable across dialects
//! should match against `target.normalized`, not `target.raw`.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct UseFacts {
    /// Which `USE` form this statement is (Role / Database / Catalog
    /// / Schema / Warehouse / Secondary Roles).
    pub kind: UseStatementKind,
    /// Target name (first dotted component, normalized). Omitted
    /// when the parser produced an empty or unreadable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<UseTargetFacts>,
}

/// Classification of a USE statement's clause kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UseStatementType"))]
pub enum UseStatementKind {
    Role,
    Database,
    Catalog,
    Schema,
    Warehouse,
    SecondaryRoles,
}

/// Single-component target name. Carries both the raw token text and
/// the normalized form so portable predicates can match against
/// `normalized` and dialect-specific predicates can match against
/// `raw`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct UseTargetFacts {
    /// Raw token text with surrounding whitespace stripped.
    pub raw: String,
    /// Dialect-aware normalized form of `raw`. UPPERCASE on
    /// Snowflake / BigQuery / MySQL / MSSQL, lowercase on PostgreSQL
    /// / Databricks (modulo `LEXEGA_IDENTIFIER_CASE`).
    pub normalized: String,
}
