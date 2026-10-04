// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `OPEN`/`CLOSE` encryption-key
//! statements.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_key_management`] for any
//! `OPEN`/`CLOSE { MASTER KEY | SYMMETRIC KEY | ALL SYMMETRIC KEYS }`. Projected
//! from [`crate::ir::key_management_plan::MssqlKeyManagementPlan`] via
//! `derive_facts_from_key_management_plan`.
//!
//! Encryption-key activation is a session-scoped key-context switch (distinct
//! from the `{CREATE|ALTER|DROP}` key *object* DDL) — the payload sits at the
//! top level of `StatementFacts` rather than under `ddl`.
//!
//! Three recognition primitives are surfaced: the verb, the key kind, and
//! whether an inline password decrypts the key. Which combination is dangerous
//! is a YAML verdict (e.g. opening a key with a hardcoded password is a
//! credential leak), never baked into Rust. The password VALUE is redacted at
//! parse time and never appears here.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_key_management
//!     - mssql_key_management.action: open
//!     - mssql_key_management.password_present: true
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// The key-context verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyManagementAction {
    /// `OPEN` — activate a key in the session.
    Open,
    /// `CLOSE` — deactivate a key.
    Close,
}

/// Which key the statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyManagementKind {
    /// `MASTER KEY` — the database master key.
    Master,
    /// `SYMMETRIC KEY <name>`.
    Symmetric,
    /// `ALL SYMMETRIC KEYS`.
    AllSymmetric,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlKeyManagementFacts {
    /// Whether the key is being opened or closed.
    pub action: KeyManagementAction,
    /// Which key the statement targets.
    pub key_kind: KeyManagementKind,
    /// True when an inline `PASSWORD = '…'` decrypts/opens the key — a
    /// hardcoded credential in the source. The value itself is redacted.
    pub password_present: bool,
}
