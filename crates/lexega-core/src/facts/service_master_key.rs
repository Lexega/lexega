// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `ALTER SERVICE MASTER KEY` statement.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_service_master_key`].
//! Projected from
//! [`crate::ir::service_master_key_plan::MssqlServiceMasterKeyPlan`] via
//! `derive_facts_from_service_master_key_plan`.
//!
//! The Service Master Key is the root of the SQL Server encryption hierarchy.
//! Three recognition primitives are surfaced: the operation, whether the
//! regenerate is forced, and whether an inline password is present. Which
//! combination is dangerous is a YAML verdict — re-keying the root,
//! force-discarding undecryptable material, or a hardcoded service-account
//! password. Each password's value is in the facts and is masked in every
//! report.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_service_master_key
//!     - mssql_service_master_key.force: true
//! ```

use serde::{Deserialize, Serialize};

use super::PasswordLiteral;

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// What an `ALTER SERVICE MASTER KEY` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ServiceMasterKeyOperation {
    /// `[FORCE] REGENERATE` — re-key the encryption root.
    Regenerate,
    /// `WITH { OLD | NEW }_ACCOUNT / _PASSWORD = '…'` — rotate the protecting
    /// service-account credentials.
    AccountChange,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlServiceMasterKeyFacts {
    /// Whether the statement re-keys the SMK or rotates its protecting
    /// service-account credentials.
    pub operation: ServiceMasterKeyOperation,
    /// `true` for `FORCE REGENERATE`, which discards undecryptable material
    /// irreversibly.
    pub force: bool,
    /// `true` when an inline `{ OLD | NEW }_PASSWORD = '…'` is present — a
    /// hardcoded service-account credential.
    pub password_present: bool,
    /// Each password literal written, decoded: doubled quotes undone and any
    /// `N` prefix dropped. A value the engine rendered from a template or
    /// substituted for a deploy variable is not listed. The value is masked
    /// in every report; a custom rule message that interpolates it shows it
    /// unmasked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_literals: Vec<PasswordLiteral>,
}
