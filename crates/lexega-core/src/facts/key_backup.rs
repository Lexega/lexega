// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `BACKUP`/`RESTORE` key-material
//! statements.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_key_backup`]. Projected
//! from [`crate::ir::key_backup_plan::MssqlKeyBackupPlan`] via
//! `derive_facts_from_key_backup_plan`.
//!
//! These statements move root key material across the filesystem boundary.
//! Three recognition primitives are surfaced: the verb, the key object, and
//! whether an inline password protects/unlocks it. Which combination is
//! dangerous is a YAML verdict — backing up the service / database master key
//! exports the root of the encryption hierarchy, restoring re-keys the
//! instance, and a hardcoded password is a credential in source. Each
//! password's value is in the facts and is masked in every report.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_key_backup
//!     - mssql_key_backup.action: backup
//!     - mssql_key_backup.key_object:
//!         in: [service_master_key, master_key]
//! ```

use serde::{Deserialize, Serialize};

use super::PasswordLiteral;

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// The key-material verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyBackupAction {
    /// `BACKUP` — export key material to a file.
    Backup,
    /// `RESTORE` — import / re-key from a file.
    Restore,
}

/// Which key material the statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackupKeyObject {
    /// `SERVICE MASTER KEY` — the instance root key.
    ServiceMasterKey,
    /// `MASTER KEY` — the database master key.
    MasterKey,
    /// `CERTIFICATE`.
    Certificate,
    /// `ASYMMETRIC KEY`.
    AsymmetricKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlKeyBackupFacts {
    /// Whether key material is being exported (`backup`) or imported
    /// (`restore`).
    pub action: KeyBackupAction,
    /// Which key object is moved.
    pub key_object: BackupKeyObject,
    /// True when an inline `{ENCRYPTION | DECRYPTION} BY PASSWORD = '…'`
    /// protects/unlocks the material — a hardcoded credential.
    pub password_present: bool,
    /// Each password literal written, decoded: doubled quotes undone and any
    /// `N` prefix dropped. A value the engine rendered from a template or
    /// substituted for a deploy variable is not listed. The value is masked
    /// in every report; a custom rule message that interpolates it shows it
    /// unmasked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_literals: Vec<PasswordLiteral>,
}
