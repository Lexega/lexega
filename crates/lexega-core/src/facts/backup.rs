// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `BACKUP { DATABASE | LOG }` statement.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_backup`] when the
//! statement backs up a database or transaction log. Projected from
//! [`crate::ir::backup_plan::MssqlBackupPlan`] via
//! `derive_facts_from_backup_plan`.
//!
//! `BACKUP` is a data-protection utility statement, not DDL — the payload
//! sits at the top level of `StatementFacts` (next to `pg_copy`) rather than
//! under `ddl`.
//!
//! The destination literal is intentionally not surfaced: backup URLs
//! commonly carry SAS credentials, and the governance signal — backing up to
//! an offsite object store — is fully captured by the device class.
//!
//! Predicate examples:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_backup
//!     - mssql_backup.destination: url      # offsite / cloud backup target
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlBackupFacts {
    /// What is backed up: the full database or the transaction log.
    pub target: BackupTarget,
    /// Destination device class. `Url` is an offsite / cloud object store;
    /// `Disk` is a local or network filesystem path; `Tape` is a tape device.
    pub destination: BackupDestination,
    /// Whether the backup is encrypted (`WITH ENCRYPTION`). Omitted when the
    /// backup is not encrypted.
    #[serde(default, skip_serializing_if = "is_false")]
    pub encryption: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// What a T-SQL `BACKUP` statement backs up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackupTarget {
    /// `BACKUP DATABASE …` — full or differential database backup.
    Database,
    /// `BACKUP LOG …` — transaction-log backup.
    Log,
}

/// Destination device class for a T-SQL `BACKUP` statement. The literal
/// path / URL is not surfaced; rules match on the `kind` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackupDestination {
    /// `TO DISK = '...'` — local or network filesystem path.
    Disk,
    /// `TO URL = '...'` — Azure blob / offsite object store.
    Url,
    /// `TO TAPE = '...'` — tape device.
    Tape,
}
