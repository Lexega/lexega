// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `RESTORE { DATABASE | LOG }` statement.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_restore`] when the
//! statement restores a database or transaction log. Projected from
//! [`crate::ir::restore_plan::MssqlRestorePlan`] via
//! `derive_facts_from_restore_plan`.
//!
//! Counterpart of [`crate::facts::MssqlBackupFacts`]. `RESTORE` is a
//! data-protection utility statement, not DDL — the payload sits at the top
//! level of `StatementFacts` (next to `mssql_backup`) rather than under
//! `ddl`.
//!
//! The source literal is intentionally not surfaced: restore URLs commonly
//! carry SAS credentials, and the governance signal — restoring from an
//! offsite object store — is fully captured by the device class.
//!
//! Predicate examples:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_restore
//!     - mssql_restore.source: url          # offsite / untrusted source
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlRestoreFacts {
    /// What is restored: the full database or the transaction log.
    pub target: RestoreTarget,
    /// Source device class. `Url` is an offsite / cloud object store;
    /// `Disk` is a local or network filesystem path; `Tape` is a tape device.
    /// Omitted for the recovery-only form (`WITH RECOVERY`, no source device).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<RestoreSource>,
    /// Whether the restore force-overwrites an existing database
    /// (`WITH REPLACE`). Omitted when not present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub replace: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// What a T-SQL `RESTORE` statement restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RestoreTarget {
    /// `RESTORE DATABASE …` — full or differential database restore.
    Database,
    /// `RESTORE LOG …` — transaction-log restore.
    Log,
}

/// Source device class for a T-SQL `RESTORE` statement. The literal
/// path / URL is not surfaced; rules match on the `kind` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RestoreSource {
    /// `FROM DISK = '...'` — local or network filesystem path.
    Disk,
    /// `FROM URL = '...'` — Azure blob / offsite object store.
    Url,
    /// `FROM TAPE = '...'` — tape device.
    Tape,
}
