// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `DBCC <command>` statement.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_dbcc`] for any DBCC
//! (database console command). Projected from
//! [`crate::ir::dbcc_plan::MssqlDbccPlan`] via `derive_facts_from_dbcc_plan`.
//!
//! `DBCC` is a maintenance / admin utility, not DDL — the payload sits at the
//! top level of `StatementFacts` (next to `mssql_backup`) rather than under
//! `ddl`.
//!
//! The single surfaced primitive is the command verb, normalized to
//! lowercase. The DBCC family spans dozens of commands of wildly different
//! risk — `CHECKDB` is a read-only integrity check, `WRITEPAGE` writes raw
//! bytes to a data page, `TRACEON` flips global engine behavior. Which
//! commands are dangerous is a YAML verdict (`mssql_dbcc.command: { in: [...] }`),
//! never baked into Rust.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_dbcc
//!     - mssql_dbcc.command:
//!         in: [writepage, traceon, traceoff, shrinkdatabase, shrinkfile]
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlDbccFacts {
    /// The DBCC command verb, normalized to lowercase (e.g. `checkdb`,
    /// `traceon`, `writepage`). Which commands are dangerous is a policy
    /// verdict expressed in rules, not here.
    pub command: String,
}
