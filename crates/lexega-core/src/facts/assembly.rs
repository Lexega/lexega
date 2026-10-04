// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `CREATE`/`ALTER ASSEMBLY` (CLR)
//! statements.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_assembly`]. Projected
//! from [`crate::ir::assembly_plan::MssqlAssemblyPlan`] via
//! `derive_facts_from_assembly_plan`.
//!
//! A CLR assembly registers .NET code that runs inside the SQL Server process.
//! Three recognition primitives are surfaced: the verb, the permission set, and
//! whether the assembly is loaded from a filesystem path. Which permission is
//! dangerous is a YAML verdict — `unsafe` grants full trust (arbitrary native
//! code), `external_access` grants filesystem / network access.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_assembly
//!     - mssql_assembly.permission_set: unsafe
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// The CLR-assembly verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AssemblyAction {
    /// `CREATE ASSEMBLY`.
    Create,
    /// `ALTER ASSEMBLY`.
    Alter,
}

/// The `WITH PERMISSION_SET = …` trust level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AssemblyPermissionSet {
    /// `SAFE` — computation only, no external resources.
    Safe,
    /// `EXTERNAL_ACCESS` — filesystem / network / registry / environment.
    ExternalAccess,
    /// `UNSAFE` — full trust; native calls, P/Invoke, arbitrary I/O.
    Unsafe,
    /// No `PERMISSION_SET` clause was given (SQL Server defaults to `safe`).
    Unset,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlAssemblyFacts {
    /// Whether the assembly is being created or altered.
    pub action: AssemblyAction,
    /// The assembly's permission set (trust level).
    pub permission_set: AssemblyPermissionSet,
    /// True when the assembly is loaded from a `FROM '<path>'` filesystem
    /// source rather than an inline binary.
    pub from_file: bool,
}
