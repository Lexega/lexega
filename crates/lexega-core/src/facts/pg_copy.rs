// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for PostgreSQL `COPY` statements.
//!
//! Populated on [`crate::facts::StatementFacts::pg_copy`] when the
//! statement is `COPY <table_or_query> { FROM | TO } { '<file>' |
//! PROGRAM '<cmd>' | STDIN | STDOUT } …`. Projected from
//! [`crate::ir::pg_copy_plan::PgCopyPlan`] via
//! `derive_facts_from_pg_copy_plan`.
//!
//! `COPY` is a data-movement utility statement, not DDL — the public
//! facts payload sits at the top level of `StatementFacts` (next to
//! `use_stmt` and `policy_attachment`) rather than under `ddl`.
//!
//! Predicate examples:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: pg_copy
//!     - pg_copy.target: program          # PROGRAM target — shell exec
//! ```
//!
//! Both [`PgCopyDirection`] and [`PgCopyTargetKind`] are deliberately
//! narrow closed enums: rules predicate against the variant tag, not
//! the source spans (which are engine-internal and dropped at the
//! AST→IR boundary).

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PgCopyFacts {
    /// Movement direction. `From` loads into a table; `To` exports
    /// from a table or query.
    pub direction: PgCopyDirection,
    /// Endpoint kind. `Program` is shell execution (critical risk);
    /// `File` is filesystem I/O; `Stdin`/`Stdout` are client-driven.
    pub target: PgCopyTargetKind,
}

/// Direction of a PostgreSQL `COPY` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PostgresCopyDirection"))]
pub enum PgCopyDirection {
    /// `COPY <target> FROM <source>` — import data into table.
    From,
    /// `COPY <target> TO <sink>` — export data from table/query.
    To,
}

/// Endpoint kind for a PostgreSQL `COPY` statement. The literal
/// filename / program string is not surfaced; rules match on the
/// `kind` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PostgresCopyTargetType"))]
pub enum PgCopyTargetKind {
    /// `'<filename>'` literal endpoint.
    File,
    /// `PROGRAM '<cmd>'` — shell command executed by the server
    /// process. Critical security surface.
    Program,
    /// `STDIN` — client-driven input stream.
    Stdin,
    /// `STDOUT` — client-driven output stream.
    Stdout,
    /// psql client variable (`:var`) standing in for the endpoint; the
    /// concrete path is not known until the psql client substitutes it.
    Placeholder,
}
