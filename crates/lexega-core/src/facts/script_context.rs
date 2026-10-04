// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Per-statement view of script-level state.
//!
//! Each `StatementFacts` carries a `ScriptContext` populated by a
//! script-level pre-fold over the statement sequence. This lets
//! customer rules express cross-statement predicates ("did this PR's
//! earlier statement create the table this one references?")
//! without violating the streaming-evaluation discipline (per-statement
//! materialization + drop) — the script context is computed once
//! upfront and copied (or referenced) into each statement.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::ddl::DdlAction;
use super::identity::{IdentName, ObjectRef};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ScriptContext {
    /// Position of this statement in the script (0 = first).
    pub statement_index: u32,

    /// Total number of statements in the script.
    pub total_statements: u32,

    /// What's enclosing this statement, if any (procedure body, function
    /// body, trigger body, control-flow block).
    pub enclosing: Option<EnclosingKind>,

    /// DDL actions that have already executed in this script before
    /// this statement. Useful for rules like "fire when this statement
    /// references a table that was created earlier in the same script."
    pub earlier_ddl: Vec<EarlierDdl>,

    /// dbt model identity if this statement is the terminal SELECT of a
    /// dbt model.
    pub dbt_model: Option<DbtModelContext>,

    /// Session context in effect at this statement (e.g. the active
    /// role), accumulated from earlier session statements such as
    /// `USE ROLE`. Absent until a session role or similar context has
    /// been established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionContextFacts>,
}

/// Session-level context in effect at a statement, carried forward from
/// preceding session statements (`USE ROLE`, …).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SessionContextFacts {
    /// The role in effect when this statement runs, set by the most
    /// recent preceding `USE ROLE`. Absent before any `USE ROLE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_role: Option<IdentName>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnclosingKind {
    Procedure {
        name: IdentName,
    },
    Function {
        name: IdentName,
    },
    Trigger {
        name: IdentName,
    },
    Block,
    /// Nested control-flow body (IF / WHILE / FOR / LOOP / TRY-CATCH).
    ControlFlow {
        flow_kind: ControlFlowKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ControlFlowType"))]
pub enum ControlFlowKind {
    If,
    Case,
    While,
    For,
    Loop,
    Repeat,
    TryCatch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PreviousDdl"))]
pub struct EarlierDdl {
    /// The DDL action that ran earlier (Create / Alter / Drop / etc.).
    pub action: DdlAction,
    /// What was acted upon.
    pub target: ObjectRef,
    /// Position of the earlier statement (0-indexed; less than the
    /// containing `statement_index`).
    pub at_index: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DbtModelContext {
    pub model_name: IdentName,
    pub upstream_models: Vec<IdentName>,
}
