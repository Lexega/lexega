// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! DECLARE HANDLER statement facts.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct HandlerFacts {
    pub handler_type: HandlerType,
    pub conditions: Vec<HandlerCondition>,
    pub body: HandlerBody,
}

/// `EXIT` (terminates the enclosing block on raise) vs `CONTINUE`
/// (resumes after the failing statement). `Simple` is the SQL/PSM
/// form with no explicit keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HandlerType {
    Simple,
    Exit,
    Continue,
}

/// One typed condition the handler subscribes to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HandlerCondition {
    /// `SQLEXCEPTION` — broad catch-all for non-warning, non-not-found
    /// SQLSTATE classes.
    SqlException,
    /// `SQLWARNING` — SQLSTATE class '01'.
    SqlWarning,
    /// `NOT FOUND` — SQLSTATE class '02'.
    NotFound,
    /// `SQLSTATE [VALUE] '<code>'` — explicit SQLSTATE code.
    SqlState,
    /// A user-defined condition name (declared via `DECLARE … CONDITION`).
    NamedCondition,
}

/// The handler action body, represented as the list of statement kinds
/// it contains (recursively, including nested blocks and control flow).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct HandlerBody {
    pub statement_kinds: Vec<HandlerBodyStatementKind>,
}

/// Statement kinds that can appear in a handler action body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "HandlerBodyStatementType"))]
pub enum HandlerBodyStatementKind {
    /// `RESIGNAL` — re-raise the current condition.
    Resignal,
    /// `SIGNAL` — raise a new condition.
    Signal,
    /// `GET DIAGNOSTICS` — read diagnostic info from the last condition.
    GetDiagnostics,
}
