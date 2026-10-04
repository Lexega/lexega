// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `COMMENT ON …` typed facts.
//!
//! `COMMENT ON <target-kind> <name> IS <value>` is cross-dialect
//! (PostgreSQL, Databricks Unity Catalog, Snowflake). The target-kind
//! keyword is curated into the `CommentTargetKind` closed enum so rules
//! can predicate against typed values rather than raw SQL text.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Per-statement facts for `COMMENT ON …`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CommentOnFacts {
    /// The kind of object the comment targets.
    pub target_kind: CommentTargetKind,
}

/// The kind of object targeted by a `COMMENT ON` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "CommentTargetType"))]
pub enum CommentTargetKind {
    /// `COMMENT ON TABLE …`.
    Table,
    /// `COMMENT ON COLUMN …`.
    Column,
    /// `COMMENT ON SCHEMA …`.
    Schema,
    /// `COMMENT ON DATABASE …`.
    Database,
    /// `COMMENT ON CATALOG …` (Databricks Unity Catalog).
    Catalog,
    /// `COMMENT ON VOLUME …` (Databricks Unity Catalog).
    Volume,
    /// `COMMENT ON CONNECTION …` (Databricks Unity Catalog).
    Connection,
    /// `COMMENT ON INDEX …`.
    Index,
    /// `COMMENT ON FUNCTION …`.
    Function,
    /// `COMMENT ON PROCEDURE …`.
    Procedure,
    /// `COMMENT ON VIEW …`.
    View,
    /// `COMMENT ON SEQUENCE …`.
    Sequence,
    /// Any other `COMMENT ON` target not listed above.
    Other,
}
