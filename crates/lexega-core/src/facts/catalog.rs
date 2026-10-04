// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Catalog-driven and derived attributes that surface on column refs.
//!
//! `Nullability` carries a `reason:` field, which lets predicates
//! discriminate WHY a column is null/non-null, not just THAT it is.
//!
//! `TaintLabel` is a customer-facing closed enum of classification labels
//! with an `Other(String)` arm for catalog-defined tags.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::identity::{IdentName, TableRef};

/// A catalog-defined tag attached to an object or column. Snowflake's
/// classification tags, dbt model tags, and dialect-specific governance
/// tags all surface here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CatalogTag {
    pub key: IdentName,
    /// Tag values can be arbitrary strings; not constrained to
    /// `IdentName`.
    pub value: Option<String>,
}

/// Classification labels attached to objects or columns. The common
/// set is enumerated below; `Other(String)` covers catalog-defined
/// extensions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TaintLabel {
    Pii,
    Phi,
    Confidential,
    Restricted,
    Internal,
    Public,
    /// Catalog-defined or dialect-specific labels. Predicates match
    /// against the inner string with `matches:` glob.
    Other(String),
}

/// Whether a tainted output column can surface the value of its
/// classified source. An output column derived from a tagged source
/// carries one of these depending on the transform between the source
/// value and the output: a pass-through or value-selecting aggregate
/// preserves the value, while a count or sum collapses it to a
/// statistic that no longer exposes the original. Governance rules use
/// it to flag only the columns that actually materialise classified
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ValueExposure {
    /// The output can surface the source value — pass-through, a
    /// value-reshaping function (UPPER, SUBSTRING, CONCAT, CAST), or a
    /// value-selecting aggregate (MAX, MIN, ANY_VALUE, LISTAGG).
    #[default]
    Value,
    /// A one-way digest of the value (SHA2, MD5, HASH): the plaintext is
    /// obscured but the result is still per-row and re-identifiable.
    Digest,
    /// A cardinality reduction (COUNT, COUNT DISTINCT): the output is a
    /// count and the original values cannot be recovered.
    Cardinality,
    /// A numeric or measure reduction (SUM, AVG, STDDEV, MEDIAN, LENGTH):
    /// the output is a derived scalar, not the source value.
    Derived,
}

/// Per-column nullability. Match `nullability.kind: derived_nullable`
/// plus `nullability.reason: left_join_outer_side` to discriminate why
/// a column may be NULL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[derive(Default)]
pub enum Nullability {
    /// Catalog says column is NOT NULL (constraint exists).
    CatalogNonNullable,
    /// Catalog says column is nullable.
    CatalogNullable,
    /// Analysis concluded the column is always non-NULL in this scope.
    DerivedNonNullable { reason: NonNullableReason },
    /// Analysis concluded the column may be NULL in this scope.
    DerivedNullable { reason: NullableReason },
    /// A predicate (e.g. `IS NOT NULL`) ensures non-null in this scope.
    FilteredNonNullable,
    /// No catalog attached and analysis could not decide.
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "NotNullReason"))]
pub enum NonNullableReason {
    /// Constant literal expression (`1`, `'x'`, etc.).
    Literal,
    /// `COUNT(*)` / `COUNT(col)` — never NULL by SQL semantics.
    AggregateCount,
    /// Aggregates that are known not to produce NULL (`ARRAY_AGG`,
    /// `STRING_AGG` over guarded inputs, etc.).
    AggregateNullSafe,
    /// Expression over only non-nullable inputs.
    DerivedFromNonNullableInputs,
    /// `COALESCE(col, fallback)` where fallback is non-nullable.
    CoalesceWithNonNullableFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum NullableReason {
    /// Outer side of a `LEFT JOIN` (right-hand columns).
    LeftJoinOuterSide,
    /// Outer side of a `RIGHT JOIN` (left-hand columns).
    RightJoinOuterSide,
    /// `FULL OUTER JOIN` null-padding on either side.
    FullOuterJoinPad,
    /// `CASE WHEN … END` without an `ELSE` branch.
    CaseWhenWithoutElse,
    /// `NULLIF(a, b)` returns null when `a = b`.
    NullIfFunc,
    /// Scalar subquery may return zero rows.
    EmptyScalarSubquery,
    /// `UNION` branch with mismatched nullability.
    UnionWithNullableBranch,
    /// `SAFE_CAST` returns null on failure.
    SafeCast,
    /// Expression could not be fully analyzed; conservatively treated
    /// as nullable.
    OpaqueExpression,
    /// Expression over inputs that include at least one nullable.
    DerivedFromNullableInputs,
}

/// Trace from a column reference back to its base-table origin. Match
/// against `lineage.base_table.canonical` plus the chain of CTE /
/// derived-table / view intermediates in `transitive_chain`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ColumnLineage {
    pub base_table: TableRef,
    pub base_column: IdentName,
    pub transitive_chain: Vec<LineageHop>,
    /// `false` when a hop in the chain could not be fully resolved
    /// (CTE body not analyzable, view definition not in the catalog,
    /// etc.).
    pub fully_resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct LineageHop {
    pub kind: LineageHopKind,
    pub name: IdentName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "LineageHopType"))]
pub enum LineageHopKind {
    Cte,
    DerivedTable,
    View,
    MaterializedView,
    Model,
}
