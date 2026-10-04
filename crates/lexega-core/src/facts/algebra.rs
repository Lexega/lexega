// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Constraint-algebra facts: contradictions, impossible ranges,
//! tautologies, redundancies, cross-scope contradictions.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use crate::lexer::token::Span;

use super::identity::{ColumnRef, IdentName, ScopeIdentity};
use super::literal::LiteralValue;
use super::query::PredicateEvent;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AlgebraFacts {
    pub contradictions: Vec<ContradictionEvent>,
    pub impossible_ranges: Vec<RangeContradictionEvent>,
    pub tautologies: Vec<TautologyEvent>,
    pub redundancies: Vec<RedundancyEvent>,
    pub cross_scope_contradictions: Vec<CrossScopeContradictionEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Contradiction"))]
pub struct ContradictionEvent {
    pub column: ColumnRef,
    pub conflicting_values: (LiteralValue, LiteralValue),
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ImpossibleRange"))]
pub struct RangeContradictionEvent {
    pub column: ColumnRef,
    pub low: LiteralValue,
    pub high: LiteralValue,
    pub low_inclusive: bool,
    pub high_inclusive: bool,
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "AlwaysTruePredicate"))]
pub struct TautologyEvent {
    pub predicate: PredicateEvent,
    pub kind: TautologyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "TautologyType"))]
pub enum TautologyKind {
    /// `1 = 1`, `TRUE`, etc.
    AlwaysTrue,
    /// `col = col` where col is non-nullable.
    SelfEquality,
    /// `col BETWEEN MIN AND MAX` over the column's domain.
    UniversalRange,
    /// `OR` chain that covers the universe (e.g. `x IS NULL OR x IS NOT NULL`).
    UniversalDisjunction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "RedundantPredicate"))]
pub struct RedundancyEvent {
    pub redundant: PredicateEvent,
    pub implied_by: PredicateEvent,
    pub scope_id: ScopeIdentity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UpstreamContradictionEvent"))]
pub struct CrossScopeContradictionEvent {
    pub upstream: UpstreamFactsRef,
    pub consumer_column: ColumnRef,
    pub upstream_constraint: UpstreamConstraint,
    pub consumer_predicate: PredicateEvent,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpstreamFactsRef {
    Cte {
        name: IdentName,
        scope_id: ScopeIdentity,
    },
    DerivedTable {
        alias: IdentName,
        scope_id: ScopeIdentity,
    },
    /// A dbt model reference resolved from the dbt manifest.
    Model { name: IdentName },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpstreamConstraint {
    EqualsLiteral {
        value: LiteralValue,
    },
    NotEqualsLiteral {
        value: LiteralValue,
    },
    InSet {
        values: Vec<LiteralValue>,
    },
    NotInSet {
        values: Vec<LiteralValue>,
    },
    IsNull,
    IsNotNull,
    Range {
        low: Option<LiteralValue>,
        high: Option<LiteralValue>,
        low_inclusive: bool,
        high_inclusive: bool,
    },
}
