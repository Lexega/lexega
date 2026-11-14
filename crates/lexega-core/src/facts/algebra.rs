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

impl AlgebraFacts {
    /// Add every event `other`, read of the same statement, holds.
    pub(crate) fn absorb(&mut self, other: AlgebraFacts) {
        let AlgebraFacts {
            contradictions,
            impossible_ranges,
            tautologies,
            redundancies,
            cross_scope_contradictions,
        } = other;
        self.contradictions.extend(contradictions);
        self.impossible_ranges.extend(impossible_ranges);
        self.tautologies.extend(tautologies);
        self.redundancies.extend(redundancies);
        self.cross_scope_contradictions
            .extend(cross_scope_contradictions);
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Contradiction"))]
pub struct ContradictionEvent {
    pub column: ColumnRef,
    pub conflicting_values: (LiteralValue, LiteralValue),
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
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

/// A contradiction as it serializes: its values masked where a report
/// prints it and the text of its predicates holds a literal it does not
/// show (`super::secrets::masked_in_print`).
impl Serialize for ContradictionEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let masked = super::secrets::masked_in_print(self.source_span);
        let (a, b) = &self.conflicting_values;
        let values = match masked {
            true => (a.masked(), b.masked()),
            false => (a.clone(), b.clone()),
        };
        let mut out = serializer.serialize_struct("ContradictionEvent", 4)?;
        out.serialize_field("column", &self.column)?;
        out.serialize_field("conflicting_values", &values)?;
        out.serialize_field("scope_id", &self.scope_id)?;
        out.serialize_field("source_span", &self.source_span)?;
        out.end()
    }
}

/// An impossible range as it serializes: its bounds masked where a report
/// prints it and the text of its predicates holds a literal it does not
/// show (`super::secrets::masked_in_print`).
impl Serialize for RangeContradictionEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let masked = super::secrets::masked_in_print(self.source_span);
        let bound = |value: &LiteralValue| match masked {
            true => value.masked(),
            false => value.clone(),
        };
        let mut out = serializer.serialize_struct("RangeContradictionEvent", 7)?;
        out.serialize_field("column", &self.column)?;
        out.serialize_field("low", &bound(&self.low))?;
        out.serialize_field("high", &bound(&self.high))?;
        out.serialize_field("low_inclusive", &self.low_inclusive)?;
        out.serialize_field("high_inclusive", &self.high_inclusive)?;
        out.serialize_field("scope_id", &self.scope_id)?;
        out.serialize_field("source_span", &self.source_span)?;
        out.end()
    }
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UpstreamContradictionEvent"))]
pub struct CrossScopeContradictionEvent {
    pub upstream: UpstreamFactsRef,
    pub consumer_column: ColumnRef,
    pub upstream_constraint: UpstreamConstraint,
    pub consumer_predicate: PredicateEvent,
    pub source_span: Option<Span>,
    /// Where the source writes the literals `upstream_constraint` holds.
    #[serde(skip)]
    pub(crate) upstream_origin: ConstraintOrigin,
}

/// A cross-scope contradiction as it serializes: the upstream constraint's
/// values masked where a report prints it and the text they are written
/// in is masked ([`ConstraintOrigin`]).
impl Serialize for CrossScopeContradictionEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut out = serializer.serialize_struct("CrossScopeContradictionEvent", 5)?;
        out.serialize_field("upstream", &self.upstream)?;
        out.serialize_field("consumer_column", &self.consumer_column)?;
        match self.upstream_origin.masked_in_print() {
            true => {
                out.serialize_field("upstream_constraint", &self.upstream_constraint.masked())?
            }
            false => out.serialize_field("upstream_constraint", &self.upstream_constraint)?,
        }
        out.serialize_field("consumer_predicate", &self.consumer_predicate)?;
        out.serialize_field("source_span", &self.source_span)?;
        out.end()
    }
}

/// Where the source writes the literals a constraint holds, which is no
/// part of the fact: the text of a statement's CTE or derived table, or
/// text outside the statement (a model, a relation another statement
/// made), which is masked wherever a report prints it.
#[derive(Debug, Clone, Copy, Default)]
pub enum ConstraintOrigin {
    At(Span),
    #[default]
    Elsewhere,
}

impl PartialEq for ConstraintOrigin {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl ConstraintOrigin {
    /// Written at `span`, where the statement writes it; elsewhere
    /// where `None`.
    pub fn of(span: Option<Span>) -> Self {
        match span {
            Some(span) => Self::At(span),
            None => Self::Elsewhere,
        }
    }

    /// Whether a report masks the constraint's values where it prints
    /// them.
    pub(crate) fn masked_in_print(self) -> bool {
        match self {
            Self::At(span) => super::secrets::masked_in_print(Some(span)),
            Self::Elsewhere => super::secrets::masked_in_print_elsewhere(),
        }
    }
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

impl UpstreamConstraint {
    /// This constraint as a report prints it where its source is masked:
    /// each value masked ([`LiteralValue::masked`]).
    pub(crate) fn masked(&self) -> UpstreamConstraint {
        let all = |values: &[LiteralValue]| values.iter().map(LiteralValue::masked).collect();
        match self {
            Self::EqualsLiteral { value } => Self::EqualsLiteral {
                value: value.masked(),
            },
            Self::NotEqualsLiteral { value } => Self::NotEqualsLiteral {
                value: value.masked(),
            },
            Self::InSet { values } => Self::InSet {
                values: all(values),
            },
            Self::NotInSet { values } => Self::NotInSet {
                values: all(values),
            },
            Self::IsNull => Self::IsNull,
            Self::IsNotNull => Self::IsNotNull,
            Self::Range {
                low,
                high,
                low_inclusive,
                high_inclusive,
            } => Self::Range {
                low: low.as_ref().map(LiteralValue::masked),
                high: high.as_ref().map(LiteralValue::masked),
                low_inclusive: *low_inclusive,
                high_inclusive: *high_inclusive,
            },
        }
    }
}
