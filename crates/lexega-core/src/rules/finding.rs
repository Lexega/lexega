// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Finding output type.
//!
//! Every finding has the uniform shape
//! `{ rule_id, evidence, source_span, risk_level, message }`; `rule_id` is
//! the sole rule-level identifier.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use crate::facts::RiskLevel;
use crate::lexer::token::Span;

/// A finding fires when a rule's predicate matches a statement's facts.
/// Carries the rule id, the matching evidence, the source span, and the
/// rendered message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct Finding {
    pub rule_id: String,
    pub evidence: FindingEvidence,
    pub source_span: Option<Span>,
    pub risk_level: RiskLevel,
    pub message: String,
    /// Populated when running with `--explain-findings`; omitted otherwise.
    pub explanation: Option<RuleExplanation>,
}

/// Evidence the predicate gathered while matching. For predicates with
/// no relational quantifiers, `witnesses` is empty (the match was
/// purely on properties). For predicates with `exists` / `each` /
/// `count` quantifiers, each entry carries a path + serialized
/// sub-fact.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FindingEvidence {
    pub witnesses: Vec<FactWitness>,
}

/// One witness — a sub-fact that satisfied a relational quantifier.
///
/// Schema-stable customer surface. Engine-internal evaluation state
/// (quantifier-origin tagging, intermediate match bookkeeping) lives
/// on and is never
/// promoted across the public boundary, so the generated JSON
/// schema for `Finding.evidence.witnesses[*]` stays the contract
/// customer rule-authoring tooling builds against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FactWitness {
    /// Dotted path on `StatementFacts` that the witness was found at,
    /// e.g. `"query.scopes.0.joins.2"`.
    pub path: String,
    /// Serialized sub-fact as JSON.
    pub value: serde_json::Value,
}

/// Optional debug payload for `--explain-findings` mode.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct RuleExplanation {
    pub matched_paths: Vec<String>,
    pub unmatched_paths: Vec<String>,
}

/// How many findings a rule raises when it matches a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EmissionMode {
    /// One finding per matching statement (default). All items that
    /// contributed to the match are reported as evidence on that one
    /// finding.
    #[default]
    Once,
    /// One finding per matching item. Use this when the rule has an
    /// `each:` clause and you want a separate finding for every item
    /// the rule visits.
    PerWitness,
}
