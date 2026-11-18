// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Closure compiler — turns a parsed `Predicate` AST into an evaluation
//! closure over `StatementFacts`.
//!
//! Closure compilation works against a serialized JSON view of
//! `StatementFacts` (`serde_json::to_value`). Path traversal walks the
//! JSON tree; predicates evaluate against scalar / array / object
//! shapes the same way regardless of the underlying Rust type.
//!
//! Trade-off: the JSON-mediated path means a per-predicate
//! serialization cost. If it dominates evaluation time, the runtime
//! can swap to a `PathAccessor` trait against the typed structs
//! directly. The closure shape doesn't change for callers; only the
//! closure body.
//!
//! Type checking: paths are validated at evaluation time by walking
//! the runtime JSON tree.

use std::borrow::Cow;
use std::sync::Arc;

use serde_json::Value;

use super::explain::{ExplainTrace, MatchReason, UnmatchReason};
use super::finding::RuleExplanation;
use super::lists::{NameForm, ValueList, ValueLists};
use super::predicate::{
    FieldName, FieldPath, NumericOp, ParseError, Predicate, PredicateLiteral, Quantifier,
    ScalarMatch, ScalarOp,
};
use crate::facts::{LiteralValue, RuleCategory, StatementKind};
// Only the test-gated `matches`/`evaluate_with_explain` take typed facts.
#[cfg(test)]
use crate::facts::StatementFacts;

// ─────────────────────────────────────────────────────────────────────
// Compile errors.
// ─────────────────────────────────────────────────────────────────────

/// Errors raised while compiling a parsed `Predicate` into a closure.
#[derive(Debug, Clone, PartialEq)]
pub enum CompileError {
    /// A `parse_predicate` error bubbled up unchanged.
    Parse(ParseError),
    /// Compile-time invariant violation (e.g. unimplemented case).
    Internal(String),
    /// A scalar / relational match at the outermost predicate scope
    /// referenced a field-path whose first segment is not a known
    /// top-level field on `StatementFacts`. Surfaces a typo in a
    /// customer rule at load time rather than letting the rule
    /// compile and silently never fire.
    UnknownRootField { path: String, unknown_root: String },
    /// A path names no fact below its first field: a field the facts do
    /// not have, or a field of a list's elements reached without naming an
    /// element. Surfaces a typo at load time, as `UnknownRootField` does.
    UnknownFactPath { path: String, problem: PathProblem },
    /// An `in_list` / `not_in_list` operator names a list the table does
    /// not hold. List names are exact.
    UnknownList { list: String },
    /// A comparison of the statement's `kind` names a kind no statement
    /// has: the rule would never fire (or, negated, always would).
    /// `suggestion` is the nearest kind.
    UnknownStatementKind {
        kind: String,
        suggestion: Option<String>,
    },
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "{}", e),
            Self::Internal(msg) => write!(f, "internal compile error: {}", msg),
            Self::UnknownRootField { path, unknown_root } => write!(
                f,
                "unknown root field '{}' in path '{}': not a top-level StatementFacts field",
                unknown_root, path
            ),
            Self::UnknownFactPath { path, problem } => match problem {
                PathProblem::UnknownField {
                    field,
                    under,
                    suggestion,
                } => {
                    write!(f, "unknown field '{field}' in path '{path}': ")?;
                    match under.is_empty() {
                        true => write!(f, "the statement's facts have no such field")?,
                        false => write!(f, "'{under}' has no such field")?,
                    }
                    match suggestion {
                        Some(nearest) => write!(f, "; did you mean '{nearest}'?"),
                        None => Ok(()),
                    }
                }
                PathProblem::ThroughList { list } => write!(
                    f,
                    "path '{path}' reads a field of the elements of '{list}', a list: \
                     name one element ('{list}.0.…') or quantify the list \
                     ('{list}: {{ exists: … }}')"
                ),
            },
            Self::UnknownList { list } => write!(f, "unknown list '{}'", list),
            Self::UnknownStatementKind { kind, suggestion } => {
                write!(f, "unknown statement kind '{}'", kind)?;
                match suggestion {
                    Some(nearest) => write!(f, "; did you mean '{}'?", nearest),
                    None => Ok(()),
                }
            }
        }
    }
}

impl std::error::Error for CompileError {}

impl From<ParseError> for CompileError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

// ─────────────────────────────────────────────────────────────────────
// CompiledPredicate — the closure-bearing handle.
// ─────────────────────────────────────────────────────────────────────

/// A compiled predicate ready for evaluation against `StatementFacts`.
/// Cloneable handles share the built evaluator via `Arc`.
///
/// Evaluation threads an `Option<&mut ExplainTrace>` so the same
/// evaluator serves both the hot path (`evaluate_value`, no trace
/// collection) and explain mode (`evaluate_value_with_explain`, typed
/// trace entries collected, then projected onto the schema-stable
/// [`RuleExplanation`] string surface at the engine boundary).
#[derive(Clone)]
pub struct CompiledPredicate {
    eval: Arc<Evaluator>,
    /// Fact-family dispatch mask (see `predicate_root_mask`). Lets the
    /// engine skip this rule on statements whose facts cannot match it.
    root_mask: u32,
    /// Statement-kind dispatch gate (see `predicate_kind_gate`). Lets the
    /// engine skip this rule on statements whose kind it cannot match.
    kind_gate: KindGate,
    /// Recognition-derived category (see `super::category::category_of_rule`).
    /// Never authored on the rule.
    category: RuleCategory,
    /// Whether the predicate reads a fact a reasoning provider supplies
    /// (see `super::depth::reads_reasoning`).
    reads_reasoning: bool,
}

/// Engine-internal witness during predicate evaluation.
///
/// Carries the same `(path, value)` pair as the public
/// [`FactWitness`] plus a `from_each` tag that distinguishes
/// outermost-`each:` quantifier matches (the per-witness emission
/// driver) from intermediate `exists:` matches. The flag never
/// crosses the rules-engine API boundary: `emit_for_match` reads it
/// to decide emission cardinality, then constructs `FactWitness`
/// values for the customer-facing `Finding.evidence`. Keeping the
/// flag here (not on `FactWitness`) ensures the generated JSON
/// schema for `Finding.evidence.witnesses[*]` stays a stable
/// customer-platform contract independent of engine internals.
///
/// `value` borrows the element of the evaluated facts: a finding copies
/// it only when it is emitted.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WitnessCandidate<'v> {
    pub(crate) path: String,
    pub(crate) value: &'v Value,
    pub(crate) from_each: bool,
}

/// The outcome of evaluating a compiled predicate.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum EvalResult<'v> {
    /// Predicate did not match. No finding emitted.
    NoMatch,
    /// Predicate matched. `witnesses` carries every relational-quantifier
    /// witness gathered along the way; `from_each` distinguishes
    /// outermost-`each:` matches from intermediate `exists:` matches
    /// so the engine's `emit_for_match` can apply per-witness
    /// emission semantics without the flag leaking onto the public
    /// `Finding.evidence` surface.
    Match {
        witnesses: Vec<WitnessCandidate<'v>>,
    },
}

impl EvalResult<'_> {
    /// Test-only convenience; engine code pattern-matches directly.
    #[cfg(test)]
    pub(crate) fn is_match(&self) -> bool {
        matches!(self, Self::Match { .. })
    }
}

impl CompiledPredicate {
    /// Evaluate against a `StatementFacts` snapshot. Hot path — no
    /// explain trace collected.
    ///
    /// Test-only convenience; serializes `facts` to a JSON value each
    /// call and says whether the predicate matches. Production batch
    /// callers serialize once and use [`Self::evaluate_value`].
    #[cfg(test)]
    pub(crate) fn matches(&self, facts: &StatementFacts) -> bool {
        let value = serde_json::to_value(facts).unwrap_or(Value::Null);
        self.run(&value, None).is_match()
    }

    /// Evaluate against a pre-serialized facts value. The engine
    /// builds this value once per statement
    /// ([`super::engine::evaluate_rules`]) and reuses it across every
    /// rule, avoiding a per-rule serialization that would dominate
    /// the rule-evaluation cost.
    pub(crate) fn evaluate_value<'v>(&self, value: &'v Value) -> EvalResult<'v> {
        self.run(value, None)
    }

    fn run<'v>(&self, value: &'v Value, trace: Option<&mut ExplainTrace>) -> EvalResult<'v> {
        let mut witnesses = Vec::new();
        if evaluate_node(&self.eval, value, &mut witnesses, Prefix::Root, trace) {
            EvalResult::Match { witnesses }
        } else {
            EvalResult::NoMatch
        }
    }

    /// Fact-family dispatch mask. `0` means "always evaluate"; a
    /// non-zero mask disjoint from a statement's `facts_present_mask`
    /// proves this predicate is NoMatch on that statement.
    pub(crate) fn root_mask(&self) -> u32 {
        self.root_mask
    }

    /// Statement-kind dispatch gate. `Only(S)` with the statement's kind
    /// outside `S` proves this predicate is NoMatch on that statement.
    pub(crate) fn kind_gate(&self) -> &KindGate {
        &self.kind_gate
    }

    /// Recognition-derived category of this rule.
    pub fn category(&self) -> RuleCategory {
        self.category
    }

    /// Whether this rule reads a fact a reasoning provider supplies.
    /// Under recognition alone such a rule evaluates that fact at its
    /// default, so it can stay silent or report more coarsely than it
    /// would with a provider.
    pub fn reads_reasoning(&self) -> bool {
        self.reads_reasoning
    }

    /// Evaluate with introspection enabled. Returns both the
    /// `EvalResult` and the customer-facing [`RuleExplanation`] (typed
    /// trace projected to the schema-stable string surface).
    /// Test-only convenience; the engine's explain path uses
    /// [`Self::evaluate_value_with_explain`].
    #[cfg(test)]
    pub(crate) fn evaluate_with_explain(&self, facts: &StatementFacts) -> (bool, RuleExplanation) {
        let value = serde_json::to_value(facts).unwrap_or(Value::Null);
        let mut trace = ExplainTrace::default();
        let matched = self.run(&value, Some(&mut trace)).is_match();
        (matched, trace.into_rule_explanation())
    }

    /// Explain-mode variant accepting a pre-serialized value.
    #[cfg(test)]
    pub(crate) fn evaluate_value_with_explain<'v>(
        &self,
        value: &'v Value,
    ) -> (EvalResult<'v>, RuleExplanation) {
        self.evaluate_value_with_explain_masking(value, None)
    }

    /// Explain-mode variant accepting a pre-serialized value, each string
    /// of it the explanation quotes masked where `quoting` holds it. Used
    /// by the engine's explain path for the same per-statement caching
    /// reason as [`Self::evaluate_value`].
    pub(crate) fn evaluate_value_with_explain_masking<'v>(
        &self,
        value: &'v Value,
        quoting: Option<&crate::facts::secrets::QuotingStrings>,
    ) -> (EvalResult<'v>, RuleExplanation) {
        let mut trace = ExplainTrace {
            entries: Vec::new(),
            quoting,
        };
        let result = self.run(value, Some(&mut trace));
        (result, trace.into_rule_explanation())
    }
}

impl std::fmt::Debug for CompiledPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPredicate").finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────
// compile() — Predicate AST → CompiledPredicate.
// ─────────────────────────────────────────────────────────────────────

/// Compile a parsed `Predicate` to a closure. The returned
/// `CompiledPredicate` evaluates against `StatementFacts` at runtime
/// (serializing to JSON internally for path traversal).
pub fn compile(predicate: &Predicate) -> Result<CompiledPredicate, CompileError> {
    compile_with_lists(predicate, &ValueLists::default())
}

/// [`compile`] with the lists an `in_list` / `not_in_list` operator may
/// name; a name the table lacks is [`CompileError::UnknownList`].
pub fn compile_with_lists(
    predicate: &Predicate,
    lists: &ValueLists,
) -> Result<CompiledPredicate, CompileError> {
    validate_root_field_paths(predicate)?;
    validate_fact_paths(predicate, FACTS_ROOT, "")?;
    build_compiled(predicate, lists)
}

/// [`compile_with_lists`] for a predicate read over values of any shape:
/// its paths below their first field are not checked against the facts.
#[cfg(test)]
fn compile_any_shape(
    predicate: &Predicate,
    lists: &ValueLists,
) -> Result<CompiledPredicate, CompileError> {
    validate_root_field_paths(predicate)?;
    build_compiled(predicate, lists)
}

/// The compiled form of a predicate whose paths were checked.
fn build_compiled(
    predicate: &Predicate,
    lists: &ValueLists,
) -> Result<CompiledPredicate, CompileError> {
    let root_mask = predicate_root_mask(predicate);
    let kind_gate = predicate_kind_gate(predicate);
    let category = super::category::category_of_rule(predicate);
    let reads_reasoning = super::depth::reads_reasoning(predicate);
    let eval = Arc::new(build_evaluator(predicate, lists)?);
    Ok(CompiledPredicate {
        eval,
        root_mask,
        kind_gate,
        category,
        reads_reasoning,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Root-scope field path validation.
//
// Customer rules whose `triggers:` reference a path that isn't a
// top-level `StatementFacts` field should fail at compile time —
// otherwise a typo silently produces a dead rule. The check fires
// at the outermost predicate scope only; quantifier inner
// predicates (`each:`, `all:`, `none:`, `exists:`) evaluate against
// a sub-element whose schema differs from `StatementFacts`, so
// their first segments are NOT validated here.
//
// The same scope validates the values the statement's `kind` is
// compared with: a kind no statement has would make the rule dead (or,
// negated, always true).
// ─────────────────────────────────────────────────────────────────────

/// A deserialization error that keeps the variant names serde lists for
/// an unknown enum value.
#[derive(Debug)]
struct UnknownVariant(&'static [&'static str]);

impl std::fmt::Display for UnknownVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown variant, expected one of {}", self.0.join(", "))
    }
}

impl std::error::Error for UnknownVariant {}

impl serde::de::Error for UnknownVariant {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        UnknownVariant(&[])
    }

    fn unknown_variant(_: &str, expected: &'static [&'static str]) -> Self {
        UnknownVariant(expected)
    }
}

/// The statement kind written `name`, or, where there is none, every name
/// a kind is written as.
fn statement_kind_named(name: &str) -> Result<StatementKind, &'static [&'static str]> {
    use serde::de::{value::StrDeserializer, Deserialize};
    StatementKind::deserialize(StrDeserializer::<UnknownVariant>::new(name)).map_err(|e| e.0)
}

/// The Levenshtein distance between `a` and `b`.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = if ca == *cb {
                diagonal
            } else {
                1 + diagonal.min(above).min(row[j])
            };
            diagonal = above;
        }
    }
    row[b.len()]
}

/// The first of `names` within a third of `name`'s length (at least one
/// edit) of it, the nearest first, ignoring case.
fn nearest_name(name: &str, names: &[&'static str]) -> Option<&'static str> {
    let limit = (name.chars().count() / 3).max(1);
    let lowered = name.to_lowercase();
    names
        .iter()
        .map(|candidate| (edit_distance(&lowered, candidate), *candidate))
        .filter(|(distance, _)| *distance <= limit)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}

/// Refuse a comparison of the statement's `kind` with a name no statement
/// kind has.
fn check_statement_kinds(s: &ScalarMatch) -> Result<(), CompileError> {
    if !is_statement_kind_path(&s.path) {
        return Ok(());
    }
    let literals: &[PredicateLiteral] = match &s.op {
        ScalarOp::Eq(lit) | ScalarOp::EqExplicit(lit) | ScalarOp::Neq(lit) => {
            std::slice::from_ref(lit)
        }
        ScalarOp::In(lits) | ScalarOp::NotIn(lits) => lits,
        ScalarOp::Gt(_)
        | ScalarOp::Lt(_)
        | ScalarOp::Gte(_)
        | ScalarOp::Lte(_)
        | ScalarOp::Matches(_)
        | ScalarOp::Contains(_)
        | ScalarOp::ContainsAny(_)
        | ScalarOp::ContainsAll(_)
        | ScalarOp::InList(_)
        | ScalarOp::NotInList(_)
        | ScalarOp::AllInField(_)
        | ScalarOp::Exists(_)
        | ScalarOp::IsNull(_)
        | ScalarOp::Range { .. } => return Ok(()),
    };
    for literal in literals {
        let PredicateLiteral::String(name) = literal else {
            continue;
        };
        if let Err(kinds) = statement_kind_named(name) {
            return Err(CompileError::UnknownStatementKind {
                kind: name.clone(),
                suggestion: nearest_name(name, kinds).map(str::to_string),
            });
        }
    }
    Ok(())
}

/// The names of the top-level fields of `crate::facts::StatementFacts`,
/// as its serde derive names them: the roots a rule's path may start at.
/// Read from the derive, so every field of the struct is a root and no
/// other name is.
fn statement_facts_roots() -> &'static [&'static str] {
    static ROOTS: std::sync::OnceLock<&'static [&'static str]> = std::sync::OnceLock::new();
    ROOTS.get_or_init(serde_struct_fields::<crate::facts::StatementFacts>)
}

/// The field names a struct `T` deserializes, from its serde derive, which
/// hands them to [`serde::Deserializer::deserialize_struct`]. Empty where
/// `T` does not deserialize as a struct.
fn serde_struct_fields<T: serde::de::DeserializeOwned>() -> &'static [&'static str] {
    let mut fields = None;
    // The deserializer records the names and answers with an error: no
    // value is read, so the error is the expected outcome.
    let _ = T::deserialize(StructFields(&mut fields));
    fields.unwrap_or(&[])
}

/// A deserializer that reads only the field names a struct's derive passes
/// it.
struct StructFields<'a>(&'a mut Option<&'static [&'static str]>);

impl<'de> serde::Deserializer<'de> for StructFields<'_> {
    type Error = serde::de::value::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        Err(serde::de::Error::custom(
            "only a struct's field names are read",
        ))
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        *self.0 = Some(fields);
        Err(serde::de::Error::custom("the field names are read"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map enum
        identifier ignored_any
    }
}

// ─────────────────────────────────────────────────────────────────────
// Fact-family dispatch index.
//
// Every statement evaluates the whole rule corpus, but most rules can
// only match one fact family (`privilege.*`, `query.*`, `ddl.*`, …).
// We compute, per compiled predicate, a `u32` bitmask of the families
// it *requires* — a sound over-approximation with the property:
//
//     present_mask ∩ root_mask = ∅  ⟹  predicate is NoMatch
//
// The engine builds `present_mask` once per statement and skips any
// rule whose non-zero `root_mask` is disjoint from it. A `root_mask`
// of 0 means "cannot be statically gated — always evaluate" (the
// predicate may match on an *absent* family, e.g. via `exists: false`,
// `count: { eq: 0 }`, `all:`, `none:`, or `not:`).
//
// Soundness rests on the evaluator's missing-path semantics
// (`evaluate_scalar` / `evaluate_relational`): on an absent/empty root
// every op returns false EXCEPT the absence-matching ones below, which
// contribute no gate.
// ─────────────────────────────────────────────────────────────────────

/// Roots present on (nearly) every statement, so gating on them never
/// discriminates. `kind` / `algebra` / `script_context` are mandatory
/// (non-`Option`) `StatementFacts` fields; `source_span` is ambient
/// metadata. Excluding them lets the index discriminate on the family
/// roots even when a rule conjoins a `kind:` clause. Excluding a root
/// only ever shrinks a mask toward 0 (always-evaluate), so it can
/// never make the index unsound — only less aggressive.
const AMBIENT_ROOTS: &[&str] = &["kind", "source_span", "algebra", "script_context"];

/// Bit (`1 << idx`) assigned to a non-ambient known root, or 0 for an
/// ambient/unknown root. Index = position in [`statement_facts_roots`]
/// skipping ambient roots. Degrades to 0 past 32 roots so future growth
/// stays sound (always-evaluate) rather than overflowing the shift.
fn root_mask_bit(name: &str) -> u32 {
    let mut idx = 0u32;
    for root in statement_facts_roots() {
        if AMBIENT_ROOTS.contains(root) {
            continue;
        }
        if *root == name {
            return if idx < 32 { 1 << idx } else { 0 };
        }
        idx += 1;
    }
    0
}

fn path_root_bit(path: &FieldPath) -> u32 {
    match path.segments.first() {
        Some(FieldName::Named(s)) => root_mask_bit(s),
        // A bare numeric index at root, or an empty path, names no
        // family — cannot gate.
        Some(FieldName::Index(_)) | None => 0,
    }
}

/// True iff this scalar op returns false whenever its path is absent —
/// i.e. it can only match a *present* field. Mirrors `evaluate_scalar`:
/// the `(_, None)` arm returns false for every op; `Exists`/`IsNull`
/// are special-cased and CAN succeed on a missing path.
fn scalar_is_presence_requiring(op: &ScalarOp) -> bool {
    match op {
        // `exists: true` needs the field; `exists: false` matches absence.
        ScalarOp::Exists(present) => *present,
        // `is_null: false` needs the field; `is_null: true` matches absence.
        ScalarOp::IsNull(null) => !*null,
        // An absent list is the empty one, which is in every list.
        ScalarOp::AllInField(_) => false,
        ScalarOp::InList(_)
        | ScalarOp::NotInList(_)
        | ScalarOp::Eq(_)
        | ScalarOp::EqExplicit(_)
        | ScalarOp::Neq(_)
        | ScalarOp::Gt(_)
        | ScalarOp::Lt(_)
        | ScalarOp::Gte(_)
        | ScalarOp::Lte(_)
        | ScalarOp::Matches(_)
        | ScalarOp::In(_)
        | ScalarOp::NotIn(_)
        | ScalarOp::Contains(_)
        | ScalarOp::ContainsAny(_)
        | ScalarOp::ContainsAll(_)
        | ScalarOp::Range { .. } => true,
    }
}

/// True iff this quantifier returns false on an absent/empty root.
/// `exists`/`each` need a witness; `all`/`none` are vacuously true on
/// an empty array, and `count` matches `0` on a missing root — those
/// can fire with the family absent, so they contribute no gate.
fn quantifier_is_presence_requiring(q: &Quantifier) -> bool {
    match q {
        Quantifier::Exists(_) | Quantifier::Each(_) => true,
        Quantifier::All(_) | Quantifier::None(_) | Quantifier::Count(_) => false,
    }
}

/// Sound over-approximation of the families a predicate requires. See
/// the section header for the guarantee. Quantifier inner predicates
/// are NOT recursed: their paths are element-relative, not
/// `StatementFacts` roots (same scoping as `validate_root_field_paths`).
pub(crate) fn predicate_root_mask(p: &Predicate) -> u32 {
    match p {
        // AND: a match needs every arm, so any single presence-gated
        // arm suffices to gate the whole. Union maximizes the families
        // that, if all absent, prove NoMatch.
        Predicate::AllOf(parts) => parts.iter().fold(0, |acc, p| acc | predicate_root_mask(p)),
        // OR: a match needs only one arm, so the gate is sound only if
        // EVERY arm is presence-gated; one absence-matching arm (mask 0)
        // could fire with no family present, forcing always-evaluate.
        Predicate::AnyOf(parts) => {
            let mut acc = 0u32;
            for part in parts {
                let m = predicate_root_mask(part);
                if m == 0 {
                    return 0;
                }
                acc |= m;
            }
            acc
        }
        // NOT can match when its body's family is absent.
        Predicate::Not(_) => 0,
        Predicate::Scalar(s) => {
            if scalar_is_presence_requiring(&s.op) {
                path_root_bit(&s.path)
            } else {
                0
            }
        }
        Predicate::Relational(r) => {
            if quantifier_is_presence_requiring(&r.quantifier) {
                path_root_bit(&r.path)
            } else {
                0
            }
        }
    }
}

/// True iff a serialized fact value is "materially empty" — the
/// conditions under which no presence-requiring predicate on that root
/// can match: JSON null, an empty array, or an empty object. Non-empty
/// scalars (including `""`, `0`, `false`) count as present.
fn value_is_materially_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// Bitmask of non-ambient fact families materially present in this
/// statement's serialized facts. Built once per statement; intersect
/// with each rule's [`predicate_root_mask`] to decide skips.
pub(crate) fn facts_present_mask(facts_value: &Value) -> u32 {
    let Value::Object(map) = facts_value else {
        return 0;
    };
    let mut mask = 0u32;
    let mut idx = 0u32;
    for root in statement_facts_roots() {
        if AMBIENT_ROOTS.contains(root) {
            continue;
        }
        if idx < 32 {
            let present = map
                .get(*root)
                .is_some_and(|v| !value_is_materially_empty(v));
            if present {
                mask |= 1 << idx;
            }
        }
        idx += 1;
    }
    mask
}

// ─────────────────────────────────────────────────────────────────────
// Statement-kind dispatch gate.
//
// The most selective trigger condition is the statement kind: 94% of
// rules gate on `kind: eq/in […]`, and every statement has exactly one
// kind. A rule whose kind-set excludes the statement's kind is provably
// NoMatch and is skipped. `predicate_kind_gate` computes a sound
// over-approximation:
//
//     predicate p matches statement s  ⟹  s.kind ∈ gate(p)
//
// so `Only(S)` with `s.kind ∉ S` proves NoMatch. `Any` = "no finite kind
// bound — always evaluate".
//
// This is the DUAL of `predicate_root_mask` (the family-presence mask):
// kind is a single-valued scalar, so AllOf is INTERSECTION (the kind must
// satisfy every constraining conjunct) and AnyOf is UNION (only when
// every arm constrains kind; one unbounded arm → Any). The inversion is
// load-bearing — getting it backwards silently drops findings.
//
// `resolve_alias` (`any_dml`, …) is NOT wired into the evaluator, so an
// alias literal fails to parse as a `StatementKind` and widens to `Any`.
// If aliases are ever wired into `match_eq`, this gate MUST resolve them
// identically; the kind-gate parity test guards against a tightening that
// would false-skip.
// ─────────────────────────────────────────────────────────────────────

/// Bitset capacity over `StatementKind` discriminants. `StatementKind`
/// has 271 unit variants; 512 bits leaves headroom. A kind
/// whose discriminant exceeds the capacity is never gated (degrades to
/// always-evaluate — sound, just unfiltered), so growth past 512 is a
/// performance, not a correctness, concern.
const KIND_WORDS: usize = 8;
const KIND_BITS: usize = KIND_WORDS * 64;

/// Set of statement kinds a predicate can match. `Any` = unbounded.
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum KindGate {
    /// No finite kind bound — the rule must be evaluated on every kind.
    Any,
    /// The rule can only match statements whose kind bit is set.
    Only([u64; KIND_WORDS]),
}

impl KindGate {
    /// True iff this gate proves the rule is NoMatch on `kind_idx`
    /// (`statement.kind as usize`). Out-of-range indices are never
    /// skipped (conservative — a kind beyond the bitset capacity).
    pub(crate) fn skips(&self, kind_idx: usize) -> bool {
        match self {
            KindGate::Any => false,
            KindGate::Only(bits) => {
                kind_idx < KIND_BITS && (bits[kind_idx >> 6] >> (kind_idx & 63)) & 1 == 0
            }
        }
    }

    fn intersect(self, other: KindGate) -> KindGate {
        match (self, other) {
            (KindGate::Any, x) | (x, KindGate::Any) => x,
            (KindGate::Only(a), KindGate::Only(b)) => {
                let mut out = [0u64; KIND_WORDS];
                for i in 0..KIND_WORDS {
                    out[i] = a[i] & b[i];
                }
                KindGate::Only(out)
            }
        }
    }
}

fn one_kind(idx: usize) -> [u64; KIND_WORDS] {
    let mut bits = [0u64; KIND_WORDS];
    bits[idx >> 6] |= 1 << (idx & 63);
    bits
}

/// Map a predicate literal naming a statement kind to its bit index.
/// Only string literals that deserialize to a known `StatementKind`
/// (whose discriminant fits the bitset) resolve; everything else
/// (non-string, typo, alias, out-of-range) returns `None`, which callers
/// widen to `Any` — never a false skip. The set-time index
/// (`string → StatementKind → as usize`) matches the check-time index
/// (`facts.kind as usize`); `kind_gate_index_consistency` locks this.
fn kind_literal_bit(lit: &PredicateLiteral) -> Option<usize> {
    let PredicateLiteral::String(s) = lit else {
        return None;
    };
    let kind = statement_kind_named(s).ok()?;
    let idx = kind as usize;
    (idx < KIND_BITS).then_some(idx)
}

/// True iff the path is exactly the top-level scalar `kind` field — the
/// statement-kind discriminant. A path like `privilege.target.kind` is
/// the kind of a *grant target*, not the statement, and must not gate.
fn is_statement_kind_path(path: &FieldPath) -> bool {
    matches!(path.segments.as_slice(), [FieldName::Named(name)] if name == "kind")
}

fn kind_scalar_gate(s: &ScalarMatch) -> KindGate {
    if !is_statement_kind_path(&s.path) {
        return KindGate::Any;
    }
    match &s.op {
        ScalarOp::Eq(lit) | ScalarOp::EqExplicit(lit) => match kind_literal_bit(lit) {
            Some(i) => KindGate::Only(one_kind(i)),
            None => KindGate::Any,
        },
        ScalarOp::In(lits) => {
            let mut bits = [0u64; KIND_WORDS];
            for lit in lits {
                match kind_literal_bit(lit) {
                    Some(i) => bits[i >> 6] |= 1 << (i & 63),
                    // An unresolvable member widens the whole op to Any.
                    None => return KindGate::Any,
                }
            }
            KindGate::Only(bits)
        }
        // Complement / inequality / presence ops cannot bound the kind to
        // a finite positive set (`neq` matches every OTHER kind, etc.).
        ScalarOp::Neq(_)
        | ScalarOp::NotIn(_)
        | ScalarOp::Gt(_)
        | ScalarOp::Lt(_)
        | ScalarOp::Gte(_)
        | ScalarOp::Lte(_)
        | ScalarOp::Matches(_)
        | ScalarOp::Contains(_)
        | ScalarOp::ContainsAny(_)
        | ScalarOp::ContainsAll(_)
        | ScalarOp::InList(_)
        | ScalarOp::NotInList(_)
        | ScalarOp::AllInField(_)
        | ScalarOp::Exists(_)
        | ScalarOp::IsNull(_)
        | ScalarOp::Range { .. } => KindGate::Any,
    }
}

/// Sound over-approximation of the statement kinds a predicate can match.
/// See the section header for the guarantee and the AllOf/AnyOf duality.
pub(crate) fn predicate_kind_gate(p: &Predicate) -> KindGate {
    match p {
        // AND: the kind must satisfy every constraining conjunct.
        Predicate::AllOf(parts) => parts.iter().fold(KindGate::Any, |acc, c| {
            acc.intersect(predicate_kind_gate(c))
        }),
        // OR: sound only if every arm bounds the kind; one unbounded arm
        // can match an un-enumerated kind, forcing `Any`.
        Predicate::AnyOf(parts) => {
            let mut acc: Option<[u64; KIND_WORDS]> = None;
            for c in parts {
                match predicate_kind_gate(c) {
                    KindGate::Any => return KindGate::Any,
                    KindGate::Only(bits) => {
                        acc = Some(match acc {
                            None => bits,
                            Some(mut a) => {
                                for i in 0..KIND_WORDS {
                                    a[i] |= bits[i];
                                }
                                a
                            }
                        });
                    }
                }
            }
            // Empty AnyOf never matches; `Any` (never skip) is sound.
            acc.map_or(KindGate::Any, KindGate::Only)
        }
        // A negated condition matches when its body does NOT — i.e. on
        // kinds outside the body's set — so it cannot bound the kind.
        Predicate::Not(_) => KindGate::Any,
        Predicate::Scalar(s) => kind_scalar_gate(s),
        // Relational paths are element-relative; they don't bound the
        // top-level statement kind.
        Predicate::Relational(_) => KindGate::Any,
    }
}

fn validate_root_field_paths(p: &Predicate) -> Result<(), CompileError> {
    match p {
        Predicate::AllOf(parts) | Predicate::AnyOf(parts) => {
            for arm in parts {
                validate_root_field_paths(arm)?;
            }
            Ok(())
        }
        Predicate::Not(inner) => validate_root_field_paths(inner),
        // Outside a quantifier a compared field is the statement's too.
        Predicate::Scalar(s) => {
            check_root_segment(&s.path)?;
            s.op.compared_field().map_or(Ok(()), check_root_segment)?;
            check_statement_kinds(s)
        }
        Predicate::Relational(r) => check_root_segment(&r.path),
    }
}

/// Every fact path a rule may name, as `generate_schema` writes them from
/// the facts types: a block per root (`@StatementFacts`, then each list's
/// element type) and a line per path, ending ` >Type` for a list of
/// objects and ` *` where the fields below are not known.
const FACT_PATHS: &str = include_str!("fact_paths.txt");

/// The root of a statement's facts in [`FACT_PATHS`].
const FACTS_ROOT: &str = "StatementFacts";

/// What a path in [`FACT_PATHS`] leads to.
#[derive(Debug, Clone, Copy)]
enum PathTo {
    /// A value with no fields of its own: a scalar, a list of scalars.
    Value,
    /// A list of objects, each read under the named root.
    Elements(&'static str),
    /// Something whose fields are not known.
    Open,
}

/// One root's paths, and every shorter path a longer one runs through.
#[derive(Default)]
struct RootPaths {
    paths: std::collections::HashMap<&'static str, PathTo>,
    inner: std::collections::HashSet<&'static str>,
}

impl RootPaths {
    fn holds(&self, path: &str) -> bool {
        self.paths.contains_key(path) || self.inner.contains(path)
    }

    /// The names of the fields directly under `at` (the root's own for an
    /// empty `at`).
    fn fields_under(&self, at: &str) -> Vec<&'static str> {
        let mut names = std::collections::BTreeSet::new();
        for path in self.paths.keys() {
            let rest = match at.is_empty() {
                true => Some(*path),
                false => path
                    .strip_prefix(at)
                    .and_then(|rest| rest.strip_prefix('.')),
            };
            if let Some(rest) = rest {
                names.insert(rest.split_once('.').map_or(rest, |(first, _)| first));
            }
        }
        names.into_iter().collect()
    }
}

fn fact_paths() -> &'static std::collections::HashMap<&'static str, RootPaths> {
    static TABLE: std::sync::OnceLock<std::collections::HashMap<&'static str, RootPaths>> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table: std::collections::HashMap<&'static str, RootPaths> =
            std::collections::HashMap::new();
        let mut root: Option<&'static str> = None;
        for line in FACT_PATHS.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('@') {
                root = Some(name);
                table.entry(name).or_default();
                continue;
            }
            let Some(root) = root else {
                continue;
            };
            let (path, to) = match line.split_once(' ') {
                Some((path, end)) => match end.strip_prefix('>') {
                    Some(element) => (path, PathTo::Elements(element)),
                    None => (path, PathTo::Open),
                },
                None => (line, PathTo::Value),
            };
            let entry = table.entry(root).or_default();
            for (at, _) in path.match_indices('.') {
                entry.inner.insert(&path[..at]);
            }
            entry.paths.insert(path, to);
        }
        table
    })
}

/// Why a rule's path names no fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathProblem {
    /// `field` is not a field of what the path names before it, `under`
    /// (empty for the statement's facts themselves). `suggestion` is the
    /// nearest field there is.
    UnknownField {
        field: String,
        under: String,
        suggestion: Option<String>,
    },
    /// The path reads a field of the elements of `list` without naming an
    /// element, which reads nothing.
    ThroughList { list: String },
}

/// Where a valid path leads: the root a quantifier's body is read under,
/// or nothing a body could be read under.
enum PathEnd {
    Elements(&'static str),
    Other,
}

/// Resolve `path`, read under `root`, against [`FACT_PATHS`]. `shown` is the
/// path of `root` within the statement's facts, for the problem's names.
fn resolve_fact_path(
    root: &'static str,
    path: &FieldPath,
    shown: &str,
) -> Result<PathEnd, PathProblem> {
    let table = fact_paths();
    let mut root = root;
    let mut at = String::new();
    let mut walked = shown.to_string();
    for segment in &path.segments {
        let Some(paths) = table.get(root) else {
            return Ok(PathEnd::Other);
        };
        let here = paths.paths.get(at.as_str()).copied();
        match segment {
            FieldName::Index(index) => {
                match here {
                    Some(PathTo::Elements(element)) => {
                        root = element;
                        at.clear();
                    }
                    Some(PathTo::Open) => return Ok(PathEnd::Other),
                    Some(PathTo::Value) | None => {}
                }
                if !walked.is_empty() {
                    walked.push('.');
                }
                walked.push_str(&index.to_string());
            }
            FieldName::Named(name) => {
                match here {
                    Some(PathTo::Open) => return Ok(PathEnd::Other),
                    Some(PathTo::Elements(_)) => {
                        return Err(PathProblem::ThroughList { list: walked });
                    }
                    Some(PathTo::Value) | None => {}
                }
                let candidate = match at.is_empty() {
                    true => name.clone(),
                    false => format!("{at}.{name}"),
                };
                if !paths.holds(&candidate) {
                    let fields = paths.fields_under(&at);
                    return Err(PathProblem::UnknownField {
                        field: name.clone(),
                        under: walked,
                        suggestion: nearest_name(name, &fields).map(str::to_string),
                    });
                }
                at = candidate;
                if !walked.is_empty() {
                    walked.push('.');
                }
                walked.push_str(name);
            }
        }
    }
    let end = table
        .get(root)
        .and_then(|paths| paths.paths.get(at.as_str()).copied());
    Ok(match end {
        Some(PathTo::Elements(element)) => PathEnd::Elements(element),
        Some(PathTo::Value) | Some(PathTo::Open) | None => PathEnd::Other,
    })
}

/// Refuse a path, anywhere in `p`, that names no fact: read under `root`,
/// whose path within the statement's facts is `shown`. A quantifier's body
/// is read under the list's element type.
fn validate_fact_paths(p: &Predicate, root: &'static str, shown: &str) -> Result<(), CompileError> {
    let check = |path: &FieldPath| {
        resolve_fact_path(root, path, shown).map_err(|problem| CompileError::UnknownFactPath {
            path: match shown.is_empty() {
                true => path.render(),
                false => format!("{shown}.{}", path.render()),
            },
            problem,
        })
    };
    match p {
        Predicate::AllOf(parts) | Predicate::AnyOf(parts) => {
            for part in parts {
                validate_fact_paths(part, root, shown)?;
            }
            Ok(())
        }
        Predicate::Not(inner) => validate_fact_paths(inner, root, shown),
        Predicate::Scalar(s) => {
            check(&s.path)?;
            s.op.compared_field()
                .map_or(Ok(()), |field| check(field).map(|_| ()))
        }
        Predicate::Relational(r) => {
            let end = check(&r.path)?;
            let body = match &r.quantifier {
                Quantifier::Exists(body)
                | Quantifier::All(body)
                | Quantifier::None(body)
                | Quantifier::Each(body) => body,
                Quantifier::Count(_) => return Ok(()),
            };
            match end {
                PathEnd::Elements(element) => {
                    let inner = match shown.is_empty() {
                        true => r.path.render(),
                        false => format!("{shown}.{}", r.path.render()),
                    };
                    validate_fact_paths(body, element, &inner)
                }
                PathEnd::Other => Ok(()),
            }
        }
    }
}

fn check_root_segment(path: &super::predicate::FieldPath) -> Result<(), CompileError> {
    use super::predicate::FieldName;
    let Some(first) = path.segments.first() else {
        return Ok(());
    };
    let root_name = match first {
        FieldName::Named(s) => s.as_str(),
        // Numeric indices (`scopes.0`) at root would be a degenerate
        // shape — `StatementFacts` is a struct, not a vec — but the
        // root validator doesn't gate on this; the JSON traversal
        // will simply not match. Skip the check rather than report
        // a misleading error.
        FieldName::Index(_) => return Ok(()),
    };
    if statement_facts_roots().contains(&root_name) {
        Ok(())
    } else {
        Err(CompileError::UnknownRootField {
            path: path.render(),
            unknown_root: root_name.to_string(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Internal evaluator tree (typed; closure-friendly).
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum Evaluator {
    AllOf(Vec<Evaluator>),
    AnyOf(Vec<Evaluator>),
    Not(Box<Evaluator>),
    Scalar(ScalarMatch),
    /// An `in_list` / `not_in_list` match with its lists resolved, in the
    /// order the rule names them.
    List {
        scalar: ScalarMatch,
        lists: Vec<ValueList>,
    },
    /// A quantifier match with its body built once.
    Relational {
        path: FieldPath,
        quantified: Quantified,
    },
}

/// A quantifier with its body compiled.
#[derive(Clone)]
enum Quantified {
    Exists(Box<Evaluator>),
    All(Box<Evaluator>),
    None(Box<Evaluator>),
    Each(Box<Evaluator>),
    Count(NumericOp),
}

fn build_evaluator(p: &Predicate, table: &ValueLists) -> Result<Evaluator, CompileError> {
    Ok(match p {
        Predicate::AllOf(parts) => Evaluator::AllOf(
            parts
                .iter()
                .map(|part| build_evaluator(part, table))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Predicate::AnyOf(parts) => Evaluator::AnyOf(
            parts
                .iter()
                .map(|part| build_evaluator(part, table))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Predicate::Not(inner) => Evaluator::Not(Box::new(build_evaluator(inner, table)?)),
        Predicate::Scalar(s) => match &s.op {
            ScalarOp::InList(refs) | ScalarOp::NotInList(refs) => Evaluator::List {
                scalar: s.clone(),
                lists: refs
                    .names
                    .iter()
                    .map(|name| {
                        table
                            .get(name)
                            .cloned()
                            .ok_or_else(|| CompileError::UnknownList { list: name.clone() })
                    })
                    .collect::<Result<_, _>>()?,
            },
            ScalarOp::Eq(_)
            | ScalarOp::EqExplicit(_)
            | ScalarOp::Neq(_)
            | ScalarOp::Gt(_)
            | ScalarOp::Lt(_)
            | ScalarOp::Gte(_)
            | ScalarOp::Lte(_)
            | ScalarOp::Matches(_)
            | ScalarOp::In(_)
            | ScalarOp::NotIn(_)
            | ScalarOp::Contains(_)
            | ScalarOp::ContainsAny(_)
            | ScalarOp::ContainsAll(_)
            | ScalarOp::AllInField(_)
            | ScalarOp::Exists(_)
            | ScalarOp::IsNull(_)
            | ScalarOp::Range { .. } => Evaluator::Scalar(s.clone()),
        },
        Predicate::Relational(r) => Evaluator::Relational {
            path: r.path.clone(),
            quantified: match &r.quantifier {
                Quantifier::Exists(inner) => {
                    Quantified::Exists(Box::new(build_evaluator(inner, table)?))
                }
                Quantifier::All(inner) => Quantified::All(Box::new(build_evaluator(inner, table)?)),
                Quantifier::None(inner) => {
                    Quantified::None(Box::new(build_evaluator(inner, table)?))
                }
                Quantifier::Each(inner) => {
                    Quantified::Each(Box::new(build_evaluator(inner, table)?))
                }
                Quantifier::Count(op) => Quantified::Count(*op),
            },
        },
    })
}

// ─────────────────────────────────────────────────────────────────────
// Evaluation against a serde_json::Value tree.
// ─────────────────────────────────────────────────────────────────────

/// Where a predicate node is evaluated, as the path text a witness or an
/// explain-trace entry records: rendered only when one is recorded, so
/// the hot path builds no string per element and per arm it visits.
#[derive(Clone, Copy)]
enum Prefix<'p> {
    /// The facts root: the empty path.
    Root,
    /// `<parent>.<path>`, or `<path>` under an empty parent.
    Field(&'p Prefix<'p>, &'p FieldPath),
    /// `<parent>.<index>`: an element of the array at `parent`.
    Item(&'p Prefix<'p>, usize),
    /// `<parent>@all_of[<index>]` (explain mode only).
    AllOfArm(&'p Prefix<'p>, usize),
    /// `<parent>@any_of[<index>]`
    AnyOfArm(&'p Prefix<'p>, usize),
    /// `<parent>@not`
    Not(&'p Prefix<'p>),
}

impl Prefix<'_> {
    fn render(&self) -> String {
        match self {
            Prefix::Root => String::new(),
            Prefix::Field(parent, path) => compose_path(&parent.render(), path),
            Prefix::Item(parent, index) => format!("{}.{}", parent.render(), index),
            Prefix::AllOfArm(parent, index) => format!("{}@all_of[{}]", parent.render(), index),
            Prefix::AnyOfArm(parent, index) => format!("{}@any_of[{}]", parent.render(), index),
            Prefix::Not(parent) => format!("{}@not", parent.render()),
        }
    }
}

fn evaluate_node<'v>(
    eval: &Evaluator,
    value: &'v Value,
    witnesses: &mut Vec<WitnessCandidate<'v>>,
    prefix: Prefix<'_>,
    mut trace: Option<&mut ExplainTrace>,
) -> bool {
    match eval {
        Evaluator::AllOf(parts) => {
            // Explain mode: visit every arm so the trace enumerates
            // each failure. Hot path: short-circuit on the first
            // failing arm (preserves existing semantics).
            let arm_count = parts.len();
            if let Some(t) = trace.as_deref_mut() {
                let mut all_pass = true;
                let mut first_failure: Option<usize> = None;
                for (idx, p) in parts.iter().enumerate() {
                    let arm = Prefix::AllOfArm(&prefix, idx);
                    let pass = evaluate_node(p, value, witnesses, arm, Some(t));
                    if !pass {
                        all_pass = false;
                        if first_failure.is_none() {
                            first_failure = Some(idx);
                        }
                    }
                }
                if all_pass {
                    t.record_matched(&prefix.render(), MatchReason::AllOfPass { arm_count });
                    true
                } else {
                    let arm_index = first_failure.unwrap_or(0);
                    t.record_unmatched(
                        &prefix.render(),
                        UnmatchReason::AllOfArmFailed {
                            arm_index,
                            arm_count,
                        },
                    );
                    false
                }
            } else {
                parts
                    .iter()
                    .all(|p| evaluate_node(p, value, witnesses, prefix, None))
            }
        }
        Evaluator::AnyOf(parts) => {
            // Every arm is read: each one that matches gives its witnesses.
            let arm_count = parts.len();
            let mut first_match: Option<usize> = None;
            for (idx, p) in parts.iter().enumerate() {
                let mut local = Vec::new();
                let arm = Prefix::AnyOfArm(&prefix, idx);
                if evaluate_node(p, value, &mut local, arm, trace.as_deref_mut()) {
                    witnesses.extend(local);
                    first_match.get_or_insert(idx);
                }
            }
            match (first_match, trace.as_deref_mut()) {
                (Some(matched_arm), Some(t)) => t.record_matched(
                    &prefix.render(),
                    MatchReason::AnyOfPass {
                        matched_arm,
                        arm_count,
                    },
                ),
                (None, Some(t)) => t.record_unmatched(
                    &prefix.render(),
                    UnmatchReason::AnyOfNoArmMatched { arm_count },
                ),
                (Some(_) | None, None) => {}
            }
            first_match.is_some()
        }
        Evaluator::Not(inner) => {
            // `not` doesn't propagate witnesses — if its body matched,
            // we wouldn't be here.
            let mut discard = Vec::new();
            let not = Prefix::Not(&prefix);
            let inner_matched =
                evaluate_node(inner, value, &mut discard, not, trace.as_deref_mut());
            let pass = !inner_matched;
            if let Some(t) = trace.as_deref_mut() {
                if pass {
                    t.record_matched(&prefix.render(), MatchReason::NotPass);
                } else {
                    t.record_unmatched(&prefix.render(), UnmatchReason::NotInverted);
                }
            }
            pass
        }
        Evaluator::Scalar(s) => evaluate_scalar(s, &[], value, prefix, trace),
        Evaluator::List { scalar, lists } => evaluate_scalar(scalar, lists, value, prefix, trace),
        Evaluator::Relational { path, quantified } => {
            evaluate_relational(path, quantified, value, witnesses, prefix, trace)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Scalar evaluation.
// ─────────────────────────────────────────────────────────────────────

/// The form of the dialect-folded name the path's leaf names
/// (`IdentName.normalized`, any `*.canonical`). Rule literals targeting
/// these paths are folded as the active dialect folds names before
/// comparison, so rule authors can write `name.normalized: PUBLIC` once
/// and have it match in Snowflake/MSSQL (upper-fold) AND
/// PostgreSQL/Databricks (lower-fold). The active dialect is threaded from
/// the analyzer by the analysis's dialect scope.
fn folded_name_form(path: &FieldPath) -> Option<NameForm> {
    match path.segments.last() {
        Some(FieldName::Named(n)) => NameForm::of_field(n),
        Some(FieldName::Index(_)) | None => None,
    }
}

fn fold_string_literal(lit: &PredicateLiteral, form: NameForm) -> Cow<'_, PredicateLiteral> {
    match lit {
        PredicateLiteral::String(s) => Cow::Owned(PredicateLiteral::String(form.fold(s))),
        other => Cow::Borrowed(other),
    }
}

fn evaluate_scalar(
    s: &ScalarMatch,
    lists: &[ValueList],
    root: &Value,
    prefix: Prefix<'_>,
    mut trace: Option<&mut ExplainTrace>,
) -> bool {
    let resolved = resolve_path(root, &s.path);
    // The composed path string is only ever read inside the explain
    // trace branches below; scalars never emit witnesses. Build it
    // lazily so the hot path (`trace: None`) skips the allocation —
    // this is per-leaf, per-rule, per-statement work otherwise.
    let scalar_path = || Prefix::Field(&prefix, &s.path).render();
    let pass: bool;
    let op_name: &'static str = scalar_op_name(&s.op);
    let name_form = folded_name_form(&s.path);
    // The `(op, resolved)` pair drives both the bool result and (in
    // explain mode) the rejection-reason classification. Scalar ops
    // split into three categories:
    //   - Presence ops (`Exists`, `IsNull`) — can succeed on a missing
    //     path, so the `PathNotResolved` rejection variant does NOT
    //     apply to them.
    //   - All other ops — `None` resolution falls through to `false`
    //     with the `PathNotResolved` reason.
    match (&s.op, &resolved) {
        (ScalarOp::Exists(want_present), v) => {
            let present = matches!(v, Some(val) if !val.is_null());
            pass = present == *want_present;
            if let Some(t) = trace.as_deref_mut() {
                if pass {
                    t.record_matched(
                        &scalar_path(),
                        MatchReason::ScalarOk {
                            op: op_name,
                            actual: format!("{}", present),
                        },
                    );
                } else {
                    t.record_unmatched(
                        &scalar_path(),
                        UnmatchReason::ScalarMismatch {
                            op: op_name,
                            expected: format!("{}", want_present),
                            actual: format!("{}", present),
                        },
                    );
                }
            }
        }
        (ScalarOp::IsNull(want_null), resolved_opt) => {
            let is_null = match resolved_opt {
                Some(v) => v.is_null(),
                None => true,
            };
            pass = is_null == *want_null;
            if let Some(t) = trace.as_deref_mut() {
                if pass {
                    t.record_matched(
                        &scalar_path(),
                        MatchReason::ScalarOk {
                            op: op_name,
                            actual: format!("{}", is_null),
                        },
                    );
                } else {
                    t.record_unmatched(
                        &scalar_path(),
                        UnmatchReason::ScalarMismatch {
                            op: op_name,
                            expected: format!("{}", want_null),
                            actual: format!("{}", is_null),
                        },
                    );
                }
            }
        }
        (ScalarOp::AllInField(field), left) => {
            pass = all_in(*left, resolve_path(root, field));
            if let Some(t) = trace.as_deref_mut() {
                let actual = left.map_or_else(|| "absent".to_string(), |v| t.render_actual(v));
                if pass {
                    t.record_matched(
                        &scalar_path(),
                        MatchReason::ScalarOk {
                            op: op_name,
                            actual,
                        },
                    );
                } else {
                    t.record_unmatched(
                        &scalar_path(),
                        UnmatchReason::ScalarMismatch {
                            op: op_name,
                            expected: render_op_expected(&s.op),
                            actual,
                        },
                    );
                }
            }
        }
        (_, None) => {
            pass = false;
            if let Some(t) = trace.as_deref_mut() {
                t.record_unmatched(&scalar_path(), UnmatchReason::PathNotResolved);
            }
        }
        (op, Some(v)) => {
            // For paths targeting a dialect-folded identifier field
            // (`*.normalized`, `*.canonical`), apply the active
            // dialect's identifier normalizer to each string literal
            // before comparison. Outside that path family the literal
            // is used verbatim.
            let fold = |lit| match name_form {
                Some(form) => fold_string_literal(lit, form),
                None => Cow::Borrowed(lit),
            };
            // A list holds an identifier's folded name where it holds each
            // item folded as a literal is; any other field, ignoring case.
            let held = |text: &str| {
                lists.iter().any(|list| match name_form {
                    Some(form) => list.holds_name(text, form),
                    None => list.holds(text),
                })
            };
            pass = match op {
                ScalarOp::Eq(lit) | ScalarOp::EqExplicit(lit) => match_eq(v, &fold(lit)),
                ScalarOp::Neq(lit) => !match_eq(v, &fold(lit)),
                ScalarOp::Gt(lit) => compare_lit(v, &fold(lit), |a, b| a > b),
                ScalarOp::Lt(lit) => compare_lit(v, &fold(lit), |a, b| a < b),
                ScalarOp::Gte(lit) => compare_lit(v, &fold(lit), |a, b| a >= b),
                ScalarOp::Lte(lit) => compare_lit(v, &fold(lit), |a, b| a <= b),
                ScalarOp::Matches(glob) => match v {
                    Value::String(s) => {
                        let pat: std::borrow::Cow<'_, str> = match name_form {
                            Some(form) => std::borrow::Cow::Owned(form.fold(glob)),
                            None => std::borrow::Cow::Borrowed(glob.as_str()),
                        };
                        glob_match(&pat, s)
                    }
                    _ => false,
                },
                ScalarOp::In(list) => list.iter().any(|lit| match_eq(v, &fold(lit))),
                ScalarOp::NotIn(list) => !list.iter().any(|lit| match_eq(v, &fold(lit))),
                ScalarOp::InList(_) => matches!(v, Value::String(text) if held(text)),
                ScalarOp::NotInList(_) => matches!(v, Value::String(text) if !held(text)),
                ScalarOp::Contains(lit) => match v {
                    Value::Array(items) => items.iter().any(|e| match_eq(e, &fold(lit))),
                    _ => false,
                },
                ScalarOp::ContainsAny(list) => match v {
                    Value::Array(items) => list
                        .iter()
                        .any(|lit| items.iter().any(|e| match_eq(e, &fold(lit)))),
                    _ => false,
                },
                ScalarOp::ContainsAll(list) => match v {
                    Value::Array(items) => list
                        .iter()
                        .all(|lit| items.iter().any(|e| match_eq(e, &fold(lit)))),
                    _ => false,
                },
                ScalarOp::Range {
                    low,
                    high,
                    low_inclusive,
                    high_inclusive,
                } => {
                    let lo_ok = if *low_inclusive {
                        compare_lit(v, low, |a, b| a >= b)
                    } else {
                        compare_lit(v, low, |a, b| a > b)
                    };
                    let hi_ok = if *high_inclusive {
                        compare_lit(v, high, |a, b| a <= b)
                    } else {
                        compare_lit(v, high, |a, b| a < b)
                    };
                    lo_ok && hi_ok
                }
                // Exists / IsNull / AllInField are handled by the earlier
                // match arms.
                ScalarOp::Exists(_) | ScalarOp::IsNull(_) | ScalarOp::AllInField(_) => {
                    unreachable!()
                }
            };
            if let Some(t) = trace {
                let actual = t.render_actual(v);
                if pass {
                    t.record_matched(
                        &scalar_path(),
                        MatchReason::ScalarOk {
                            op: op_name,
                            actual: actual.clone(),
                        },
                    );
                } else {
                    let expected = render_op_expected(op);
                    t.record_unmatched(
                        &scalar_path(),
                        UnmatchReason::ScalarMismatch {
                            op: op_name,
                            expected,
                            actual,
                        },
                    );
                }
            }
        }
    }
    pass
}

fn scalar_op_name(op: &ScalarOp) -> &'static str {
    match op {
        ScalarOp::Eq(_) | ScalarOp::EqExplicit(_) => "eq",
        ScalarOp::Neq(_) => "neq",
        ScalarOp::Gt(_) => "gt",
        ScalarOp::Lt(_) => "lt",
        ScalarOp::Gte(_) => "gte",
        ScalarOp::Lte(_) => "lte",
        ScalarOp::Matches(_) => "matches",
        ScalarOp::In(_) => "in",
        ScalarOp::NotIn(_) => "not_in",
        ScalarOp::InList(_) => "in_list",
        ScalarOp::NotInList(_) => "not_in_list",
        ScalarOp::Contains(_) => "contains",
        ScalarOp::ContainsAny(_) => "contains_any",
        ScalarOp::ContainsAll(_) => "contains_all",
        ScalarOp::AllInField(_) => "all_in_field",
        ScalarOp::Exists(_) => "exists",
        ScalarOp::IsNull(_) => "is_null",
        ScalarOp::Range { .. } => "range",
    }
}

fn render_op_expected(op: &ScalarOp) -> String {
    match op {
        ScalarOp::Eq(lit) | ScalarOp::EqExplicit(lit) => render_literal_for_trace(lit),
        ScalarOp::Neq(lit) => format!("!= {}", render_literal_for_trace(lit)),
        ScalarOp::Gt(lit) => format!("> {}", render_literal_for_trace(lit)),
        ScalarOp::Lt(lit) => format!("< {}", render_literal_for_trace(lit)),
        ScalarOp::Gte(lit) => format!(">= {}", render_literal_for_trace(lit)),
        ScalarOp::Lte(lit) => format!("<= {}", render_literal_for_trace(lit)),
        ScalarOp::Matches(glob) => format!("matches {}", glob),
        ScalarOp::In(list) => format!(
            "in [{}]",
            list.iter()
                .map(render_literal_for_trace)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ScalarOp::NotIn(list) => format!(
            "not_in [{}]",
            list.iter()
                .map(render_literal_for_trace)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ScalarOp::InList(refs) => format!("in_list {}", refs.names.join(", ")),
        ScalarOp::NotInList(refs) => format!("not_in_list {}", refs.names.join(", ")),
        ScalarOp::Contains(lit) => format!("contains {}", render_literal_for_trace(lit)),
        ScalarOp::ContainsAny(list) => format!(
            "contains_any [{}]",
            list.iter()
                .map(render_literal_for_trace)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ScalarOp::ContainsAll(list) => format!(
            "contains_all [{}]",
            list.iter()
                .map(render_literal_for_trace)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ScalarOp::AllInField(field) => field.render(),
        ScalarOp::Exists(b) => format!("exists {}", b),
        ScalarOp::IsNull(b) => format!("is_null {}", b),
        ScalarOp::Range {
            low,
            high,
            low_inclusive,
            high_inclusive,
        } => format!(
            "{}{}, {}{}",
            if *low_inclusive { "[" } else { "(" },
            render_literal_for_trace(low),
            render_literal_for_trace(high),
            if *high_inclusive { "]" } else { ")" },
        ),
    }
}

fn render_literal_for_trace(lit: &PredicateLiteral) -> String {
    match lit {
        PredicateLiteral::Bool(b) => format!("{}", b),
        PredicateLiteral::Integer(i) => format!("{}", i),
        PredicateLiteral::Float(f) => format!("{}", f),
        PredicateLiteral::String(s) => format!("\"{}\"", s),
        PredicateLiteral::Null => "null".to_string(),
        PredicateLiteral::Typed(_) => "<typed>".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Relational evaluation.
// ─────────────────────────────────────────────────────────────────────

fn evaluate_relational<'v>(
    path: &FieldPath,
    quantified: &Quantified,
    root: &'v Value,
    witnesses: &mut Vec<WitnessCandidate<'v>>,
    prefix: Prefix<'_>,
    mut trace: Option<&mut ExplainTrace>,
) -> bool {
    let resolved = resolve_path(root, path);
    let field = Prefix::Field(&prefix, path);
    // Read only by explain-trace entries: the hot path renders no path.
    let path_text = if trace.is_some() {
        field.render()
    } else {
        String::new()
    };
    let arr = match resolved {
        Some(Value::Array(arr)) => arr,
        Some(_) => {
            // Path resolves but isn't an array. `count: { eq: 0 }` on a
            // non-array still falls through to the array-shape check
            // below — treat as zero-length collection for count only.
            if let Quantified::Count(op) = quantified {
                let pass = numeric_match(op, 0);
                if let Some(t) = trace.as_deref_mut() {
                    if pass {
                        t.record_matched(&path_text, MatchReason::CountOk { actual: 0 });
                    } else {
                        t.record_unmatched(&path_text, UnmatchReason::CountMismatch { actual: 0 });
                    }
                }
                return pass;
            }
            if let Some(t) = trace.as_deref_mut() {
                t.record_unmatched(&path_text, UnmatchReason::NotAnArray);
            }
            return false;
        }
        None => {
            // Missing path. `count: { eq: 0 }` still meaningful.
            if let Quantified::Count(op) = quantified {
                let pass = numeric_match(op, 0);
                if let Some(t) = trace.as_deref_mut() {
                    if pass {
                        t.record_matched(&path_text, MatchReason::CountOk { actual: 0 });
                    } else {
                        t.record_unmatched(&path_text, UnmatchReason::CountMismatch { actual: 0 });
                    }
                }
                return pass;
            }
            if let Some(t) = trace.as_deref_mut() {
                t.record_unmatched(&path_text, UnmatchReason::PathNotResolved);
            }
            return false;
        }
    };

    let total = arr.len();
    match quantified {
        Quantified::Exists(inner_eval) => {
            for (i, item) in arr.iter().enumerate() {
                let mut local = Vec::new();
                let item_prefix = Prefix::Item(&field, i);
                if evaluate_node(
                    inner_eval,
                    item,
                    &mut local,
                    item_prefix,
                    trace.as_deref_mut(),
                ) {
                    witnesses.push(WitnessCandidate {
                        path: item_prefix.render(),
                        value: item,
                        from_each: false,
                    });
                    witnesses.extend(local);
                    if let Some(t) = trace.as_deref_mut() {
                        t.record_matched(
                            &path_text,
                            MatchReason::ExistsWitness {
                                witness_index: i,
                                total_candidates: total,
                            },
                        );
                    }
                    return true;
                }
            }
            if let Some(t) = trace.as_deref_mut() {
                t.record_unmatched(
                    &path_text,
                    UnmatchReason::ExistsNoWitness {
                        total_candidates: total,
                    },
                );
            }
            false
        }
        Quantified::All(inner_eval) => {
            // Universal claim on an empty array carries no evidence.
            // Rule authors writing `path: { all: P }` mean "I have at
            // least one element of `path` and every element satisfies
            // P"; the vacuous-truth reading (∀x ∈ ∅: P is true) fires
            // rules on shapes the rule author never inspected (e.g.
            // LATERAL / USING / NATURAL / CROSS joins with empty
            // `on_columns`). The "no offending element" reading is
            // available as `none: !P` and already returns true on
            // empty — using that there is the principled way to
            // express vacuous-on-empty.
            if arr.is_empty() {
                if let Some(t) = trace.as_deref_mut() {
                    t.record_unmatched(&path_text, UnmatchReason::AllEmpty);
                }
                return false;
            }
            for (i, item) in arr.iter().enumerate() {
                let mut local = Vec::new();
                if !evaluate_node(
                    inner_eval,
                    item,
                    &mut local,
                    Prefix::Item(&field, i),
                    trace.as_deref_mut(),
                ) {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record_unmatched(
                            &path_text,
                            UnmatchReason::AllViolator {
                                violator_index: i,
                                total_candidates: total,
                            },
                        );
                    }
                    return false;
                }
                witnesses.extend(local);
            }
            if let Some(t) = trace.as_deref_mut() {
                t.record_matched(
                    &path_text,
                    MatchReason::AllPass {
                        total_candidates: total,
                    },
                );
            }
            true
        }
        Quantified::None(inner_eval) => {
            for (i, item) in arr.iter().enumerate() {
                let mut discard = Vec::new();
                if evaluate_node(
                    inner_eval,
                    item,
                    &mut discard,
                    Prefix::Item(&field, i),
                    trace.as_deref_mut(),
                ) {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record_unmatched(
                            &path_text,
                            UnmatchReason::NoneWitnessPresent {
                                witness_index: i,
                                total_candidates: total,
                            },
                        );
                    }
                    return false;
                }
            }
            if let Some(t) = trace.as_deref_mut() {
                t.record_matched(
                    &path_text,
                    MatchReason::NonePass {
                        total_candidates: total,
                    },
                );
            }
            true
        }
        Quantified::Each(inner_eval) => {
            // Per-witness emission driver. Predicate satisfaction
            // mirrors `Exists` (one matching witness is enough for
            // the rule to fire), but each matching element is
            // tagged `from_each: true` so the engine's
            // `emit_for_match` PerWitness path fans out findings
            // only over these — not the intermediate `exists:`
            // witnesses gathered along the predicate path.
            let mut witness_count = 0usize;
            for (i, item) in arr.iter().enumerate() {
                let mut local = Vec::new();
                let item_prefix = Prefix::Item(&field, i);
                if evaluate_node(
                    inner_eval,
                    item,
                    &mut local,
                    item_prefix,
                    trace.as_deref_mut(),
                ) {
                    witnesses.push(WitnessCandidate {
                        path: item_prefix.render(),
                        value: item,
                        from_each: true,
                    });
                    witnesses.extend(local);
                    witness_count += 1;
                }
            }
            let any = witness_count > 0;
            if let Some(t) = trace.as_deref_mut() {
                if any {
                    t.record_matched(
                        &path_text,
                        MatchReason::EachPass {
                            witness_count,
                            total_candidates: total,
                        },
                    );
                } else {
                    t.record_unmatched(
                        &path_text,
                        UnmatchReason::EachNoWitness {
                            total_candidates: total,
                        },
                    );
                }
            }
            any
        }
        Quantified::Count(op) => {
            let actual = arr.len() as u64;
            let pass = numeric_match(op, actual);
            if let Some(t) = trace {
                if pass {
                    t.record_matched(&path_text, MatchReason::CountOk { actual });
                } else {
                    t.record_unmatched(&path_text, UnmatchReason::CountMismatch { actual });
                }
            }
            pass
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Path resolution.
// ─────────────────────────────────────────────────────────────────────

fn resolve_path<'a>(root: &'a Value, path: &FieldPath) -> Option<&'a Value> {
    let mut current = root;
    for seg in &path.segments {
        match (current, seg) {
            (Value::Object(map), FieldName::Named(name)) => {
                current = map.get(name)?;
            }
            (Value::Array(arr), FieldName::Index(i)) => {
                current = arr.get(*i as usize)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

fn compose_path(prefix: &str, path: &FieldPath) -> String {
    let suffix = path.render();
    if prefix.is_empty() {
        suffix
    } else {
        format!("{}.{}", prefix, suffix)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Literal comparison.
// ─────────────────────────────────────────────────────────────────────

fn match_eq(v: &Value, lit: &PredicateLiteral) -> bool {
    match (v, lit) {
        (Value::Null, PredicateLiteral::Null) => true,
        (Value::Bool(a), PredicateLiteral::Bool(b)) => a == b,
        (Value::Number(n), PredicateLiteral::Integer(i)) => {
            n.as_i64().map(|x| x == *i).unwrap_or(false)
                || n.as_f64().map(|x| x == *i as f64).unwrap_or(false)
        }
        (Value::Number(n), PredicateLiteral::Float(f)) => n
            .as_f64()
            .map(|x| (x - f).abs() < f64::EPSILON)
            .unwrap_or(false),
        (Value::String(a), PredicateLiteral::String(b)) => a == b,
        // String → tagged-enum match: customer writes `kind: select` and
        // the IdentName / enum variant serializes to the same string.
        // (StatementKind variants serialize with `rename_all = "snake_case"`.)
        (Value::Object(map), PredicateLiteral::String(b)) => {
            // Three cases:
            //   - Tagged enum: { "kind": "<variant>", ... } — variant
            //     discriminator strings are dialect-insensitive.
            //   - IdentName: { "raw": "...", "normalized": "..." } — the
            //     `normalized` form is dialect-folded; apply the active
            //     dialect's identifier normalizer to the rule literal
            //     before comparing so `name: PUBLIC` matches whether
            //     the dialect folds upper (Snowflake/MSSQL) or lower
            //     (PostgreSQL/Databricks).
            //   - Externally-tagged newtype wrapping an IdentName:
            //     { "other": { "raw", "normalized" } } (e.g.
            //     `Privilege::Other`) — match against the inner
            //     `normalized` so `contains:` / `in:` reach
            //     dialect-specific variants.
            map.get("kind")
                .and_then(Value::as_str)
                .map(|k| k == b)
                .unwrap_or_else(|| {
                    map.get("normalized")
                        .and_then(Value::as_str)
                        .map(|n| n == crate::ir::normalize::normalize_identifier(b))
                        .unwrap_or_else(|| {
                            if map.len() != 1 {
                                return false;
                            }
                            map.values()
                                .next()
                                .and_then(Value::as_object)
                                .and_then(|inner| inner.get("normalized"))
                                .and_then(Value::as_str)
                                .map(|n| n == crate::ir::normalize::normalize_identifier(b))
                                .unwrap_or(false)
                        })
                })
        }
        (_, PredicateLiteral::Typed(typed)) => match_eq_typed(v, typed),
        _ => false,
    }
}

fn match_eq_typed(_v: &Value, _lit: &LiteralValue) -> bool {
    // Programmatic-only path; YAML rules don't produce
    // `PredicateLiteral::Typed`. Typed-literal comparison (Date,
    // Timestamp, Decimal, etc.) is not implemented.
    false
}

fn compare_lit(v: &Value, lit: &PredicateLiteral, cmp: impl Fn(f64, f64) -> bool) -> bool {
    let a = value_as_f64(v);
    let b = literal_as_f64(lit);
    match (a, b) {
        (Some(x), Some(y)) => cmp(x, y),
        _ => {
            // Fall back to lexicographic comparison for strings.
            if let (Some(s), Some(t)) = (value_as_str(v), literal_as_str(lit)) {
                let ord_lt = s < t;
                let ord_gt = s > t;
                // We only know cmp's intent is lt/lte/gt/gte through the
                // closure; reconstruct from probes.
                let lt = cmp(0.0, 1.0);
                let gt = cmp(1.0, 0.0);
                let eq = cmp(0.0, 0.0);
                if lt && !eq {
                    return ord_lt;
                }
                if gt && !eq {
                    return ord_gt;
                }
                if lt && eq {
                    return ord_lt || s == t;
                }
                if gt && eq {
                    return ord_gt || s == t;
                }
                return s == t;
            }
            false
        }
    }
}

fn value_as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

fn literal_as_f64(lit: &PredicateLiteral) -> Option<f64> {
    match lit {
        PredicateLiteral::Integer(i) => Some(*i as f64),
        PredicateLiteral::Float(f) => Some(*f),
        _ => None,
    }
}

fn value_as_str(v: &Value) -> Option<&str> {
    match v {
        Value::String(s) => Some(s),
        Value::Object(map) => {
            identifier_form(v).or_else(|| map.get("kind").and_then(Value::as_str))
        }
        _ => None,
    }
}

fn literal_as_str(lit: &PredicateLiteral) -> Option<&str> {
    match lit {
        PredicateLiteral::String(s) => Some(s.as_str()),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Field comparison.
// ─────────────────────────────────────────────────────────────────────

/// Whether every item of the list `left` is an item of the list `right`.
/// An absent or `null` field is the empty list; a field that is present
/// and not a list makes the comparison not hold.
fn all_in(left: Option<&Value>, right: Option<&Value>) -> bool {
    let (Some(left), Some(right)) = (list_items(left), list_items(right)) else {
        return false;
    };
    left.iter()
        .all(|item| right.iter().any(|other| items_equal(item, other)))
}

/// The items of a list field: none for an absent or `null` field, `None`
/// for one that is not a list.
fn list_items(field: Option<&Value>) -> Option<&[Value]> {
    match field {
        None | Some(Value::Null) => Some(&[]),
        Some(Value::Array(items)) => Some(items),
        Some(Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Object(_)) => None,
    }
}

/// Two items are equal when their values are, two identifiers when their
/// `normalized` forms are.
fn items_equal(a: &Value, b: &Value) -> bool {
    match (identifier_form(a), identifier_form(b)) {
        (Some(a), Some(b)) => a == b,
        (None, _) | (_, None) => a == b,
    }
}

/// The `normalized` form of an item that is an identifier.
fn identifier_form(item: &Value) -> Option<&str> {
    item.as_object()?.get("normalized")?.as_str()
}

fn numeric_match(op: &NumericOp, len: u64) -> bool {
    match op {
        NumericOp::Eq(n) => len == *n,
        NumericOp::Neq(n) => len != *n,
        NumericOp::Gt(n) => len > *n,
        NumericOp::Lt(n) => len < *n,
        NumericOp::Gte(n) => len >= *n,
        NumericOp::Lte(n) => len <= *n,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Glob matching (supports leading-, trailing-, and middle-`*`).
// ─────────────────────────────────────────────────────────────────────

pub(crate) fn glob_match(pattern: &str, input: &str) -> bool {
    // Split pattern on '*'; each segment must appear in order.
    let parts: Vec<&str> = pattern.split('*').collect();
    let n = parts.len();

    // No wildcards → exact match.
    if n == 1 {
        return pattern == input;
    }

    let mut cursor = 0usize;

    // Anchor first segment unless pattern starts with '*'.
    if !parts[0].is_empty() {
        if !input[cursor..].starts_with(parts[0]) {
            return false;
        }
        cursor += parts[0].len();
    }

    // Middle segments may match anywhere subsequent.
    for part in &parts[1..n - 1] {
        if part.is_empty() {
            continue;
        }
        match input[cursor..].find(part) {
            Some(idx) => cursor += idx + part.len(),
            None => return false,
        }
    }

    // Anchor last segment unless pattern ends with '*'.
    let last = parts[n - 1];
    if !last.is_empty() {
        if !input[cursor..].ends_with(last) {
            return false;
        }
        let _ = (input.len() as isize) - (last.len() as isize);
    }

    true
}

// ─────────────────────────────────────────────────────────────────────
// Tests.
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{AlgebraFacts, ScriptContext, StatementFacts, StatementKind};

    fn empty_facts(kind: StatementKind) -> StatementFacts {
        StatementFacts {
            declare: None,
            call: None,
            kind,
            source_span: None,
            query: None,
            ddl: None,
            privilege: None,
            policy: None,
            integration: None,
            policy_attachment: None,
            use_stmt: None,
            pg_copy: None,

            mssql_backup: None,

            mssql_restore: None,
            mssql_dbcc: None,
            mssql_key_management: None,
            mssql_security_policy: None,
            mssql_key_backup: None,
            mssql_assembly: None,
            mssql_add_signature: None,
            mssql_service_master_key: None,
            pg_default_privileges: None,
            comment: None,
            handler: None,
            dynamic_sql_calls: Vec::new(),
            mssql_exec: None,
            impersonation: None,
            audit: None,
            security_object: None,
            execute_immediate_from: None,
            algebra: AlgebraFacts::default(),
            script_context: ScriptContext::default(),
            diff: None,
        }
    }

    /// The predicate `yaml`, compiled to be read over any shape of value.
    fn compile_yaml(yaml: &str) -> CompiledPredicate {
        let parsed = parse_yaml(yaml).expect("predicate parses");
        compile_any_shape(&parsed, &ValueLists::default()).expect("predicate compiles")
    }

    #[test]
    fn glob_no_wildcards_exact_only() {
        assert!(glob_match("FOO", "FOO"));
        assert!(!glob_match("FOO", "FOOBAR"));
        assert!(!glob_match("FOO", "BAR"));
    }

    #[test]
    fn glob_trailing_wildcard() {
        assert!(glob_match("FOO*", "FOOBAR"));
        assert!(glob_match("FOO*", "FOO"));
        assert!(!glob_match("FOO*", "BAR"));
    }

    #[test]
    fn glob_leading_wildcard() {
        assert!(glob_match("*BAR", "FOOBAR"));
        assert!(glob_match("*BAR", "BAR"));
        assert!(!glob_match("*BAR", "BAZ"));
    }

    #[test]
    fn glob_middle_wildcard() {
        assert!(glob_match("FOO*BAR", "FOOXYZBAR"));
        assert!(glob_match("FOO*BAR", "FOOBAR"));
        assert!(!glob_match("FOO*BAR", "FOOBAZ"));
    }

    #[test]
    fn match_eq_externally_tagged_newtype_ident() {
        let _folding = crate::ir::normalize::default_folding();
        // Privilege::Other(IdentName) shape: { "other": { raw, normalized } }.
        let v =
            serde_json::json!({"other": {"raw": "Control Server", "normalized": "CONTROL SERVER"}});
        assert!(match_eq(
            &v,
            &PredicateLiteral::String("CONTROL SERVER".to_string())
        ));
        assert!(!match_eq(
            &v,
            &PredicateLiteral::String("IMPERSONATE".to_string())
        ));
        // Unit-variant strings unaffected.
        let unit = serde_json::json!("select");
        assert!(match_eq(
            &unit,
            &PredicateLiteral::String("select".to_string())
        ));
        // Multi-key objects (tagged enums without `kind`) stay unmatched.
        let multi = serde_json::json!({"a": {"normalized": "X"}, "b": 1});
        assert!(!match_eq(
            &multi,
            &PredicateLiteral::String("X".to_string())
        ));
    }

    #[test]
    fn statement_kind_eq_match() {
        let facts = empty_facts(StatementKind::Select);
        let pred = compile_yaml("kind: select");
        assert!(pred.matches(&facts));

        let pred_neg = compile_yaml("kind: insert");
        assert!(!pred_neg.matches(&facts));
    }

    #[test]
    fn statement_kind_in_list() {
        let facts = empty_facts(StatementKind::Select);
        let pred = compile_yaml("kind: { in: [select, set_select, insert] }");
        assert!(pred.matches(&facts));

        let pred_neg = compile_yaml("kind: { in: [insert, update, delete] }");
        assert!(!pred_neg.matches(&facts));
    }

    #[test]
    fn option_field_none_evaluates_false() {
        let facts = empty_facts(StatementKind::Grant);
        // facts.query is None → query.has_where leaf evaluates to false.
        let pred = compile_yaml("query.has_where: false");
        assert!(!pred.matches(&facts));
    }

    #[test]
    fn option_field_exists_handles_none() {
        let facts = empty_facts(StatementKind::Grant);
        let pred = compile_yaml("query: { exists: false }");
        assert!(pred.matches(&facts));

        let pred_neg = compile_yaml("query: { exists: true }");
        assert!(!pred_neg.matches(&facts));
    }

    #[test]
    fn all_of_combinator() {
        let facts = empty_facts(StatementKind::Grant);
        let pred = compile_yaml(
            r#"
all_of:
  - kind: grant
  - query: { exists: false }
"#,
        );
        assert!(pred.matches(&facts));
    }

    #[test]
    fn any_of_combinator() {
        let facts = empty_facts(StatementKind::Grant);
        let pred = compile_yaml(
            r#"
any_of:
  - kind: insert
  - kind: grant
"#,
        );
        assert!(pred.matches(&facts));
    }

    #[test]
    fn any_of_gives_the_witnesses_of_every_matching_arm() {
        let pred = compile_yaml(
            r#"
any_of:
  - query.reads_table:
      each:
        in_catalog: false
  - query.writes_table:
      each:
        in_catalog: false
"#,
        );
        let value = serde_json::json!({
            "query": {
                "reads_table": [{"in_catalog": false}, {"in_catalog": true}],
                "writes_table": [{"in_catalog": false}],
            }
        });
        let EvalResult::Match { witnesses } = pred.evaluate_value(&value) else {
            panic!("any_of matches");
        };
        assert_eq!(witnesses.len(), 2);
    }

    #[test]
    fn not_combinator() {
        let facts = empty_facts(StatementKind::Grant);
        let pred = compile_yaml(
            r#"
not:
  kind: insert
"#,
        );
        assert!(pred.matches(&facts));
    }

    #[test]
    fn count_op_zero_on_missing() {
        let facts = empty_facts(StatementKind::Grant);
        // facts.query is None, so query.scopes resolves to nothing.
        // count: { eq: 0 } should still match.
        let pred = compile_yaml("query.scopes: { count: { eq: 0 } }");
        assert!(pred.matches(&facts));
    }

    // ─────────────────────────────────────────────────────────────────
    // Explain-mode introspection.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn explain_scalar_mismatch_records_actual_value() {
        let facts = empty_facts(StatementKind::Select);
        let pred = compile_yaml("kind: grant");
        let (matched, exp) = pred.evaluate_with_explain(&facts);
        assert!(!matched);
        assert!(exp.matched_paths.is_empty());
        assert_eq!(exp.unmatched_paths.len(), 1);
        let entry = &exp.unmatched_paths[0];
        assert!(entry.contains("kind"), "got: {}", entry);
        assert!(entry.contains("eq"), "got: {}", entry);
        assert!(entry.contains("\"grant\""), "got: {}", entry);
        assert!(entry.contains("\"select\""), "got: {}", entry);
    }

    #[test]
    fn explain_scalar_match_records_matched_path() {
        let facts = empty_facts(StatementKind::Grant);
        let pred = compile_yaml("kind: grant");
        let (matched, exp) = pred.evaluate_with_explain(&facts);
        assert!(matched);
        assert_eq!(exp.matched_paths.len(), 1);
        assert!(exp.unmatched_paths.is_empty());
        assert!(exp.matched_paths[0].contains("kind"));
    }

    #[test]
    fn explain_path_not_resolved_when_query_missing() {
        let facts = empty_facts(StatementKind::Grant);
        // facts.query is None; query.has_where path does not resolve.
        let pred = compile_yaml("query.has_where: false");
        let (matched, exp) = pred.evaluate_with_explain(&facts);
        assert!(!matched);
        assert_eq!(exp.unmatched_paths.len(), 1);
        assert!(
            exp.unmatched_paths[0].contains("path did not resolve"),
            "got: {}",
            exp.unmatched_paths[0]
        );
        assert!(exp.unmatched_paths[0].contains("query.has_where"));
    }

    #[test]
    fn explain_all_of_arm_failure_reports_arm_index() {
        let facts = empty_facts(StatementKind::Grant);
        // arm 0 matches (kind: grant), arm 1 fails (query is None).
        let pred = compile_yaml(
            r#"
all_of:
  - kind: grant
  - query.has_where: false
"#,
        );
        let (matched, exp) = pred.evaluate_with_explain(&facts);
        assert!(!matched);
        // Should record: arm 0 matched (kind), arm 1 path-not-resolved
        // (query.has_where), and outer all_of arm-1-failed.
        let matched_kind = exp.matched_paths.iter().any(|e| e.contains("kind"));
        assert!(
            matched_kind,
            "expected kind match in: {:?}",
            exp.matched_paths
        );

        let has_path_not_resolved = exp
            .unmatched_paths
            .iter()
            .any(|e| e.contains("query.has_where") && e.contains("path did not resolve"));
        assert!(
            has_path_not_resolved,
            "expected query.has_where path-not-resolved in: {:?}",
            exp.unmatched_paths
        );

        let has_all_of_arm_failed = exp
            .unmatched_paths
            .iter()
            .any(|e| e.contains("all_of") && e.contains("arm [1]"));
        assert!(
            has_all_of_arm_failed,
            "expected all_of arm [1] failure in: {:?}",
            exp.unmatched_paths
        );
    }

    #[test]
    fn explain_any_of_matched_arm_recorded() {
        let facts = empty_facts(StatementKind::Grant);
        let pred = compile_yaml(
            r#"
any_of:
  - kind: insert
  - kind: grant
  - kind: update
"#,
        );
        let (matched, exp) = pred.evaluate_with_explain(&facts);
        assert!(matched);
        // The successful arm at index 1 should be recorded.
        let has_any_of_match = exp
            .matched_paths
            .iter()
            .any(|e| e.contains("any_of") && e.contains("arm [1]"));
        assert!(
            has_any_of_match,
            "expected any_of arm [1] match in: {:?}",
            exp.matched_paths
        );
    }

    #[test]
    fn explain_any_of_no_arm_matched() {
        let facts = empty_facts(StatementKind::Select);
        let pred = compile_yaml(
            r#"
any_of:
  - kind: insert
  - kind: update
  - kind: delete
"#,
        );
        let (matched, exp) = pred.evaluate_with_explain(&facts);
        assert!(!matched);
        let has_no_match = exp
            .unmatched_paths
            .iter()
            .any(|e| e.contains("any_of") && e.contains("0 of 3"));
        assert!(
            has_no_match,
            "expected any_of no-arm-matched in: {:?}",
            exp.unmatched_paths
        );
    }

    #[test]
    fn explain_count_mismatch_reports_actual() {
        let facts = empty_facts(StatementKind::Grant);
        // facts.query is None, count resolves to 0; predicate wants > 0.
        let pred = compile_yaml("query.scopes: { count: { gt: 0 } }");
        let (matched, exp) = pred.evaluate_with_explain(&facts);
        assert!(!matched);
        let has_count_mismatch = exp
            .unmatched_paths
            .iter()
            .any(|e| e.contains("query.scopes") && e.contains("count mismatch"));
        assert!(
            has_count_mismatch,
            "expected count mismatch in: {:?}",
            exp.unmatched_paths
        );
    }

    // ── Statement-kind dispatch gate ──────────────────────────────────

    fn gate(yaml: &str) -> KindGate {
        compile_yaml(yaml).kind_gate().clone()
    }

    #[test]
    fn kind_gate_eq_single_kind() {
        let g = gate("kind: select");
        assert_eq!(g, KindGate::Only(one_kind(StatementKind::Select as usize)));
        assert!(!g.skips(StatementKind::Select as usize));
        assert!(g.skips(StatementKind::Insert as usize));
    }

    #[test]
    fn kind_gate_in_list() {
        let g = gate("kind: { in: [select, insert] }");
        assert!(!g.skips(StatementKind::Select as usize));
        assert!(!g.skips(StatementKind::Insert as usize));
        assert!(g.skips(StatementKind::Update as usize));
    }

    #[test]
    fn kind_gate_in_with_unknown_member_widens_to_any() {
        // One unresolvable member widens the whole op — never a false skip.
        // `compile` refuses such a predicate, so the gate is read from the
        // parsed predicate.
        let parsed = parse_yaml("kind: { in: [select, not_a_real_kind] }").expect("parses");
        assert_eq!(predicate_kind_gate(&parsed), KindGate::Any);
    }

    #[test]
    fn kind_gate_unknown_literal_is_any() {
        let parsed = parse_yaml("kind: not_a_real_kind").expect("parses");
        assert_eq!(predicate_kind_gate(&parsed), KindGate::Any);
    }

    #[test]
    fn kind_gate_neq_is_any() {
        // `neq` matches every OTHER kind — cannot bound to a finite set.
        assert_eq!(gate("kind: { neq: select }"), KindGate::Any);
    }

    #[test]
    fn kind_gate_non_statement_kind_path_is_any() {
        // `privilege.target.kind` is the kind of a grant target, not the
        // statement kind, so it must not gate.
        assert_eq!(gate("privilege.target.kind: role"), KindGate::Any);
    }

    #[test]
    fn kind_gate_allof_empty_intersection_skips_every_kind() {
        // A scalar kind can't equal two values: empty intersection. The
        // rule can never match, so skipping every kind is sound.
        let g = gate("all_of: [ { kind: select }, { kind: insert } ]");
        assert!(g.skips(StatementKind::Select as usize));
        assert!(g.skips(StatementKind::Insert as usize));
        assert!(g.skips(StatementKind::Update as usize));
    }

    #[test]
    fn kind_gate_allof_narrows_through_nonkind_conjunct() {
        // kind:select ∧ (non-kind family clause) → still Only({Select}).
        let g = gate("all_of: [ { kind: select }, { query: { exists: true } } ]");
        assert!(!g.skips(StatementKind::Select as usize));
        assert!(g.skips(StatementKind::Insert as usize));
    }

    #[test]
    fn kind_gate_not_is_any() {
        assert_eq!(gate("not: { kind: select }"), KindGate::Any);
    }

    #[test]
    fn kind_gate_anyof_one_unbounded_arm_forces_any() {
        let g = gate("any_of: [ { kind: select }, { query: { exists: true } } ]");
        assert_eq!(g, KindGate::Any);
    }

    #[test]
    fn kind_gate_anyof_all_bounded_unions() {
        let g = gate("any_of: [ { kind: select }, { kind: insert } ]");
        assert!(!g.skips(StatementKind::Select as usize));
        assert!(!g.skips(StatementKind::Insert as usize));
        assert!(g.skips(StatementKind::Grant as usize));
    }

    #[test]
    fn kind_gate_relational_does_not_bound_statement_kind() {
        // An inner `kind:` inside a quantifier is element-relative; the
        // relational must widen to Any, never read as the statement kind.
        assert_eq!(
            gate("query.scopes: { exists: { kind: select } }"),
            KindGate::Any
        );
    }

    #[test]
    fn the_roots_are_the_fields_of_statement_facts() {
        let roots = statement_facts_roots();
        for field in [
            "kind",
            "query",
            "ddl",
            "privilege",
            "call",
            "script_context",
            "diff",
        ] {
            assert!(roots.contains(&field), "{field} in {roots:?}");
        }
        let mut distinct = roots.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), roots.len(), "{roots:?}");
    }

    #[test]
    fn kind_gate_index_consistency() {
        // The set-time index (string → StatementKind → as usize) must equal
        // the check-time index (facts.kind as usize) for the bitset to be
        // valid. Catches a future variant reorder/insert desyncing them.
        for (s, k) in [
            ("select", StatementKind::Select),
            ("insert", StatementKind::Insert),
            ("grant", StatementKind::Grant),
            ("create_procedure", StatementKind::CreateProcedure),
            ("create_masking_policy", StatementKind::CreateMaskingPolicy),
            ("mssql_exec", StatementKind::MssqlExec),
        ] {
            let lit = PredicateLiteral::String(s.to_string());
            assert_eq!(kind_literal_bit(&lit), Some(k as usize), "literal {s}");
        }
    }

    #[test]
    fn kind_gate_empty_anyof_is_any() {
        // An empty disjunction matches nothing, so `Any` (never skip) is
        // vacuously sound. Reachable from YAML (`any_of: []`).
        assert_eq!(gate("any_of: []"), KindGate::Any);
    }

    #[test]
    fn kind_gate_skips_is_conservative_out_of_range() {
        // The "sound on growth past KIND_BITS" contract: a kind whose
        // discriminant exceeds the bitset capacity is NEVER skipped
        // (degrades to always-evaluate). Unreachable with today's 271
        // variants, but the soundness argument depends on it holding.
        let g = KindGate::Only(one_kind(StatementKind::Select as usize));
        assert!(!g.skips(KIND_BITS), "out-of-range index must not skip");
        assert!(!g.skips(KIND_BITS + 9999), "far-out-of-range must not skip");
        // In-range sanity: the set kind isn't skipped; a different one is.
        assert!(!g.skips(StatementKind::Select as usize));
        assert!(g.skips(StatementKind::Insert as usize));
    }

    // ── Comparing two fields ──────────────────────────────────────────

    /// Whether `yaml` matches the serialized facts `facts`.
    fn holds(yaml: &str, facts: Value) -> bool {
        compile_yaml(yaml).evaluate_value(&facts).is_match()
    }

    const LEFT_IN_RIGHT: &str = "query.left: { all_in_field: query.right }";

    #[test]
    fn all_in_field_holds_when_every_item_is_in_the_other_list() {
        use serde_json::json;
        assert!(holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": ["a", "b"], "right": ["b", "c", "a"]}})
        ));
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": ["a", "d"], "right": ["a", "b"]}})
        ));
        assert!(holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [], "right": []}})
        ));
        assert!(holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [1, 1], "right": [1]}})
        ));
    }

    #[test]
    fn all_in_field_reads_an_absent_or_null_field_as_the_empty_list() {
        use serde_json::json;
        // No item on the left: in any list.
        assert!(holds(LEFT_IN_RIGHT, json!({"query": {"right": ["a"]}})));
        assert!(holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": null, "right": ["a"]}})
        ));
        assert!(holds(LEFT_IN_RIGHT, json!({"query": {}})));
        assert!(holds(LEFT_IN_RIGHT, json!({"query": null})));
        // No item on the right: only the empty list is in it.
        assert!(!holds(LEFT_IN_RIGHT, json!({"query": {"left": ["a"]}})));
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": ["a"], "right": null}})
        ));
        assert!(holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [], "right": null}})
        ));
    }

    #[test]
    fn all_in_field_does_not_hold_on_a_field_that_is_not_a_list() {
        use serde_json::json;
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": "a", "right": ["a"]}})
        ));
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": ["a"], "right": "a"}})
        ));
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": {"x": 1}, "right": [{"x": 1}]}})
        ));
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [], "right": false}})
        ));
        // Negated, a field that is not a list reads as "not all in".
        assert!(holds(
            "not: { query.left: { all_in_field: query.right } }",
            json!({"query": {"left": "a", "right": ["a"]}})
        ));
    }

    #[test]
    fn all_in_field_resolves_its_field_against_the_element_matched() {
        use serde_json::json;
        let facts = json!({"query": {
            "items": [
                {"left": ["a"], "right": ["a", "b"]},
                {"left": ["c"], "right": ["a"]},
            ],
            "right": ["c"],
        }});
        let rule = "query.items: { each: { left: { all_in_field: right } } }";
        let EvalResult::Match { witnesses } = compile_yaml(rule).evaluate_value(&facts) else {
            panic!("the first item's list is in its own `right`");
        };
        let matched: Vec<&str> = witnesses
            .iter()
            .filter(|witness| witness.from_each)
            .map(|witness| witness.path.as_str())
            .collect();
        assert_eq!(matched, ["query.items.0"]);
        // A field nested in the element.
        assert!(holds(
            "query.items: { exists: { left: { all_in_field: inner.right } } }",
            json!({"query": {"items": [{"left": ["a"], "inner": {"right": ["a"]}}]}})
        ));
    }

    /// A witness's path names each quantifier and `any_of` arm it was
    /// found under, the same in the hot path and in explain mode, and its
    /// value is the element matched.
    #[test]
    fn witness_paths_name_the_quantifiers_and_arms_they_were_found_under() {
        use serde_json::json;
        let facts = json!({"query": {"scopes": [
            {"projections": [{"k": 1}]},
            {"projections": [{"k": 1}, {"k": 2}]},
        ]}});
        let rule = "query.scopes: { each: { any_of: [ \
                    { projections: { each: { k: 3 } } }, \
                    { projections: { exists: { not: { k: 1 } } } } ] } }";
        let expected = [
            (
                "query.scopes.1",
                true,
                json!({"projections": [{"k": 1}, {"k": 2}]}),
            ),
            (
                "query.scopes.1@any_of[1].projections.1",
                false,
                json!({"k": 2}),
            ),
        ];
        let compiled = compile_yaml(rule);
        let (explained, _) = compiled.evaluate_value_with_explain(&facts);
        for result in [compiled.evaluate_value(&facts), explained] {
            let EvalResult::Match { witnesses } = result else {
                panic!("the second scope has a projection whose k is not 1");
            };
            let got: Vec<(&str, bool, &Value)> = witnesses
                .iter()
                .map(|w| (w.path.as_str(), w.from_each, w.value))
                .collect();
            let want: Vec<(&str, bool, &Value)> =
                expected.iter().map(|(p, e, v)| (*p, *e, v)).collect();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn all_in_field_compares_identifiers_by_their_normalized_form() {
        use serde_json::json;
        let ident = |raw: &str, normalized: &str| json!({"raw": raw, "normalized": normalized});
        assert!(holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [ident("Email", "EMAIL")], "right": [ident("\"EMAIL\"", "EMAIL")]}})
        ));
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [ident("email", "email")], "right": [ident("EMAIL", "EMAIL")]}})
        ));
        // Labels compare as values: a unit label, a named one.
        assert!(holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [{"other": "GOV.TAGS.PII"}, "pii"], "right": ["pii", {"other": "GOV.TAGS.PII"}]}})
        ));
        assert!(!holds(
            LEFT_IN_RIGHT,
            json!({"query": {"left": [{"other": "GOV.TAGS.PII"}], "right": [{"other": "PII"}]}})
        ));
    }

    #[test]
    fn all_in_field_neither_gates_the_family_nor_bounds_the_kind() {
        let compiled = compile_yaml(LEFT_IN_RIGHT);
        assert_eq!(compiled.root_mask(), 0);
        assert_eq!(compiled.kind_gate(), &KindGate::Any);
    }

    #[test]
    fn all_in_field_checks_its_fields_root_outside_a_quantifier() {
        let parse = |yaml: &str| {
            let val: Value = serde_yaml_ng::from_str(yaml).expect("yaml parses");
            super::super::predicate::parse_predicate(&val).expect("predicate parses")
        };
        assert!(matches!(
            compile(&parse("query.left: { all_in_field: qurey.right }")),
            Err(CompileError::UnknownRootField { unknown_root, .. }) if unknown_root == "qurey"
        ));
        // Inside a quantifier the field is the element's, of any name.
        assert!(compile_any_shape(
            &parse("query.items: { exists: { left: { all_in_field: qurey } } }"),
            &ValueLists::default()
        )
        .is_ok());
    }

    #[test]
    fn a_statement_kind_no_statement_has_is_refused_with_the_nearest_kind() {
        for (yaml, kind, suggestion) in [
            ("kind: delet", "delet", Some("delete")),
            ("kind: DELETE", "DELETE", Some("delete")),
            ("kind: {in: [select, delet]}", "delet", Some("delete")),
            ("kind: {neq: selct}", "selct", Some("select")),
            ("kind: {not_in: [grnt]}", "grnt", Some("grant")),
            (
                "kind: nothing_like_a_statement_kind_at_all",
                "nothing_like_a_statement_kind_at_all",
                None,
            ),
        ] {
            let parsed = parse_yaml(yaml).expect("predicate parses");
            assert_eq!(
                compile(&parsed).err(),
                Some(CompileError::UnknownStatementKind {
                    kind: kind.to_string(),
                    suggestion: suggestion.map(str::to_string),
                }),
                "{yaml}"
            );
        }
        for yaml in [
            "kind: {in: [select, grant]}",
            "kind: {neq: select}",
            // Inside a quantifier `kind` is the element's, of any value.
            "diff.events: {exists: {kind: statement_added}}",
            // Only the top-level `kind` is the statement's.
            "privilege.target.kind: schema",
        ] {
            let parsed = parse_yaml(yaml).expect("predicate parses");
            assert!(compile(&parsed).is_ok(), "{yaml}");
        }
    }

    #[test]
    fn explain_all_in_field_names_the_operator_and_the_field() {
        let facts = serde_json::json!({"query": {"left": ["a", "d"], "right": ["a"]}});
        let (result, exp) = compile_yaml(LEFT_IN_RIGHT).evaluate_value_with_explain(&facts);
        assert!(!result.is_match());
        assert!(
            exp.unmatched_paths
                .iter()
                .any(|entry| entry.contains("query.left all_in_field query.right")),
            "{:?}",
            exp.unmatched_paths
        );
    }

    // ── Named value lists ─────────────────────────────────────────────

    fn list_table() -> ValueLists {
        let entries = serde_yaml_ng::from_str(
            "dummies: {values: [REPLACE_ME]}\n\
             credential_references: {values: [x]}\n\
             refs: {values: [From_Pipeline], patterns: [\"{{*secrets.*}}\", \"vault:*\"]}\n",
        )
        .expect("list yaml parses");
        super::super::lists::define_builtin_lists(entries).expect("lists define")
    }

    fn parse_yaml(yaml: &str) -> Result<Predicate, ParseError> {
        let val: Value = serde_yaml_ng::from_str(yaml).expect("yaml parses");
        super::super::predicate::parse_predicate(&val)
    }

    fn holds_with_lists(yaml: &str, facts: Value) -> bool {
        let parsed = parse_yaml(yaml).expect("predicate parses");
        compile_any_shape(&parsed, &list_table())
            .expect("predicate compiles")
            .evaluate_value(&facts)
            .is_match()
    }

    fn x(value: Value) -> Value {
        serde_json::json!({"query": {"x": value}})
    }

    #[test]
    fn in_list_matches_values_and_patterns_ignoring_case() {
        let yaml = "query.x: { in_list: refs }";
        assert!(holds_with_lists(yaml, x("from_pipeline".into())));
        assert!(holds_with_lists(yaml, x("{{ SECRETS.pw }}".into())));
        assert!(!holds_with_lists(yaml, x("S3cret!".into())));
    }

    #[test]
    fn not_in_list_over_two_lists() {
        let yaml = "query.x: { not_in_list: [dummies, refs] }";
        assert!(!holds_with_lists(yaml, x("REPLACE_ME".into())));
        assert!(!holds_with_lists(yaml, x("vault:kv/a".into())));
        assert!(holds_with_lists(yaml, x("S3cret!".into())));
    }

    #[test]
    fn list_ops_read_strings_only() {
        use serde_json::json;
        for yaml in [
            "query.x: { in_list: refs }",
            "query.x: { not_in_list: refs }",
        ] {
            assert!(!holds_with_lists(yaml, x(json!(5))), "{yaml}");
            assert!(!holds_with_lists(yaml, x(Value::Null)), "{yaml}");
            assert!(!holds_with_lists(yaml, x(json!(["a"]))), "{yaml}");
            assert!(!holds_with_lists(yaml, json!({"query": {}})), "{yaml}");
        }
    }

    #[test]
    fn unknown_list_is_a_compile_error() {
        let parsed = parse_yaml("query.x: { in_list: nope }").expect("predicate parses");
        assert!(matches!(
            compile_any_shape(&parsed, &list_table()),
            Err(CompileError::UnknownList { list }) if list == "nope"
        ));
    }

    #[test]
    fn list_names_are_case_sensitive() {
        let parsed =
            parse_yaml("query.x: { in_list: Credential_References }").expect("predicate parses");
        assert!(matches!(
            compile_any_shape(&parsed, &list_table()),
            Err(CompileError::UnknownList { list }) if list == "Credential_References"
        ));
    }

    #[test]
    fn non_string_list_name_is_a_parse_error() {
        for yaml in [
            "query.x: { in_list: 3 }",
            "query.x: { in_list: [] }",
            "query.x: { not_in_list: [refs, 3] }",
        ] {
            assert!(
                matches!(parse_yaml(yaml), Err(ParseError::InvalidLiteral { .. })),
                "{yaml}"
            );
        }
    }

    #[test]
    fn list_ops_resolve_inside_quantifier_bodies() {
        use serde_json::json;
        let yaml = "query.items: { exists: { value: { not_in_list: refs } } }";
        let facts = |v: &str| json!({"query": {"items": [{"value": v}]}});
        assert!(holds_with_lists(yaml, facts("S3cret!")));
        assert!(!holds_with_lists(yaml, facts("vault:kv/a")));
        let parsed = parse_yaml("query.items: { none: { value: { in_list: nope } } }")
            .expect("predicate parses");
        assert!(matches!(
            compile_any_shape(&parsed, &list_table()),
            Err(CompileError::UnknownList { list }) if list == "nope"
        ));
    }

    #[test]
    fn explain_renders_list_names() {
        let parsed = parse_yaml("query.x: { not_in_list: [dummies, refs] }").expect("parses");
        let compiled = compile_any_shape(&parsed, &list_table()).expect("compiles");
        let facts = x("REPLACE_ME".into());
        let (result, exp) = compiled.evaluate_value_with_explain(&facts);
        assert!(!result.is_match());
        assert!(
            exp.unmatched_paths
                .iter()
                .any(|entry| entry.contains("not_in_list dummies, refs")),
            "{:?}",
            exp.unmatched_paths
        );
    }
}
