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

use std::sync::Arc;

use serde_json::Value;

use super::explain::{ExplainTrace, MatchReason, UnmatchReason};
use super::predicate::{
    FieldName, FieldPath, NumericOp, ParseError, Predicate, PredicateLiteral, Quantifier,
    RelationalMatch, ScalarMatch, ScalarOp,
};
use super::signal::RuleExplanation;
use crate::facts::{LiteralValue, RuleCategory};
// Only the test-gated `evaluate`/`evaluate_with_explain` take typed facts.
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

/// The closure a predicate compiles to: evaluates serialized facts and,
/// when a trace is passed, records why it matched or not.
type EvalFn = dyn Fn(&Value, Option<&mut ExplainTrace>) -> EvalResult + Send + Sync;

/// A compiled predicate ready for evaluation against `StatementFacts`.
/// Cloneable handles share the underlying closure via `Arc`.
///
/// The underlying closure threads an `Option<&mut ExplainTrace>` so the
/// same closure serves both the hot path (`evaluate`, no trace
/// collection) and explain mode (`evaluate_with_explain`, typed trace
/// entries collected, then projected onto the schema-stable
/// [`RuleExplanation`] string surface at the engine boundary).
#[derive(Clone)]
pub struct CompiledPredicate {
    eval: Arc<EvalFn>,
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
/// values for the customer-facing `Signal.evidence`. Keeping the
/// flag here (not on `FactWitness`) ensures the generated JSON
/// schema for `Signal.evidence.witnesses[*]` stays a stable
/// customer-platform contract independent of engine internals.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WitnessCandidate {
    pub(crate) path: String,
    pub(crate) value: Value,
    pub(crate) from_each: bool,
}

/// The outcome of evaluating a compiled predicate.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum EvalResult {
    /// Predicate did not match. No signal emitted.
    NoMatch,
    /// Predicate matched. `witnesses` carries every relational-quantifier
    /// witness gathered along the way; `from_each` distinguishes
    /// outermost-`each:` matches from intermediate `exists:` matches
    /// so the engine's `emit_for_match` can apply per-witness
    /// emission semantics without the flag leaking onto the public
    /// `Signal.evidence` surface.
    Match { witnesses: Vec<WitnessCandidate> },
}

impl EvalResult {
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
    /// call. Production batch callers serialize once and use
    /// [`Self::evaluate_value`].
    #[cfg(test)]
    pub(crate) fn evaluate(&self, facts: &StatementFacts) -> EvalResult {
        let value = serde_json::to_value(facts).unwrap_or(Value::Null);
        (self.eval)(&value, None)
    }

    /// Evaluate against a pre-serialized facts value. The engine
    /// builds this value once per statement
    /// ([`super::engine::evaluate_rules`]) and reuses it across every
    /// rule, avoiding a per-rule serialization that would dominate
    /// the rule-evaluation cost.
    pub(crate) fn evaluate_value(&self, value: &Value) -> EvalResult {
        (self.eval)(value, None)
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
    pub(crate) fn evaluate_with_explain(
        &self,
        facts: &StatementFacts,
    ) -> (EvalResult, RuleExplanation) {
        let value = serde_json::to_value(facts).unwrap_or(Value::Null);
        let mut trace = ExplainTrace::default();
        let result = (self.eval)(&value, Some(&mut trace));
        (result, trace.into_rule_explanation())
    }

    /// Explain-mode variant accepting a pre-serialized value. Used
    /// by the engine's explain path for the same per-statement
    /// caching reason as [`Self::evaluate_value`].
    pub(crate) fn evaluate_value_with_explain(
        &self,
        value: &Value,
    ) -> (EvalResult, RuleExplanation) {
        let mut trace = ExplainTrace::default();
        let result = (self.eval)(value, Some(&mut trace));
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
    validate_root_field_paths(predicate)?;
    let root_mask = predicate_root_mask(predicate);
    let kind_gate = predicate_kind_gate(predicate);
    let category = super::category::category_of_rule(predicate);
    let reads_reasoning = super::depth::reads_reasoning(predicate);
    let evaluator = build_evaluator(predicate)?;
    let eval: Arc<EvalFn> = Arc::new(
        move |value: &Value, trace: Option<&mut ExplainTrace>| -> EvalResult {
            let mut witnesses = Vec::new();
            if evaluate_node(&evaluator, value, &mut witnesses, "", trace) {
                EvalResult::Match { witnesses }
            } else {
                EvalResult::NoMatch
            }
        },
    );
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
// ─────────────────────────────────────────────────────────────────────

/// Snake-case names of every top-level field on
/// `crate::facts::StatementFacts`. Kept in sync with the struct
/// definition in `src/facts/statement.rs`; if a new top-level field
/// is added there, this list must grow with it.
const KNOWN_STATEMENT_FACTS_ROOTS: &[&str] = &[
    "kind",
    "source_span",
    "query",
    "ddl",
    "privilege",
    "policy",
    "policy_attachment",
    "integration",
    "use_stmt",
    "pg_copy",
    "mssql_backup",
    "mssql_restore",
    "mssql_dbcc",
    "mssql_key_management",
    "mssql_security_policy",
    "mssql_key_backup",
    "mssql_assembly",
    "mssql_add_signature",
    "mssql_service_master_key",
    "pg_default_privileges",
    "comment",
    "handler",
    "dynamic_sql_calls",
    "mssql_exec",
    "impersonation",
    "execute_immediate_from",
    "audit",
    "security_object",
    "algebra",
    "blast_radius",
    "script_context",
    "diff",
];

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
/// ambient/unknown root. Index = position in `KNOWN_STATEMENT_FACTS_ROOTS`
/// skipping ambient roots. Degrades to 0 past 32 roots so future growth
/// stays sound (always-evaluate) rather than overflowing the shift.
fn root_mask_bit(name: &str) -> u32 {
    let mut idx = 0u32;
    for root in KNOWN_STATEMENT_FACTS_ROOTS {
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
    for root in KNOWN_STATEMENT_FACTS_ROOTS {
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
    let kind: crate::facts::StatementKind =
        serde_json::from_value(Value::String(s.clone())).ok()?;
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
        Predicate::Scalar(s) => check_root_segment(&s.path),
        Predicate::Relational(r) => check_root_segment(&r.path),
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
    if KNOWN_STATEMENT_FACTS_ROOTS.contains(&root_name) {
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
    Relational(RelationalMatch),
}

fn build_evaluator(p: &Predicate) -> Result<Evaluator, CompileError> {
    Ok(match p {
        Predicate::AllOf(parts) => Evaluator::AllOf(
            parts
                .iter()
                .map(build_evaluator)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Predicate::AnyOf(parts) => Evaluator::AnyOf(
            parts
                .iter()
                .map(build_evaluator)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Predicate::Not(inner) => Evaluator::Not(Box::new(build_evaluator(inner)?)),
        Predicate::Scalar(s) => Evaluator::Scalar(s.clone()),
        Predicate::Relational(r) => Evaluator::Relational(r.clone()),
    })
}

// ─────────────────────────────────────────────────────────────────────
// Evaluation against a serde_json::Value tree.
// ─────────────────────────────────────────────────────────────────────

fn evaluate_node(
    eval: &Evaluator,
    value: &Value,
    witnesses: &mut Vec<WitnessCandidate>,
    path_prefix: &str,
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
                    let arm_path = format!("{}@all_of[{}]", path_prefix, idx);
                    let pass = evaluate_node(p, value, witnesses, &arm_path, Some(t));
                    if !pass {
                        all_pass = false;
                        if first_failure.is_none() {
                            first_failure = Some(idx);
                        }
                    }
                }
                if all_pass {
                    t.record_matched(path_prefix, MatchReason::AllOfPass { arm_count });
                    true
                } else {
                    let arm_index = first_failure.unwrap_or(0);
                    t.record_unmatched(
                        path_prefix,
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
                    .all(|p| evaluate_node(p, value, witnesses, path_prefix, None))
            }
        }
        Evaluator::AnyOf(parts) => {
            let arm_count = parts.len();
            for (idx, p) in parts.iter().enumerate() {
                let mut local = Vec::new();
                let arm_path = format!("{}@any_of[{}]", path_prefix, idx);
                if evaluate_node(p, value, &mut local, &arm_path, trace.as_deref_mut()) {
                    witnesses.extend(local);
                    if let Some(t) = trace.as_deref_mut() {
                        t.record_matched(
                            path_prefix,
                            MatchReason::AnyOfPass {
                                matched_arm: idx,
                                arm_count,
                            },
                        );
                    }
                    return true;
                }
            }
            if let Some(t) = trace.as_deref_mut() {
                t.record_unmatched(path_prefix, UnmatchReason::AnyOfNoArmMatched { arm_count });
            }
            false
        }
        Evaluator::Not(inner) => {
            // `not` doesn't propagate witnesses — if its body matched,
            // we wouldn't be here.
            let mut discard = Vec::new();
            let not_path = format!("{}@not", path_prefix);
            let inner_matched =
                evaluate_node(inner, value, &mut discard, &not_path, trace.as_deref_mut());
            let pass = !inner_matched;
            if let Some(t) = trace.as_deref_mut() {
                if pass {
                    t.record_matched(path_prefix, MatchReason::NotPass);
                } else {
                    t.record_unmatched(path_prefix, UnmatchReason::NotInverted);
                }
            }
            pass
        }
        Evaluator::Scalar(s) => evaluate_scalar(s, value, path_prefix, trace),
        Evaluator::Relational(r) => evaluate_relational(r, value, witnesses, path_prefix, trace),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Scalar evaluation.
// ─────────────────────────────────────────────────────────────────────

/// True iff the leaf path segment names a dialect-folded identifier
/// field (`IdentName.normalized` or any `*.canonical` joined-normalized
/// form). Rule literals targeting these paths must run through the
/// active dialect's identifier normalizer before comparison so rule
/// authors can write `name.normalized: PUBLIC` once and have it match
/// in Snowflake/MSSQL (upper-fold) AND PostgreSQL/Databricks
/// (lower-fold). The active dialect is threaded from the analyzer to
/// `normalize_identifier` via the thread-local set in
/// `apply_dialect_normalization`.
fn path_is_dialect_folded(path: &FieldPath) -> bool {
    matches!(
        path.segments.last(),
        Some(FieldName::Named(n)) if n == "normalized" || n == "canonical"
    )
}

fn fold_string_literal(lit: &PredicateLiteral) -> PredicateLiteral {
    match lit {
        PredicateLiteral::String(s) => {
            PredicateLiteral::String(crate::ir::normalize::normalize_identifier(s))
        }
        other => other.clone(),
    }
}

fn evaluate_scalar(
    s: &ScalarMatch,
    root: &Value,
    path_prefix: &str,
    mut trace: Option<&mut ExplainTrace>,
) -> bool {
    let resolved = resolve_path(root, &s.path);
    // The composed path string is only ever read inside the explain
    // trace branches below; scalars never emit witnesses. Build it
    // lazily so the hot path (`trace: None`) skips the allocation —
    // this is per-leaf, per-rule, per-statement work otherwise.
    let scalar_path = || compose_path(path_prefix, &s.path);
    let pass: bool;
    let op_name: &'static str = scalar_op_name(&s.op);
    let fold_lits = path_is_dialect_folded(&s.path);
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
            let fold = |lit: &PredicateLiteral| -> PredicateLiteral {
                if fold_lits {
                    fold_string_literal(lit)
                } else {
                    lit.clone()
                }
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
                        let pat: std::borrow::Cow<'_, str> = if fold_lits {
                            std::borrow::Cow::Owned(crate::ir::normalize::normalize_identifier(
                                glob,
                            ))
                        } else {
                            std::borrow::Cow::Borrowed(glob.as_str())
                        };
                        glob_match(&pat, s)
                    }
                    _ => false,
                },
                ScalarOp::In(list) => list.iter().any(|lit| match_eq(v, &fold(lit))),
                ScalarOp::NotIn(list) => !list.iter().any(|lit| match_eq(v, &fold(lit))),
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
                // Exists / IsNull are handled by the earlier match arms.
                ScalarOp::Exists(_) | ScalarOp::IsNull(_) => unreachable!(),
            };
            if let Some(t) = trace {
                let actual = render_value_for_trace(v);
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
        ScalarOp::Contains(_) => "contains",
        ScalarOp::ContainsAny(_) => "contains_any",
        ScalarOp::ContainsAll(_) => "contains_all",
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

fn render_value_for_trace(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => format!("{}", b),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", s),
        Value::Array(items) => format!("<array len={}>", items.len()),
        Value::Object(map) => {
            // Two common tagged shapes get specialized rendering so
            // the trace reads naturally:
            //   - tagged enum: `{ "kind": "...", ... }` → render kind
            //   - IdentName: `{ "normalized": "...", "raw": "..." }`
            if let Some(k) = map.get("kind").and_then(Value::as_str) {
                return format!("\"{}\"", k);
            }
            if let Some(n) = map.get("normalized").and_then(Value::as_str) {
                return format!("\"{}\"", n);
            }
            format!("<object keys={}>", map.len())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Relational evaluation.
// ─────────────────────────────────────────────────────────────────────

fn evaluate_relational(
    r: &RelationalMatch,
    root: &Value,
    witnesses: &mut Vec<WitnessCandidate>,
    path_prefix: &str,
    mut trace: Option<&mut ExplainTrace>,
) -> bool {
    let resolved = resolve_path(root, &r.path);
    let path_text = compose_path(path_prefix, &r.path);
    let arr = match resolved {
        Some(Value::Array(arr)) => arr,
        Some(_) => {
            // Path resolves but isn't an array. `count: { eq: 0 }` on a
            // non-array still falls through to the array-shape check
            // below — treat as zero-length collection for count only.
            if let Quantifier::Count(op) = &r.quantifier {
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
            if let Quantifier::Count(op) = &r.quantifier {
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
    match &r.quantifier {
        Quantifier::Exists(inner) => {
            let inner_eval = match build_evaluator(inner) {
                Ok(e) => e,
                Err(_) => return false,
            };
            for (i, item) in arr.iter().enumerate() {
                let mut local = Vec::new();
                let item_path = format!("{}.{}", path_text, i);
                if evaluate_node(
                    &inner_eval,
                    item,
                    &mut local,
                    &item_path,
                    trace.as_deref_mut(),
                ) {
                    witnesses.push(WitnessCandidate {
                        path: item_path,
                        value: item.clone(),
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
        Quantifier::All(inner) => {
            let inner_eval = match build_evaluator(inner) {
                Ok(e) => e,
                Err(_) => return false,
            };
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
                let item_path = format!("{}.{}", path_text, i);
                if !evaluate_node(
                    &inner_eval,
                    item,
                    &mut local,
                    &item_path,
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
        Quantifier::None(inner) => {
            let inner_eval = match build_evaluator(inner) {
                Ok(e) => e,
                Err(_) => return false,
            };
            for (i, item) in arr.iter().enumerate() {
                let mut discard = Vec::new();
                let item_path = format!("{}.{}", path_text, i);
                if evaluate_node(
                    &inner_eval,
                    item,
                    &mut discard,
                    &item_path,
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
        Quantifier::Each(inner) => {
            // Per-witness emission driver. Predicate satisfaction
            // mirrors `Exists` (one matching witness is enough for
            // the rule to fire), but each matching element is
            // tagged `from_each: true` so the engine's
            // `emit_for_match` PerWitness path fans out signals
            // only over these — not the intermediate `exists:`
            // witnesses gathered along the predicate path.
            let inner_eval = match build_evaluator(inner) {
                Ok(e) => e,
                Err(_) => return false,
            };
            let mut witness_count = 0usize;
            for (i, item) in arr.iter().enumerate() {
                let mut local = Vec::new();
                let item_path = format!("{}.{}", path_text, i);
                if evaluate_node(
                    &inner_eval,
                    item,
                    &mut local,
                    &item_path,
                    trace.as_deref_mut(),
                ) {
                    witnesses.push(WitnessCandidate {
                        path: item_path,
                        value: item.clone(),
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
        Quantifier::Count(op) => {
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
        Value::Object(map) => map
            .get("normalized")
            .and_then(Value::as_str)
            .or_else(|| map.get("kind").and_then(Value::as_str)),
        _ => None,
    }
}

fn literal_as_str(lit: &PredicateLiteral) -> Option<&str> {
    match lit {
        PredicateLiteral::String(s) => Some(s.as_str()),
        _ => None,
    }
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

fn glob_match(pattern: &str, input: &str) -> bool {
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

    fn compile_yaml(yaml: &str) -> CompiledPredicate {
        let val: serde_json::Value = serde_yaml_ng::from_str(yaml).expect("yaml parses");
        let parsed = super::super::predicate::parse_predicate(&val).expect("predicate parses");
        compile(&parsed).expect("predicate compiles")
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
        assert!(pred.evaluate(&facts).is_match());

        let pred_neg = compile_yaml("kind: insert");
        assert!(!pred_neg.evaluate(&facts).is_match());
    }

    #[test]
    fn statement_kind_in_list() {
        let facts = empty_facts(StatementKind::Select);
        let pred = compile_yaml("kind: { in: [select, set_select, insert] }");
        assert!(pred.evaluate(&facts).is_match());

        let pred_neg = compile_yaml("kind: { in: [insert, update, delete] }");
        assert!(!pred_neg.evaluate(&facts).is_match());
    }

    #[test]
    fn option_field_none_evaluates_false() {
        let facts = empty_facts(StatementKind::Grant);
        // facts.query is None → query.has_where leaf evaluates to false.
        let pred = compile_yaml("query.has_where: false");
        assert!(!pred.evaluate(&facts).is_match());
    }

    #[test]
    fn option_field_exists_handles_none() {
        let facts = empty_facts(StatementKind::Grant);
        let pred = compile_yaml("query: { exists: false }");
        assert!(pred.evaluate(&facts).is_match());

        let pred_neg = compile_yaml("query: { exists: true }");
        assert!(!pred_neg.evaluate(&facts).is_match());
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
        assert!(pred.evaluate(&facts).is_match());
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
        assert!(pred.evaluate(&facts).is_match());
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
        assert!(pred.evaluate(&facts).is_match());
    }

    #[test]
    fn count_op_zero_on_missing() {
        let facts = empty_facts(StatementKind::Grant);
        // facts.query is None, so query.scopes resolves to nothing.
        // count: { eq: 0 } should still match.
        let pred = compile_yaml("query.scopes: { count: { eq: 0 } }");
        assert!(pred.evaluate(&facts).is_match());
    }

    // ─────────────────────────────────────────────────────────────────
    // Explain-mode introspection.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn explain_scalar_mismatch_records_actual_value() {
        let facts = empty_facts(StatementKind::Select);
        let pred = compile_yaml("kind: grant");
        let (result, exp) = pred.evaluate_with_explain(&facts);
        assert!(!result.is_match());
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
        let (result, exp) = pred.evaluate_with_explain(&facts);
        assert!(result.is_match());
        assert_eq!(exp.matched_paths.len(), 1);
        assert!(exp.unmatched_paths.is_empty());
        assert!(exp.matched_paths[0].contains("kind"));
    }

    #[test]
    fn explain_path_not_resolved_when_query_missing() {
        let facts = empty_facts(StatementKind::Grant);
        // facts.query is None; query.has_where path does not resolve.
        let pred = compile_yaml("query.has_where: false");
        let (result, exp) = pred.evaluate_with_explain(&facts);
        assert!(!result.is_match());
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
        let (result, exp) = pred.evaluate_with_explain(&facts);
        assert!(!result.is_match());
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
        let (result, exp) = pred.evaluate_with_explain(&facts);
        assert!(result.is_match());
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
        let (result, exp) = pred.evaluate_with_explain(&facts);
        assert!(!result.is_match());
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
        let (result, exp) = pred.evaluate_with_explain(&facts);
        assert!(!result.is_match());
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
        assert_eq!(
            gate("kind: { in: [select, not_a_real_kind] }"),
            KindGate::Any
        );
    }

    #[test]
    fn kind_gate_unknown_literal_is_any() {
        assert_eq!(gate("kind: not_a_real_kind"), KindGate::Any);
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
}
