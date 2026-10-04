// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! V1 rule engine — predicate language + closure compiler + evaluator.
//!
//! Module map:
//! - [`signal`]   — v1 `Signal` output type, `SignalEvidence`, `EmissionMode`.
//! - [`predicate`] — parsed `Predicate` AST + YAML/JSON parser.
//! - [`mod@compile`]  — closure compiler; produces `CompiledPredicate`.
//! - [`engine`]   — `Rule` + `evaluate_rules` runtime.
//! - [`aliases`]  — statement-kind aliases (`any_dml`, `any_policy_ddl`, …).

pub mod aliases;
pub mod builtin_rules;
pub(crate) mod category;
pub mod compile;
pub(crate) mod depth;
pub mod engine;
pub(crate) mod explain;
pub mod loader;
pub mod predicate;
pub mod schema;
pub mod signal;

pub use builtin_rules::{all_builtin_rules, canonical_rule_id, former_ids_for};
pub use compile::{compile, CompileError, CompiledPredicate};
pub use engine::{evaluate_rules, evaluate_rules_with_explain, MessageTemplate, Rule};
pub use loader::{load_v1_rules, LoadError, LoadedEntry, LoadedRuleset, PartialRuleOverride};
pub use predicate::{parse_predicate, FieldName, FieldPath, ParseError, Predicate};
pub use signal::{EmissionMode, FactWitness, RuleExplanation, Signal, SignalEvidence};

/// Typed error for [`build_v1_rule_corpus`] failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// A partial override entry referenced a rule id that does not
    /// exist in the built-in corpus. Either the customer mistyped the
    /// id or the entry was meant to be a full rule and is missing
    /// required fields. Diagnostic carries the offending id.
    UnresolvedPartialOverride { rule_id: String },
    /// A partial override entry was supplied alongside `include_builtins
    /// = false` (e.g. the customer ran `--no-builtin --custom-rules
    /// partial.yaml`). With no built-in corpus to inherit from, there
    /// is nothing the partial entry can resolve against.
    PartialOverrideWithoutBuiltins { rule_id: String },
    /// The embedded built-in rule corpus failed to load. Strictly a
    /// build-time programming error (the YAML is `include_str!`d), but
    /// propagated through the merge layer rather than panicked so
    /// callers receive a typed surface and can produce a structured
    /// diagnostic.
    BuiltinCorpusFailed(LoadError),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnresolvedPartialOverride { rule_id } => write!(
                f,
                "partial override '{}' does not match any built-in rule id — \
                 either correct the id, or restate the full rule (with `triggers`)",
                rule_id
            ),
            Self::PartialOverrideWithoutBuiltins { rule_id } => write!(
                f,
                "partial override '{}' was supplied with built-in rules disabled; \
                 partial overlays require the built-in corpus to inherit from",
                rule_id
            ),
            Self::BuiltinCorpusFailed(err) => write!(
                f,
                "built-in rule corpus failed to load (build artifact bug): {}",
                err
            ),
        }
    }
}

impl std::error::Error for MergeError {}

impl From<LoadError> for MergeError {
    fn from(err: LoadError) -> Self {
        Self::BuiltinCorpusFailed(err)
    }
}

/// Build a customer-facing rule corpus by layering `loaded` over the
/// optional built-in corpus.
///
/// Semantics:
/// - `include_builtins == true`: start from [`all_builtin_rules`]
///   (the default behaviour).
/// - `include_builtins == false`: start from an empty corpus
///   (`--no-builtin`).
/// - Each [`LoadedEntry::Full`] in `loaded` overrides the built-in
///   entry with the same `rule_id` wholesale (last-write-wins on the
///   merge), so customers can replace any built-in's behaviour by
///   re-stating its `id` with their own predicate / message / risk
///   level.
/// - Each [`LoadedEntry::Partial`] is a per-field overlay on the
///   built-in with the same `id`. The built-in's `triggers` /
///   `emission` / `per_statement` are inherited verbatim; the
///   partial entry's `risk_level` / `message` / `enabled` fields
///   replace the built-in's only where set. A partial entry that
///   does not match any built-in id returns
///   [`MergeError::UnresolvedPartialOverride`].
///
/// The returned `Vec<Rule>` is owned and can be stored on the
/// `AnalysisConfig.custom_rules` field; [`evaluate_rules`] is invoked
/// against `&[Rule]` at every per-statement seam.
///
/// In-process callers who hold a pre-materialized `Vec<Rule>` (i.e.
/// no Partial entries) should call [`merge_full_rule_corpus`] instead
/// — its signature is infallible, removing the need for the caller to
/// handle a `MergeError` arm that cannot occur.
pub fn build_v1_rule_corpus(
    loaded: LoadedRuleset,
    include_builtins: bool,
) -> Result<Vec<Rule>, MergeError> {
    use std::collections::HashMap;
    // Order is part of the contract: evaluation order matches authoring
    // order (see `load_v1_rules`), and emission order must be identical
    // across runs. Merge in place — built-ins keep corpus order, an
    // override replaces the rule at its existing position, net-new
    // customer rules append in authoring order. The map is an
    // id → position index only; the corpus is never collected from
    // hash-iteration order.
    let mut corpus: Vec<Rule> = Vec::new();
    let mut index_by_id: HashMap<String, usize> = HashMap::new();
    if include_builtins {
        for r in all_builtin_rules()? {
            index_by_id.insert(r.id.clone(), corpus.len());
            corpus.push(r.clone());
        }
    }
    for entry in loaded.into_entries() {
        match entry {
            LoadedEntry::Full(rule) => match index_by_id.get(&rule.id) {
                Some(&i) => corpus[i] = rule,
                None => {
                    index_by_id.insert(rule.id.clone(), corpus.len());
                    corpus.push(rule);
                }
            },
            LoadedEntry::Partial(overlay) => {
                let existing = index_by_id.get(&overlay.id).copied();
                match existing {
                    Some(i) => {
                        let base = corpus[i].clone();
                        corpus[i] = apply_partial_overlay(base, overlay);
                    }
                    None => {
                        // No built-in matched. If built-ins were excluded
                        // wholesale, the customer ran `--no-builtin` with
                        // partial overrides — there's no corpus to inherit
                        // from. Otherwise, the id simply doesn't exist.
                        return Err(if include_builtins {
                            MergeError::UnresolvedPartialOverride {
                                rule_id: overlay.id,
                            }
                        } else {
                            MergeError::PartialOverrideWithoutBuiltins {
                                rule_id: overlay.id,
                            }
                        });
                    }
                }
            }
        }
    }
    Ok(corpus)
}

/// Merge a pre-materialized `Vec<Rule>` with the optional built-in
/// corpus (every entry is a full rule — no partial overrides are
/// expressible at this signature, so the only failure mode is a
/// malformed built-in corpus).
///
/// Semantics match [`build_v1_rule_corpus`] for the all-Full case:
/// built-ins (when `include_builtins`) underlie; customer rules
/// override by `id`, last-write-wins.
///
/// Use this from in-process integration paths where the caller holds
/// owned `Rule` values rather than a `LoadedRuleset` and would
/// otherwise wrap each `MergeError` arm — most of which cannot occur
/// here.
pub fn merge_full_rule_corpus(
    custom_rules: Vec<Rule>,
    include_builtins: bool,
) -> Result<Vec<Rule>, LoadError> {
    use std::collections::HashMap;
    // Same order contract as `build_v1_rule_corpus`: built-ins keep
    // corpus order, overrides replace in place, net-new rules append in
    // authoring order — never hash-iteration order.
    let mut corpus: Vec<Rule> = Vec::new();
    let mut index_by_id: HashMap<String, usize> = HashMap::new();
    if include_builtins {
        for r in all_builtin_rules()? {
            index_by_id.insert(r.id.clone(), corpus.len());
            corpus.push(r.clone());
        }
    }
    for r in custom_rules {
        match index_by_id.get(&r.id) {
            Some(&i) => corpus[i] = r,
            None => {
                index_by_id.insert(r.id.clone(), corpus.len());
                corpus.push(r);
            }
        }
    }
    Ok(corpus)
}

/// Layer a partial override's fields onto the built-in rule. The
/// built-in's `triggers` / `emission` / `per_statement` are inherited
/// verbatim — the loader guarantees a partial entry never sets those.
fn apply_partial_overlay(base: Rule, overlay: PartialRuleOverride) -> Rule {
    let Rule {
        id,
        former_ids,
        description,
        risk_level,
        enabled,
        triggers,
        message_template,
        emission,
        per_statement,
    } = base;
    let new_description = overlay.message.clone().unwrap_or(description);
    let new_message_template = match overlay.message {
        Some(m) => Some(MessageTemplate::new(m)),
        None => message_template,
    };
    Rule {
        id,
        // A partial override inherits the canonical rule's aliases verbatim.
        former_ids,
        description: new_description,
        risk_level: overlay.risk_level.unwrap_or(risk_level),
        enabled: overlay.enabled.unwrap_or(enabled),
        triggers,
        message_template: new_message_template,
        emission,
        per_statement,
    }
}
