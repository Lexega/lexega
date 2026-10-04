// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Engine introspection — typed trace entries collected during
//! explain-mode predicate evaluation, projected onto the public
//! [`RuleExplanation`] surface at the rules-engine boundary.
//!
//! Why typed entries (`pub(crate)`) instead of writing strings directly
//! into [`RuleExplanation`]: per the schema-as-contract discipline,
//! `RuleExplanation` carries `#[derive(JsonSchema)]` and is part of the
//! customer-visible `Signal.explanation` JSON shape. Promoting typed
//! rejection variants directly onto that surface would commit them to
//! the public JSON schema forever. Instead the engine collects rich
//! typed entries here, then renders to `Vec<String>` at the projection
//! seam (`into_rule_explanation`). When/if a richer explanation
//! contract is exposed to customers, this is where the new public
//! types are introduced; nothing else changes.

use super::signal::RuleExplanation;

/// One step the predicate evaluator took, with the path it was at and
/// the outcome (matched / didn't match, plus the reason).
#[derive(Debug, Clone)]
pub(crate) struct TraceEntry {
    pub(crate) path: String,
    pub(crate) outcome: Outcome,
}

#[derive(Debug, Clone)]
pub(crate) enum Outcome {
    Matched(MatchReason),
    Unmatched(UnmatchReason),
}

/// Why a sub-evaluation matched. Records the structure that succeeded
/// so the customer-facing matched_paths entry can name the rule's
/// successful predicate path concretely.
#[derive(Debug, Clone)]
pub(crate) enum MatchReason {
    /// Scalar op succeeded against the value at `path`.
    ScalarOk { op: &'static str, actual: String },
    /// `exists` quantifier — element at child index matched the body.
    ExistsWitness {
        witness_index: usize,
        total_candidates: usize,
    },
    /// `all` quantifier — every element passed the body.
    AllPass { total_candidates: usize },
    /// `none` quantifier — no element matched the body.
    NonePass { total_candidates: usize },
    /// `each` quantifier — one or more witnesses tagged for emission.
    EachPass {
        witness_count: usize,
        total_candidates: usize,
    },
    /// `count` op passed.
    CountOk { actual: u64 },
    /// `not` wrapper — inner didn't match, so wrapper matched.
    NotPass,
    /// `all_of` — every arm matched.
    AllOfPass { arm_count: usize },
    /// `any_of` — at least one arm matched.
    AnyOfPass {
        matched_arm: usize,
        arm_count: usize,
    },
}

/// Why a sub-evaluation did not match. The variants mirror the
/// evaluator's branch structure so every NoMatch path has a typed
/// reason rather than a generic "predicate failed".
#[derive(Debug, Clone)]
pub(crate) enum UnmatchReason {
    /// The dotted path did not resolve to any value in the facts JSON.
    PathNotResolved,
    /// Scalar op failed (e.g. `kind: grant` but actual was `select`).
    ScalarMismatch {
        op: &'static str,
        expected: String,
        actual: String,
    },
    /// Quantifier was applied to a path that exists but isn't an array.
    NotAnArray,
    /// `exists` walked the candidate set, none matched the body.
    ExistsNoWitness { total_candidates: usize },
    /// `all` quantifier failed because element at `violator_index`
    /// did not match the body.
    AllViolator {
        violator_index: usize,
        total_candidates: usize,
    },
    /// `all` quantifier failed because the array was empty. Reported
    /// distinctly from `AllViolator` so explain mode can name the
    /// "no evidence to support the universal claim" case directly.
    AllEmpty,
    /// `none` quantifier failed because element at `witness_index`
    /// matched the body.
    NoneWitnessPresent {
        witness_index: usize,
        total_candidates: usize,
    },
    /// `each` quantifier produced zero per-witness emissions.
    EachNoWitness { total_candidates: usize },
    /// `count` op failed.
    CountMismatch { actual: u64 },
    /// `not` wrapper failed because the inner predicate matched.
    NotInverted,
    /// `all_of` — arm at `arm_index` failed.
    AllOfArmFailed { arm_index: usize, arm_count: usize },
    /// `any_of` — no arm matched.
    AnyOfNoArmMatched { arm_count: usize },
}

/// Buffer of trace entries collected during one predicate evaluation.
#[derive(Debug, Clone, Default)]
pub(crate) struct ExplainTrace {
    pub(crate) entries: Vec<TraceEntry>,
}

impl ExplainTrace {
    pub(crate) fn record_matched(&mut self, path: &str, reason: MatchReason) {
        self.entries.push(TraceEntry {
            path: path.to_string(),
            outcome: Outcome::Matched(reason),
        });
    }

    pub(crate) fn record_unmatched(&mut self, path: &str, reason: UnmatchReason) {
        self.entries.push(TraceEntry {
            path: path.to_string(),
            outcome: Outcome::Unmatched(reason),
        });
    }

    /// Project typed trace entries onto the customer-facing
    /// [`RuleExplanation`] string vectors. This is the single boundary
    /// where engine-internal typed bookkeeping crosses into the
    /// schema-stable public surface.
    pub(crate) fn into_rule_explanation(self) -> RuleExplanation {
        let mut matched_paths = Vec::new();
        let mut unmatched_paths = Vec::new();
        for entry in self.entries {
            let line = render_entry(&entry);
            match entry.outcome {
                Outcome::Matched(_) => matched_paths.push(line),
                Outcome::Unmatched(_) => unmatched_paths.push(line),
            }
        }
        RuleExplanation {
            matched_paths,
            unmatched_paths,
        }
    }
}

fn render_entry(entry: &TraceEntry) -> String {
    let path = if entry.path.is_empty() {
        "<root>"
    } else {
        entry.path.as_str()
    };
    match &entry.outcome {
        Outcome::Matched(reason) => match reason {
            MatchReason::ScalarOk { op, actual } => {
                format!("{} {} (actual: {})", path, op, actual)
            }
            MatchReason::ExistsWitness {
                witness_index,
                total_candidates,
            } => format!(
                "{} exists: witness at [{}] of {}",
                path, witness_index, total_candidates
            ),
            MatchReason::AllPass { total_candidates } => {
                format!("{} all: {} elements passed", path, total_candidates)
            }
            MatchReason::NonePass { total_candidates } => {
                format!(
                    "{} none: {} elements, none matched body",
                    path, total_candidates
                )
            }
            MatchReason::EachPass {
                witness_count,
                total_candidates,
            } => format!(
                "{} each: {} witness(es) of {}",
                path, witness_count, total_candidates
            ),
            MatchReason::CountOk { actual } => {
                format!("{} count ok (actual: {})", path, actual)
            }
            MatchReason::NotPass => format!("{} not: inner did not match", path),
            MatchReason::AllOfPass { arm_count } => {
                format!("{} all_of: {} arm(s) passed", path, arm_count)
            }
            MatchReason::AnyOfPass {
                matched_arm,
                arm_count,
            } => format!(
                "{} any_of: arm [{}] of {} matched",
                path, matched_arm, arm_count
            ),
        },
        Outcome::Unmatched(reason) => match reason {
            UnmatchReason::PathNotResolved => format!("{} path did not resolve", path),
            UnmatchReason::ScalarMismatch {
                op,
                expected,
                actual,
            } => format!("{} {} {} (actual: {})", path, op, expected, actual),
            UnmatchReason::NotAnArray => {
                format!("{} not an array (quantifier requires array)", path)
            }
            UnmatchReason::ExistsNoWitness { total_candidates } => format!(
                "{} exists: no witness among {} candidate(s)",
                path, total_candidates
            ),
            UnmatchReason::AllViolator {
                violator_index,
                total_candidates,
            } => format!(
                "{} all: element [{}] of {} did not match body",
                path, violator_index, total_candidates
            ),
            UnmatchReason::AllEmpty => {
                format!("{} all: array is empty (no evidence)", path)
            }
            UnmatchReason::NoneWitnessPresent {
                witness_index,
                total_candidates,
            } => format!(
                "{} none: element [{}] of {} matched body (violation)",
                path, witness_index, total_candidates
            ),
            UnmatchReason::EachNoWitness { total_candidates } => format!(
                "{} each: 0 witnesses among {} candidate(s)",
                path, total_candidates
            ),
            UnmatchReason::CountMismatch { actual } => {
                format!("{} count mismatch (actual: {})", path, actual)
            }
            UnmatchReason::NotInverted => format!("{} not: inner matched (inversion failed)", path),
            UnmatchReason::AllOfArmFailed {
                arm_index,
                arm_count,
            } => format!(
                "{} all_of: arm [{}] of {} failed",
                path, arm_index, arm_count
            ),
            UnmatchReason::AnyOfNoArmMatched { arm_count } => {
                format!("{} any_of: 0 of {} arm(s) matched", path, arm_count)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_renders_matched_and_unmatched() {
        let mut trace = ExplainTrace::default();
        trace.record_matched(
            "kind",
            MatchReason::ScalarOk {
                op: "eq",
                actual: "grant".into(),
            },
        );
        trace.record_unmatched(
            "query.has_where",
            UnmatchReason::ScalarMismatch {
                op: "eq",
                expected: "false".into(),
                actual: "true".into(),
            },
        );
        let exp = trace.into_rule_explanation();
        assert_eq!(exp.matched_paths.len(), 1);
        assert_eq!(exp.unmatched_paths.len(), 1);
        assert!(exp.matched_paths[0].contains("kind"));
        assert!(exp.unmatched_paths[0].contains("query.has_where"));
        assert!(exp.unmatched_paths[0].contains("actual: true"));
    }

    #[test]
    fn empty_path_renders_as_root() {
        let mut trace = ExplainTrace::default();
        trace.record_unmatched(
            "",
            UnmatchReason::AllOfArmFailed {
                arm_index: 2,
                arm_count: 4,
            },
        );
        let exp = trace.into_rule_explanation();
        assert!(exp.unmatched_paths[0].starts_with("<root>"));
        assert!(exp.unmatched_paths[0].contains("arm [2] of 4"));
    }
}
