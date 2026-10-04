// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! End-to-end tests for the rule-evaluation explanation surface.
//!
//! Verifies that `AnalysisReport.statement_explanations` is:
//!   - empty when `trace_mode == false` (default)
//!   - populated when `trace_mode == true`, with one entry per
//!     statement that resolved to facts under any per-family
//!     evaluator (privilege / DDL / query / policy_attachment)
//!   - carries matched rule_ids in `matched_rules`
//!   - carries rejected rule_ids + path-level `RuleExplanation`
//!     reasons in `rejected_rules`

use lexega_core::analyzer::{AnalysisConfig, AnalysisReport};
use lexega_core::api::analyze_risk_with_policy_config;

fn analyze(sql: &str, trace: bool) -> AnalysisReport {
    let config = AnalysisConfig {
        trace_mode: trace,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analyze succeeds")
}

#[test]
fn trace_off_leaves_statement_explanations_empty() {
    let sql = "GRANT SELECT ON db.public.t TO ROLE r;";
    let report = analyze(sql, false);
    assert!(
        report.statement_explanations.is_empty(),
        "statement_explanations must stay empty without --trace, got {} entries",
        report.statement_explanations.len()
    );
}

#[test]
fn trace_on_populates_statement_explanations_for_grant() {
    let sql = "GRANT SELECT ON db.public.t TO ROLE r;";
    let report = analyze(sql, true);
    assert!(
        !report.statement_explanations.is_empty(),
        "statement_explanations must be populated under --trace"
    );
    // Every entry should have either matched_rules or rejected_rules
    // populated (or both); the entry's preview should be non-empty.
    for entry in &report.statement_explanations {
        let has_evaluations = !entry.matched_rules.is_empty() || !entry.rejected_rules.is_empty();
        assert!(
            has_evaluations,
            "explanation entry must have evaluations: {:?}",
            entry
        );
        assert!(
            !entry.statement_preview.is_empty(),
            "explanation entry must have a non-empty preview: {:?}",
            entry
        );
    }
}

#[test]
fn trace_explanations_carry_rejected_rule_paths() {
    // GRANT to PUBLIC fires GRT-TO-PUBLIC; many other privilege rules
    // are evaluated and don't match — those land in rejected_rules
    // with typed explanations.
    let sql = "GRANT SELECT ON db.public.t TO ROLE PUBLIC;";
    let report = analyze(sql, true);
    let grant_entry = report
        .statement_explanations
        .iter()
        .find(|e| !e.matched_rules.is_empty() || !e.rejected_rules.is_empty())
        .expect("at least one entry has evaluations");
    // Sanity: the rejected list must surface at least one
    // `unmatched_paths` reason from the v1 engine.
    let rejected_with_reason = grant_entry
        .rejected_rules
        .iter()
        .find(|r| !r.explanation.unmatched_paths.is_empty());
    assert!(
        rejected_with_reason.is_some(),
        "trace mode must carry path-level rejection reasons; got: {:?}",
        grant_entry
            .rejected_rules
            .iter()
            .map(|r| (&r.rule_id, &r.explanation))
            .collect::<Vec<_>>()
    );
}
