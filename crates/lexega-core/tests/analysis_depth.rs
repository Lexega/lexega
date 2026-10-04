// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A recognition-only report says how many rules ran at reduced depth.

use lexega_core::analyzer::AnalysisDepth;
use lexega_core::rules::all_builtin_rules;
use lexega_core::Engine;

fn builtin_depth() -> AnalysisDepth {
    let corpus = all_builtin_rules().expect("builtin corpus loads");
    AnalysisDepth {
        rules_total: corpus.len(),
        rules_limited: corpus
            .iter()
            .filter(|rule| rule.triggers.reads_reasoning())
            .count(),
    }
}

#[test]
fn recognition_report_counts_the_rules_it_cannot_fully_evaluate() {
    let report = Engine::recognition()
        .analyze_risk("SELECT 1;")
        .expect("analysis succeeds");
    let expected = builtin_depth();
    assert!(expected.rules_limited > 0 && expected.rules_limited < expected.rules_total);
    assert_eq!(report.summary.analysis_depth, Some(expected));
}

#[test]
fn depth_is_serialized_in_the_summary() {
    let report = Engine::recognition()
        .analyze_risk("SELECT 1;")
        .expect("analysis succeeds");
    let json = serde_json::to_value(&report).expect("report serializes");
    let expected = builtin_depth();
    assert_eq!(
        json["summary"]["analysis_depth"],
        serde_json::json!({
            "rules_total": expected.rules_total,
            "rules_limited": expected.rules_limited,
        })
    );
}

#[test]
fn notice_states_both_counts() {
    let depth = AnalysisDepth {
        rules_total: 930,
        rules_limited: 52,
    };
    assert_eq!(
        depth.to_string(),
        "52 of 930 rules use analysis this build does not include and may stay silent or report less precisely."
    );
}
