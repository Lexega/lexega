// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Databricks DML guardrail coverage tests.
//!
//! Verifies dialect-aware analysis still emits core guardrail/query-pattern
//! rules for Databricks SQL workloads.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{analyzer::AnalysisConfig, DatabricksDialect};
use std::sync::Arc;

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

#[test]
fn dbx_cross_join_stays_silent_without_catalog() {
    // Under the unified Q-JOIN-CROSS-CENH rule (catalog-gated, 10M-row
    // cartesian threshold), a catalog-less analysis cannot produce a
    // `cartesian_estimate` so the rule stays silent. Catalog-attested
    // firing is covered by `tests/test_cross_join_cost_with_catalog.rs`.
    let sql = "SELECT * FROM users u CROSS JOIN orders o;";
    let report = dbx_analyze(sql);

    assert!(
        !has_signal(&report, "Q-JOIN-CROSS-CENH"),
        "Q-JOIN-CROSS-CENH must stay silent without catalog (Databricks dialect). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn dbx_unbounded_update_triggers_br001() {
    let sql = "UPDATE users SET status = 'inactive';";
    let report = dbx_analyze(sql);

    let has_unbounded = report.signals.iter().any(|s| {
        matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DML-WRITE-UNBOUNDED" || g.unbounded_write == Some(true))
    });

    assert!(
        has_unbounded,
        "Expected DML-WRITE-UNBOUNDED/unbounded_write for UPDATE without WHERE under Databricks dialect. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn dbx_bounded_update_does_not_trigger_br001() {
    let sql = "UPDATE users SET status = 'inactive' WHERE user_id = 42;";
    let report = dbx_analyze(sql);

    assert!(
        !has_signal(&report, "DML-WRITE-UNBOUNDED"),
        "DML-WRITE-UNBOUNDED should not fire for bounded UPDATE under Databricks dialect. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}
