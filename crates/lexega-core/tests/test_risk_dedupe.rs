// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;

// Q-JOIN-CROSS-CENH is catalog-gated (10M row threshold): without a catalog
// the cartesian-estimate gate is unmet and `analyze_risk` does not surface
// the rule. Catalog-attached firing is covered by
// `tests/test_cross_join_cost_with_catalog.rs`.

#[test]
fn risk_flags_update_without_where_as_unbounded_write() {
    let sql = "UPDATE prod.analytics.users SET status = 'inactive'";
    let report = analyze_risk(sql).expect("risk analysis should succeed");

    // DML-WRITE-UNBOUNDED is now a AnalysisSignal with unbounded_write enrichment
    assert!(
        report.signals.iter().any(|f| {
            matches!(
                f,
                lexega_core::analyzer::RuleMatch::Analysis(g)
                    if g.matched_rule == "DML-WRITE-UNBOUNDED" || g.unbounded_write == Some(true)
            )
        }),
        "Expected unbounded write signal (DML-WRITE-UNBOUNDED or unbounded_write=true)"
    );
}
