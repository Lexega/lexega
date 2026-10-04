// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;

#[test]
fn test_cartesian_join_stays_silent_without_catalog() {
    // Q-JOIN-CROSS-CENH is catalog-gated (10M cartesian threshold);
    // `analyze_risk` runs without catalog so the rule
    // stays silent. Catalog-attached firing is covered by
    // `tests/test_cross_join_cost_with_catalog.rs`.
    let sql = r#"
        SELECT *
        FROM users u
        CROSS JOIN orders o
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    let cartesian_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(p) if p.matched_rule == "Q-JOIN-CROSS-CENH"))
        .collect();

    assert!(
        cartesian_signals.is_empty(),
        "Q-JOIN-CROSS-CENH should stay silent without catalog row counts"
    );
}

#[test]
fn test_large_table_without_filter() {
    let sql = r#"
        SELECT *
        FROM large_fact_table
    "#;

    // Detecting large tables takes catalog metadata; without it this
    // verifies that the analysis runs.
    let report = analyze_risk(sql).expect("should analyze");

    // Without catalog, we won't get signals about table size
    // But semantic info should show has_where=false
    assert_eq!(
        report.summary.total_reported_signals, 0,
        "No signals without catalog"
    );
}

#[test]
fn test_temporal_query_detection() {
    let sql = r#"
        SELECT *
        FROM orders
        WHERE order_date > CURRENT_DATE - INTERVAL '30 days'
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should detect temporal pattern
    let temporal_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "INFO-Q-PRED-TEMPORAL",
        })
        .collect();

    assert!(
        temporal_signals.len() > 0,
        "Should detect temporal query pattern"
    );
}

#[test]
fn test_join_with_condition_ok() {
    let sql = r#"
        SELECT *
        FROM users u
        INNER JOIN orders o ON u.id = o.user_id
        WHERE u.created_at > CURRENT_DATE - 30
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should NOT flag proper join with ON condition
    let cartesian_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f: &&RuleMatch| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "Q-SCAN-NOFILT",
        })
        .collect();

    assert_eq!(cartesian_signals.len(), 0, "Should not flag proper join");

    // Should detect temporal pattern in WHERE clause
    let temporal_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "INFO-Q-PRED-TEMPORAL",
        })
        .collect();

    assert!(temporal_signals.len() > 0, "Should detect temporal pattern");
}

#[test]
fn test_aggregate_with_group_by() {
    let sql = r#"
        SELECT 
            region,
            COUNT(*) as total_orders,
            SUM(amount) as total_revenue,
            AVG(amount) as avg_order_value,
            LISTAGG(DISTINCT product_name, ', ') as products
        FROM orders
        WHERE order_date > CURRENT_DATE - INTERVAL '30 days'
        GROUP BY region
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Verify analysis succeeds with complex aggregates
    assert!(report.summary.statements_analyzed >= 1);

    // Should detect temporal pattern
    let temporal_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "INFO-Q-PRED-TEMPORAL",
        })
        .collect();

    assert!(temporal_signals.len() > 0, "Should detect temporal pattern");
}
