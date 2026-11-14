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

    let cartesian_findings: Vec<_> = report
        .entries()
        .filter(|f| matches!(f, RuleMatch::Analysis(p) if p.matched_rule == "Q-JOIN-CROSS-CENH"))
        .collect();

    assert!(
        cartesian_findings.is_empty(),
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

    // Without catalog, we won't get findings about table size
    // But semantic info should show has_where=false
    assert_eq!(
        report.summary.total_reported_findings, 0,
        "No findings without catalog"
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
    let temporal_findings: Vec<_> = report
        .entries()
        .filter(|f| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "INFO-Q-PRED-TEMPORAL",
        })
        .collect();

    assert!(
        !temporal_findings.is_empty(),
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
    let cartesian_findings: Vec<_> = report
        .entries()
        .filter(|f: &&RuleMatch| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "Q-SCAN-NOFILT",
        })
        .collect();

    assert_eq!(cartesian_findings.len(), 0, "Should not flag proper join");

    // Should detect temporal pattern in WHERE clause
    let temporal_findings: Vec<_> = report
        .entries()
        .filter(|f| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "INFO-Q-PRED-TEMPORAL",
        })
        .collect();

    assert!(
        !temporal_findings.is_empty(),
        "Should detect temporal pattern"
    );
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
    let temporal_findings: Vec<_> = report
        .entries()
        .filter(|f| match f {
            RuleMatch::Analysis(p) => p.matched_rule == "INFO-Q-PRED-TEMPORAL",
        })
        .collect();

    assert!(
        !temporal_findings.is_empty(),
        "Should detect temporal pattern"
    );
}

#[test]
fn many_occurrences_of_one_rule_are_aggregated_in_linear_time() {
    // One rule raised on 30,000 statements, each with its own evidence: the
    // report folds them into one finding holding every evidence once.
    use lexega_core::analyzer::{AnalysisFinding, AnalysisReport};
    let measure = |n: usize| {
        let mut report = AnalysisReport::new();
        report.findings = (0..n)
            .map(|line| {
                let value = serde_json::json!({
                    "message": "an unbounded write",
                    "risk_level": "High",
                    "matched_rule": "DML-WRITE-UNBOUNDED",
                    "finding_type": "governance",
                    "evidence": [{
                        "type": "RuleMatch",
                        "finding_type": "governance",
                        "rule_id": "DELETE",
                        "line_number": line,
                        "statement_preview": "DELETE FROM orders",
                    }],
                });
                RuleMatch::Analysis(
                    serde_json::from_value::<AnalysisFinding>(value).expect("a finding"),
                )
            })
            .collect();
        let started = std::time::Instant::now();
        report.deduplicate_with_per_statement_rules(&std::collections::HashSet::new());
        let elapsed = started.elapsed();
        let [RuleMatch::Analysis(finding)] = report.findings.as_slice() else {
            panic!("one finding: {:?}", report.findings.len());
        };
        assert_eq!(finding.evidence.len(), n);
        elapsed
    };
    let small = measure(7_500);
    let large = measure(30_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_join_written_inside_another_is_analysed_as_if_parenthesised() {
    let rules = |sql: &str| {
        let report = analyze_risk(sql).expect("should analyze");
        assert_eq!(report.summary.statements_partial, 0, "{sql}");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let mut ids: Vec<String> = report
            .entries()
            .map(|RuleMatch::Analysis(p)| p.matched_rule.clone())
            .collect();
        ids.sort();
        ids
    };
    let nested = rules(
        "SELECT o.id FROM users k, accounts t \
         JOIN orders o JOIN orders p ON p.user_id = o.id ON o.id = t.id",
    );
    assert!(nested.iter().any(|id| id == "Q-SCAN-NOFILT"), "{nested:?}");
    assert_eq!(
        nested,
        rules(
            "SELECT o.id FROM users k, accounts t \
             JOIN (orders o JOIN orders p ON p.user_id = o.id) ON o.id = t.id"
        )
    );
}
