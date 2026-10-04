// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(
        |s| matches!(s, lexega_core::analyzer::RuleMatch::Analysis(g) if g.matched_rule == rule_id),
    )
}

fn print_signals(report: &lexega_core::analyzer::AnalysisReport) {
    println!("Total signals: {}", report.summary.total_reported_signals);
    for signal in &report.signals {
        let lexega_core::analyzer::RuleMatch::Analysis(g) = signal;
        println!("  [{}] {:?} - {}", g.matched_rule, g.risk_level, g.message);
    }
}

// ============================================================================
// CREATE WAREHOUSE signals
// ============================================================================

#[test]
fn test_create_warehouse_emits_created_signal() {
    let sql = "CREATE WAREHOUSE analytics_wh;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-NEW"),
        "Should find SNW-WH-NEW (Warehouse Created)"
    );
}

#[test]
fn test_create_warehouse_with_size_no_large_flag() {
    // MEDIUM size — should NOT trigger the large-size rule
    let sql = "CREATE WAREHOUSE my_wh WAREHOUSE_SIZE = 'MEDIUM';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-NEW"),
        "Should find SNW-WH-NEW (Warehouse Created)"
    );
    assert!(
        !has_rule(&report, "SNW-WH-LARGE"),
        "MEDIUM size should NOT trigger SNW-WH-LARGE"
    );
}

#[test]
fn test_create_warehouse_with_resource_monitor() {
    let sql = "CREATE WAREHOUSE my_wh RESOURCE_MONITOR = my_monitor;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-NEW"),
        "Should find SNW-WH-NEW (Warehouse Created)"
    );
    assert!(
        has_rule(&report, "INFO-SNW-WH-RESMON"),
        "Should find INFO-SNW-WH-RESMON (Resource Monitor Assigned)"
    );
}

// ============================================================================
// DROP WAREHOUSE signals
// ============================================================================

#[test]
fn test_drop_warehouse_emits_critical_signal() {
    let sql = "DROP WAREHOUSE old_wh;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-DROP"),
        "Should find SNW-WH-DROP (Warehouse Dropped)"
    );
    assert!(
        report.summary.critical_count >= 1,
        "DROP WAREHOUSE should be Critical"
    );
}

#[test]
fn test_drop_warehouse_if_exists() {
    let sql = "DROP WAREHOUSE IF EXISTS staging_wh;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-DROP"),
        "Should find SNW-WH-DROP even with IF EXISTS"
    );
}

// ============================================================================
// ALTER WAREHOUSE signals
// ============================================================================

#[test]
fn test_alter_warehouse_suspend() {
    let sql = "ALTER WAREHOUSE prod_wh SUSPEND;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-SUSPEND"),
        "Should find SNW-WH-SUSPEND (Warehouse Suspended)"
    );
}

#[test]
fn test_alter_warehouse_resume() {
    let sql = "ALTER WAREHOUSE prod_wh RESUME;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-RESUME"),
        "Should find SNW-WH-RESUME (Warehouse Resumed)"
    );
}

#[test]
fn test_alter_warehouse_abort_all_queries() {
    let sql = "ALTER WAREHOUSE prod_wh ABORT ALL QUERIES;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-ABORT"),
        "Should find SNW-WH-ABORT (All Queries Aborted)"
    );
    assert!(
        report.summary.high_count >= 1,
        "ABORT ALL QUERIES should be High risk"
    );
}

#[test]
fn test_alter_warehouse_rename() {
    let sql = "ALTER WAREHOUSE old_wh RENAME TO new_wh;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-RENAME"),
        "Should find SNW-WH-RENAME (Warehouse Renamed)"
    );
}

#[test]
fn test_alter_warehouse_set_size() {
    let sql = "ALTER WAREHOUSE prod_wh SET WAREHOUSE_SIZE = '2X-LARGE';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-SIZE-CHG"),
        "Should find SNW-WH-SIZE-CHG (Warehouse Size Changed)"
    );
    assert!(
        has_rule(&report, "SNW-WH-SET"),
        "Should also find SNW-WH-SET (Warehouse Properties Modified)"
    );
}

#[test]
fn test_alter_warehouse_set_generic() {
    let sql = "ALTER WAREHOUSE prod_wh SET AUTO_RESUME = TRUE;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-SET"),
        "Should find SNW-WH-SET (Warehouse Properties Modified)"
    );
}

// ============================================================================
// CREATE PIPE signals
// ============================================================================

#[test]
fn test_create_pipe_emits_created_signal() {
    let sql = "CREATE PIPE my_pipe AS COPY INTO my_table FROM @my_stage;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-NEW"),
        "Should find SNW-PIPE-NEW (Pipe Created)"
    );
}

#[test]
fn test_create_pipe_with_auto_ingest() {
    let sql = "CREATE PIPE my_pipe AUTO_INGEST = TRUE AS COPY INTO my_table FROM @my_stage;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-NEW"),
        "Should find SNW-PIPE-NEW (Pipe Created)"
    );
    assert!(
        has_rule(&report, "SNW-PIPE-AUTOINGEST"),
        "Should find SNW-PIPE-AUTOINGEST (Auto-Ingest Enabled)"
    );
}

#[test]
fn test_create_pipe_with_error_integration() {
    let sql =
        "CREATE PIPE my_pipe ERROR_INTEGRATION = my_notif AS COPY INTO my_table FROM @my_stage;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-NEW"),
        "Should find SNW-PIPE-NEW (Pipe Created)"
    );
    assert!(
        has_rule(&report, "INFO-SNW-PIPE-ERRINT"),
        "Should find INFO-SNW-PIPE-ERRINT (Error Integration Configured)"
    );
}

// ============================================================================
// DROP PIPE signals
// ============================================================================

#[test]
fn test_drop_pipe_emits_high_signal() {
    let sql = "DROP PIPE my_pipe;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-DROP"),
        "Should find SNW-PIPE-DROP (Pipe Dropped)"
    );
    assert!(
        report.summary.high_count >= 1,
        "DROP PIPE should be High risk"
    );
}

// ============================================================================
// ALTER PIPE signals
// ============================================================================

#[test]
fn test_alter_pipe_set_properties() {
    let sql = "ALTER PIPE my_pipe SET PIPE_EXECUTION_PAUSED = TRUE;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-SET"),
        "Should find SNW-PIPE-SET (Pipe Properties Modified)"
    );
}

#[test]
fn test_alter_pipe_refresh() {
    let sql = "ALTER PIPE my_pipe REFRESH;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-REFRESH"),
        "Should find SNW-PIPE-REFRESH (Pipe Refreshed)"
    );
}

// ============================================================================
// Multi-statement tests (verify evidence counts, not signal dedup)
// ============================================================================

#[test]
fn test_multi_warehouse_operations() {
    let sql = r#"
        CREATE WAREHOUSE wh1;
        CREATE WAREHOUSE wh2;
        DROP WAREHOUSE wh3;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    // Evidence count should reflect all operations
    let total_evidence: usize = report
        .signals
        .iter()
        .filter_map(|s| {
            let lexega_core::analyzer::RuleMatch::Analysis(g) = s;
            Some(g.evidence_count.unwrap_or(1))
        })
        .sum();

    assert!(
        total_evidence >= 3,
        "Should have evidence for all 3 warehouse operations, got {}",
        total_evidence
    );
}

#[test]
fn test_multi_pipe_operations() {
    let sql = r#"
        CREATE PIPE p1 AS COPY INTO t1 FROM @s1;
        CREATE PIPE p2 AUTO_INGEST = TRUE AS COPY INTO t2 FROM @s2;
        DROP PIPE p3;
        ALTER PIPE p4 REFRESH;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    // Should have signals from multiple pipe operations
    assert!(
        report.summary.total_reported_signals >= 4,
        "Should have at least 4 signals from pipe operations, got {}",
        report.summary.total_reported_signals
    );
}

// ============================================================================
// Negative tests (false positive prevention)
// ============================================================================

#[test]
fn test_select_does_not_trigger_warehouse_signals() {
    let sql = "SELECT * FROM warehouse_metrics;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        !has_rule(&report, "SNW-WH-NEW"),
        "SELECT should NOT trigger warehouse signals"
    );
    assert!(
        !has_rule(&report, "SNW-WH-DROP"),
        "SELECT should NOT trigger warehouse drop signals"
    );
}

#[test]
fn test_select_does_not_trigger_pipe_signals() {
    let sql = "SELECT * FROM pipe_status WHERE pipe_name = 'test';";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        !has_rule(&report, "SNW-PIPE-NEW"),
        "SELECT should NOT trigger pipe signals"
    );
    assert!(
        !has_rule(&report, "SNW-PIPE-DROP"),
        "SELECT should NOT trigger pipe drop signals"
    );
}

// ============================================================================
// SET TAG / UNSET TAG signals (no parentheses — official Snowflake syntax)
// ============================================================================

#[test]
fn test_alter_warehouse_set_tag_no_parens() {
    let sql = "ALTER WAREHOUSE prod_wh SET TAG env = 'prod';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-TAG-SET"),
        "Should find SNW-WH-TAG-SET for SET TAG without parens"
    );
}

#[test]
fn test_alter_warehouse_set_tag_with_parens() {
    let sql = "ALTER WAREHOUSE prod_wh SET TAG (env = 'prod');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-TAG-SET"),
        "Should find SNW-WH-TAG-SET for SET TAG with parens"
    );
}

#[test]
fn test_alter_warehouse_set_tag_multiple_no_parens() {
    let sql = "ALTER WAREHOUSE prod_wh SET TAG env = 'prod', team = 'data';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-TAG-SET"),
        "Should find SNW-WH-TAG-SET for multiple tags without parens"
    );
}

#[test]
fn test_alter_warehouse_unset_tag_no_parens() {
    let sql = "ALTER WAREHOUSE prod_wh UNSET TAG env;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-TAG-UNSET"),
        "Should find SNW-WH-TAG-UNSET for UNSET TAG without parens"
    );
}

#[test]
fn test_alter_warehouse_unset_tag_multiple_no_parens() {
    let sql = "ALTER WAREHOUSE prod_wh UNSET TAG env, team;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-WH-TAG-UNSET"),
        "Should find SNW-WH-TAG-UNSET for multiple UNSET TAG without parens"
    );
}

#[test]
fn test_alter_pipe_set_tag_no_parens() {
    let sql = "ALTER PIPE my_pipe SET TAG team = 'data';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-TAG-SET"),
        "Should find SNW-PIPE-TAG-SET for SET TAG without parens"
    );
}

#[test]
fn test_alter_pipe_unset_tag_no_parens() {
    let sql = "ALTER PIPE my_pipe UNSET TAG team;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    print_signals(&report);

    assert!(
        has_rule(&report, "SNW-PIPE-TAG-UNSET"),
        "Should find SNW-PIPE-TAG-UNSET for UNSET TAG without parens"
    );
}
