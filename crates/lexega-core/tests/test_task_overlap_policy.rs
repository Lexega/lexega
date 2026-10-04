// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(
        |s| matches!(s, lexega_core::analyzer::RuleMatch::Analysis(g) if g.matched_rule == rule_id),
    )
}

fn rule_ids(report: &lexega_core::analyzer::AnalysisReport) -> Vec<String> {
    report
        .signals
        .iter()
        .filter_map(|s| match s {
            lexega_core::analyzer::RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

// ============================================================
// Formatter / parser tests
// ============================================================

#[test]
fn test_format_overlap_policy_no_overlap() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh SCHEDULE = '5 MINUTES' OVERLAP_POLICY = NO_OVERLAP AS SELECT 1;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_format_overlap_policy_allow_child_overlap() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh OVERLAP_POLICY = ALLOW_CHILD_OVERLAP SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_format_overlap_policy_allow_all_overlap() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh OVERLAP_POLICY = ALLOW_ALL_OVERLAP SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_format_legacy_allow_overlapping_execution() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh ALLOW_OVERLAPPING_EXECUTION = TRUE SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_format_overlap_policy_with_or_replace() {
    let sql = "CREATE OR REPLACE TASK my_schema.my_task WAREHOUSE = mywh OVERLAP_POLICY = ALLOW_ALL_OVERLAP SCHEDULE = 'USING CRON 0 9-17 * * SUN America/Los_Angeles' AS SELECT CURRENT_TIMESTAMP;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ============================================================
// Risk analysis signal tests
// ============================================================

#[test]
fn test_overlap_policy_allow_all_overlap_signal() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh OVERLAP_POLICY = ALLOW_ALL_OVERLAP SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_rule(&report, "SNW-TASK-OVERLAP-ALL"),
        "Expected SNW-TASK-OVERLAP-ALL for ALLOW_ALL_OVERLAP. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_overlap_policy_allow_child_overlap_signal() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh OVERLAP_POLICY = ALLOW_CHILD_OVERLAP SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_rule(&report, "SNW-TASK-OVERLAP-CHILD"),
        "Expected SNW-TASK-OVERLAP-CHILD for ALLOW_CHILD_OVERLAP. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_overlap_policy_no_overlap_no_signal() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh OVERLAP_POLICY = NO_OVERLAP SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    // NO_OVERLAP is the default/safe value — should NOT trigger overlap warnings
    assert!(
        !has_rule(&report, "SNW-TASK-OVERLAP-ALL"),
        "Should NOT have SNW-TASK-OVERLAP-ALL for NO_OVERLAP"
    );
    assert!(
        !has_rule(&report, "SNW-TASK-OVERLAP-CHILD"),
        "Should NOT have SNW-TASK-OVERLAP-CHILD for NO_OVERLAP"
    );
}

#[test]
fn test_legacy_allow_overlapping_execution_true_signal() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh ALLOW_OVERLAPPING_EXECUTION = TRUE SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Legacy TRUE maps to ALLOW_CHILD_OVERLAP per Snowflake docs
    assert!(
        has_rule(&report, "SNW-TASK-OVERLAP-CHILD"),
        "Expected SNW-TASK-OVERLAP-CHILD for legacy ALLOW_OVERLAPPING_EXECUTION = TRUE. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_legacy_allow_overlapping_execution_false_no_signal() {
    let sql = "CREATE TASK t1 WAREHOUSE = mywh ALLOW_OVERLAPPING_EXECUTION = FALSE SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Legacy FALSE maps to NO_OVERLAP — should not trigger overlap warnings
    assert!(
        !has_rule(&report, "SNW-TASK-OVERLAP-ALL"),
        "Should NOT have SNW-TASK-OVERLAP-ALL for FALSE"
    );
    assert!(
        !has_rule(&report, "SNW-TASK-OVERLAP-CHILD"),
        "Should NOT have SNW-TASK-OVERLAP-CHILD for FALSE"
    );
}

#[test]
fn test_no_overlap_policy_no_signal() {
    // Task without any overlap policy — should not trigger overlap warnings
    let sql = "CREATE TASK t1 WAREHOUSE = mywh SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        !has_rule(&report, "SNW-TASK-OVERLAP-ALL"),
        "Should NOT have SNW-TASK-OVERLAP-ALL when no overlap policy specified"
    );
    assert!(
        !has_rule(&report, "SNW-TASK-OVERLAP-CHILD"),
        "Should NOT have SNW-TASK-OVERLAP-CHILD when no overlap policy specified"
    );
}

#[test]
fn test_multi_task_overlap_evidence() {
    let sql = r#"
        CREATE TASK t1 WAREHOUSE = mywh OVERLAP_POLICY = ALLOW_ALL_OVERLAP SCHEDULE = '5 MINUTES' AS SELECT 1;
        CREATE TASK t2 WAREHOUSE = mywh OVERLAP_POLICY = ALLOW_CHILD_OVERLAP SCHEDULE = '10 MINUTES' AS SELECT 2;
        CREATE TASK t3 WAREHOUSE = mywh SCHEDULE = '15 MINUTES' AS SELECT 3;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_rule(&report, "SNW-TASK-OVERLAP-ALL"),
        "Expected SNW-TASK-OVERLAP-ALL for t1. Got: {:?}",
        rule_ids(&report)
    );
    assert!(
        has_rule(&report, "SNW-TASK-OVERLAP-CHILD"),
        "Expected SNW-TASK-OVERLAP-CHILD for t2. Got: {:?}",
        rule_ids(&report)
    );
}
