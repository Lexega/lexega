// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule BQ-SNAP-TBL-DROP
//!
//! Rule: Snapshot Table Dropped
//! Risk Level: Medium
//! Syntax: DROP SNAPSHOT TABLE [IF EXISTS] name
//! AST: AstBqSimpleUtility (span-only, no parsed fields)

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;

/// Helper: collect all rule IDs from an analysis report.
fn extract_rule_ids(signals: &[RuleMatch]) -> Vec<String> {
    signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(a) => Some(a.matched_rule.clone()),
        })
        .collect()
}

// ──────────────────────────────────────────────────────────
// Positive detection
// ──────────────────────────────────────────────────────────

#[test]
fn test_basic_drop_snapshot_table() {
    let sql = "DROP SNAPSHOT TABLE my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "Should detect BQ-SNAP-TBL-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_exists_variant() {
    let sql = "DROP SNAPSHOT TABLE IF EXISTS my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "IF EXISTS variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_qualified_name() {
    let sql = "DROP SNAPSHOT TABLE ds.my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "Qualified name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_fully_qualified_name() {
    let sql = "DROP SNAPSHOT TABLE proj.ds.my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "Fully-qualified 3-part name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_exists_with_qualified_name() {
    let sql = "DROP SNAPSHOT TABLE IF EXISTS ds.my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "IF EXISTS + qualified name should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_medium() {
    let sql = "DROP SNAPSHOT TABLE my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-DROP"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Medium,
                "BQ-SNAP-TBL-DROP should be Medium risk"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "DROP SNAPSHOT TABLE my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-DROP"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("Snapshot table dropped"),
                "Message should mention drop. Got: {}",
                a.message
            );
            assert!(
                a.message.contains("recovery"),
                "Message should mention recovery impact. Got: {}",
                a.message
            );
        }
    }
}

// ──────────────────────────────────────────────────────────
// Summary counts
// ──────────────────────────────────────────────────────────

#[test]
fn test_summary_counts() {
    let sql = "DROP SNAPSHOT TABLE my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        report.summary.medium_count >= 1,
        "medium_count should be at least 1. Got: {}",
        report.summary.medium_count
    );
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "Should analyze 1 statement"
    );
    assert!(
        report.summary.ddl_operations >= 1,
        "Should count at least 1 DDL operation"
    );
}

// ──────────────────────────────────────────────────────────
// Multi-statement and deduplication
// ──────────────────────────────────────────────────────────

#[test]
fn test_multi_statement_evidence_count() {
    let sql = r#"
        DROP SNAPSHOT TABLE snap1;
        DROP SNAPSHOT TABLE snap2;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-DROP"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two DROP SNAPSHOT TABLE stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_multi_statement_both_analyzed() {
    let sql = r#"
        DROP SNAPSHOT TABLE snap_a;
        DROP SNAPSHOT TABLE snap_b;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        report.summary.statements_analyzed >= 2,
        "Both statements should be analyzed. Got: {}",
        report.summary.statements_analyzed
    );
}

// ──────────────────────────────────────────────────────────
// Signal evidence
// ──────────────────────────────────────────────────────────

#[test]
fn test_signal_evidence_present() {
    let sql = "DROP SNAPSHOT TABLE my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-DROP"));
    assert!(signal.is_some(), "Signal should exist");
    let evidence = signal.unwrap().evidence();
    assert!(!evidence.is_empty(), "Signal should have evidence entries");
}

// ──────────────────────────────────────────────────────────
// Negative cases (false positive prevention)
// ──────────────────────────────────────────────────────────

#[test]
fn test_not_triggered_by_create_snapshot_table() {
    let sql = "CREATE SNAPSHOT TABLE snap CLONE src;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "CREATE SNAPSHOT TABLE should NOT trigger BQ-SNAP-TBL-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_drop_table() {
    let sql = "DROP TABLE my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "Plain DROP TABLE should NOT trigger BQ-SNAP-TBL-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_drop_search_index() {
    let sql = "DROP SEARCH INDEX idx ON tbl;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "DROP SEARCH INDEX should NOT trigger BQ-SNAP-TBL-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_create_triggers_new_rule_not_drop() {
    let sql = "CREATE SNAPSHOT TABLE snap CLONE src;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "CREATE SNAPSHOT TABLE should trigger BQ-SNAP-TBL-NEW. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "CREATE should not trigger DROP"
    );
}
