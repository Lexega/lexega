// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule BQ-VECIDX-DROP
//!
//! Rule: Vector Index Dropped
//! Risk Level: Medium
//! Syntax: DROP VECTOR INDEX [IF EXISTS] name ON table

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
fn test_basic_drop_vector_index() {
    let sql = "DROP VECTOR INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "Should detect BQ-VECIDX-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_exists_variant() {
    let sql = "DROP VECTOR INDEX IF EXISTS my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "IF EXISTS variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_qualified_table_name() {
    let sql = "DROP VECTOR INDEX my_idx ON ds.my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "Qualified table name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_fully_qualified_table_name() {
    let sql = "DROP VECTOR INDEX my_idx ON proj.ds.my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "Fully-qualified 3-part table name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_exists_with_qualified_table() {
    let sql = "DROP VECTOR INDEX IF EXISTS idx ON ds.tbl;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "IF EXISTS + qualified name should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_medium() {
    let sql = "DROP VECTOR INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-DROP"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Medium,
                "BQ-VECIDX-DROP should be Medium risk"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "DROP VECTOR INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-DROP"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("Vector index dropped"),
                "Message should mention drop. Got: {}",
                a.message
            );
            assert!(
                a.message.contains("embedding"),
                "Message should mention ML embedding impact. Got: {}",
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
    let sql = "DROP VECTOR INDEX my_idx ON my_table;";
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
        DROP VECTOR INDEX idx1 ON table1;
        DROP VECTOR INDEX idx2 ON table2;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-DROP"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two DROP VECTOR INDEX stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_multi_statement_both_analyzed() {
    let sql = r#"
        DROP VECTOR INDEX idx_a ON tbl_a;
        DROP VECTOR INDEX idx_b ON tbl_b;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        report.summary.statements_analyzed >= 2,
        "Both statements should be analyzed. Got: {}",
        report.summary.statements_analyzed
    );
}

// ──────────────────────────────────────────────────────────
// Signal evidence and details
// ──────────────────────────────────────────────────────────

#[test]
fn test_signal_evidence_present() {
    let sql = "DROP VECTOR INDEX my_idx ON embeddings_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-DROP"));
    assert!(signal.is_some(), "Signal should exist");
    let evidence = signal.unwrap().evidence();
    assert!(!evidence.is_empty(), "Signal should have evidence entries");
}

// ──────────────────────────────────────────────────────────
// Negative cases (false positive prevention)
// ──────────────────────────────────────────────────────────

#[test]
fn test_not_triggered_by_create_vector_index() {
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "CREATE VECTOR INDEX should NOT trigger BQ-VECIDX-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_drop_search_index() {
    let sql = "DROP SEARCH INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "DROP SEARCH INDEX should NOT trigger BQ-VECIDX-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_drop_table() {
    let sql = "DROP TABLE my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "DROP TABLE should NOT trigger BQ-VECIDX-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_create_triggers_new_rule_not_drop() {
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "CREATE VECTOR INDEX should trigger BQ-VECIDX-NEW. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "CREATE should not trigger DROP"
    );
}
