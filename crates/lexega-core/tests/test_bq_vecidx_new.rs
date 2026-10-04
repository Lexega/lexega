// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule BQ-VECIDX-NEW
//!
//! Rule: Vector Index Created
//! Risk Level: Low
//! Syntax: CREATE [OR REPLACE] VECTOR INDEX [IF NOT EXISTS] name ON table(column) [STORING(...)] [OPTIONS(...)]

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
fn test_basic_create_vector_index() {
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "Should detect BQ-VECIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_or_replace_variant() {
    let sql =
        "CREATE OR REPLACE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "OR REPLACE variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_not_exists_variant() {
    let sql = "CREATE VECTOR INDEX IF NOT EXISTS my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "IF NOT EXISTS variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_or_replace_and_if_not_exists() {
    let sql = "CREATE OR REPLACE VECTOR INDEX IF NOT EXISTS my_idx ON my_table(emb) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "OR REPLACE + IF NOT EXISTS combo should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_qualified_table_name() {
    let sql = "CREATE VECTOR INDEX my_idx ON ds.my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "Qualified table name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_fully_qualified_table_name() {
    let sql =
        "CREATE VECTOR INDEX my_idx ON proj.ds.my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "Fully-qualified 3-part table name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_with_storing_clause() {
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) STORING(id, name) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "STORING clause variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_full_combo() {
    let sql = "CREATE OR REPLACE VECTOR INDEX IF NOT EXISTS idx ON ds.tbl(emb) STORING(id) OPTIONS(index_type='TREE_AH');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "Full combo should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_low() {
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Low,
                "BQ-VECIDX-NEW should be Low risk"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("Vector index created"),
                "Message should mention creation. Got: {}",
                a.message
            );
            assert!(
                a.message.contains("embedding"),
                "Message should mention ML embedding. Got: {}",
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
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        report.summary.low_count >= 1,
        "low_count should be at least 1. Got: {}",
        report.summary.low_count
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
        CREATE VECTOR INDEX idx1 ON table1(emb1) OPTIONS(index_type='IVF');
        CREATE VECTOR INDEX idx2 ON table2(emb2) OPTIONS(index_type='IVF');
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two CREATE VECTOR INDEX stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_distinct_tables_prevent_dedup() {
    let sql = r#"
        CREATE VECTOR INDEX idx_a ON alpha(emb) OPTIONS(index_type='IVF');
        CREATE VECTOR INDEX idx_b ON beta(emb) OPTIONS(index_type='IVF');
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Distinct table names should prevent false dedup. Got evidence count: {}",
        total_evidence
    );
}

// ──────────────────────────────────────────────────────────
// Signal evidence
// ──────────────────────────────────────────────────────────

#[test]
fn test_signal_evidence_present() {
    let sql = "CREATE VECTOR INDEX my_idx ON embeddings(vec_col) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-VECIDX-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    let evidence = signal.unwrap().evidence();
    assert!(!evidence.is_empty(), "Signal should have evidence entries");
}

// ──────────────────────────────────────────────────────────
// Negative cases (false positive prevention)
// ──────────────────────────────────────────────────────────

#[test]
fn test_not_triggered_by_drop_vector_index() {
    let sql = "DROP VECTOR INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "DROP VECTOR INDEX should NOT trigger BQ-VECIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_search_index() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "CREATE SEARCH INDEX should NOT trigger BQ-VECIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_index() {
    let sql = "CREATE INDEX my_idx ON my_table(col1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "Plain CREATE INDEX should NOT trigger BQ-VECIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_drop_triggers_drop_rule_not_new() {
    let sql = "DROP VECTOR INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-VECIDX-DROP".to_string()),
        "DROP VECTOR INDEX should trigger BQ-VECIDX-DROP. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"BQ-VECIDX-NEW".to_string()),
        "DROP should not trigger NEW"
    );
}
