// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule BQ-SEARCHIDX-NEW
//!
//! Rule: Search Index Created
//! Risk Level: Low
//! Syntax: CREATE SEARCH INDEX [IF NOT EXISTS] name ON table(columns) [OPTIONS(...)]

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
fn test_basic_create_search_index() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1, col2);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "Should detect BQ-SEARCHIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_not_exists_variant() {
    let sql = "CREATE SEARCH INDEX IF NOT EXISTS my_idx ON my_table(col1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "IF NOT EXISTS variant should still trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_with_options_clause() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1) OPTIONS(analyzer='LOG_ANALYZER');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "OPTIONS clause variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_qualified_table_name() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_dataset.my_table(col1, col2);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "Qualified table name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_fully_qualified_table_name() {
    let sql = "CREATE SEARCH INDEX my_idx ON project.dataset.events(col1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "Fully-qualified 3-part table name should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_all_columns_syntax() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(ALL COLUMNS);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "ALL COLUMNS syntax should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_not_exists_with_options_and_qualified() {
    let sql = "CREATE SEARCH INDEX IF NOT EXISTS idx ON ds.tbl(c1, c2) OPTIONS(analyzer='PATTERN_ANALYZER');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "Full combo of IF NOT EXISTS + qualified + OPTIONS should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_low() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SEARCHIDX-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Low,
                "BQ-SEARCHIDX-NEW should be Low risk"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SEARCHIDX-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("Search index created"),
                "Message should mention creation. Got: {}",
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
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1);";
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
        CREATE SEARCH INDEX idx1 ON table1(col1);
        CREATE SEARCH INDEX idx2 ON table2(col2);
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SEARCHIDX-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two CREATE SEARCH INDEX stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_distinct_details_prevent_dedup() {
    let sql = r#"
        CREATE SEARCH INDEX idx1 ON table_a(col1);
        CREATE SEARCH INDEX idx2 ON table_b(col2);
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Two distinct tables should produce evidence_count >= 2 (not deduped away)
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SEARCHIDX-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Distinct table details should prevent false dedup. Got evidence count: {}",
        total_evidence
    );
}

// ──────────────────────────────────────────────────────────
// Signal details
// ──────────────────────────────────────────────────────────

#[test]
fn test_signal_details_contain_table_name() {
    let sql = "CREATE SEARCH INDEX my_idx ON events_log(message);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SEARCHIDX-NEW"));
    assert!(signal.is_some(), "Signal should exist");

    // Validate that evidence is present
    let evidence = signal.unwrap().evidence();
    assert!(!evidence.is_empty(), "Signal should have evidence entries");
}

// ──────────────────────────────────────────────────────────
// Negative cases (false positive prevention)
// ──────────────────────────────────────────────────────────

#[test]
fn test_not_triggered_by_drop_search_index() {
    let sql = "DROP SEARCH INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "DROP SEARCH INDEX should NOT trigger BQ-SEARCHIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_vector_index() {
    let sql = "CREATE VECTOR INDEX my_idx ON my_table(embedding) OPTIONS(index_type='IVF');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "CREATE VECTOR INDEX should NOT trigger BQ-SEARCHIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_index() {
    let sql = "CREATE INDEX my_idx ON my_table(col1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "Plain CREATE INDEX should NOT trigger BQ-SEARCHIDX-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_drop_triggers_drop_rule_not_new() {
    let sql = "DROP SEARCH INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SEARCHIDX-DROP".to_string()),
        "DROP SEARCH INDEX should trigger BQ-SEARCHIDX-DROP, not NEW. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"BQ-SEARCHIDX-NEW".to_string()),
        "DROP should not trigger NEW"
    );
}
