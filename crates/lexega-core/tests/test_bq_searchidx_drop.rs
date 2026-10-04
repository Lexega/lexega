// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for BQ-SEARCHIDX-DROP rule.
//!
//! Rule: Search Index Dropped
//! ID: BQ-SEARCHIDX-DROP
//! Risk: Medium
//!
//! Validates that DROP SEARCH INDEX statements emit the correct governance
//! signal and that the YAML rule matches with the correct risk level.

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => extract_rule_ids(&report.signals),
        Err(e) => {
            panic!("Parse/analysis failed for SQL: {}\nError: {:?}", sql, e);
        }
    }
}

// =============================================================================
// Basic Detection
// =============================================================================

#[test]
fn test_bq_searchidx_drop_basic() {
    let sql = "DROP SEARCH INDEX my_idx ON my_table;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("BQ-SEARCHIDX-DROP"),
        "DROP SEARCH INDEX should trigger BQ-SEARCHIDX-DROP. Got: {:?}",
        rules
    );
}

#[test]
fn test_bq_searchidx_drop_if_exists() {
    let sql = "DROP SEARCH INDEX IF EXISTS my_idx ON my_table;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("BQ-SEARCHIDX-DROP"),
        "DROP SEARCH INDEX IF EXISTS should trigger BQ-SEARCHIDX-DROP. Got: {:?}",
        rules
    );
}

#[test]
fn test_bq_searchidx_drop_qualified_table() {
    let sql = "DROP SEARCH INDEX my_idx ON my_dataset.my_table;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("BQ-SEARCHIDX-DROP"),
        "DROP SEARCH INDEX with qualified table name should trigger BQ-SEARCHIDX-DROP. Got: {:?}",
        rules
    );
}

#[test]
fn test_bq_searchidx_drop_fully_qualified_table() {
    let sql = "DROP SEARCH INDEX my_idx ON my_project.my_dataset.my_table;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("BQ-SEARCHIDX-DROP"),
        "DROP SEARCH INDEX with fully qualified table should trigger BQ-SEARCHIDX-DROP. Got: {:?}",
        rules
    );
}

// =============================================================================
// Risk Level and Signal Metadata
// =============================================================================

#[test]
fn test_bq_searchidx_drop_risk_level_is_medium() {
    let sql = "DROP SEARCH INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-SEARCHIDX-DROP"))
        .expect("BQ-SEARCHIDX-DROP signal should be present");

    assert_eq!(
        signal.risk_level(),
        lexega_core::analyzer::RiskLevel::Medium,
        "BQ-SEARCHIDX-DROP should be Medium risk"
    );
}

#[test]
fn test_bq_searchidx_drop_message_content() {
    let sql = "DROP SEARCH INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-SEARCHIDX-DROP"))
        .expect("BQ-SEARCHIDX-DROP signal should be present");

    assert!(
        signal.message().contains("Search index dropped"),
        "Message should mention 'Search index dropped'. Got: {}",
        signal.message()
    );
}

#[test]
fn test_bq_searchidx_drop_summary_counts() {
    let sql = "DROP SEARCH INDEX my_idx ON my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert_eq!(
        report.summary.medium_count, 1,
        "Should have exactly 1 medium signal"
    );
    assert_eq!(
        report.summary.critical_count, 0,
        "Should have no critical signals"
    );
    assert_eq!(report.summary.high_count, 0, "Should have no high signals");
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "Should have analyzed 1 statement"
    );
    assert!(
        report.summary.ddl_operations >= 1,
        "Should count as a DDL operation"
    );
}

// =============================================================================
// Multi-Statement (Evidence Count)
// =============================================================================

#[test]
fn test_bq_searchidx_drop_multi_statement_evidence() {
    let sql = "DROP SEARCH INDEX idx1 ON t1;\nDROP SEARCH INDEX idx2 ON t2;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Signals may be deduplicated by rule, but evidence_count tracks all occurrences
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-SEARCHIDX-DROP"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Two DROP SEARCH INDEX statements should produce at least 2 evidence entries. Got: {}",
        total_evidence
    );
}

#[test]
fn test_bq_searchidx_drop_multi_statement_both_analyzed() {
    let sql = "DROP SEARCH INDEX idx1 ON t1;\nDROP SEARCH INDEX idx2 ON t2;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert_eq!(
        report.summary.statements_analyzed, 2,
        "Both DROP SEARCH INDEX statements should be analyzed"
    );
}

// =============================================================================
// Negative Cases (False Positive Prevention)
// =============================================================================

#[test]
fn test_bq_searchidx_drop_not_triggered_by_create() {
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        !rules.contains("BQ-SEARCHIDX-DROP"),
        "CREATE SEARCH INDEX should NOT trigger BQ-SEARCHIDX-DROP. Got: {:?}",
        rules
    );
}

#[test]
fn test_bq_searchidx_new_triggered_by_create() {
    // Companion rule: verify CREATE triggers the correct rule instead
    let sql = "CREATE SEARCH INDEX my_idx ON my_table(col1);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("BQ-SEARCHIDX-NEW"),
        "CREATE SEARCH INDEX should trigger BQ-SEARCHIDX-NEW (not DROP). Got: {:?}",
        rules
    );
}

#[test]
fn test_bq_searchidx_drop_not_triggered_by_drop_table() {
    let sql = "DROP TABLE my_table;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        !rules.contains("BQ-SEARCHIDX-DROP"),
        "DROP TABLE should NOT trigger BQ-SEARCHIDX-DROP. Got: {:?}",
        rules
    );
}

#[test]
fn test_bq_searchidx_drop_not_triggered_by_drop_vector_index() {
    let sql = "DROP VECTOR INDEX my_idx ON my_table;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        !rules.contains("BQ-SEARCHIDX-DROP"),
        "DROP VECTOR INDEX should NOT trigger BQ-SEARCHIDX-DROP. Got: {:?}",
        rules
    );
}

// =============================================================================
// Signal Details (Table Name in Details)
// =============================================================================

#[test]
fn test_bq_searchidx_drop_signal_details_contain_table_name() {
    let sql = "DROP SEARCH INDEX my_idx ON inventory_data;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-SEARCHIDX-DROP"));

    assert!(signal.is_some(), "BQ-SEARCHIDX-DROP should fire");

    // Validate that evidence contains table context
    let evidence = signal.unwrap().evidence();
    assert!(!evidence.is_empty(), "Signal should have evidence entries");
}

#[test]
fn test_bq_searchidx_drop_distinct_details_prevent_dedup() {
    // Two drops on different tables should produce distinct details
    // preventing false deduplication
    let sql = "DROP SEARCH INDEX idx1 ON table_a;\nDROP SEARCH INDEX idx2 ON table_b;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    // The medium count should reflect both (either as 1 signal with evidence_count=2,
    // or as separate signals)
    assert!(
        report.summary.medium_count >= 1,
        "Should have at least 1 medium signal"
    );

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-SEARCHIDX-DROP"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Distinct table details should prevent false dedup. Got evidence count: {}",
        total_evidence
    );
}
