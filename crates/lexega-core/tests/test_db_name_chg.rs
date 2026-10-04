// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule DB-NAME-CHG
//!
//! Rule: Database Renamed
//! Risk Level: Medium
//! Syntax: ALTER DATABASE [IF EXISTS] db_name RENAME TO new_name

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
fn test_basic_alter_database_rename() {
    let sql = "ALTER DATABASE my_db RENAME TO new_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-NAME-CHG".to_string()),
        "Should detect DB-NAME-CHG. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_exists_variant() {
    let sql = "ALTER DATABASE IF EXISTS my_db RENAME TO new_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-NAME-CHG".to_string()),
        "IF EXISTS variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_quoted_database_name() {
    let sql = r#"ALTER DATABASE "My_Database" RENAME TO "New_Database";"#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-NAME-CHG".to_string()),
        "Quoted identifiers should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_medium() {
    let sql = "ALTER DATABASE my_db RENAME TO new_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-NAME-CHG"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Medium,
                "DB-NAME-CHG should be Medium risk"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "ALTER DATABASE my_db RENAME TO new_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-NAME-CHG"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("renamed"),
                "Message should mention rename. Got: {}",
                a.message
            );
            assert!(
                a.message.contains("references"),
                "Message should mention updating references. Got: {}",
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
    let sql = "ALTER DATABASE my_db RENAME TO new_db;";
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
        ALTER DATABASE db1 RENAME TO db1_new;
        ALTER DATABASE db2 RENAME TO db2_new;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-NAME-CHG"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two RENAME stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_multi_statement_analyzed() {
    let sql = r#"
        ALTER DATABASE db1 RENAME TO db1_new;
        ALTER DATABASE db2 RENAME TO db2_new;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert_eq!(
        report.summary.statements_analyzed, 2,
        "Should analyze 2 statements"
    );
}

// ──────────────────────────────────────────────────────────
// Signal evidence
// ──────────────────────────────────────────────────────────

#[test]
fn test_signal_evidence_present() {
    let sql = "ALTER DATABASE my_db RENAME TO new_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-NAME-CHG"));
    assert!(signal.is_some(), "Signal should exist");
    let evidence = signal.unwrap().evidence();
    assert!(!evidence.is_empty(), "Signal should have evidence entries");
}

// ──────────────────────────────────────────────────────────
// Negative cases (false positive prevention)
// ──────────────────────────────────────────────────────────

#[test]
fn test_not_triggered_by_set_tag() {
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-NAME-CHG".to_string()),
        "SET TAG should NOT trigger DB-NAME-CHG. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_unset_tag() {
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-NAME-CHG".to_string()),
        "UNSET TAG should NOT trigger DB-NAME-CHG. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_set_properties() {
    let sql = "ALTER DATABASE my_db SET DATA_RETENTION_TIME_IN_DAYS = 30;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-NAME-CHG".to_string()),
        "SET properties should NOT trigger DB-NAME-CHG. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_swap() {
    let sql = "ALTER DATABASE my_db SWAP WITH other_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-NAME-CHG".to_string()),
        "SWAP WITH should NOT trigger DB-NAME-CHG. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_database() {
    let sql = "CREATE DATABASE my_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-NAME-CHG".to_string()),
        "CREATE DATABASE should NOT trigger DB-NAME-CHG. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Cross-rule verification
// ──────────────────────────────────────────────────────────

#[test]
fn test_swap_triggers_swap_rule_not_rename() {
    let sql = "ALTER DATABASE my_db SWAP WITH other_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"SNW-DB-SWAP".to_string()),
        "SWAP WITH should trigger SNW-DB-SWAP. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"DB-NAME-CHG".to_string()),
        "SWAP should not trigger RENAME rule"
    );
}
