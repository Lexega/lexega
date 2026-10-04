// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule DB-TAG-RMV
//!
//! Rule: Database Tag Removed
//! Risk Level: Medium
//! Syntax: ALTER DATABASE [IF EXISTS] db_name UNSET TAG tag_name [, ...]

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
fn test_basic_unset_tag() {
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-TAG-RMV".to_string()),
        "Should detect DB-TAG-RMV. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_exists_variant() {
    let sql = "ALTER DATABASE IF EXISTS my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-TAG-RMV".to_string()),
        "IF EXISTS variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_multiple_tags() {
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center, env;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-TAG-RMV".to_string()),
        "Multiple tags in one UNSET TAG should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_quoted_database_name() {
    let sql = r#"ALTER DATABASE "My_Database" UNSET TAG owner;"#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-TAG-RMV".to_string()),
        "Quoted database name should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_medium() {
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-RMV"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Medium,
                "DB-TAG-RMV should be Medium risk"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-RMV"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("tag removed") || a.message.contains("tag"),
                "Message should mention tag. Got: {}",
                a.message
            );
            assert!(
                a.message.contains("incomplete") || a.message.contains("intentional"),
                "Message should warn about incomplete metadata. Got: {}",
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
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
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
        ALTER DATABASE db1 UNSET TAG env;
        ALTER DATABASE db2 UNSET TAG env;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-RMV"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two UNSET TAG stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_multi_statement_analyzed() {
    let sql = r#"
        ALTER DATABASE db1 UNSET TAG env;
        ALTER DATABASE db2 UNSET TAG env;
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
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-RMV"));
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
        !ids.contains(&"DB-TAG-RMV".to_string()),
        "SET TAG should NOT trigger DB-TAG-RMV. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_rename() {
    let sql = "ALTER DATABASE my_db RENAME TO new_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-TAG-RMV".to_string()),
        "RENAME should NOT trigger DB-TAG-RMV. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_set_properties() {
    let sql = "ALTER DATABASE my_db SET DATA_RETENTION_TIME_IN_DAYS = 30;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-TAG-RMV".to_string()),
        "SET properties should NOT trigger DB-TAG-RMV. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_database() {
    let sql = "CREATE DATABASE my_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"DB-TAG-RMV".to_string()),
        "CREATE DATABASE should NOT trigger DB-TAG-RMV. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Cross-rule verification
// ──────────────────────────────────────────────────────────

#[test]
fn test_set_tag_triggers_add_not_rmv() {
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"DB-TAG-ADD".to_string()),
        "SET TAG should trigger DB-TAG-ADD. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"DB-TAG-RMV".to_string()),
        "SET TAG should not trigger RMV rule"
    );
}
