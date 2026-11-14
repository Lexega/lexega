// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule DB-TAG-ADD
//!
//! Rule: Database Tag Set
//! Risk Level: Info
//! Syntax: ALTER DATABASE [IF EXISTS] db_name SET TAG tag = 'value' [, ...]

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;

/// Helper: collect all rule IDs from an analysis report.
fn extract_rule_ids(findings: &[RuleMatch]) -> Vec<String> {
    findings
        .iter()
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.matched_rule.clone(),
        })
        .collect()
}

// ──────────────────────────────────────────────────────────
// Positive detection
// ──────────────────────────────────────────────────────────

#[test]
fn test_basic_set_tag() {
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.context);
    assert!(
        ids.contains(&"DB-TAG-ADD".to_string()),
        "Should detect DB-TAG-ADD. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_exists_variant() {
    let sql = "ALTER DATABASE IF EXISTS my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.context);
    assert!(
        ids.contains(&"DB-TAG-ADD".to_string()),
        "IF EXISTS variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_multiple_tags() {
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance', env = 'prod';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.context);
    assert!(
        ids.contains(&"DB-TAG-ADD".to_string()),
        "Multiple tags in one SET TAG should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_quoted_database_name() {
    let sql = r#"ALTER DATABASE "My_Database" SET TAG owner = 'team_a';"#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.context);
    assert!(
        ids.contains(&"DB-TAG-ADD".to_string()),
        "Quoted database name should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_info() {
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let finding = report
        .context
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-ADD"));
    assert!(finding.is_some(), "Finding should exist");
    match finding.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Info,
                "DB-TAG-ADD should be Info"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let finding = report
        .context
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-ADD"));
    assert!(finding.is_some(), "Finding should exist");
    match finding.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("tag"),
                "Message should mention tag. Got: {}",
                a.message
            );
            assert!(
                a.message.contains("Governance"),
                "Message should mention governance. Got: {}",
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
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        report.summary.info_count >= 1,
        "info_count should be at least 1. Got: {}",
        report.summary.info_count
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
        ALTER DATABASE db1 SET TAG env = 'prod';
        ALTER DATABASE db2 SET TAG env = 'staging';
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .context
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-ADD"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two SET TAG stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_multi_statement_analyzed() {
    let sql = r#"
        ALTER DATABASE db1 SET TAG env = 'prod';
        ALTER DATABASE db2 SET TAG env = 'staging';
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert_eq!(
        report.summary.statements_analyzed, 2,
        "Should analyze 2 statements"
    );
}

// ──────────────────────────────────────────────────────────
// Finding evidence
// ──────────────────────────────────────────────────────────

#[test]
fn test_finding_evidence_present() {
    let sql = "ALTER DATABASE my_db SET TAG cost_center = 'finance';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let finding = report
        .context
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DB-TAG-ADD"));
    assert!(finding.is_some(), "Finding should exist");
    let evidence = finding.unwrap().evidence();
    assert!(!evidence.is_empty(), "Finding should have evidence entries");
}

// ──────────────────────────────────────────────────────────
// Negative cases (false positive prevention)
// ──────────────────────────────────────────────────────────

#[test]
fn test_not_triggered_by_unset_tag() {
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let mut ids = extract_rule_ids(&report.findings);
    ids.extend(extract_rule_ids(&report.context));
    assert!(
        !ids.contains(&"DB-TAG-ADD".to_string()),
        "UNSET TAG should NOT trigger DB-TAG-ADD. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_rename() {
    let sql = "ALTER DATABASE my_db RENAME TO new_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let mut ids = extract_rule_ids(&report.findings);
    ids.extend(extract_rule_ids(&report.context));
    assert!(
        !ids.contains(&"DB-TAG-ADD".to_string()),
        "RENAME should NOT trigger DB-TAG-ADD. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_set_properties() {
    let sql = "ALTER DATABASE my_db SET DATA_RETENTION_TIME_IN_DAYS = 30;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let mut ids = extract_rule_ids(&report.findings);
    ids.extend(extract_rule_ids(&report.context));
    assert!(
        !ids.contains(&"DB-TAG-ADD".to_string()),
        "SET properties should NOT trigger DB-TAG-ADD. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_database() {
    let sql = "CREATE DATABASE my_db;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let mut ids = extract_rule_ids(&report.findings);
    ids.extend(extract_rule_ids(&report.context));
    assert!(
        !ids.contains(&"DB-TAG-ADD".to_string()),
        "CREATE DATABASE should NOT trigger DB-TAG-ADD. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Cross-rule verification
// ──────────────────────────────────────────────────────────

#[test]
fn test_unset_tag_triggers_rmv_not_add() {
    let sql = "ALTER DATABASE my_db UNSET TAG cost_center;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let mut ids = extract_rule_ids(&report.findings);
    ids.extend(extract_rule_ids(&report.context));
    assert!(
        ids.contains(&"DB-TAG-RMV".to_string()),
        "UNSET TAG should trigger DB-TAG-RMV. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"DB-TAG-ADD".to_string()),
        "UNSET TAG should not trigger ADD rule"
    );
}
