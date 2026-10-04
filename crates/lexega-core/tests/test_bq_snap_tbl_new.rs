// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for built-in rule BQ-SNAP-TBL-NEW
//!
//! Rule: Snapshot Table Created
//! Risk Level: Low
//! Syntax: CREATE SNAPSHOT TABLE [IF NOT EXISTS] name CLONE source [FOR SYSTEM_TIME AS OF ...] [OPTIONS(...)]
//!
//! Also covers the placement of IF NOT EXISTS: after SNAPSHOT TABLE, not
//! before it (BigQuery syntax).

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
fn test_basic_create_snapshot_table() {
    let sql = "CREATE SNAPSHOT TABLE my_snap CLONE my_source;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "Should detect BQ-SNAP-TBL-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_not_exists_variant() {
    // This tests the parser bug fix: IF NOT EXISTS after SNAPSHOT TABLE
    let sql = "CREATE SNAPSHOT TABLE IF NOT EXISTS my_snap CLONE my_source;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "IF NOT EXISTS variant should trigger (parser fix). Got: {:?}",
        ids
    );
}

#[test]
fn test_qualified_table_names() {
    let sql = "CREATE SNAPSHOT TABLE ds.my_snap CLONE ds.my_source;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "Qualified table names should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_fully_qualified_table_names() {
    let sql = "CREATE SNAPSHOT TABLE proj.ds.snap CLONE proj.ds.src;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "Fully-qualified 3-part names should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_with_for_system_time_as_of() {
    let sql = "CREATE SNAPSHOT TABLE snap CLONE src FOR SYSTEM_TIME AS OF '2024-01-01';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "FOR SYSTEM_TIME AS OF trailing clause should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_with_options_clause() {
    let sql = "CREATE SNAPSHOT TABLE snap CLONE src OPTIONS(expiration_timestamp=TIMESTAMP '2025-06-01');";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "OPTIONS clause variant should trigger. Got: {:?}",
        ids
    );
}

#[test]
fn test_if_not_exists_with_qualified_and_trailing() {
    let sql = "CREATE SNAPSHOT TABLE IF NOT EXISTS ds.snap CLONE ds.src FOR SYSTEM_TIME AS OF '2024-06-15';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "Full combo of IF NOT EXISTS + qualified + trailing should trigger. Got: {:?}",
        ids
    );
}

// ──────────────────────────────────────────────────────────
// Risk level and message
// ──────────────────────────────────────────────────────────

#[test]
fn test_risk_level_is_low() {
    let sql = "CREATE SNAPSHOT TABLE snap CLONE src;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert_eq!(
                a.risk_level,
                lexega_core::analyzer::RiskLevel::Low,
                "BQ-SNAP-TBL-NEW should be Low risk"
            );
        }
    }
}

#[test]
fn test_message_content() {
    let sql = "CREATE SNAPSHOT TABLE snap CLONE src;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    match signal.unwrap() {
        RuleMatch::Analysis(a) => {
            assert!(
                a.message.contains("Snapshot table created"),
                "Message should mention creation. Got: {}",
                a.message
            );
            assert!(
                a.message.contains("clone"),
                "Message should mention clone. Got: {}",
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
    let sql = "CREATE SNAPSHOT TABLE snap CLONE src;";
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
        CREATE SNAPSHOT TABLE snap1 CLONE src1;
        CREATE SNAPSHOT TABLE snap2 CLONE src2;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Two CREATE SNAPSHOT TABLE stmts should produce evidence >= 2. Got: {}",
        total_evidence
    );
}

#[test]
fn test_distinct_sources_prevent_dedup() {
    let sql = r#"
        CREATE SNAPSHOT TABLE snap_a CLONE source_alpha;
        CREATE SNAPSHOT TABLE snap_b CLONE source_beta;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Distinct source tables should prevent false dedup. Got evidence count: {}",
        total_evidence
    );
}

// ──────────────────────────────────────────────────────────
// Signal details
// ──────────────────────────────────────────────────────────

#[test]
fn test_signal_evidence_present() {
    let sql = "CREATE SNAPSHOT TABLE snap CLONE important_data;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "BQ-SNAP-TBL-NEW"));
    assert!(signal.is_some(), "Signal should exist");
    let evidence = signal.unwrap().evidence();
    assert!(!evidence.is_empty(), "Signal should have evidence entries");
}

// ──────────────────────────────────────────────────────────
// Negative cases (false positive prevention)
// ──────────────────────────────────────────────────────────

#[test]
fn test_not_triggered_by_drop_snapshot_table() {
    let sql = "DROP SNAPSHOT TABLE my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "DROP SNAPSHOT TABLE should NOT trigger BQ-SNAP-TBL-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_table() {
    let sql = "CREATE TABLE my_table (id INT, name STRING);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "Plain CREATE TABLE should NOT trigger BQ-SNAP-TBL-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_not_triggered_by_create_table_clone() {
    let sql = "CREATE TABLE my_clone CLONE my_source;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "CREATE TABLE ... CLONE should NOT trigger BQ-SNAP-TBL-NEW. Got: {:?}",
        ids
    );
}

#[test]
fn test_drop_triggers_drop_rule_not_new() {
    let sql = "DROP SNAPSHOT TABLE my_snap;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    let ids = extract_rule_ids(&report.signals);
    assert!(
        ids.contains(&"BQ-SNAP-TBL-DROP".to_string()),
        "DROP SNAPSHOT TABLE should trigger BQ-SNAP-TBL-DROP. Got: {:?}",
        ids
    );
    assert!(
        !ids.contains(&"BQ-SNAP-TBL-NEW".to_string()),
        "DROP should not trigger NEW"
    );
}
