// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-EXTUSE-LOC — Grant EXTERNAL USE LOCATION
///
/// Rule ID: DBX-GRT-EXTUSE-LOC
/// Risk: Critical
/// YAML detail pattern: privilege=EXTERNAL USE LOCATION* (glob — trailing wildcard)
///
/// Databricks design: ALL PRIVILEGES intentionally EXCLUDES this privilege.
/// Tests must cover the ALL PRIVILEGES exclusion boundary, sibling rule
/// EXTERNAL USE SCHEMA distinction, and dual-signal with GRANT TO PUBLIC.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-EXTUSE-LOC";

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
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

// ─── Core Detection ───

#[test]
fn test_basic_detection() {
    let rules = analyze_and_get_rules("GRANT EXTERNAL USE LOCATION ON CATALOG main TO data_eng;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_critical() {
    let report = analyze_risk("GRANT EXTERNAL USE LOCATION ON CATALOG main TO data_eng;")
        .expect("should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .expect("signal must exist");
    let RuleMatch::Analysis(g) = signal;
    assert_eq!(g.risk_level, lexega_core::analyzer::RiskLevel::Critical);
}

// ─── Privilege Boundary ───

/// EXTERNAL USE SCHEMA is the sibling privilege — must fire EXTUSE-SCHEMA, NOT EXTUSE-LOC.
#[test]
fn test_external_use_schema_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT EXTERNAL USE SCHEMA ON CATALOG main TO data_eng;");
    assert!(
        !rules.contains(RULE_ID),
        "EXTERNAL USE SCHEMA must not trigger EXTUSE-LOC — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-EXTUSE-SCHEMA"),
        "EXTUSE-SCHEMA should fire instead — got: {rules:?}"
    );
}

/// READ FILES is a completely different privilege family.
#[test]
fn test_read_files_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT READ FILES ON EXTERNAL LOCATION my_loc TO readers;");
    assert!(
        !rules.contains(RULE_ID),
        "READ FILES must not trigger EXTUSE-LOC — got: {rules:?}"
    );
}

/// MODIFY ON CATALOG — wrong privilege entirely.
#[test]
fn test_modify_on_catalog_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON CATALOG main TO admins;");
    assert!(
        !rules.contains(RULE_ID),
        "MODIFY ON CATALOG must not trigger EXTUSE-LOC — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

/// ALL PRIVILEGES intentionally excludes EXTERNAL USE LOCATION in Databricks.
/// This test verifies our pipeline doesn't false-positive.
#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON CATALOG main TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as EXTUSE-LOC — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules =
        analyze_and_get_rules("REVOKE EXTERNAL USE LOCATION ON CATALOG main FROM data_eng;");
    assert!(
        !rules.contains(RULE_ID),
        "REVOKE must not trigger — got: {rules:?}"
    );
}

// ─── Mixed Script ───

#[test]
fn test_grant_signal_survives_in_mixed_script() {
    let sql = r#"
        CREATE TABLE staging.events (id INT);
        GRANT EXTERNAL USE LOCATION ON CATALOG main TO data_eng;
        DROP TABLE staging.tmp;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "EXTUSE-LOC signal must survive mixed DDL — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT EXTERNAL USE LOCATION ON CATALOG cat_a TO eng_a;
        GRANT EXTERNAL USE LOCATION ON CATALOG cat_b TO eng_b;
        GRANT EXTERNAL USE LOCATION ON CATALOG cat_c TO eng_c;
    "#;
    let report = analyze_risk(sql).expect("should succeed");
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 3,
        "3 GRANT stmts → evidence_count >= 3, got: {total_evidence}"
    );
}

// ─── GRANT TO PUBLIC (dual-signal) ───

/// EXTERNAL USE LOCATION TO PUBLIC fires both privilege-level and public-grant rules.
/// Both are Critical, so critical_count must reflect accumulation.
#[test]
fn test_grant_to_public_fires_both_privilege_and_public_rule() {
    let sql = "GRANT EXTERNAL USE LOCATION ON CATALOG main TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "EXTUSE-LOC privilege rule should fire for PUBLIC — got: {rules:?}"
    );
    let report = analyze_risk(sql).expect("should succeed");
    assert!(
        report.summary.critical_count >= 2,
        "Should have critical from BOTH EXTUSE-LOC and PUBLIC grant, got: {}",
        report.summary.critical_count
    );
}
