// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-EXTUSE-SCHEMA — Grant EXTERNAL USE SCHEMA
///
/// Rule ID: DBX-GRT-EXTUSE-SCHEMA
/// Risk: Critical
/// YAML detail pattern: privilege=EXTERNAL USE SCHEMA* (glob — trailing wildcard)
///
/// Databricks design: ALL PRIVILEGES intentionally EXCLUDES this privilege.
/// Tests cover sibling distinction (LOCATION vs SCHEMA), ALL PRIVILEGES exclusion,
/// and dual-signal with GRANT TO PUBLIC.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-EXTUSE-SCHEMA";

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
    let rules = analyze_and_get_rules("GRANT EXTERNAL USE SCHEMA ON CATALOG main TO data_eng;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_critical() {
    let report = analyze_risk("GRANT EXTERNAL USE SCHEMA ON CATALOG main TO data_eng;")
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

/// EXTERNAL USE LOCATION is the sibling — must fire EXTUSE-LOC, NOT EXTUSE-SCHEMA.
#[test]
fn test_external_use_location_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT EXTERNAL USE LOCATION ON CATALOG main TO data_eng;");
    assert!(
        !rules.contains(RULE_ID),
        "EXTERNAL USE LOCATION must not trigger EXTUSE-SCHEMA — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-EXTUSE-LOC"),
        "EXTUSE-LOC should fire instead — got: {rules:?}"
    );
}

/// WRITE FILES is a completely different privilege family.
#[test]
fn test_write_files_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT WRITE FILES ON EXTERNAL LOCATION my_loc TO writers;");
    assert!(
        !rules.contains(RULE_ID),
        "WRITE FILES must not trigger EXTUSE-SCHEMA — got: {rules:?}"
    );
}

/// MODIFY ON SCHEMA — different privilege, same object type.
#[test]
fn test_modify_on_schema_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON SCHEMA cat.analytics TO writers;");
    assert!(
        !rules.contains(RULE_ID),
        "MODIFY ON SCHEMA must not trigger EXTUSE-SCHEMA — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

/// ALL PRIVILEGES intentionally excludes EXTERNAL USE SCHEMA in Databricks.
#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON CATALOG main TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as EXTUSE-SCHEMA — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules = analyze_and_get_rules("REVOKE EXTERNAL USE SCHEMA ON CATALOG main FROM data_eng;");
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
        GRANT EXTERNAL USE SCHEMA ON CATALOG main TO data_eng;
        DROP TABLE staging.tmp;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "EXTUSE-SCHEMA signal must survive mixed DDL — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT EXTERNAL USE SCHEMA ON CATALOG cat_a TO eng_a;
        GRANT EXTERNAL USE SCHEMA ON CATALOG cat_b TO eng_b;
        GRANT EXTERNAL USE SCHEMA ON CATALOG cat_c TO eng_c;
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

/// EXTERNAL USE SCHEMA TO PUBLIC fires both privilege-level and public-grant rules.
#[test]
fn test_grant_to_public_fires_both_privilege_and_public_rule() {
    let sql = "GRANT EXTERNAL USE SCHEMA ON CATALOG main TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "EXTUSE-SCHEMA privilege rule should fire for PUBLIC — got: {rules:?}"
    );
    let report = analyze_risk(sql).expect("should succeed");
    assert!(
        report.summary.critical_count >= 2,
        "Should have critical from BOTH EXTUSE-SCHEMA and PUBLIC grant, got: {}",
        report.summary.critical_count
    );
}
