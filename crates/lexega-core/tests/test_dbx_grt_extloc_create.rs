// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-EXTLOC-CREATE — Grant CREATE EXTERNAL LOCATION
///
/// Rule ID: DBX-GRT-EXTLOC-CREATE
/// Risk: High
/// YAML detail pattern: privilege=CREATE EXTERNAL LOCATION* (glob — trailing wildcard)
///
/// Tests the glob specificity: "CREATE EXTERNAL LOCATION" matches but
/// "CREATE STORAGE CREDENTIAL", "CREATE EXTERNAL TABLE", and bare "CREATE" do not.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-EXTLOC-CREATE";

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
    let rules = analyze_and_get_rules("GRANT CREATE EXTERNAL LOCATION ON METASTORE TO data_ops;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_high() {
    let report = analyze_risk("GRANT CREATE EXTERNAL LOCATION ON METASTORE TO data_ops;")
        .expect("should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .expect("signal must exist");
    let RuleMatch::Analysis(g) = signal;
    assert_eq!(g.risk_level, lexega_core::analyzer::RiskLevel::High);
}

// ─── Privilege Prefix Boundary ───

/// CREATE STORAGE CREDENTIAL shares the "CREATE" prefix — must not match
/// the "CREATE EXTERNAL LOCATION*" glob.
#[test]
fn test_create_storage_credential_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO data_ops;");
    assert!(
        !rules.contains(RULE_ID),
        "CREATE STORAGE CREDENTIAL must not trigger EXTLOC-CREATE — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-CRED-CREATE"),
        "CRED-CREATE should fire instead — got: {rules:?}"
    );
}

/// "CREATE EXTERNAL TABLE" shares "CREATE EXTERNAL" prefix but is not
/// "CREATE EXTERNAL LOCATION".
#[test]
fn test_create_external_table_does_not_trigger() {
    let rules = analyze_and_get_rules(
        "GRANT CREATE EXTERNAL TABLE ON SCHEMA my_catalog.my_schema TO etl_role;",
    );
    assert!(
        !rules.contains(RULE_ID),
        "CREATE EXTERNAL TABLE must not trigger EXTLOC-CREATE — got: {rules:?}"
    );
}

/// Simple "CREATE ON SCHEMA" — just the "CREATE" keyword.
#[test]
fn test_bare_create_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT CREATE ON SCHEMA prod.raw TO devs;");
    assert!(
        !rules.contains(RULE_ID),
        "bare CREATE must not trigger EXTLOC-CREATE — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON METASTORE TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules =
        analyze_and_get_rules("REVOKE CREATE EXTERNAL LOCATION ON METASTORE FROM data_ops;");
    assert!(
        !rules.contains(RULE_ID),
        "REVOKE must not trigger — got: {rules:?}"
    );
}

// ─── Mixed Script ───

#[test]
fn test_grant_signal_survives_in_mixed_script() {
    let sql = r#"
        CREATE SCHEMA staging;
        GRANT CREATE EXTERNAL LOCATION ON METASTORE TO infra_role;
        ALTER TABLE staging.events ADD COLUMN source STRING;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "EXTLOC-CREATE signal must survive mixed DDL — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT CREATE EXTERNAL LOCATION ON METASTORE TO role_a;
        GRANT CREATE EXTERNAL LOCATION ON METASTORE TO role_b;
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
        total_evidence >= 2,
        "2 GRANT stmts → evidence_count >= 2, got: {total_evidence}"
    );
}

// ─── GRANT TO PUBLIC ───

#[test]
fn test_grant_to_public_fires_privilege_rule() {
    let sql = "GRANT CREATE EXTERNAL LOCATION ON METASTORE TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "EXTLOC-CREATE should still fire for PUBLIC grantee — got: {rules:?}"
    );
}
