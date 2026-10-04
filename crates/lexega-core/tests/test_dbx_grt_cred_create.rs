// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-CRED-CREATE — Grant CREATE STORAGE CREDENTIAL
///
/// Rule ID: DBX-GRT-CRED-CREATE
/// Risk: High
/// YAML detail pattern: privilege=CREATE STORAGE CREDENTIAL* (glob — trailing wildcard)
///
/// Tests the glob matching: "CREATE STORAGE CREDENTIAL" must match but "CREATE" alone,
/// "CREATE EXTERNAL LOCATION", or "CREATE EXTERNAL TABLE" must NOT.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-CRED-CREATE";

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
    let rules = analyze_and_get_rules("GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO data_ops;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_high() {
    let report = analyze_risk("GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO data_ops;")
        .expect("should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .expect("signal must exist");
    let RuleMatch::Analysis(g) = signal;
    assert_eq!(g.risk_level, lexega_core::analyzer::RiskLevel::High);
}

// ─── Privilege Prefix Boundary (glob specificity) ───

/// "CREATE EXTERNAL LOCATION" shares the prefix "CREATE" but is a different
/// multi-word privilege. The glob "CREATE STORAGE CREDENTIAL*" must not match it.
#[test]
fn test_create_external_location_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT CREATE EXTERNAL LOCATION ON METASTORE TO data_ops;");
    assert!(
        !rules.contains(RULE_ID),
        "CREATE EXTERNAL LOCATION must not false-positive as CRED-CREATE — got: {rules:?}"
    );
    // Verify the correct sibling fires
    assert!(
        rules.contains("DBX-GRT-EXTLOC-CREATE"),
        "EXTLOC-CREATE should fire instead — got: {rules:?}"
    );
}

/// "CREATE ON SCHEMA" is a short privilege — the word "CREATE" is just a prefix
/// of the glob but doesn't satisfy "CREATE STORAGE CREDENTIAL*".
#[test]
fn test_create_on_schema_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT CREATE ON SCHEMA prod.raw TO devs;");
    assert!(
        !rules.contains(RULE_ID),
        "bare CREATE ON SCHEMA must not trigger CRED-CREATE — got: {rules:?}"
    );
}

/// "CREATE EXTERNAL TABLE" shares "CREATE EXTERNAL" prefix. Tests that
/// glob boundary matching doesn't false-positive on partial overlap.
#[test]
fn test_create_external_table_does_not_trigger() {
    let rules = analyze_and_get_rules(
        "GRANT CREATE EXTERNAL TABLE ON SCHEMA my_catalog.my_schema TO etl_role;",
    );
    assert!(
        !rules.contains(RULE_ID),
        "CREATE EXTERNAL TABLE must not trigger CRED-CREATE — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON METASTORE TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as CRED-CREATE — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules =
        analyze_and_get_rules("REVOKE CREATE STORAGE CREDENTIAL ON METASTORE FROM data_ops;");
    assert!(
        !rules.contains(RULE_ID),
        "REVOKE must not trigger — got: {rules:?}"
    );
}

// ─── Mixed Script ───

#[test]
fn test_grant_signal_survives_in_mixed_script() {
    let sql = r#"
        CREATE TABLE staging.events (id INT, ts TIMESTAMP);
        GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO infra_role;
        DROP TABLE staging.old_events;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "CRED-CREATE signal must survive mixed DDL context — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO role_a;
        GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO role_b;
        GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO role_c;
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

// ─── GRANT TO PUBLIC ───

#[test]
fn test_grant_to_public_fires_privilege_rule() {
    let sql = "GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "CRED-CREATE should still fire for PUBLIC grantee — got: {rules:?}"
    );
}
