// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-SHARE-SETPERM — Grant SET SHARE PERMISSION
///
/// Rule ID: DBX-GRT-SHARE-SETPERM
/// Risk: High
/// YAML detail pattern: privilege=SET SHARE PERMISSION* (glob suffix)
///
/// SET SHARE PERMISSION is a multi-word privilege used for Databricks Delta Sharing.
/// The `*` glob suffix means prefix matching: any privilege string starting with
/// "SET SHARE PERMISSION" matches.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-SHARE-SETPERM";

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
    let rules = analyze_and_get_rules("GRANT SET SHARE PERMISSION ON METASTORE TO share_admins;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_high() {
    let report = analyze_risk("GRANT SET SHARE PERMISSION ON METASTORE TO share_admins;")
        .expect("should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .expect("signal must exist");
    let RuleMatch::Analysis(g) = signal;
    assert_eq!(g.risk_level, lexega_core::analyzer::RiskLevel::High);
}

// ─── Privilege Boundary ───

/// MODIFY ON SCHEMA is an unrelated privilege — must not trigger SHARE-SETPERM.
#[test]
fn test_modify_on_schema_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON SCHEMA cat.my_schema TO writers;");
    assert!(
        !rules.contains(RULE_ID),
        "MODIFY ON SCHEMA must not trigger SHARE-SETPERM — got: {rules:?}"
    );
}

/// READ FILES is an unrelated privilege — must not trigger SHARE-SETPERM.
#[test]
fn test_read_files_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT READ FILES ON EXTERNAL LOCATION my_loc TO readers;");
    assert!(
        !rules.contains(RULE_ID),
        "READ FILES must not trigger SHARE-SETPERM — got: {rules:?}"
    );
}

/// CREATE STORAGE CREDENTIAL is an unrelated privilege.
#[test]
fn test_create_storage_credential_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT CREATE STORAGE CREDENTIAL ON METASTORE TO infra;");
    assert!(
        !rules.contains(RULE_ID),
        "CREATE STORAGE CREDENTIAL must not trigger SHARE-SETPERM — got: {rules:?}"
    );
}

/// EXTERNAL USE LOCATION is an unrelated privilege.
#[test]
fn test_external_use_location_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT EXTERNAL USE LOCATION ON METASTORE TO etl;");
    assert!(
        !rules.contains(RULE_ID),
        "EXTERNAL USE LOCATION must not trigger SHARE-SETPERM — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON METASTORE TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as SHARE-SETPERM — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules =
        analyze_and_get_rules("REVOKE SET SHARE PERMISSION ON METASTORE FROM share_admins;");
    assert!(
        !rules.contains(RULE_ID),
        "REVOKE must not trigger — got: {rules:?}"
    );
}

// ─── Mixed Script Survival ───

/// SHARE-SETPERM signal must survive alongside other DDL in multi-statement scripts.
#[test]
fn test_mixed_ddl_and_grant() {
    let sql = r#"
        CREATE TABLE staging.events (id INT);
        GRANT SET SHARE PERMISSION ON METASTORE TO share_admins;
        DROP TABLE staging.old_events;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "SHARE-SETPERM must survive in mixed script — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT SET SHARE PERMISSION ON METASTORE TO admin_a;
        GRANT SET SHARE PERMISSION ON METASTORE TO admin_b;
        GRANT SET SHARE PERMISSION ON METASTORE TO admin_c;
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

/// GRANT TO PUBLIC should fire SHARE-SETPERM and potentially a public-grant signal.
#[test]
fn test_grant_to_public_fires_privilege_rule() {
    let sql = "GRANT SET SHARE PERMISSION ON METASTORE TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "SHARE-SETPERM should fire for PUBLIC grantee — got: {rules:?}"
    );
}

// ─── Cross-Rule Verification ───

/// MODIFY ON CATALOG is completely unrelated — it fires CAT-MODIFY, not SHARE-SETPERM.
#[test]
fn test_modify_on_catalog_triggers_cat_modify_not_share_setperm() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON CATALOG main TO admins;");
    assert!(
        !rules.contains(RULE_ID),
        "MODIFY ON CATALOG must not trigger SHARE-SETPERM — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-CAT-MODIFY"),
        "CAT-MODIFY should fire instead — got: {rules:?}"
    );
}
