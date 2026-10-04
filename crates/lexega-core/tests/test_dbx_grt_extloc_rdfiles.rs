// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-EXTLOC-RDFILES — Grant READ FILES on External Location
///
/// Rule ID: DBX-GRT-EXTLOC-RDFILES
/// Risk: Medium
/// YAML detail pattern: privilege=READ FILES* (glob — trailing wildcard)
///
/// Key edge cases: multi-privilege extraction (READ FILES + WRITE FILES in one GRANT
/// must fire BOTH RDFILES and WRFILES independently), partial name "READ" alone must
/// not match, and WRITE FILES must not false-positive.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-EXTLOC-RDFILES";

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
    let rules =
        analyze_and_get_rules("GRANT READ FILES ON EXTERNAL LOCATION my_location TO data_readers;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_medium() {
    let report = analyze_risk("GRANT READ FILES ON EXTERNAL LOCATION my_location TO data_readers;")
        .expect("should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .expect("signal must exist");
    let RuleMatch::Analysis(g) = signal;
    assert_eq!(g.risk_level, lexega_core::analyzer::RiskLevel::Medium);
}

// ─── Privilege Boundary ───

/// WRITE FILES is the sibling privilege — must fire WRFILES, NOT RDFILES.
#[test]
fn test_write_files_does_not_trigger() {
    let rules = analyze_and_get_rules(
        "GRANT WRITE FILES ON EXTERNAL LOCATION my_location TO data_writers;",
    );
    assert!(
        !rules.contains(RULE_ID),
        "WRITE FILES must not trigger RDFILES — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-EXTLOC-WRFILES"),
        "WRFILES should fire instead — got: {rules:?}"
    );
}

/// Bare "READ" on a TABLE is not "READ FILES" — must not match glob.
#[test]
fn test_bare_read_on_table_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT READ ON TABLE my_catalog.schema.tbl TO data_readers;");
    assert!(
        !rules.contains(RULE_ID),
        "bare READ ON TABLE must not trigger RDFILES — got: {rules:?}"
    );
}

// ─── Multi-Privilege Extraction ───

/// extract_privileges() must split "READ FILES, WRITE FILES" into two separate
/// signals. Both RDFILES and WRFILES must fire from a single GRANT statement.
#[test]
fn test_multi_privilege_read_and_write_files_both_fire() {
    let rules = analyze_and_get_rules(
        "GRANT READ FILES, WRITE FILES ON EXTERNAL LOCATION my_loc TO etl_role;",
    );
    assert!(
        rules.contains(RULE_ID),
        "RDFILES must fire from multi-privilege GRANT — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-EXTLOC-WRFILES"),
        "WRFILES must also fire from same GRANT — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON EXTERNAL LOCATION my_loc TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as RDFILES — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules = analyze_and_get_rules(
        "REVOKE READ FILES ON EXTERNAL LOCATION my_location FROM data_readers;",
    );
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
        GRANT READ FILES ON EXTERNAL LOCATION s3_input TO readers;
        DROP TABLE staging.tmp;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "RDFILES signal must survive mixed DDL — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT READ FILES ON EXTERNAL LOCATION loc_a TO team_a;
        GRANT READ FILES ON EXTERNAL LOCATION loc_b TO team_b;
        GRANT READ FILES ON EXTERNAL LOCATION loc_c TO team_c;
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
    let sql = "GRANT READ FILES ON EXTERNAL LOCATION s3_input TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "RDFILES should still fire for PUBLIC grantee — got: {rules:?}"
    );
}
