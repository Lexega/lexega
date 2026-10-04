// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-EXTLOC-WRFILES — Grant WRITE FILES on External Location
///
/// Rule ID: DBX-GRT-EXTLOC-WRFILES
/// Risk: High
/// YAML detail pattern: privilege=WRITE FILES* (glob — trailing wildcard)
///
/// Key edge cases: bare "WRITE" alone must NOT match, multi-privilege split with
/// READ FILES must trigger both RDFILES and WRFILES, GRANT TO PUBLIC fires dual signal.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-EXTLOC-WRFILES";

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
    let rules = analyze_and_get_rules(
        "GRANT WRITE FILES ON EXTERNAL LOCATION my_location TO data_writers;",
    );
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_high() {
    let report =
        analyze_risk("GRANT WRITE FILES ON EXTERNAL LOCATION my_location TO data_writers;")
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

/// READ FILES is the sibling privilege — must fire RDFILES, NOT WRFILES.
#[test]
fn test_read_files_does_not_trigger() {
    let rules =
        analyze_and_get_rules("GRANT READ FILES ON EXTERNAL LOCATION my_location TO data_readers;");
    assert!(
        !rules.contains(RULE_ID),
        "READ FILES must not trigger WRFILES — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-EXTLOC-RDFILES"),
        "RDFILES should fire instead — got: {rules:?}"
    );
}

/// Bare "WRITE" on a TABLE is not "WRITE FILES" — must not match glob.
/// Verified via CLI: "GRANT WRITE ON TABLE t TO r" → 0 DBX-GRT signals.
#[test]
fn test_bare_write_on_table_does_not_trigger() {
    let rules =
        analyze_and_get_rules("GRANT WRITE ON TABLE my_catalog.schema.tbl TO data_writers;");
    assert!(
        !rules.contains(RULE_ID),
        "bare WRITE ON TABLE must not trigger WRFILES — got: {rules:?}"
    );
}

// ─── Multi-Privilege Extraction ───

/// extract_privileges() splits "READ FILES, WRITE FILES" — both rules must fire.
#[test]
fn test_multi_privilege_read_and_write_files_both_fire() {
    let rules = analyze_and_get_rules(
        "GRANT READ FILES, WRITE FILES ON EXTERNAL LOCATION my_loc TO etl_role;",
    );
    assert!(
        rules.contains(RULE_ID),
        "WRFILES must fire from multi-privilege GRANT — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-EXTLOC-RDFILES"),
        "RDFILES must also fire from same GRANT — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON EXTERNAL LOCATION my_loc TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as WRFILES — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules = analyze_and_get_rules(
        "REVOKE WRITE FILES ON EXTERNAL LOCATION my_location FROM data_writers;",
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
        GRANT WRITE FILES ON EXTERNAL LOCATION s3_output TO writers;
        DROP TABLE staging.tmp;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "WRFILES signal must survive mixed DDL — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT WRITE FILES ON EXTERNAL LOCATION loc_a TO writers_a;
        GRANT WRITE FILES ON EXTERNAL LOCATION loc_b TO writers_b;
        GRANT WRITE FILES ON EXTERNAL LOCATION loc_c TO writers_c;
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

/// WRITE FILES TO PUBLIC should fire BOTH the privilege rule AND public-grant rule.
#[test]
fn test_grant_to_public_fires_both_privilege_and_public_rule() {
    let sql = "GRANT WRITE FILES ON EXTERNAL LOCATION s3_sink TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "WRFILES privilege rule should fire for PUBLIC grantee — got: {rules:?}"
    );
    let report = analyze_risk(sql).expect("should succeed");
    // Public grant is always Critical; WRFILES is High → expect both
    assert!(
        report.summary.critical_count >= 1,
        "Should have critical signal from PUBLIC grant"
    );
    assert!(
        report.summary.high_count >= 1,
        "Should have high signal from WRFILES privilege"
    );
}
