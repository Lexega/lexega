// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-CAT-MODIFY — Grant MODIFY on Catalog
///
/// Rule ID: DBX-GRT-CAT-MODIFY
/// Risk: Critical
/// YAML detail pattern: privilege=MODIFY,object_type=CATALOG (exact, no globs)
///
/// Pipeline under test:
///   grant_extraction.rs → extract_grant_info() tokenises GRANT, splits privileges,
///   extracts object_type → ddl.rs emits "privilege={priv},object_type={obj}" →
///   custom_rules.rs matches_pattern() → builtin_rules.yaml fires rule
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-CAT-MODIFY";

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

/// End-to-end: GRANT text → signal emission → YAML match → Critical signal.
#[test]
fn test_basic_detection() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON CATALOG main TO admin_role;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

/// Critical severity — regression here would misclassify sweeping DML grant.
#[test]
fn test_risk_level_is_critical() {
    let report =
        analyze_risk("GRANT MODIFY ON CATALOG main TO admin_role;").expect("should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .expect("signal must exist");
    let RuleMatch::Analysis(g) = signal;
    assert_eq!(g.risk_level, lexega_core::analyzer::RiskLevel::Critical);
}

// ─── Object Type Boundary (detail pattern specificity) ───

/// MODIFY ON SCHEMA → fires DBX-GRT-SCHEMA-MODIFY (glob *SCHEMA*), NOT CAT-MODIFY.
/// The exact detail string "object_type=SCHEMA" must not match "object_type=CATALOG".
#[test]
fn test_modify_on_schema_does_not_trigger_cat_modify() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON SCHEMA prod.analytics TO writers;");
    assert!(
        !rules.contains(RULE_ID),
        "CAT-MODIFY must not fire for MODIFY ON SCHEMA — got: {rules:?}"
    );
    // Verify the correct sibling rule fires instead
    assert!(
        rules.contains("DBX-GRT-SCHEMA-MODIFY"),
        "SCHEMA-MODIFY should fire for MODIFY ON SCHEMA — got: {rules:?}"
    );
}

/// MODIFY ON TABLE → no DBX-GRT rule covers this. Tests exact "CATALOG" match.
#[test]
fn test_modify_on_table_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON TABLE prod.analytics.orders TO writers;");
    assert!(
        !rules.contains(RULE_ID),
        "CAT-MODIFY must not fire for MODIFY ON TABLE — got: {rules:?}"
    );
    assert!(
        !rules.contains("DBX-GRT-SCHEMA-MODIFY"),
        "SCHEMA-MODIFY must not fire for TABLE either — got: {rules:?}"
    );
}

/// SELECT ON CATALOG — wrong privilege, right object. Tests privilege matching.
#[test]
fn test_select_on_catalog_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT SELECT ON CATALOG main TO readers;");
    assert!(
        !rules.contains(RULE_ID),
        "CAT-MODIFY must not fire for SELECT privilege — got: {rules:?}"
    );
}

// ─── Multi-Privilege Extraction ───

/// extract_privileges() must split comma-separated privileges and emit separate
/// per-privilege signals. MODIFY should trigger even combined with SELECT.
#[test]
fn test_multi_privilege_single_grant_still_fires() {
    let rules = analyze_and_get_rules("GRANT SELECT, MODIFY ON CATALOG main TO admin_role;");
    assert!(
        rules.contains(RULE_ID),
        "MODIFY must be extracted from multi-privilege GRANT — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

/// ALL PRIVILEGES emits AllPrivileges signal, NOT individual SpecificPrivilege signals.
/// CAT-MODIFY should NOT fire — it requires specific MODIFY detail string.
#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON CATALOG main TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as CAT-MODIFY — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

/// extract_grant_info() checks tokens[0] == "GRANT". REVOKE returns empty GrantInfo.
#[test]
fn test_revoke_does_not_trigger() {
    let rules = analyze_and_get_rules("REVOKE MODIFY ON CATALOG main FROM admin_role;");
    assert!(
        !rules.contains(RULE_ID),
        "REVOKE must not trigger — got: {rules:?}"
    );
}

// ─── Mixed Script (signal survival) ───

/// Grant signals must survive alongside DDL statements in the same script.
#[test]
fn test_grant_signal_survives_in_mixed_script() {
    let sql = r#"
        CREATE TABLE staging.events (id INT, ts TIMESTAMP);
        GRANT MODIFY ON CATALOG main TO etl_role;
        DROP TABLE staging.old_events;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "CAT-MODIFY signal must survive mixed DDL context — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

/// Multiple identical-rule signals get deduplicated; evidence_count accumulates.
#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT MODIFY ON CATALOG cat_a TO role_a;
        GRANT MODIFY ON CATALOG cat_b TO role_b;
        GRANT MODIFY ON CATALOG cat_c TO role_c;
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
        "3 GRANT MODIFY ON CATALOG → evidence_count >= 3, got: {total_evidence}"
    );
}

// ─── GRANT TO PUBLIC (dangerous grantee combination) ───

/// MODIFY ON CATALOG TO PUBLIC should fire BOTH the MODIFY rule and the
/// PUBLIC-grant rule — they represent distinct risks.
#[test]
fn test_grant_to_public_fires_privilege_rule() {
    let sql = "GRANT MODIFY ON CATALOG main TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "MODIFY privilege rule should still fire for PUBLIC grantee — got: {rules:?}"
    );
    let report = analyze_risk(sql).expect("should succeed");
    // PUBLIC grant is always Critical
    assert!(
        report.summary.critical_count >= 2,
        "Should have critical signals from both MODIFY and PUBLIC rules"
    );
}
