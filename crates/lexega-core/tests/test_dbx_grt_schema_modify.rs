// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for DBX-GRT-SCHEMA-MODIFY — Grant MODIFY on Schema
///
/// Rule ID: DBX-GRT-SCHEMA-MODIFY
/// Risk: High
/// YAML detail pattern: privilege=MODIFY,object_type=*SCHEMA* (glob on object_type)
///
/// The `*SCHEMA*` glob is the most interesting pattern in the DBX-GRT rules because
/// it catches future grants where extract_object() returns multi-word object types:
///   - `ON FUTURE TABLES IN SCHEMA s` → object_type = "TABLES IN SCHEMA"
///   - `ON FUTURE SCHEMAS IN CATALOG c` → object_type = "SCHEMAS IN CATALOG"
/// Both contain "SCHEMA" and match the `*SCHEMA*` glob.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE_ID: &str = "DBX-GRT-SCHEMA-MODIFY";

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
    let rules = analyze_and_get_rules("GRANT MODIFY ON SCHEMA my_catalog.my_schema TO etl_role;");
    assert!(
        rules.contains(RULE_ID),
        "Expected {RULE_ID}, got: {rules:?}"
    );
}

#[test]
fn test_risk_level_is_high() {
    let report = analyze_risk("GRANT MODIFY ON SCHEMA my_catalog.my_schema TO etl_role;")
        .expect("should succeed");
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == RULE_ID))
        .expect("signal must exist");
    let RuleMatch::Analysis(g) = signal;
    assert_eq!(g.risk_level, lexega_core::analyzer::RiskLevel::High);
}

// ─── Object Type Boundary ───

/// MODIFY ON TABLE → object_type="TABLE" → does NOT contain "SCHEMA".
/// Verified via CLI: 0 DBX-GRT signals for MODIFY ON TABLE.
#[test]
fn test_modify_on_table_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON TABLE prod.analytics.orders TO writers;");
    assert!(
        !rules.contains(RULE_ID),
        "MODIFY ON TABLE must not trigger SCHEMA-MODIFY — got: {rules:?}"
    );
}

/// MODIFY ON CATALOG → exact match on "CATALOG", no "SCHEMA" substring.
/// Must fire CAT-MODIFY, NOT SCHEMA-MODIFY.
#[test]
fn test_modify_on_catalog_triggers_cat_modify_not_schema_modify() {
    let rules = analyze_and_get_rules("GRANT MODIFY ON CATALOG main TO admins;");
    assert!(
        !rules.contains(RULE_ID),
        "MODIFY ON CATALOG must not trigger SCHEMA-MODIFY — got: {rules:?}"
    );
    assert!(
        rules.contains("DBX-GRT-CAT-MODIFY"),
        "CAT-MODIFY should fire instead — got: {rules:?}"
    );
}

/// SELECT ON SCHEMA — right object type but wrong privilege.
#[test]
fn test_select_on_schema_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT SELECT ON SCHEMA my_catalog.my_schema TO readers;");
    assert!(
        !rules.contains(RULE_ID),
        "SELECT ON SCHEMA must not trigger SCHEMA-MODIFY — got: {rules:?}"
    );
}

// ─── Future Grants (glob matching on multi-word object_type) ───

/// FUTURE TABLES IN SCHEMA → extract_object() returns object_type="TABLES IN SCHEMA".
/// The `*SCHEMA*` glob matches because "TABLES IN SCHEMA" contains "SCHEMA".
/// Verified via CLI: SCHEMA-MODIFY fires.
#[test]
fn test_future_tables_in_schema_triggers() {
    let rules =
        analyze_and_get_rules("GRANT MODIFY ON FUTURE TABLES IN SCHEMA cat.analytics TO etl_role;");
    assert!(
        rules.contains(RULE_ID),
        "FUTURE TABLES IN SCHEMA must trigger SCHEMA-MODIFY (object_type contains SCHEMA) — got: {rules:?}"
    );
}

/// FUTURE SCHEMAS IN CATALOG → extract_object() returns object_type="SCHEMAS IN CATALOG".
/// "SCHEMAS IN CATALOG" contains "SCHEMA" → glob matches.
/// Verified via CLI: SCHEMA-MODIFY fires.
#[test]
fn test_future_schemas_in_catalog_triggers() {
    let rules =
        analyze_and_get_rules("GRANT MODIFY ON FUTURE SCHEMAS IN CATALOG main TO etl_role;");
    assert!(
        rules.contains(RULE_ID),
        "FUTURE SCHEMAS IN CATALOG must trigger SCHEMA-MODIFY (object_type contains SCHEMA) — got: {rules:?}"
    );
}

// ─── Multi-Privilege Extraction ───

/// SELECT + MODIFY in one GRANT — MODIFY should still be extracted and trigger.
#[test]
fn test_multi_privilege_grant_still_fires() {
    let rules = analyze_and_get_rules("GRANT SELECT, MODIFY ON SCHEMA cat.analytics TO writers;");
    assert!(
        rules.contains(RULE_ID),
        "MODIFY must be extracted from multi-privilege GRANT — got: {rules:?}"
    );
}

// ─── ALL PRIVILEGES Boundary ───

#[test]
fn test_all_privileges_does_not_trigger() {
    let rules = analyze_and_get_rules("GRANT ALL PRIVILEGES ON SCHEMA cat.analytics TO admin;");
    assert!(
        !rules.contains(RULE_ID),
        "ALL PRIVILEGES must not false-positive as SCHEMA-MODIFY — got: {rules:?}"
    );
}

// ─── REVOKE Boundary ───

#[test]
fn test_revoke_does_not_trigger() {
    let rules =
        analyze_and_get_rules("REVOKE MODIFY ON SCHEMA my_catalog.my_schema FROM etl_role;");
    assert!(
        !rules.contains(RULE_ID),
        "REVOKE must not trigger — got: {rules:?}"
    );
}

// ─── Evidence Deduplication ───

#[test]
fn test_multiple_grants_produce_correct_evidence_count() {
    let sql = r#"
        GRANT MODIFY ON SCHEMA cat.schema_a TO role_a;
        GRANT MODIFY ON SCHEMA cat.schema_b TO role_b;
        GRANT MODIFY ON SCHEMA cat.schema_c TO role_c;
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
    let sql = "GRANT MODIFY ON SCHEMA cat.analytics TO PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains(RULE_ID),
        "SCHEMA-MODIFY should fire for PUBLIC grantee — got: {rules:?}"
    );
}
