// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake JOIN POLICY statements (ninth policy kind).
//!
//! Covers CREATE / ALTER / DROP JOIN POLICY parsing + formatting, the
//! SNW-JOINPOL-* governance rules (including JOIN_REQUIRED body analysis),
//! and the `ALTER TABLE … SET JOIN POLICY` table-attach rule.

use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.signals)
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ───────────────────────── formatting ─────────────────────────

#[test]
fn test_join_policy_formatting_variants() {
    assert_formats_safe(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE);\n\
         CREATE OR REPLACE JOIN POLICY IF NOT EXISTS db1.sch1.jp2 AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE) COMMENT = 'permits';\n\
         ALTER JOIN POLICY jp RENAME TO jp_new;\n\
         ALTER JOIN POLICY jp SET BODY -> JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE);\n\
         ALTER JOIN POLICY IF EXISTS jp SET COMMENT = 'x';\n\
         ALTER JOIN POLICY jp UNSET COMMENT;\n\
         ALTER JOIN POLICY jp SET TAG t1 = 'v1';\n\
         ALTER JOIN POLICY jp UNSET TAG t1;\n\
         DROP JOIN POLICY jp;\n\
         DROP JOIN POLICY IF EXISTS db1.sch1.jp2;",
    );
}

// ───────────────────────── lifecycle rules ─────────────────────────

#[test]
fn test_join_policy_create_and_drop() {
    let rules = analyze_and_get_rules(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE);",
    );
    assert!(rules.contains("SNW-JOINPOL-NEW"), "got {rules:?}");

    let report = analyze_risk("DROP JOIN POLICY jp;").expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("SNW-JOINPOL-DROP"), "got {rules:?}");
    assert!(
        report.summary.high_count >= 1,
        "dropping a join policy is high severity"
    );
}

#[test]
fn test_join_policy_rename_fires_name_chg() {
    let rules = analyze_and_get_rules("ALTER JOIN POLICY jp RENAME TO jp2;");
    assert!(rules.contains("SNW-JOINPOL-CHG"), "got {rules:?}");
    assert!(rules.contains("SNW-JOINPOL-NAME-CHG"), "got {rules:?}");
}

// ───────────────────────── body analysis ─────────────────────────

#[test]
fn test_join_policy_permissive_body() {
    // JOIN_REQUIRED => FALSE permits unrestricted joins.
    let rules = analyze_and_get_rules(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE);",
    );
    assert!(rules.contains("SNW-JOINPOL-PERMISSIVE"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-JOINPOL-REQUIRED"),
        "JOIN_REQUIRED => FALSE must not fire REQUIRED, got {rules:?}"
    );
}

#[test]
fn test_join_policy_required_body() {
    let rules = analyze_and_get_rules(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE);",
    );
    assert!(rules.contains("SNW-JOINPOL-REQUIRED"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-JOINPOL-PERMISSIVE"),
        "JOIN_REQUIRED => TRUE must not fire PERMISSIVE, got {rules:?}"
    );
}

#[test]
fn test_join_policy_set_body_permissive() {
    // The permissive body must be detected through ALTER … SET BODY too.
    let rules = analyze_and_get_rules(
        "ALTER JOIN POLICY jp SET BODY -> JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE);",
    );
    assert!(rules.contains("SNW-JOINPOL-PERMISSIVE"), "got {rules:?}");
}

#[test]
fn test_join_policy_tag_actions() {
    let rules = analyze_and_get_rules("ALTER JOIN POLICY jp SET TAG t = 'v';");
    assert!(rules.contains("SNW-JOINPOL-TAG-ADD"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER JOIN POLICY jp UNSET TAG t;");
    assert!(rules.contains("SNW-JOINPOL-TAG-RMV"), "got {rules:?}");
}

// ───────────────────────── table-attach ─────────────────────────

#[test]
fn test_table_set_join_policy_fires_attach_rule() {
    let rules = analyze_and_get_rules("ALTER TABLE t1 SET JOIN POLICY jp;");
    assert!(rules.contains("TBL-JOINPOL-SET"), "got {rules:?}");
}

#[test]
fn test_table_unset_join_policy_unchanged() {
    // UNSET JOIN POLICY remains covered by the existing TBL-AGGPOL-RMV rule
    // and must not fire the SET-attach rule.
    let rules = analyze_and_get_rules("ALTER TABLE t1 UNSET JOIN POLICY;");
    assert!(rules.contains("TBL-AGGPOL-RMV"), "got {rules:?}");
    assert!(!rules.contains("TBL-JOINPOL-SET"), "got {rules:?}");
}
