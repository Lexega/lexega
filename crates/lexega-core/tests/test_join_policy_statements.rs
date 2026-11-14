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

fn extract_rule_ids(findings: &[RuleMatch]) -> HashSet<String> {
    findings
        .iter()
        .map(|f| match f {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.findings)
}

fn analyze_and_get_context(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.context)
}

/// Rule ids across findings and context.
fn analyze_and_get_entries(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    let mut ids = extract_rule_ids(&report.findings);
    ids.extend(extract_rule_ids(&report.context));
    ids
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
    let rules = analyze_and_get_context(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE);",
    );
    assert!(rules.contains("SNW-JOINPOL-NEW"), "got {rules:?}");

    let report = analyze_risk("DROP JOIN POLICY jp;").expect("should analyze");
    let rules = extract_rule_ids(&report.findings);
    assert!(rules.contains("SNW-JOINPOL-DROP"), "got {rules:?}");
    assert!(
        report.summary.medium_count >= 1,
        "dropping a join policy is medium severity"
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
    let rules = analyze_and_get_entries(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE);",
    );
    assert!(rules.contains("SNW-JOINPOL-PERMISSIVE"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-JOINPOL-REQUIRED"),
        "JOIN_REQUIRED => FALSE must not fire REQUIRED, got {rules:?}"
    );
}

#[test]
fn test_join_policy_exempted_role_is_not_permissive() {
    // One authorised role is exempt, everyone else must join on a predicate.
    for sql in [
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> CASE WHEN CURRENT_ROLE() = 'ADMIN' THEN JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE) ELSE JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE) END;",
        "ALTER JOIN POLICY jp SET BODY -> CASE WHEN CURRENT_ROLE() = 'ADMIN' THEN JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE) ELSE JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE) END;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(!rules.contains("SNW-JOINPOL-PERMISSIVE"), "got {rules:?} for {sql}");
    }
}

#[test]
fn test_join_policy_permissive_default_fires() {
    // A restrictive WHEN does not matter: the ELSE is permissive, or absent
    // (the default is NULL, undecided).
    for body in [
        "CASE WHEN CURRENT_ROLE() = 'ANALYST' THEN JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE) ELSE JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE) END",
        "CASE WHEN CURRENT_ROLE() = 'ANALYST' THEN JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE) END",
    ] {
        for sql in [
            format!("CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> {body};"),
            format!("ALTER JOIN POLICY jp SET BODY -> {body};"),
        ] {
            let rules = analyze_and_get_rules(&sql);
            assert!(rules.contains("SNW-JOINPOL-PERMISSIVE"), "got {rules:?} for {sql}");
        }
    }
}

#[test]
fn test_join_policy_every_branch_permissive() {
    let rules = analyze_and_get_rules(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> CASE WHEN CURRENT_ROLE() = 'ADMIN' THEN JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE) ELSE JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE) END;",
    );
    assert!(rules.contains("SNW-JOINPOL-PERMISSIVE"), "got {rules:?}");
}

#[test]
fn test_join_policy_permissive_is_high() {
    let report = analyze_risk(
        "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => FALSE);",
    )
    .expect("should analyze successfully");
    assert!(report.findings.iter().any(|f| {
        let RuleMatch::Analysis(g) = f;
        g.matched_rule == "SNW-JOINPOL-PERMISSIVE"
            && g.risk_level == lexega_core::analyzer::RiskLevel::High
    }));
}

#[test]
fn test_join_policy_required_body() {
    let sql = "CREATE JOIN POLICY jp AS () RETURNS JOIN_CONSTRAINT -> JOIN_CONSTRAINT(JOIN_REQUIRED => TRUE);";
    let context = analyze_and_get_context(sql);
    assert!(context.contains("SNW-JOINPOL-REQUIRED"), "got {context:?}");
    let rules = analyze_and_get_entries(sql);
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
    let rules = analyze_and_get_context("ALTER JOIN POLICY jp SET TAG t = 'v';");
    assert!(rules.contains("SNW-JOINPOL-TAG-ADD"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER JOIN POLICY jp UNSET TAG t;");
    assert!(rules.contains("SNW-JOINPOL-TAG-RMV"), "got {rules:?}");
}

// ───────────────────────── table-attach ─────────────────────────

#[test]
fn test_table_set_join_policy_fires_attach_rule() {
    let rules = analyze_and_get_context("ALTER TABLE t1 SET JOIN POLICY jp;");
    assert!(rules.contains("TBL-JOINPOL-SET"), "got {rules:?}");
}

#[test]
fn test_table_unset_join_policy_unchanged() {
    // UNSET JOIN POLICY remains covered by the existing TBL-AGGPOL-RMV rule
    // and must not fire the SET-attach rule.
    let rules = analyze_and_get_entries("ALTER TABLE t1 UNSET JOIN POLICY;");
    assert!(rules.contains("TBL-AGGPOL-RMV"), "got {rules:?}");
    assert!(!rules.contains("TBL-JOINPOL-SET"), "got {rules:?}");
}
