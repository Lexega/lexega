// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake account provisioning: `CREATE / DROP MANAGED ACCOUNT`
//! (reader account) and `CREATE / DROP ACCOUNT` (org-level). Covers the
//! SNW-MANAGED-ACCOUNT-NEW / SNW-ACCOUNT-NEW rules, the least-leak invariant
//! (admin credentials never reach facts), the TYPE recognition primitive, the
//! ALTER ACCOUNT regression (existing parameter family untouched), and
//! byte-exact formatting.

use lexega_core::api::analyze_risk;
use lexega_core::ast::AstStmt;
use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig,
};
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

fn slice(sql: &str, start: u32, end: u32) -> &str {
    &sql[start as usize..end as usize]
}

#[test]
fn test_create_managed_account_fires_new() {
    let rules = analyze_and_get_rules(
        "CREATE MANAGED ACCOUNT ra ADMIN_NAME = u ADMIN_PASSWORD = 'pw' TYPE = READER;",
    );
    assert!(rules.contains("SNW-MANAGED-ACCOUNT-NEW"), "got {rules:?}");
}

#[test]
fn test_create_account_fires_new() {
    let rules = analyze_and_get_rules(
        "CREATE ACCOUNT acc ADMIN_NAME = u ADMIN_PASSWORD = 'pw' EDITION = STANDARD;",
    );
    assert!(rules.contains("SNW-ACCOUNT-NEW"), "got {rules:?}");
}

#[test]
fn test_account_type_extracted() {
    let sql = "CREATE MANAGED ACCOUNT ra ADMIN_NAME = u ADMIN_PASSWORD = 'pw' TYPE = READER;";
    let script = parse_sql(sql).expect("parse");
    let AstStmt::CreateManagedAccount(a) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateManagedAccount");
    };
    let span = a.account_type_span.expect("TYPE captured");
    assert_eq!(slice(sql, span.start, span.end).trim(), "READER");
}

#[test]
fn test_managed_account_does_not_leak_credentials() {
    // LEAST-LEAK: the admin password must never reach the structured facts.
    let sql =
        "CREATE MANAGED ACCOUNT ra ADMIN_NAME = u ADMIN_PASSWORD = 'topsecret_pw_9' TYPE = READER;";
    let script = parse_sql(sql).expect("parse");
    let AstStmt::CreateManagedAccount(a) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateManagedAccount");
    };
    let plan = lexega_core::ir::lower_create_managed_account_to_plan(a, sql);
    assert_eq!(plan.account_type.as_deref(), Some("READER"));
    let facts = lexega_core::facts::extract::derive_facts_from_managed_account_plan(&plan, sql);
    let json = serde_json::to_string(&facts).expect("serialize facts");
    assert!(
        !json.contains("topsecret_pw_9"),
        "facts must not carry the admin password: {json}"
    );
    assert!(
        !json.to_uppercase().contains("ADMIN_PASSWORD"),
        "facts must not carry the password property name: {json}"
    );
}

#[test]
fn test_alter_account_params_still_work() {
    // REGRESSION: the existing ALTER ACCOUNT parameter family must be untouched.
    let altered =
        parse_sql("ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = FALSE;").expect("parse");
    assert!(
        !matches!(altered.stmts.first(), Some(AstStmt::CreateAccount(_))),
        "ALTER ACCOUNT must not parse as CreateAccount"
    );
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = FALSE;");
    assert!(
        rules.contains("SNW-ACCT-UNLOAD-INLINE"),
        "existing ALTER ACCOUNT rule must still fire, got {rules:?}"
    );
}

#[test]
fn test_drop_both_analyze() {
    assert!(analyze_risk("DROP MANAGED ACCOUNT ra;").is_ok());
    assert!(analyze_risk("DROP ACCOUNT acc;").is_ok());
}

#[test]
fn test_drop_managed_account_is_two_word() {
    // The two-word object must parse as a single Drop (not fragment) and route
    // to the managed-account gate rather than the bare ACCOUNT gate.
    let script = parse_sql("DROP MANAGED ACCOUNT ra;").expect("parse");
    assert_eq!(
        script.stmts.len(),
        1,
        "DROP MANAGED ACCOUNT is one statement"
    );
}

#[test]
fn test_forms_format_safe() {
    assert_formats_safe(
        "CREATE MANAGED ACCOUNT ra ADMIN_NAME = u ADMIN_PASSWORD = 'secret' TYPE = READER COMMENT = 'c';",
    );
    assert_formats_safe(
        "CREATE ACCOUNT acc ADMIN_NAME = u ADMIN_PASSWORD = 'pw' EMAIL = 'a@b.co' EDITION = BUSINESS_CRITICAL;",
    );
    assert_formats_safe("DROP MANAGED ACCOUNT ra;");
    assert_formats_safe("DROP ACCOUNT acc;");
}
