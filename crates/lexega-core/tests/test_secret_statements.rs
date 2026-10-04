// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake SECRET lifecycle statements.
//!
//! Covers parsing/formatting round-trips for CREATE / ALTER / DROP
//! SECRET and the SNW-SECRET-* governance rules. Also asserts the
//! least-leak invariant: secret values never appear in serialized
//! facts.

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
fn test_secret_formatting_variants() {
    assert_formats_safe(
        "CREATE SECRET my_oauth TYPE = OAUTH2 API_AUTHENTICATION = my_secintg OAUTH_SCOPES = ('read', 'write');\n\
         CREATE OR REPLACE SECRET db1.sch1.tok TYPE = OAUTH2 OAUTH_REFRESH_TOKEN = 'rt-1' OAUTH_REFRESH_TOKEN_EXPIRY_TIME = '2026-12-31' API_AUTHENTICATION = intg COMMENT = 'rt';\n\
         CREATE SECRET IF NOT EXISTS cloud_tok TYPE = CLOUD_PROVIDER_TOKEN API_AUTHENTICATION = 'aws_intg' ENABLED = TRUE;\n\
         CREATE SECRET basic_cred TYPE = PASSWORD USERNAME = 'svc_user' PASSWORD = 'hunter2';\n\
         CREATE SECRET \"My Secret\" TYPE = GENERIC_STRING SECRET_STRING = 'api-key' COMMENT = 'vendor';\n\
         CREATE SECRET sym TYPE = SYMMETRIC_KEY ALGORITHM = GENERIC;\n\
         ALTER SECRET my_oauth SET OAUTH_SCOPES = ('admin');\n\
         ALTER SECRET IF EXISTS basic_cred SET USERNAME = 'svc2' PASSWORD = 'npw' COMMENT = 'rotated';\n\
         ALTER SECRET basic_cred UNSET COMMENT;\n\
         DROP SECRET my_oauth;\n\
         DROP SECRET IF EXISTS db1.sch1.tok;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_secret_create_and_drop() {
    let rules = analyze_and_get_rules(
        "CREATE SECRET basic_cred TYPE = PASSWORD USERNAME = 'u' PASSWORD = 'p';",
    );
    assert!(rules.contains("SNW-SECRET-NEW"), "got {rules:?}");

    let rules = analyze_and_get_rules("DROP SECRET IF EXISTS basic_cred;");
    assert!(rules.contains("SNW-SECRET-DROP"), "got {rules:?}");
}

#[test]
fn test_secret_rotation() {
    let rules = analyze_and_get_rules("ALTER SECRET tok SET OAUTH_REFRESH_TOKEN = 'rt-99';");
    assert!(rules.contains("SNW-SECRET-ROTATED"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER SECRET s SET SECRET_STRING = 'new';");
    assert!(rules.contains("SNW-SECRET-ROTATED"), "got {rules:?}");

    // Non-credential property change is CHG, not ROTATED.
    let rules = analyze_and_get_rules("ALTER SECRET s SET OAUTH_SCOPES = ('read');");
    assert!(rules.contains("SNW-SECRET-CHG"), "got {rules:?}");
    assert!(!rules.contains("SNW-SECRET-ROTATED"), "got {rules:?}");
}

#[test]
fn test_secret_auth_integration_change() {
    let rules = analyze_and_get_rules("ALTER SECRET s SET API_AUTHENTICATION = other_intg;");
    assert!(rules.contains("SNW-SECRET-AUTH-CHG"), "got {rules:?}");
}

// ───────────────────────── least-leak invariant ─────────────────────────

#[test]
fn test_secret_values_never_in_facts() {
    // The serialized facts must carry property NAMES, never the literal
    // secret values written in the statement.
    let report = analyze_risk(
        "CREATE SECRET basic_cred TYPE = PASSWORD USERNAME = 'svc_user' PASSWORD = 'hunter2-value';",
    )
    .expect("should analyze");
    let json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        !json.contains("hunter2-value"),
        "secret value leaked into the serialized report"
    );
}

// ───────────────────────── negative cases ─────────────────────────

#[test]
fn test_drop_table_does_not_fire_secret_drop() {
    let rules = analyze_and_get_rules("DROP TABLE secret_audit;");
    assert!(!rules.contains("SNW-SECRET-DROP"), "got {rules:?}");
}

#[test]
fn test_security_integration_does_not_fire_secret_rules() {
    let rules =
        analyze_and_get_rules("CREATE SECURITY INTEGRATION my_saml TYPE = SAML2 ENABLED = TRUE;");
    assert!(
        !rules.iter().any(|r| r.starts_with("SNW-SECRET-")),
        "got {rules:?}"
    );
}
