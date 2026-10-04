// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake SECURITY INTEGRATION governance facts + rules.
//!
//! Covers the SNW-SECINTG-* family across CREATE / ALTER (SET, UNSET,
//! RENAME) / DROP, plus formatting round-trips and negative cases
//! (sibling integration kinds must not trip these rules).

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
fn test_security_integration_formatting_variants() {
    assert_formats_safe(
        "CREATE SECURITY INTEGRATION my_oauth TYPE = OAUTH ENABLED = TRUE OAUTH_CLIENT = CUSTOM;\n\
         CREATE OR REPLACE SECURITY INTEGRATION IF NOT EXISTS my_saml TYPE = SAML2 SAML2_ISSUER = 'https://idp.example.com' SAML2_FORCE_AUTHN = FALSE COMMENT = 'sso';\n\
         ALTER SECURITY INTEGRATION my_saml SET ENABLED = FALSE;\n\
         ALTER SECURITY INTEGRATION my_saml SET SAML2_FORCE_AUTHN = TRUE SAML2_SSO_URL = 'https://x';\n\
         ALTER SECURITY INTEGRATION my_saml UNSET SAML2_REQUESTED_NAMEID_FORMAT, COMMENT;\n\
         ALTER SECURITY INTEGRATION IF EXISTS my_saml RENAME TO my_saml2;\n\
         DROP SECURITY INTEGRATION my_saml2;\n\
         DROP SECURITY INTEGRATION IF EXISTS db1.my_scim;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_secintg_create() {
    let rules =
        analyze_and_get_rules("CREATE SECURITY INTEGRATION my_saml TYPE = SAML2 ENABLED = TRUE;");
    assert!(rules.contains("SNW-SECINTG-NEW"), "got {rules:?}");
}

#[test]
fn test_secintg_disable_enable() {
    let rules = analyze_and_get_rules("ALTER SECURITY INTEGRATION my_saml SET ENABLED = FALSE;");
    assert!(rules.contains("SNW-SECINTG-OFF"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-SECINTG-CHG"),
        "ENABLED is a typed flag, not a generic property change, got {rules:?}"
    );

    let rules = analyze_and_get_rules("ALTER SECURITY INTEGRATION my_saml SET ENABLED = TRUE;");
    assert!(rules.contains("SNW-SECINTG-ON"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER SECURITY INTEGRATION my_saml UNSET ENABLED;");
    assert!(
        rules.contains("SNW-SECINTG-ON"),
        "UNSET ENABLED reverts to default-enabled, got {rules:?}"
    );
}

#[test]
fn test_secintg_property_change() {
    let rules =
        analyze_and_get_rules("ALTER SECURITY INTEGRATION my_saml SET SAML2_FORCE_AUTHN = FALSE;");
    assert!(rules.contains("SNW-SECINTG-CHG"), "got {rules:?}");

    let rules =
        analyze_and_get_rules("ALTER SECURITY INTEGRATION my_saml UNSET SAML2_FORCE_AUTHN;");
    assert!(rules.contains("SNW-SECINTG-UNSET"), "got {rules:?}");
}

#[test]
fn test_secintg_rename_and_drop() {
    let rules = analyze_and_get_rules("ALTER SECURITY INTEGRATION my_saml RENAME TO my_saml2;");
    assert!(rules.contains("SNW-SECINTG-NAME-CHG"), "got {rules:?}");

    let rules = analyze_and_get_rules("DROP SECURITY INTEGRATION IF EXISTS my_saml2;");
    assert!(rules.contains("SNW-SECINTG-DROP"), "got {rules:?}");
}

// ───────────────────────── negative cases ─────────────────────────

#[test]
fn test_sibling_integrations_do_not_fire_secintg() {
    let rules = analyze_and_get_rules(
        "ALTER STORAGE INTEGRATION my_s3 SET ENABLED = FALSE;\n\
         CREATE NOTIFICATION INTEGRATION my_notif TYPE = QUEUE ENABLED = TRUE;",
    );
    assert!(
        !rules.iter().any(|r| r.contains("SECINTG")),
        "sibling integration kinds must not fire SNW-SECINTG-*, got {rules:?}"
    );
}

#[test]
fn test_drop_table_does_not_fire_secintg_drop() {
    let rules = analyze_and_get_rules("DROP TABLE security_integration_audit;");
    assert!(!rules.contains("SNW-SECINTG-DROP"), "got {rules:?}");
}
