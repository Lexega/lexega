// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake SHARE governance facts + rules.
//!
//! Covers the SNW-SHARE-* family across CREATE / ALTER (ADD / REMOVE /
//! SET ACCOUNTS, property changes) / DROP, plus formatting round-trips
//! and negative cases (Redshift DATASHARE and GRANT TO SHARE flow
//! through their own substrates).

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
fn test_share_formatting_variants() {
    assert_formats_safe(
        "CREATE SHARE sales_share COMMENT = 'q4 partner share';\n\
         CREATE OR REPLACE SHARE IF NOT EXISTS s2;\n\
         ALTER SHARE sales_share ADD ACCOUNTS = org1.partner_acct, org2.other;\n\
         ALTER SHARE sales_share REMOVE ACCOUNTS = org2.other;\n\
         ALTER SHARE sales_share SET ACCOUNTS = org9.replacement;\n\
         ALTER SHARE IF EXISTS sales_share SET SHARE_RESTRICTIONS = FALSE;\n\
         ALTER SHARE sales_share UNSET COMMENT;\n\
         DROP SHARE IF EXISTS sales_share;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_share_create_and_drop() {
    let rules = analyze_and_get_rules("CREATE SHARE sales_share;");
    assert!(rules.contains("SNW-SHARE-NEW"), "got {rules:?}");

    let rules = analyze_and_get_rules("DROP SHARE IF EXISTS sales_share;");
    assert!(rules.contains("SNW-SHARE-DROP"), "got {rules:?}");
}

#[test]
fn test_share_account_changes() {
    let report =
        analyze_risk("ALTER SHARE s ADD ACCOUNTS = org1.partner_acct;").expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("SNW-SHARE-ACCOUNTS-ADD"), "got {rules:?}");
    assert!(
        report.summary.critical_count >= 1,
        "adding a consumer account is the exfil-enable action"
    );

    let rules = analyze_and_get_rules("ALTER SHARE s SET ACCOUNTS = org9.r1, org9.r2;");
    assert!(rules.contains("SNW-SHARE-ACCOUNTS-SET"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-SHARE-ACCOUNTS-ADD"),
        "SET is not ADD, got {rules:?}"
    );

    let rules = analyze_and_get_rules("ALTER SHARE s REMOVE ACCOUNTS = org1.partner_acct;");
    assert!(rules.contains("SNW-SHARE-ACCOUNTS-RMV"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-SHARE-ACCOUNTS-ADD"),
        "REMOVE must not fire ADD, got {rules:?}"
    );
}

#[test]
fn test_share_property_changes() {
    let rules = analyze_and_get_rules("ALTER SHARE s SET SHARE_RESTRICTIONS = FALSE;");
    assert!(rules.contains("SNW-SHARE-CHG"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER SHARE s UNSET COMMENT;");
    assert!(rules.contains("SNW-SHARE-CHG"), "got {rules:?}");
}

// ───────────────────────── negative cases ─────────────────────────

#[test]
fn test_datashare_does_not_fire_snowflake_share_rules() {
    let rules = analyze_and_get_rules("CREATE DATASHARE rs_share SET PUBLICACCESSIBLE TRUE;");
    assert!(
        !rules.iter().any(|r| r.starts_with("SNW-SHARE")),
        "Redshift DATASHARE must not fire SNW-SHARE-*, got {rules:?}"
    );
}

#[test]
fn test_grant_to_share_not_duplicated() {
    // GRANT … TO SHARE flows through the privilege substrate (GRT-TO-SHARE);
    // the share facts path must not double-report it.
    let rules = analyze_and_get_rules("GRANT SELECT ON TABLE t1 TO SHARE sales_share;");
    assert!(rules.contains("GRT-TO-SHARE"), "got {rules:?}");
    assert!(
        !rules.iter().any(|r| r.starts_with("SNW-SHARE")),
        "grants must not fire SNW-SHARE-* lifecycle rules, got {rules:?}"
    );
}

#[test]
fn test_drop_table_does_not_fire_share_drop() {
    let rules = analyze_and_get_rules("DROP TABLE share_audit;");
    assert!(!rules.contains("SNW-SHARE-DROP"), "got {rules:?}");
}
