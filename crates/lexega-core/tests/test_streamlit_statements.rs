// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP STREAMLIT` statement family.
//! A Streamlit object runs a Python app hosted from a stage. The governance
//! recognition surface is whether it declares `EXTERNAL_ACCESS_INTEGRATIONS`
//! (network egress); covers the SNW-STREAMLIT-* rules, the create/alter
//! recognition, and byte-exact formatting.

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

#[test]
fn test_create_streamlit_fires_new() {
    let rules = analyze_and_get_rules(
        "CREATE STREAMLIT s ROOT_LOCATION='@db.sc.stage/app' MAIN_FILE='app.py' QUERY_WAREHOUSE=wh;",
    );
    assert!(rules.contains("SNW-STREAMLIT-NEW"), "got {rules:?}");
}

#[test]
fn test_create_streamlit_without_eai_is_not_external_access() {
    // A Streamlit with no EXTERNAL_ACCESS_INTEGRATIONS is recognized but is not
    // an egress surface — the external-access rule must not fire.
    let rules = analyze_and_get_rules(
        "CREATE STREAMLIT s ROOT_LOCATION='@s/a' MAIN_FILE='app.py' QUERY_WAREHOUSE=wh;",
    );
    assert!(rules.contains("SNW-STREAMLIT-NEW"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-STREAMLIT-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_create_streamlit_with_eai_fires_external_access() {
    // EXTERNAL_ACCESS_INTEGRATIONS declares network egress — the egress rule
    // fires in addition to NEW.
    let rules = analyze_and_get_rules(
        "CREATE STREAMLIT s ROOT_LOCATION='@s/a' MAIN_FILE='app.py' EXTERNAL_ACCESS_INTEGRATIONS=(eai1,eai2);",
    );
    assert!(rules.contains("SNW-STREAMLIT-NEW"), "got {rules:?}");
    assert!(
        rules.contains("SNW-STREAMLIT-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_alter_streamlit_set_eai_fires_external_access() {
    // ALTER … SET EXTERNAL_ACCESS_INTEGRATIONS adds egress after creation — the
    // egress rule must fire on the alter path too.
    let rules = analyze_and_get_rules("ALTER STREAMLIT s SET EXTERNAL_ACCESS_INTEGRATIONS=(eai1);");
    assert!(
        rules.contains("SNW-STREAMLIT-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_alter_streamlit_benign_set_fires_nothing() {
    // A non-egress SET / UNSET parses but is governance-benign.
    let set_rules = analyze_and_get_rules("ALTER STREAMLIT s SET QUERY_WAREHOUSE=wh2;");
    assert!(
        !set_rules.iter().any(|r| r.starts_with("SNW-STREAMLIT")),
        "got {set_rules:?}"
    );
    let unset_rules = analyze_and_get_rules("ALTER STREAMLIT IF EXISTS s UNSET COMMENT;");
    assert!(
        !unset_rules.iter().any(|r| r.starts_with("SNW-STREAMLIT")),
        "got {unset_rules:?}"
    );
}

#[test]
fn test_drop_streamlit_analyzes() {
    // DROP STREAMLIT routes through the generic single-word Drop; analyze clean.
    let report = analyze_risk("DROP STREAMLIT s;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_streamlit_forms_format_safe() {
    assert_formats_safe(
        "CREATE STREAMLIT s ROOT_LOCATION='@db.sc.stage/app' MAIN_FILE='app.py' QUERY_WAREHOUSE=wh;",
    );
    assert_formats_safe(
        "CREATE OR REPLACE STREAMLIT s ROOT_LOCATION='@s/a' MAIN_FILE='app.py' EXTERNAL_ACCESS_INTEGRATIONS=(eai1,eai2);",
    );
    assert_formats_safe("ALTER STREAMLIT IF EXISTS s SET QUERY_WAREHOUSE=wh2;");
    assert_formats_safe("ALTER STREAMLIT s UNSET COMMENT;");
    assert_formats_safe("DROP STREAMLIT s;");
}
