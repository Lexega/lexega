// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP NOTEBOOK` statement family.
//! A notebook runs code hosted from a stage. Covers the SNW-NOTEBOOK-* rules,
//! the EXTERNAL_ACCESS_INTEGRATIONS egress recognition (shared with
//! STREAMLIT/SERVICE), and byte-exact formatting — including the optional
//! `FROM '<stage_path>'` clause absorbed by the property walk.

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
fn test_create_notebook_fires_new() {
    let rules = analyze_and_get_rules(
        "CREATE NOTEBOOK n FROM '@s/a' MAIN_FILE='n.ipynb' QUERY_WAREHOUSE=wh;",
    );
    assert!(rules.contains("SNW-NOTEBOOK-NEW"), "got {rules:?}");
}

#[test]
fn test_create_notebook_without_eai_is_not_external_access() {
    let rules = analyze_and_get_rules("CREATE NOTEBOOK n MAIN_FILE='n.ipynb' QUERY_WAREHOUSE=wh;");
    assert!(rules.contains("SNW-NOTEBOOK-NEW"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-NOTEBOOK-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_create_notebook_with_eai_fires_external_access() {
    let rules = analyze_and_get_rules(
        "CREATE NOTEBOOK n MAIN_FILE='n.ipynb' EXTERNAL_ACCESS_INTEGRATIONS=(eai1,eai2);",
    );
    assert!(rules.contains("SNW-NOTEBOOK-NEW"), "got {rules:?}");
    assert!(
        rules.contains("SNW-NOTEBOOK-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_alter_notebook_set_eai_fires_external_access() {
    let rules = analyze_and_get_rules("ALTER NOTEBOOK n SET EXTERNAL_ACCESS_INTEGRATIONS=(eai1);");
    assert!(
        rules.contains("SNW-NOTEBOOK-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_alter_notebook_benign_set_fires_nothing() {
    let set_rules = analyze_and_get_rules("ALTER NOTEBOOK n SET COMMENT='x';");
    assert!(
        !set_rules.iter().any(|r| r.starts_with("SNW-NOTEBOOK")),
        "got {set_rules:?}"
    );
    let unset_rules = analyze_and_get_rules("ALTER NOTEBOOK IF EXISTS n UNSET COMMENT;");
    assert!(
        !unset_rules.iter().any(|r| r.starts_with("SNW-NOTEBOOK")),
        "got {unset_rules:?}"
    );
}

#[test]
fn test_drop_notebook_analyzes() {
    let report = analyze_risk("DROP NOTEBOOK n;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_notebook_forms_format_safe() {
    // The optional `FROM '<stage_path>'` clause must round-trip byte-exactly.
    assert_formats_safe(
        "CREATE NOTEBOOK n FROM '@stage/path' MAIN_FILE='n.ipynb' QUERY_WAREHOUSE=wh;",
    );
    assert_formats_safe(
        "CREATE OR REPLACE NOTEBOOK db.sc.n MAIN_FILE='n.ipynb' EXTERNAL_ACCESS_INTEGRATIONS=(eai1,eai2);",
    );
    assert_formats_safe("ALTER NOTEBOOK IF EXISTS n SET COMMENT='x';");
    assert_formats_safe("ALTER NOTEBOOK n UNSET COMMENT;");
    assert_formats_safe("DROP NOTEBOOK n;");
}
