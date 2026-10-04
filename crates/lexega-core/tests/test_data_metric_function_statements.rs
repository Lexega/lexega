// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake CREATE / DROP DATA METRIC FUNCTION statements.
//!
//! Covers parsing/formatting round-trips and the SNW-DMF-* lifecycle rules.
//! (The ALTER TABLE ADD/DROP DATA METRIC FUNCTION table-attach is covered by
//! `test_data_metric_function_attach.rs`.)

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
fn test_dmf_formatting_variants() {
    assert_formats_safe(
        "CREATE DATA METRIC FUNCTION dmf1 (t TABLE(c NUMBER)) RETURNS NUMBER AS 'SELECT COUNT(*) FROM t WHERE c IS NULL';\n\
         CREATE OR REPLACE SECURE DATA METRIC FUNCTION db.sch.dmf2 (arg TABLE(col VARCHAR)) RETURNS NUMBER NOT NULL LANGUAGE SQL COMMENT = 'null count' AS $$ SELECT COUNT_IF(col IS NULL) FROM arg $$;\n\
         CREATE DATA METRIC FUNCTION IF NOT EXISTS dmf3 (t TABLE(a NUMBER, b NUMBER)) RETURNS NUMBER AS 'SELECT 0';\n\
         DROP DATA METRIC FUNCTION dmf1;\n\
         DROP DATA METRIC FUNCTION IF EXISTS db.sch.dmf2;",
    );
}

// ───────────────────────── rules ─────────────────────────

#[test]
fn test_dmf_create_fires_new() {
    let rules = analyze_and_get_rules(
        "CREATE DATA METRIC FUNCTION dmf (t TABLE(c NUMBER)) RETURNS NUMBER AS 'SELECT 1';",
    );
    assert!(rules.contains("INFO-SNW-DMF-NEW"), "got {rules:?}");
    assert!(
        !rules.contains("INFO-SNW-DMF-SECURE"),
        "a non-secure DMF must not fire SECURE, got {rules:?}"
    );
}

#[test]
fn test_dmf_secure_fires_secure() {
    let rules = analyze_and_get_rules(
        "CREATE SECURE DATA METRIC FUNCTION dmf (t TABLE(c NUMBER)) RETURNS NUMBER AS 'SELECT 1';",
    );
    assert!(rules.contains("INFO-SNW-DMF-NEW"), "got {rules:?}");
    assert!(rules.contains("INFO-SNW-DMF-SECURE"), "got {rules:?}");
}

#[test]
fn test_dmf_drop_fires_drop() {
    let rules = analyze_and_get_rules("DROP DATA METRIC FUNCTION dmf1;");
    assert!(rules.contains("SNW-DMF-DROP"), "got {rules:?}");

    let rules = analyze_and_get_rules("DROP DATA METRIC FUNCTION IF EXISTS db.sch.dmf2;");
    assert!(rules.contains("SNW-DMF-DROP"), "got {rules:?}");
}

#[test]
fn test_dmf_dollar_quoted_body() {
    // Dollar-quoted body must not fragment into a standalone SELECT.
    let report = analyze_risk(
        "CREATE DATA METRIC FUNCTION dmf (t TABLE(c NUMBER)) RETURNS NUMBER AS $$ SELECT COUNT(*) FROM t $$;",
    )
    .expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("INFO-SNW-DMF-NEW"), "got {rules:?}");
    assert!(
        rules.iter().all(|r| r.contains("DMF")),
        "the body must not surface standalone query findings, got {rules:?}"
    );
}

// ───────────────────────── negative cases ─────────────────────────

#[test]
fn test_regular_create_function_unaffected() {
    // A plain CREATE FUNCTION must not be treated as a data metric function.
    let rules = analyze_and_get_rules("CREATE FUNCTION f() RETURNS NUMBER AS 'SELECT 1';");
    assert!(!rules.contains("INFO-SNW-DMF-NEW"), "got {rules:?}");
}

#[test]
fn test_drop_function_unaffected() {
    // A plain DROP FUNCTION must not fire the DMF drop rule.
    let rules = analyze_and_get_rules("DROP FUNCTION f();");
    assert!(!rules.contains("SNW-DMF-DROP"), "got {rules:?}");
}
