// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP IMAGE REPOSITORY` statement
//! family (Snowpark Container Services OCI registry): recognition of the
//! statement kind, the OR REPLACE supply-chain-swap distinction, the
//! SNW-IMGREPO-* rules, and byte-exact formatting. An image repository has no
//! governance value-slots (only COMMENT / TAG), so the only recognition axes
//! are existence (`kind`) and replacement (`ddl.options.or_replace`).

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
fn test_create_image_repository_fires_new() {
    let rules = analyze_and_get_rules("CREATE IMAGE REPOSITORY my_repo;");
    assert!(rules.contains("SNW-IMGREPO-NEW"), "got {rules:?}");
}

#[test]
fn test_create_image_repository_plain_is_not_replace() {
    // A fresh CREATE is recognized but is not a replacement — the supply-chain
    // swap recognition must not fire.
    let rules = analyze_and_get_rules("CREATE IMAGE REPOSITORY IF NOT EXISTS db.sc.my_repo;");
    assert!(rules.contains("SNW-IMGREPO-NEW"), "got {rules:?}");
    assert!(!rules.contains("SNW-IMGREPO-REPLACE"), "got {rules:?}");
}

#[test]
fn test_create_or_replace_image_repository_fires_replace() {
    // OR REPLACE drops and recreates the registry — the swap is recognized in
    // addition to NEW.
    let rules = analyze_and_get_rules("CREATE OR REPLACE IMAGE REPOSITORY my_repo COMMENT = 'x';");
    assert!(rules.contains("SNW-IMGREPO-NEW"), "got {rules:?}");
    assert!(rules.contains("SNW-IMGREPO-REPLACE"), "got {rules:?}");
}

#[test]
fn test_alter_image_repository_is_benign() {
    // ALTER SET / UNSET (comment/tag maintenance) parses but is governance-
    // benign: no IMGREPO rule fires.
    let set_rules = analyze_and_get_rules("ALTER IMAGE REPOSITORY r SET COMMENT = 'x';");
    assert!(
        !set_rules.iter().any(|r| r.starts_with("SNW-IMGREPO")),
        "got {set_rules:?}"
    );
    let unset_rules = analyze_and_get_rules("ALTER IMAGE REPOSITORY IF EXISTS r UNSET COMMENT;");
    assert!(
        !unset_rules.iter().any(|r| r.starts_with("SNW-IMGREPO")),
        "got {unset_rules:?}"
    );
}

#[test]
fn test_drop_image_repository_analyzes() {
    // DROP IMAGE REPOSITORY routes through the generic Drop gated on the
    // two-word object type; it must analyze cleanly.
    let report = analyze_risk("DROP IMAGE REPOSITORY r;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_image_repository_forms_format_safe() {
    assert_formats_safe("CREATE IMAGE REPOSITORY my_repo;");
    assert_formats_safe("CREATE OR REPLACE IMAGE REPOSITORY db.sc.my_repo COMMENT = 'images';");
    assert_formats_safe("CREATE IMAGE REPOSITORY IF NOT EXISTS r;");
    assert_formats_safe("ALTER IMAGE REPOSITORY r SET COMMENT = 'x';");
    assert_formats_safe("ALTER IMAGE REPOSITORY IF EXISTS r UNSET COMMENT;");
    assert_formats_safe("DROP IMAGE REPOSITORY r;");
}
