// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake `ALTER TABLE { ADD | DROP } DATA METRIC FUNCTION`.
//!
//! These attach/detach a data-quality metric function to a table. Covers the
//! parsed action variants (ADD is not an ADD COLUMN) and the
//! TBL-DMF-{ADD,DROP} governance rules.

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
fn test_dmf_attach_formatting() {
    assert_formats_safe(
        "ALTER TABLE t1 ADD DATA METRIC FUNCTION dmf1 ON (c1);\n\
         ALTER TABLE db.sch.t2 ADD DATA METRIC FUNCTION my_db.my_sch.null_count ON (col_a, col_b);\n\
         ALTER TABLE t1 DROP DATA METRIC FUNCTION dmf1 ON (c1);",
    );
}

#[test]
fn test_dmf_add_fires_rule() {
    let rules = analyze_and_get_rules("ALTER TABLE t1 ADD DATA METRIC FUNCTION dmf1 ON (c1);");
    assert!(rules.contains("TBL-DMF-ADD"), "got {rules:?}");
    // Must NOT be mis-parsed as an ADD COLUMN.
    assert!(
        !rules.contains("TBL-COL-ADD"),
        "ADD DATA METRIC FUNCTION must not parse as ADD COLUMN, got {rules:?}"
    );
}

#[test]
fn test_dmf_drop_fires_rule() {
    let rules = analyze_and_get_rules("ALTER TABLE t1 DROP DATA METRIC FUNCTION dmf1 ON (c1);");
    assert!(rules.contains("TBL-DMF-DROP"), "got {rules:?}");
    assert!(
        !rules.contains("TBL-COL-DROP"),
        "DROP DATA METRIC FUNCTION must not parse as DROP COLUMN, got {rules:?}"
    );
}

#[test]
fn test_dmf_qualified_name_and_multi_column() {
    let rules = analyze_and_get_rules(
        "ALTER TABLE t ADD DATA METRIC FUNCTION my_db.my_sch.dmf ON (a, b, c);",
    );
    assert!(rules.contains("TBL-DMF-ADD"), "got {rules:?}");
}

// ───────────────────────── negative cases ─────────────────────────

#[test]
fn test_real_add_column_still_works() {
    // A genuine ADD COLUMN must still parse as a column add (the DMF branch
    // is gated on DATA + METRIC lookahead).
    let rules = analyze_and_get_rules("ALTER TABLE t1 ADD COLUMN data_col NUMBER;");
    assert!(rules.contains("TBL-COL-ADD"), "got {rules:?}");
    assert!(!rules.contains("TBL-DMF-ADD"), "got {rules:?}");
}

#[test]
fn test_unset_join_policy_unaffected() {
    // Sanity: the sibling SET/UNSET JOIN POLICY actions still behave.
    let rules = analyze_and_get_rules("ALTER TABLE t1 UNSET JOIN POLICY;");
    assert!(rules.contains("TBL-AGGPOL-RMV"), "got {rules:?}");
    assert!(!rules.contains("TBL-DMF-ADD"), "got {rules:?}");
}
