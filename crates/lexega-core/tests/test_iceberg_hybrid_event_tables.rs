// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE { ICEBERG | HYBRID | EVENT } TABLE`
//! variants: parser routing through CreateTable, the `ddl.table.variant`
//! recognition fact, the per-kind governance rules
//! (SNW-ICEBERG-TABLE / INFO-SNW-HYBRID-TABLE / SNW-EVENT-TABLE), and
//! byte-exact formatting of the variant keyword.

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
fn test_iceberg_table_fires_rule() {
    let rules = analyze_and_get_rules("CREATE ICEBERG TABLE t (id INT);");
    assert!(rules.contains("SNW-ICEBERG-TABLE"), "got {rules:?}");
}

#[test]
fn test_hybrid_table_fires_rule() {
    let rules = analyze_and_get_rules("CREATE HYBRID TABLE t (id INT);");
    assert!(rules.contains("INFO-SNW-HYBRID-TABLE"), "got {rules:?}");
}

#[test]
fn test_event_table_fires_rule() {
    let rules = analyze_and_get_rules("CREATE EVENT TABLE t (id INT);");
    assert!(rules.contains("SNW-EVENT-TABLE"), "got {rules:?}");
}

#[test]
fn test_iceberg_table_with_external_volume_and_or_replace() {
    // Realistic Iceberg form: external volume + catalog + base location, with
    // OR REPLACE. The trailing options are absorbed by the table-options
    // parser; the variant is still recognized and OR REPLACE still flagged.
    let rules = analyze_and_get_rules(
        "CREATE OR REPLACE ICEBERG TABLE db.sch.t (id INT) \
         EXTERNAL_VOLUME='vol' CATALOG='cat' BASE_LOCATION='path/';",
    );
    assert!(rules.contains("SNW-ICEBERG-TABLE"), "got {rules:?}");
    assert!(rules.contains("TBL-REPLACE"), "got {rules:?}");
}

#[test]
fn test_plain_table_fires_no_variant_rule() {
    // An ordinary table must carry no variant fact and fire none of the
    // three kind-specific rules.
    let rules = analyze_and_get_rules("CREATE TABLE t (id INT);");
    assert!(!rules.contains("SNW-ICEBERG-TABLE"), "got {rules:?}");
    assert!(!rules.contains("INFO-SNW-HYBRID-TABLE"), "got {rules:?}");
    assert!(!rules.contains("SNW-EVENT-TABLE"), "got {rules:?}");
}

#[test]
fn test_bare_create_event_is_not_an_event_table() {
    // EVENT is a table-kind modifier ONLY when followed by TABLE. A bare
    // `CREATE EVENT <name>` must not be misclassified as an event table.
    let rules = analyze_and_get_rules("CREATE EVENT some_event;");
    assert!(!rules.contains("SNW-EVENT-TABLE"), "got {rules:?}");
}

#[test]
fn test_variant_tables_format_safe() {
    assert_formats_safe("CREATE ICEBERG TABLE t (id INT);");
    assert_formats_safe("CREATE HYBRID TABLE t (id INT);");
    assert_formats_safe("CREATE EVENT TABLE t (id INT);");
    assert_formats_safe(
        "CREATE OR REPLACE ICEBERG TABLE db.sch.t (id INT) \
         EXTERNAL_VOLUME='vol' CATALOG='cat' BASE_LOCATION='path/';",
    );
}
