// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake FILE FORMAT lifecycle statements.
//!
//! Covers parsing/formatting round-trips for CREATE / ALTER / DROP FILE
//! FORMAT and the SNW-FILEFORMAT-* / INFO-SNW-FILEFORMAT-* governance
//! rules. DROP routes through the generic DROP parser, gated to the
//! `FILE FORMAT` object type.

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
fn test_create_file_format_basic() {
    assert_formats_safe("CREATE FILE FORMAT my_csv_format TYPE = CSV;");
}

#[test]
fn test_create_file_format_all_variants() {
    assert_formats_safe(
        "CREATE FILE FORMAT my_csv_format TYPE = CSV;\n\
         CREATE OR REPLACE FILE FORMAT my_json_format TYPE = JSON COMMENT = 'json loader';\n\
         CREATE TEMPORARY FILE FORMAT IF NOT EXISTS db1.sch1.ff_qualified \
            TYPE = CSV FIELD_DELIMITER = '|' SKIP_HEADER = 1 COMPRESSION = GZIP \
            TRIM_SPACE = TRUE NULL_IF = ('NULL', '\\N', '') \
            FIELD_OPTIONALLY_ENCLOSED_BY = '\"' COMMENT = 'complex csv';\n\
         CREATE VOLATILE FILE FORMAT \"My Quoted FF\" TYPE = PARQUET;\n\
         CREATE FILE FORMAT just_a_name;",
    );
}

#[test]
fn test_alter_file_format_all_variants() {
    assert_formats_safe(
        "ALTER FILE FORMAT my_csv_format RENAME TO my_csv_format_v2;\n\
         ALTER FILE FORMAT IF EXISTS db1.sch1.ff_qualified RENAME TO db1.sch1.ff_new;\n\
         ALTER FILE FORMAT IF EXISTS my_csv SET FIELD_DELIMITER = ',' COMMENT = 'updated';\n\
         ALTER FILE FORMAT my_json SET COMPRESSION = AUTO;",
    );
}

#[test]
fn test_drop_file_format_formats() {
    assert_formats_safe("DROP FILE FORMAT my_csv_format;");
    assert_formats_safe("DROP FILE FORMAT IF EXISTS db1.sch1.ff_qualified;");
}

#[test]
fn test_file_format_multi_statement() {
    // Multi-statement block catches NodeId-collision and span bugs.
    assert_formats_safe(
        "CREATE FILE FORMAT ff1 TYPE = CSV;\n\
         CREATE OR REPLACE FILE FORMAT ff2 TYPE = JSON;\n\
         ALTER FILE FORMAT ff1 RENAME TO ff1_v2;\n\
         DROP FILE FORMAT ff2;",
    );
}

// ───────────────────────── recognition ─────────────────────────

#[test]
fn test_file_format_is_analyzed_not_skipped() {
    // Recognition: the statement reaches the analyzer (was OpaqueContent).
    let report = analyze_risk("CREATE FILE FORMAT my_csv TYPE = CSV;").expect("should analyze");
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(report.summary.statements_skipped, 0);
}

// ───────────────────────── rules ─────────────────────────

#[test]
fn test_rule_create_fires() {
    let rules = analyze_and_get_rules("CREATE FILE FORMAT my_csv TYPE = CSV;");
    assert!(rules.contains("INFO-SNW-FILEFORMAT-CREATE"));
}

#[test]
fn test_rule_replace_fires() {
    let rules = analyze_and_get_rules("CREATE OR REPLACE FILE FORMAT j TYPE = JSON;");
    assert!(rules.contains("SNW-FILEFORMAT-REPLACE"));
    // Creation info still fires alongside the replace signal.
    assert!(rules.contains("INFO-SNW-FILEFORMAT-CREATE"));
}

#[test]
fn test_rule_rename_fires() {
    let rules = analyze_and_get_rules("ALTER FILE FORMAT my_csv RENAME TO my_csv2;");
    assert!(rules.contains("SNW-FILEFORMAT-RENAME"));
}

#[test]
fn test_rule_drop_fires() {
    let rules = analyze_and_get_rules("DROP FILE FORMAT my_csv;");
    assert!(rules.contains("SNW-FILEFORMAT-DROP"));
}

// ───────────────────────── negatives ─────────────────────────

#[test]
fn test_plain_create_does_not_fire_replace() {
    let rules = analyze_and_get_rules("CREATE FILE FORMAT my_csv TYPE = CSV;");
    assert!(!rules.contains("SNW-FILEFORMAT-REPLACE"));
}

#[test]
fn test_alter_set_does_not_fire_rename() {
    // SET without RENAME must not surface the rename signal.
    let rules = analyze_and_get_rules("ALTER FILE FORMAT my_csv SET COMPRESSION = GZIP;");
    assert!(!rules.contains("SNW-FILEFORMAT-RENAME"));
}

#[test]
fn test_drop_other_object_does_not_fire_fileformat_drop() {
    // The `FILE FORMAT` drop gate must not catch unrelated drops.
    let rules = analyze_and_get_rules("DROP TABLE my_table;");
    assert!(!rules.contains("SNW-FILEFORMAT-DROP"));
}
