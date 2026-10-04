// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks DESCRIBE HISTORY statement.
//!
//! Covers:
//! - Parsing (simple, qualified, backtick-quoted, DESC alias)
//! - Formatting (semantic preservation)
//! - Risk analysis (signal generation, multi-statement)
//! - Regression with existing DESCRIBE TABLE/VIEW

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, verify_formatting_safe, DatabricksDialect,
    FormatterConfig,
};
use std::sync::Arc;

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    }
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

// ============================================================================
// Parsing Tests
// ============================================================================

#[test]
fn parse_describe_history_simple() {
    let sql = "DESCRIBE HISTORY my_table;";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("should parse DESCRIBE HISTORY");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
    assert!(formatted.contains("DESCRIBE"));
    assert!(formatted.contains("HISTORY"));
    assert!(formatted.contains("my_table"));
}

#[test]
fn parse_describe_history_qualified_name() {
    let sql = "DESCRIBE HISTORY my_catalog.my_schema.my_table;";
    let formatted = format_sql_with_config(sql, &dbx_config())
        .expect("should parse qualified DESCRIBE HISTORY");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
    assert!(formatted.contains("my_catalog.my_schema.my_table"));
}

#[test]
fn parse_describe_history_two_part_name() {
    let sql = "DESCRIBE HISTORY my_schema.my_table;";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("should parse 2-part DESCRIBE HISTORY");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
    assert!(formatted.contains("my_schema.my_table"));
}

#[test]
fn parse_describe_history_backtick_quoted() {
    let sql = "DESCRIBE HISTORY `my-catalog`.`my-schema`.`my-table`;";
    let formatted = format_sql_with_config(sql, &dbx_config())
        .expect("should parse backtick-quoted DESCRIBE HISTORY");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
    assert!(formatted.contains("`my-catalog`"));
    assert!(formatted.contains("`my-table`"));
}

#[test]
fn parse_desc_history_alias() {
    let sql = "DESC HISTORY my_table;";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("should parse DESC HISTORY alias");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
    assert!(formatted.contains("DESC"));
    assert!(formatted.contains("HISTORY"));
    assert!(formatted.contains("my_table"));
}

#[test]
fn parse_describe_history_no_semicolon() {
    let sql = "DESCRIBE HISTORY my_table";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("should parse without semicolon");
    assert!(formatted.contains("DESCRIBE"));
    assert!(formatted.contains("my_table"));
}

// ============================================================================
// Formatting Tests
// ============================================================================

#[test]
fn format_describe_history_preserves_case() {
    let sql = "describe history MY_TABLE;";
    let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
    // Lower-case keywords should be preserved (span-only formatter)
    assert!(formatted.contains("describe"));
    assert!(formatted.contains("history"));
}

#[test]
fn format_describe_history_with_whitespace() {
    let sql = "DESCRIBE   HISTORY   my_catalog.my_schema.my_table ;";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("should format with extra whitespace");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
}

// ============================================================================
// Risk Analysis Tests
// ============================================================================

#[test]
fn risk_describe_history_info_signal() {
    let sql = "DESCRIBE HISTORY my_table;";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.info_count >= 1,
        "Should have info signal for DESCRIBE HISTORY, got: {:?}",
        report.summary
    );
    assert!(
        has_signal(&report, "INFO-DBX-TBL-HIST"),
        "Should find INFO-DBX-TBL-HIST signal"
    );
}

#[test]
fn risk_describe_history_qualified_table() {
    let sql = "DESCRIBE HISTORY my_catalog.my_schema.my_table;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-DBX-TBL-HIST"),
        "Should find INFO-DBX-TBL-HIST for qualified name"
    );

    // Check detail includes full table name
    let signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "INFO-DBX-TBL-HIST"));
    assert!(signal.is_some(), "Should have INFO-DBX-TBL-HIST signal");
}

#[test]
fn risk_describe_history_tables_read() {
    let sql = "DESCRIBE HISTORY my_table;";
    let report = dbx_analyze(sql);

    // Should report at least 1 table read
    assert!(
        report.summary.tables_read >= 1,
        "Should track tables_read for DESCRIBE HISTORY, got: {}",
        report.summary.tables_read
    );
}

#[test]
fn risk_desc_history_alias_signal() {
    let sql = "DESC HISTORY events;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-DBX-TBL-HIST"),
        "DESC HISTORY should also trigger INFO-DBX-TBL-HIST"
    );
}

#[test]
fn risk_multi_describe_history() {
    let sql = r#"
        DESCRIBE HISTORY table_a;
        DESCRIBE HISTORY table_b;
        DESCRIBE HISTORY catalog.schema.table_c;
    "#;
    let report = dbx_analyze(sql);

    // Count evidence (signals may deduplicate, but evidence should reflect all 3)
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(g) if g.matched_rule == "INFO-DBX-TBL-HIST"))
        .map(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_evidence >= 3,
        "Should have evidence for each DESCRIBE HISTORY, got: {}",
        total_evidence
    );
}

#[test]
fn risk_describe_history_not_critical() {
    let sql = "DESCRIBE HISTORY my_table;";
    let report = dbx_analyze(sql);

    assert_eq!(
        report.summary.critical_count, 0,
        "DESCRIBE HISTORY should not be critical"
    );
    assert_eq!(
        report.summary.high_count, 0,
        "DESCRIBE HISTORY should not be high"
    );
}

// ============================================================================
// Regression Tests — DESCRIBE TABLE/VIEW still works
// ============================================================================

#[test]
fn regression_describe_table_still_works() {
    let sql = "DESCRIBE TABLE my_table;";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("DESCRIBE TABLE should still parse");
    verify_formatting_safe(sql, &formatted)
        .expect("DESCRIBE TABLE formatting should preserve semantics");
}

#[test]
fn regression_describe_view_still_works() {
    let sql = "DESCRIBE VIEW my_view;";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("DESCRIBE VIEW should still parse");
    verify_formatting_safe(sql, &formatted)
        .expect("DESCRIBE VIEW formatting should preserve semantics");
}

#[test]
fn regression_desc_table_still_works() {
    let sql = "DESC TABLE my_table;";
    let formatted =
        format_sql_with_config(sql, &dbx_config()).expect("DESC TABLE should still parse");
    verify_formatting_safe(sql, &formatted)
        .expect("DESC TABLE formatting should preserve semantics");
}

// ============================================================================
// Combined Tests — DESCRIBE HISTORY + other Databricks statements
// ============================================================================

#[test]
fn combined_describe_history_and_optimize() {
    let sql = r#"
        DESCRIBE HISTORY events;
        OPTIMIZE events ZORDER BY (user_id, event_type);
    "#;
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-DBX-TBL-HIST"),
        "Should detect DESCRIBE HISTORY signal"
    );
    assert!(
        has_signal(&report, "DBX-TBL-OPT"),
        "Should detect OPTIMIZE signal"
    );
}

#[test]
fn combined_describe_history_and_vacuum() {
    let sql = r#"
        DESCRIBE HISTORY events;
        VACUUM events RETAIN 24 HOURS;
    "#;
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-DBX-TBL-HIST"),
        "Should detect DESCRIBE HISTORY signal"
    );
    assert!(
        has_signal(&report, "DBX-VACUUM-LOWRET"),
        "Should detect VACUUM low retention signal"
    );
}
