// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks RESTORE statement.
//!
//! Covers:
//! - Parsing (TIMESTAMP AS OF, VERSION AS OF, optional TABLE/TO, qualified names)
//! - Formatting (semantic preservation)
//! - Risk analysis (signal generation, tables_written, multi-statement)
//! - Regression with existing Databricks statements

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql_with_dialect,
    verify_formatting_safe, AstStmt, DatabricksDialect, FormatterConfig,
};
use std::sync::Arc;

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    }
}

fn dbx_format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &dbx_config())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
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

fn parses_as_restore(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::Restore(_)))
}

// ============================================================================
// Parsing Tests — verify RESTORE parses as AstRestore, not OpaqueContent
// ============================================================================

#[test]
fn parse_restore_timestamp_basic() {
    assert!(parses_as_restore(
        "RESTORE TABLE my_table TO TIMESTAMP AS OF '2024-01-01';"
    ));
}

#[test]
fn parse_restore_version_basic() {
    assert!(parses_as_restore(
        "RESTORE TABLE my_table TO VERSION AS OF 5;"
    ));
}

#[test]
fn parse_restore_without_table_keyword() {
    assert!(parses_as_restore(
        "RESTORE my_table TO TIMESTAMP AS OF '2024-06-15';"
    ));
}

#[test]
fn parse_restore_without_to_keyword() {
    assert!(parses_as_restore(
        "RESTORE TABLE my_table TIMESTAMP AS OF '2024-01-01';"
    ));
}

#[test]
fn parse_restore_minimal() {
    // No TABLE, no TO
    assert!(parses_as_restore(
        "RESTORE my_table TIMESTAMP AS OF '2024-01-01';"
    ));
}

#[test]
fn parse_restore_qualified_name() {
    assert!(parses_as_restore(
        "RESTORE TABLE my_catalog.my_schema.my_table TO VERSION AS OF 10;"
    ));
}

#[test]
fn parse_restore_two_part_name() {
    assert!(parses_as_restore(
        "RESTORE TABLE my_schema.my_table TO TIMESTAMP AS OF '2024-06-15T10:00:00';"
    ));
}

#[test]
fn parse_restore_backtick_quoted() {
    assert!(parses_as_restore(
        "RESTORE TABLE `my-catalog`.`my-schema`.`my-table` TO VERSION AS OF 3;"
    ));
}

#[test]
fn parse_restore_no_semicolon() {
    assert!(parses_as_restore(
        "RESTORE TABLE my_table TO VERSION AS OF 42"
    ));
}

#[test]
fn parse_restore_version_zero() {
    assert!(parses_as_restore(
        "RESTORE TABLE my_table TO VERSION AS OF 0;"
    ));
}

// ============================================================================
// Parsing — complex timestamp expressions
// ============================================================================

#[test]
fn parse_restore_timestamp_string_literal() {
    assert!(parses_as_restore(
        "RESTORE TABLE events TO TIMESTAMP AS OF '2024-01-15 08:30:00';"
    ));
}

#[test]
fn parse_restore_timestamp_cast() {
    assert!(parses_as_restore(
        "RESTORE TABLE events TO TIMESTAMP AS OF CAST('2024-01-01' AS TIMESTAMP);"
    ));
}

// ============================================================================
// Formatting Tests
// ============================================================================

#[test]
fn format_restore_timestamp_preserves() {
    let sql = "RESTORE TABLE my_table TO TIMESTAMP AS OF '2024-01-01';";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("RESTORE"));
    assert!(formatted.contains("TABLE"));
    assert!(formatted.contains("my_table"));
    assert!(formatted.contains("TIMESTAMP"));
    assert!(formatted.contains("AS"));
    assert!(formatted.contains("OF"));
    assert!(formatted.contains("'2024-01-01'"));
}

#[test]
fn format_restore_version_preserves() {
    let sql = "RESTORE TABLE my_table TO VERSION AS OF 5;";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("RESTORE"));
    assert!(formatted.contains("VERSION"));
    assert!(formatted.contains("5"));
}

#[test]
fn format_restore_preserves_case() {
    let sql = "restore table MY_TABLE to timestamp as of '2024-01-01';";
    let formatted = dbx_format_and_verify(sql);
    // span-only: original case preserved
    assert!(formatted.contains("restore"));
    assert!(formatted.contains("timestamp"));
}

#[test]
fn format_restore_qualified_preserves() {
    let sql = "RESTORE TABLE my_catalog.my_schema.my_table TO VERSION AS OF 10;";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("my_catalog.my_schema.my_table"));
}

#[test]
fn format_restore_minimal_preserves() {
    let sql = "RESTORE my_table TIMESTAMP AS OF '2024-06-15';";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("RESTORE"));
    assert!(formatted.contains("my_table"));
    assert!(formatted.contains("TIMESTAMP"));
}

#[test]
fn format_restore_backtick_quoted_preserves() {
    let sql = "RESTORE TABLE `my-catalog`.`my-schema`.`my-table` TO VERSION AS OF 3;";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("`my-catalog`"));
    assert!(formatted.contains("`my-table`"));
}

// ============================================================================
// Risk Analysis Tests
// ============================================================================

#[test]
fn risk_restore_high_signal() {
    let sql = "RESTORE TABLE my_table TO TIMESTAMP AS OF '2024-01-01';";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.high_count >= 1,
        "Should have high signal for RESTORE, got: {:?}",
        report.summary
    );
    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "Should find DBX-TBL-RESTORE signal"
    );
}

#[test]
fn risk_restore_version_signal() {
    let sql = "RESTORE TABLE events TO VERSION AS OF 5;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "VERSION AS OF should also trigger DBX-TBL-RESTORE"
    );
}

#[test]
fn risk_restore_tables_written() {
    let sql = "RESTORE TABLE my_table TO TIMESTAMP AS OF '2024-01-01';";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.tables_written >= 1,
        "RESTORE should track tables_written, got: {}",
        report.summary.tables_written
    );
}

#[test]
fn risk_restore_qualified_table() {
    let sql = "RESTORE TABLE my_catalog.my_schema.my_table TO VERSION AS OF 10;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "Should find DBX-TBL-RESTORE for qualified name"
    );
}

#[test]
fn risk_restore_not_critical() {
    let sql = "RESTORE TABLE my_table TO TIMESTAMP AS OF '2024-01-01';";
    let report = dbx_analyze(sql);

    assert_eq!(
        report.summary.critical_count, 0,
        "RESTORE should not be critical"
    );
}

#[test]
fn risk_restore_minimal_form() {
    // No TABLE, no TO
    let sql = "RESTORE my_table TIMESTAMP AS OF '2024-01-01';";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "Minimal RESTORE should also trigger DBX-TBL-RESTORE"
    );
}

#[test]
fn risk_multi_restore() {
    let sql = r#"
        RESTORE TABLE table_a TO TIMESTAMP AS OF '2024-01-01';
        RESTORE TABLE table_b TO VERSION AS OF 5;
        RESTORE TABLE catalog.schema.table_c TO TIMESTAMP AS OF '2024-06-15';
    "#;
    let report = dbx_analyze(sql);

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(g) if g.matched_rule == "DBX-TBL-RESTORE"))
        .map(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_evidence >= 3,
        "Should have evidence for each RESTORE, got: {}",
        total_evidence
    );
}

// ============================================================================
// Combined Tests — RESTORE + other Databricks statements
// ============================================================================

#[test]
fn combined_restore_and_optimize() {
    let sql = r#"
        RESTORE TABLE events TO TIMESTAMP AS OF '2024-01-01';
        OPTIMIZE events ZORDER BY (user_id, event_type);
    "#;
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "Should detect RESTORE signal"
    );
    assert!(
        has_signal(&report, "DBX-TBL-OPT"),
        "Should detect OPTIMIZE signal"
    );
}

#[test]
fn combined_restore_and_vacuum() {
    let sql = r#"
        RESTORE TABLE events TO VERSION AS OF 5;
        VACUUM events RETAIN 24 HOURS;
    "#;
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "Should detect RESTORE signal"
    );
    assert!(
        has_signal(&report, "DBX-VACUUM-LOWRET"),
        "Should detect VACUUM low retention signal"
    );
}

#[test]
fn combined_restore_and_describe_history() {
    let sql = r#"
        DESCRIBE HISTORY events;
        RESTORE TABLE events TO VERSION AS OF 3;
    "#;
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-DBX-TBL-HIST"),
        "Should detect DESCRIBE HISTORY signal"
    );
    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "Should detect RESTORE signal"
    );
}

#[test]
fn combined_all_delta_operations() {
    let sql = r#"
        DESCRIBE HISTORY events;
        RESTORE TABLE events TO VERSION AS OF 3;
        VACUUM events RETAIN 168 HOURS;
        OPTIMIZE events ZORDER BY (event_type);
    "#;
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-DBX-TBL-HIST"),
        "Should detect DESCRIBE HISTORY signal"
    );
    assert!(
        has_signal(&report, "DBX-TBL-RESTORE"),
        "Should detect RESTORE signal"
    );
    assert!(
        has_signal(&report, "DBX-TBL-OPT"),
        "Should detect OPTIMIZE signal"
    );
}
