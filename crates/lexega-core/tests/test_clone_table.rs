// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for table CLONE statements (both Snowflake and Databricks syntax).
//!
//! Covers:
//! - Databricks: DEEP CLONE, SHALLOW CLONE, TIMESTAMP AS OF, VERSION AS OF,
//!   TBLPROPERTIES, LOCATION, qualified names, backtick-quoted identifiers
//! - Snowflake: CLONE with AT/BEFORE time travel
//! - Formatting (semantic preservation)
//! - Risk analysis (signal generation)

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

fn sf_config() -> FormatterConfig {
    FormatterConfig::default() // Snowflake is default
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

fn sf_format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &sf_config())
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

fn sf_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
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

fn parses_as_create_table_clone_dbx(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script.stmts.iter().any(|s| {
        if let AstStmt::CreateTable(ct) = s {
            matches!(ct.variant, lexega_core::ast::AstCreateTableVariant::Clone)
        } else {
            false
        }
    })
}

fn parses_as_create_table_clone_sf(sql: &str) -> bool {
    use lexega_core::parse_sql;
    let script = parse_sql(sql).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script.stmts.iter().any(|s| {
        if let AstStmt::CreateTable(ct) = s {
            matches!(ct.variant, lexega_core::ast::AstCreateTableVariant::Clone)
        } else {
            false
        }
    })
}

// ============================================================================
// Databricks Parsing Tests — DEEP/SHALLOW CLONE variants
// ============================================================================

#[test]
fn parse_dbx_shallow_clone_basic() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE my_clone SHALLOW CLONE source_table;"
    ));
}

#[test]
fn parse_dbx_deep_clone_basic() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE my_clone DEEP CLONE source_table;"
    ));
}

#[test]
fn parse_dbx_clone_without_kind() {
    // Bare CLONE (no DEEP/SHALLOW) should still work
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE my_clone CLONE source_table;"
    ));
}

#[test]
fn parse_dbx_clone_if_not_exists() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE IF NOT EXISTS my_clone SHALLOW CLONE source_table;"
    ));
}

#[test]
fn parse_dbx_clone_or_replace() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE OR REPLACE TABLE my_clone DEEP CLONE source_table;"
    ));
}

#[test]
fn parse_dbx_clone_qualified_names() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE catalog.schema.my_clone SHALLOW CLONE catalog.schema.source_table;"
    ));
}

#[test]
fn parse_dbx_clone_backtick_quoted() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE `my-catalog`.`my-schema`.`my-clone` DEEP CLONE `my-catalog`.`my-schema`.`source-table`;"
    ));
}

#[test]
fn parse_dbx_clone_timestamp_as_of() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE my_clone SHALLOW CLONE source_table TIMESTAMP AS OF '2024-01-01';"
    ));
}

#[test]
fn parse_dbx_clone_version_as_of() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE my_clone DEEP CLONE source_table VERSION AS OF 5;"
    ));
}

#[test]
fn parse_dbx_clone_tblproperties() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE my_clone SHALLOW CLONE source_table TBLPROPERTIES ('key' = 'value');"
    ));
}

#[test]
fn parse_dbx_clone_location() {
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE my_clone DEEP CLONE source_table LOCATION 's3://bucket/path';"
    ));
}

#[test]
fn parse_dbx_clone_full_options() {
    // DEEP CLONE with TIMESTAMP AS OF + TBLPROPERTIES + LOCATION
    assert!(parses_as_create_table_clone_dbx(
        "CREATE OR REPLACE TABLE my_clone DEEP CLONE source_table TIMESTAMP AS OF '2024-06-15' TBLPROPERTIES ('delta.autoOptimize.optimizeWrite' = 'true') LOCATION 's3://bucket/clone/';"
    ));
}

// ============================================================================
// Snowflake Parsing Tests — CLONE with AT/BEFORE time travel
// ============================================================================

#[test]
fn parse_sf_clone_basic() {
    assert!(parses_as_create_table_clone_sf(
        "CREATE TABLE my_clone CLONE source_table;"
    ));
}

#[test]
fn parse_sf_clone_qualified_names() {
    assert!(parses_as_create_table_clone_sf(
        "CREATE TABLE db.schema.my_clone CLONE db.schema.source_table;"
    ));
}

#[test]
fn parse_sf_clone_at_timestamp() {
    assert!(parses_as_create_table_clone_sf(
        "CREATE TABLE my_clone CLONE source_table AT (TIMESTAMP => '2024-01-01 00:00:00');"
    ));
}

#[test]
fn parse_sf_clone_before_statement() {
    assert!(parses_as_create_table_clone_sf(
        "CREATE TABLE my_clone CLONE source_table BEFORE (STATEMENT => '8e5d0ca9-0052-4e12-a53e-123456789012');"
    ));
}

#[test]
fn parse_sf_clone_at_offset() {
    assert!(parses_as_create_table_clone_sf(
        "CREATE TABLE my_clone CLONE source_table AT (OFFSET => -60*5);"
    ));
}

// ============================================================================
// Databricks Formatting Tests
// ============================================================================

#[test]
fn format_dbx_shallow_clone_preserves() {
    let sql = "CREATE TABLE my_clone SHALLOW CLONE source_table;";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("my_clone"));
    assert!(formatted.contains("SHALLOW"));
    assert!(formatted.contains("CLONE"));
    assert!(formatted.contains("source_table"));
}

#[test]
fn format_dbx_deep_clone_preserves() {
    let sql = "CREATE TABLE my_clone DEEP CLONE source_table;";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("DEEP"));
    assert!(formatted.contains("CLONE"));
}

#[test]
fn format_dbx_clone_timestamp_preserves() {
    let sql = "CREATE TABLE my_clone SHALLOW CLONE source_table TIMESTAMP AS OF '2024-01-01';";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("TIMESTAMP"));
    assert!(formatted.contains("2024-01-01"));
}

#[test]
fn format_dbx_clone_version_preserves() {
    let sql = "CREATE TABLE my_clone DEEP CLONE source_table VERSION AS OF 5;";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("VERSION"));
}

#[test]
fn format_dbx_clone_tblproperties_preserves() {
    let sql = "CREATE TABLE my_clone SHALLOW CLONE source_table TBLPROPERTIES ('key' = 'value');";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("TBLPROPERTIES"));
}

#[test]
fn format_dbx_clone_location_preserves() {
    let sql = "CREATE TABLE my_clone DEEP CLONE source_table LOCATION 's3://bucket/path';";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("LOCATION"));
    assert!(formatted.contains("s3://bucket"));
}

#[test]
fn format_dbx_clone_backtick_quoted_preserves() {
    let sql = "CREATE TABLE `my-catalog`.`my-schema`.`my-clone` DEEP CLONE `source-table`;";
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("`my-catalog`"));
    assert!(formatted.contains("`my-clone`"));
    assert!(formatted.contains("`source-table`"));
}

// ============================================================================
// Snowflake Formatting Tests
// ============================================================================

#[test]
fn format_sf_clone_at_timestamp_preserves() {
    let sql = "CREATE TABLE my_clone CLONE source_table AT (TIMESTAMP => '2024-01-01');";
    let formatted = sf_format_and_verify(sql);
    assert!(formatted.contains("CLONE"));
    assert!(formatted.contains("AT"));
    assert!(formatted.contains("TIMESTAMP"));
}

#[test]
fn format_sf_clone_before_statement_preserves() {
    let sql = "CREATE TABLE my_clone CLONE source_table BEFORE (STATEMENT => 'abc123');";
    let formatted = sf_format_and_verify(sql);
    assert!(formatted.contains("BEFORE"));
    assert!(formatted.contains("STATEMENT"));
}

// ============================================================================
// Risk Analysis Tests — Databricks
// ============================================================================

#[test]
fn risk_dbx_clone_signal() {
    let sql = "CREATE TABLE my_clone SHALLOW CLONE source_table;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-TBL-CLONE"),
        "Should find INFO-TBL-CLONE (table cloned) signal, signals: {:?}",
        report.signals
    );
}

#[test]
fn risk_dbx_deep_clone_signal() {
    let sql = "CREATE TABLE my_clone DEEP CLONE source_table;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-TBL-CLONE"),
        "DEEP CLONE should also trigger INFO-TBL-CLONE"
    );
}

#[test]
fn risk_dbx_clone_with_temporal_signal() {
    let sql = "CREATE TABLE my_clone SHALLOW CLONE source_table VERSION AS OF 5;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-TBL-CLONE"),
        "CLONE with VERSION AS OF should trigger INFO-TBL-CLONE"
    );
}

// ============================================================================
// Risk Analysis Tests — Snowflake
// ============================================================================

#[test]
fn risk_sf_clone_signal() {
    let sql = "CREATE TABLE my_clone CLONE source_table;";
    let report = sf_analyze(sql);

    assert!(
        has_signal(&report, "INFO-TBL-CLONE"),
        "Snowflake CLONE should trigger INFO-TBL-CLONE, signals: {:?}",
        report.signals
    );
}

#[test]
fn risk_sf_clone_at_timestamp_signal() {
    let sql = "CREATE TABLE my_clone CLONE source_table AT (TIMESTAMP => '2024-01-01');";
    let report = sf_analyze(sql);

    assert!(
        has_signal(&report, "INFO-TBL-CLONE"),
        "Snowflake CLONE with AT should trigger INFO-TBL-CLONE"
    );
}

// ============================================================================
// Multi-Statement Tests
// ============================================================================

#[test]
fn risk_dbx_multi_clone_signals() {
    let sql = r#"
        CREATE TABLE clone1 SHALLOW CLONE source1;
        CREATE TABLE clone2 DEEP CLONE source2;
        CREATE TABLE clone3 CLONE source3;
    "#;
    let report = dbx_analyze(sql);

    // Signals are deduplicated by rule — test evidence_count, not signal count
    let clone_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "INFO-TBL-CLONE"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        clone_evidence >= 3,
        "Should have at least 3 clone evidences, got: {}",
        clone_evidence
    );
}

#[test]
fn format_dbx_multi_clone_preserves() {
    let sql = r#"
        CREATE TABLE clone1 SHALLOW CLONE source1;
        CREATE TABLE clone2 DEEP CLONE source2;
    "#;
    let formatted = dbx_format_and_verify(sql);
    assert!(formatted.contains("SHALLOW"));
    assert!(formatted.contains("DEEP"));
    assert!(formatted.contains("clone1"));
    assert!(formatted.contains("clone2"));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn parse_dbx_clone_table_named_deep() {
    // Table named "deep" should not confuse parser
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE deep_backup SHALLOW CLONE deep;"
    ));
}

#[test]
fn parse_dbx_clone_table_named_shallow() {
    // Table named "shallow" should not confuse parser
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE shallow_backup DEEP CLONE shallow;"
    ));
}

#[test]
fn parse_dbx_clone_table_named_clone() {
    // Table named "clone" — tricky case
    assert!(parses_as_create_table_clone_dbx(
        "CREATE TABLE clone_backup SHALLOW CLONE clone;"
    ));
}

// ============================================================================
// DBX-TBL-CLONE-SHALLOW: Shallow Clone Warning
// ============================================================================

#[test]
fn risk_dbx_shallow_clone_triggers_tbl_clone_shallow() {
    let sql = "CREATE TABLE my_clone SHALLOW CLONE source_table;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-TBL-CLONE-SHALLOW"),
        "SHALLOW CLONE should trigger DBX-TBL-CLONE-SHALLOW, signals: {:?}",
        report.signals
    );
}

#[test]
fn risk_dbx_deep_clone_does_not_trigger_tbl_clone_shallow() {
    let sql = "CREATE TABLE my_clone DEEP CLONE source_table;";
    let report = dbx_analyze(sql);

    assert!(
        !has_signal(&report, "DBX-TBL-CLONE-SHALLOW"),
        "DEEP CLONE should NOT trigger DBX-TBL-CLONE-SHALLOW"
    );
}

#[test]
fn risk_dbx_bare_clone_does_not_trigger_tbl_clone_shallow() {
    // Bare CLONE (no SHALLOW/DEEP keyword) should not trigger shallow warning
    let sql = "CREATE TABLE my_clone CLONE source_table;";
    let report = dbx_analyze(sql);

    assert!(
        !has_signal(&report, "DBX-TBL-CLONE-SHALLOW"),
        "Bare CLONE (no SHALLOW keyword) should NOT trigger DBX-TBL-CLONE-SHALLOW"
    );
}

#[test]
fn risk_sf_clone_does_not_trigger_tbl_clone_shallow() {
    // Snowflake CLONE has no SHALLOW concept — should not trigger
    let sql = "CREATE TABLE my_clone CLONE source_table;";
    let report = sf_analyze(sql);

    assert!(
        !has_signal(&report, "DBX-TBL-CLONE-SHALLOW"),
        "Snowflake CLONE should NOT trigger DBX-TBL-CLONE-SHALLOW"
    );
}

#[test]
fn risk_dbx_shallow_clone_also_triggers_info_c350() {
    // SHALLOW CLONE should trigger both the specific DBX-TBL-CLONE-SHALLOW AND the generic INFO-TBL-CLONE
    let sql = "CREATE TABLE my_clone SHALLOW CLONE source_table;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-TBL-CLONE"),
        "SHALLOW CLONE should also trigger generic INFO-TBL-CLONE"
    );
    assert!(
        has_signal(&report, "DBX-TBL-CLONE-SHALLOW"),
        "SHALLOW CLONE should trigger DBX-TBL-CLONE-SHALLOW"
    );
}
