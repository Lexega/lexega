// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks / SparkSQL REPAIR TABLE and MSCK REPAIR TABLE.
//!
//! Covers:
//! - Parsing (REPAIR vs MSCK REPAIR, qualified names, backtick identifiers, optional suffix)
//! - Formatting (semantic preservation)
//! - Risk analysis (info signal generation, tables_read)

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

fn parses_as_repair_table(sql: &str) -> bool {
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
        .any(|s| matches!(s, AstStmt::RepairTable(_)))
}

// ============================================================================
// Parsing Tests
// ============================================================================

#[test]
fn parse_repair_table_basic() {
    assert!(parses_as_repair_table("REPAIR TABLE t1;"));
}

#[test]
fn parse_msck_repair_table_basic() {
    assert!(parses_as_repair_table("MSCK REPAIR TABLE t1;"));
}

#[test]
fn parse_repair_table_add_partitions() {
    assert!(parses_as_repair_table("REPAIR TABLE t1 ADD PARTITIONS;"));
}

#[test]
fn parse_repair_table_drop_partitions() {
    assert!(parses_as_repair_table("REPAIR TABLE t1 DROP PARTITIONS;"));
}

#[test]
fn parse_repair_table_sync_partitions() {
    assert!(parses_as_repair_table("REPAIR TABLE t1 SYNC PARTITIONS;"));
}

#[test]
fn parse_msck_repair_table_qualified_name() {
    assert!(parses_as_repair_table("MSCK REPAIR TABLE db1.t1;"));
    assert!(parses_as_repair_table(
        "MSCK REPAIR TABLE main.db1.t1 DROP PARTITIONS;"
    ));
}

#[test]
fn parse_msck_repair_table_backticks() {
    assert!(parses_as_repair_table("MSCK REPAIR TABLE `db1`.`t1`;"));
    assert!(parses_as_repair_table(
        "MSCK REPAIR TABLE `main`.`db1`.`t1` SYNC PARTITIONS;"
    ));
}

// ============================================================================
// Formatting Tests
// ============================================================================

#[test]
fn format_repair_table_preserves_semantics() {
    dbx_format_and_verify("REPAIR TABLE t1;");
    dbx_format_and_verify("MSCK REPAIR TABLE t1;");
    dbx_format_and_verify("MSCK REPAIR TABLE db1.t1 ADD PARTITIONS;");
    dbx_format_and_verify("MSCK REPAIR TABLE db1.t1 DROP PARTITIONS;");
    dbx_format_and_verify("MSCK REPAIR TABLE db1.t1 SYNC PARTITIONS;");
}

#[test]
fn format_repair_table_multistatement() {
    let sql = r#"
        REPAIR TABLE a;
        MSCK REPAIR TABLE b;
        MSCK REPAIR TABLE c DROP PARTITIONS;
    "#;
    let formatted = dbx_format_and_verify(sql);
    assert!(!formatted.is_empty());
}

// ============================================================================
// Risk Analysis Tests
// ============================================================================

#[test]
fn risk_repair_table_info_signal() {
    let sql = "REPAIR TABLE my_table;";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.info_count >= 1,
        "Should have info signal for REPAIR TABLE, got: {:?}",
        report.summary
    );
    assert!(
        has_signal(&report, "INFO-DBX-TBL-REPAIR"),
        "Should find INFO-DBX-TBL-REPAIR signal"
    );
}

#[test]
fn risk_msck_repair_table_info_signal() {
    let sql = "MSCK REPAIR TABLE my_table ADD PARTITIONS;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "INFO-DBX-TBL-REPAIR"),
        "MSCK REPAIR TABLE should trigger INFO-DBX-TBL-REPAIR"
    );
}

#[test]
fn risk_repair_table_tables_read() {
    let sql = "REPAIR TABLE my_table;";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.tables_read >= 1,
        "Should track tables_read for REPAIR TABLE, got: {}",
        report.summary.tables_read
    );
}
