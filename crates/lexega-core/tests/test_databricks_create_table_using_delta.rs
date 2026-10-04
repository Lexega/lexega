// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks CREATE TABLE ... USING DELTA.
//!
//! Covers:
//! - Parsing as CreateTable (not OpaqueContent)
//! - Formatting roundtrip safety
//! - Analysis path executes under Databricks dialect

use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql_with_dialect,
    verify_formatting_safe, AstStmt, DatabricksDialect, FormatterConfig,
};

use lexega_core::api::analyze_risk_with_policy_config;
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
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn parses_as_create_table(sql: &str) -> bool {
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
        .any(|s| matches!(s, AstStmt::CreateTable(_)))
}

#[test]
fn parse_create_table_using_delta_basic() {
    assert!(parses_as_create_table(
        "CREATE TABLE events (id INT, ts TIMESTAMP) USING DELTA;"
    ));
}

#[test]
fn parse_create_table_using_delta_three_part_name() {
    assert!(parses_as_create_table(
        "CREATE TABLE my_catalog.my_schema.events (id INT) USING DELTA;"
    ));
}

#[test]
fn parse_create_table_using_delta_with_location() {
    assert!(parses_as_create_table(
        "CREATE TABLE events (id INT) USING DELTA LOCATION 's3://bucket/path';"
    ));
}

#[test]
fn format_create_table_using_delta_roundtrip_safe() {
    let sql = "CREATE TABLE events (id INT, ts TIMESTAMP) USING DELTA;";
    let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
}

#[test]
fn analyze_create_table_using_delta_with_databricks_dialect() {
    let sql = "CREATE TABLE events (id INT) USING DELTA;";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.statements_parsed >= 1,
        "Expected at least one parsed statement, got {}",
        report.summary.statements_parsed
    );
    assert!(
        report.summary.statements_analyzed >= 1,
        "Expected at least one analyzed statement, got {}",
        report.summary.statements_analyzed
    );
}
