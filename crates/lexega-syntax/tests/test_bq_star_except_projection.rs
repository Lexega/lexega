// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Regression tests for star modifiers in mixed projection lists.
//! Covers all dialects that currently support star modifiers:
//! - BigQuery: `* EXCEPT(...)`
//! - Snowflake: `* EXCLUDE(...)`

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe, AstStmt,
    BigQueryDialect, Dialect, FormatterConfig, SnowflakeDialect,
};

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = std::sync::Arc::new(BigQueryDialect);
    config
}

fn snowflake_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = std::sync::Arc::new(SnowflakeDialect);
    config
}

fn assert_no_opaque_with_dialect(sql: &str, dialect: &dyn Dialect) {
    let script = parse_sql_with_dialect(sql, dialect)
        .unwrap_or_else(|e| panic!("parse_sql_with_dialect failed: {e}\nSQL: {sql}"));

    for stmt in &script.stmts {
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
}

fn roundtrip_bq(sql: &str) -> String {
    assert_no_opaque_with_dialect(sql, &BigQueryDialect);

    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("format_sql_with_config failed: {e}\nSQL: {sql}"));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!("verify_formatting_safe failed: {e}\nSQL: {sql}\nFormatted: {formatted}")
    });
    formatted
}

fn roundtrip_snowflake(sql: &str) -> String {
    assert_no_opaque_with_dialect(sql, &SnowflakeDialect);

    let config = snowflake_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("format_sql_with_config failed: {e}\nSQL: {sql}"));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!("verify_formatting_safe failed: {e}\nSQL: {sql}\nFormatted: {formatted}")
    });
    formatted
}

#[test]
fn test_bq_unqualified_star_except_with_additional_projection_items() {
    let sql = "SELECT * EXCEPT(col1), name FROM t;";
    let formatted = roundtrip_bq(sql);
    assert!(formatted.contains("EXCEPT"));
    assert!(formatted.contains("name"));
}

#[test]
fn test_bq_qualified_star_except_with_additional_projection_items() {
    let sql = "SELECT a.* EXCEPT(col1), b.name FROM a JOIN b ON a.id = b.id;";
    let formatted = roundtrip_bq(sql);
    assert!(formatted.contains("a.* EXCEPT"));
    assert!(formatted.contains("b.name"));
}

#[test]
fn test_bq_multiple_star_except_items() {
    let sql = "SELECT a.* EXCEPT(col1), b.* EXCEPT(col2) FROM a JOIN b ON a.id = b.id;";
    let formatted = roundtrip_bq(sql);
    assert!(formatted.contains("a.* EXCEPT"));
    assert!(formatted.contains("b.* EXCEPT"));
}

#[test]
fn test_snowflake_unqualified_star_exclude_with_additional_projection_items() {
    let sql = "SELECT * EXCLUDE(col1), name FROM t;";
    let formatted = roundtrip_snowflake(sql);
    assert!(formatted.contains("EXCLUDE"));
    assert!(formatted.contains("name"));
}

#[test]
fn test_snowflake_qualified_star_exclude_with_additional_projection_items() {
    let sql = "SELECT a.* EXCLUDE(col1), b.name FROM a JOIN b ON a.id = b.id;";
    let formatted = roundtrip_snowflake(sql);
    assert!(formatted.contains("a.* EXCLUDE"));
    assert!(formatted.contains("b.name"));
}

#[test]
fn test_snowflake_multiple_star_exclude_items() {
    let sql = "SELECT a.* EXCLUDE(col1), b.* EXCLUDE(col2) FROM a JOIN b ON a.id = b.id;";
    let formatted = roundtrip_snowflake(sql);
    assert!(formatted.contains("a.* EXCLUDE"));
    assert!(formatted.contains("b.* EXCLUDE"));
}
