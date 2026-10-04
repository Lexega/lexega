// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatting of DROP, TRUNCATE, SHOW and DESCRIBE statements.

use lexega_core::context::RenderContext;
use lexega_core::format_sql_with_config;
use lexega_core::formatter::Formatter;
use lexega_core::lexer::tokenize;
use lexega_core::parser::parse_script;

fn format_sql(source: &str) -> Result<String, String> {
    let tokens = tokenize(source);
    let script = parse_script(source, &tokens.tokens).ok_or_else(|| "Parse failed".to_string())?;

    let context = RenderContext::from_source(source.to_string());
    let formatter = Formatter::new();

    let result = formatter
        .format_script(context, &script)
        .map_err(|e| format!("Format error: {}", e))?;

    result
        .formatted()
        .map(|f| f.formatted_sql().to_string())
        .ok_or_else(|| "No formatted output".to_string())
}

#[test]
fn test_drop_table_basic() {
    let sql = "DROP TABLE users";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DROP TABLE users");
}

#[test]
fn test_drop_table_if_exists() {
    let sql = "DROP TABLE IF EXISTS users";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DROP TABLE IF EXISTS users");
}

#[test]
fn test_drop_view_cascade() {
    let sql = "DROP VIEW reporting.user_view CASCADE";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DROP VIEW reporting.user_view CASCADE");
}

#[test]
fn test_drop_schema() {
    let sql = "DROP SCHEMA test_schema";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DROP SCHEMA test_schema");
}

#[test]
fn test_truncate_table_basic() {
    let sql = "TRUNCATE TABLE orders";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "TRUNCATE TABLE orders");
}

#[test]
fn test_truncate_no_table_keyword() {
    let sql = "TRUNCATE staging_data";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "TRUNCATE staging_data");
}

#[test]
fn test_truncate_if_exists() {
    let sql = "TRUNCATE TABLE IF EXISTS temp.raw_data";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "TRUNCATE TABLE IF EXISTS temp.raw_data");
}

#[test]
fn test_truncate_qualified_name() {
    let sql = "TRUNCATE TABLE db.schema.table_name";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "TRUNCATE TABLE db.schema.table_name");
}

#[test]
fn test_show_tables() {
    let sql = "SHOW TABLES";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "SHOW TABLES");
}

#[test]
fn test_show_tables_in_schema() {
    let sql = "SHOW TABLES IN SCHEMA public";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "SHOW TABLES IN SCHEMA public");
}

#[test]
fn test_show_tables_like() {
    let sql = "SHOW TABLES LIKE 'user%'";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "SHOW TABLES LIKE 'user%'");
}

#[test]
fn test_show_views() {
    let sql = "SHOW VIEWS";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "SHOW VIEWS");
}

#[test]
fn test_describe_table() {
    let sql = "DESCRIBE TABLE users";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DESCRIBE TABLE users");
}

#[test]
fn test_desc_table() {
    let sql = "DESC TABLE orders";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DESC TABLE orders");
}

#[test]
fn test_describe_view() {
    let sql = "DESCRIBE VIEW user_summary";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DESCRIBE VIEW user_summary");
}

#[test]
fn test_describe_qualified_table() {
    let sql = "DESCRIBE TABLE reporting.user_metrics";
    let result = format_sql(sql).expect("Should format");
    assert_eq!(result.trim(), "DESCRIBE TABLE reporting.user_metrics");
}

#[test]
fn test_multiple_statements() {
    // Statement terminators are handled at script level, so each statement
    // is formatted on its own here.
    let sql1 = "DROP TABLE old_data";
    let result1 = format_sql(sql1).expect("Should format DROP");
    assert!(result1.contains("DROP TABLE old_data"));

    let sql2 = "TRUNCATE TABLE staging";
    let result2 = format_sql(sql2).expect("Should format TRUNCATE");
    assert!(result2.contains("TRUNCATE TABLE staging"));

    let sql3 = "SHOW TABLES";
    let result3 = format_sql(sql3).expect("Should format SHOW");
    assert!(result3.contains("SHOW TABLES"));
}

#[test]
fn test_keyword_case_preserved() {
    use lexega_core::formatter::config::{FormatterConfig, KeywordCase};

    let mut config = FormatterConfig::default();
    config.keyword_case = KeywordCase::Upper;

    let sql = "drop table users";
    let formatted = format_sql_with_config(sql, &config);

    let formatted = formatted.unwrap();
    assert!(formatted.contains("DROP"));
    assert!(formatted.contains("TABLE"));
}

#[test]
fn test_span_coverage_drop() {
    let sql = "DROP TABLE users";
    let tokens = tokenize(sql);
    let script = parse_script(sql, &tokens.tokens).expect("Parse failed");
    let context = RenderContext::from_source(sql.to_string());
    let formatter = Formatter::new();

    let result = formatter
        .format_script(context, &script)
        .expect("Format failed");

    // Verify span map exists
    let span_map = result.formatted().unwrap().span_map();
    assert!(!span_map.forward().is_empty());
}

#[test]
fn test_span_coverage_truncate() {
    let sql = "TRUNCATE TABLE orders";
    let tokens = tokenize(sql);
    let script = parse_script(sql, &tokens.tokens).expect("Parse failed");
    let context = RenderContext::from_source(sql.to_string());
    let formatter = Formatter::new();

    let result = formatter
        .format_script(context, &script)
        .expect("Format failed");

    // Verify span map exists
    let span_map = result.formatted().unwrap().span_map();
    assert!(!span_map.forward().is_empty());
}
