// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatting of SELECT statements.

use lexega_core::context::RenderContext;
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
        .map_err(|e| format!("{:?}", e))?;
    result
        .formatted()
        .map(|f| f.formatted_sql().to_string())
        .ok_or_else(|| "Formatting failed".to_string())
}

#[test]
fn test_select_star() {
    let result = format_sql("SELECT * FROM users").unwrap();
    assert_eq!(result.trim(), "SELECT *\nFROM users");
}

#[test]
fn test_select_columns() {
    let result = format_sql("SELECT id, name FROM users").unwrap();
    assert_eq!(result.trim(), "SELECT id, name\nFROM users");
}

#[test]
fn test_select_no_from() {
    let result = format_sql("SELECT 1").unwrap();
    assert_eq!(result.trim(), "SELECT 1");
}

#[test]
fn test_select_with_where() {
    let result = format_sql("SELECT * FROM users WHERE id = 1").unwrap();
    let expected = "SELECT *\nFROM users\nWHERE\n    id = 1";
    assert_eq!(result.trim(), expected);
}

#[test]
fn test_select_distinct() {
    let result = format_sql("SELECT DISTINCT name FROM users").unwrap();
    assert_eq!(result.trim(), "SELECT DISTINCT name\nFROM users");
}

#[test]
fn test_select_with_limit() {
    let result = format_sql("SELECT * FROM users LIMIT 10").unwrap();
    let expected = "SELECT *\nFROM users\nLIMIT 10";
    assert_eq!(result.trim(), expected);
}

#[test]
fn test_select_with_offset() {
    let result = format_sql("SELECT * FROM users LIMIT 10 OFFSET 5").unwrap();
    let expected = "SELECT *\nFROM users\nLIMIT 10\nOFFSET 5";
    assert_eq!(result.trim(), expected);
}

#[test]
fn test_select_multiple_tables() {
    let result = format_sql("SELECT * FROM users, orders").unwrap();
    assert_eq!(result.trim(), "SELECT *\nFROM users, orders");
}

#[test]
fn test_select_with_having() {
    let result =
        format_sql("SELECT name, COUNT(*) FROM users GROUP BY name HAVING COUNT(*) > 5").unwrap();
    assert!(result.contains("SELECT"));
    assert!(result.contains("GROUP BY name"));
    assert!(result.contains("HAVING COUNT(*) > 5"));
}

#[test]
fn test_select_with_qualify() {
    let result =
        format_sql("SELECT * FROM users QUALIFY row_number() OVER (ORDER BY id) = 1").unwrap();
    let expected = "SELECT *\nFROM users\nQUALIFY row_number() OVER (\n    ORDER BY id\n) = 1";
    assert_eq!(result.trim(), expected);
}

#[test]
fn test_select_complex_projection() {
    let result = format_sql("SELECT id, name AS user_name, UPPER(email) FROM users").unwrap();
    let expected = "SELECT\n    id,\n    name AS user_name,\n    UPPER(email)\nFROM users";
    assert_eq!(result.trim(), expected);
}

#[test]
fn test_select_with_table_alias() {
    let result = format_sql("SELECT u.id FROM users u").unwrap();
    assert_eq!(result.trim(), "SELECT u.id\nFROM users u");
}
