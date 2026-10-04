// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Integration tests for the SQL formatter.
//!
//! Tests formatting with real SQL statements, verifying that source text
//! is extracted correctly from spans and formatted according to configuration.

use lexega_syntax::{
    format_sql, format_sql_with_config, FormatterConfig, IdentifierCase, KeywordCase,
};

#[test]
fn test_format_simple_select() {
    let sql = "select id,name from users";
    let result = format_sql(sql).expect("format failed");

    eprintln!("Formatted SQL:\n{}", result);
    eprintln!("---");

    // Default config uses UPPER keywords
    assert!(result.contains("SELECT"));
    assert!(result.contains("FROM"));
    assert!(result.contains("id"));
    assert!(result.contains("name"));
    assert!(result.contains("users"));
}

#[test]
fn test_format_select_with_where() {
    let sql = "select id, name from users where active = true";
    let result = format_sql(sql).expect("format failed");

    assert!(result.contains("SELECT"));
    assert!(result.contains("FROM"));
    assert!(result.contains("WHERE"));
    assert!(result.contains("active = true"));
}

#[test]
fn test_format_with_custom_config() {
    let sql = "SELECT ID, NAME FROM USERS";
    let config = FormatterConfig {
        keyword_case: KeywordCase::Lower,
        identifier_case: IdentifierCase::Lower,
        ..Default::default()
    };

    let result = format_sql_with_config(sql, &config).expect("format failed");

    eprintln!("Result: {}", result);

    // Should lowercase keywords
    assert!(result.contains("select"));
    assert!(result.contains("from"));
    // Identifier casing is applied to simple identifiers.
    assert!(result.contains("id"));
    assert!(result.contains("name"));
    assert!(result.contains("users"));
}

#[test]
fn test_format_with_newlines() {
    let sql = "select id, name from users where active = true";
    let config = FormatterConfig {
        clauses_on_newlines: true,
        ..Default::default()
    };

    let result = format_sql_with_config(sql, &config).expect("format failed");

    // FROM should be on new line
    assert!(result.contains("\nFROM"));
    // WHERE should be on new line
    assert!(result.contains("\nWHERE"));
}

#[test]
fn test_format_with_group_by() {
    let sql = "select dept, count(*) from employees group by dept";
    let result = format_sql(sql).expect("format failed");

    assert!(result.contains("SELECT"));
    assert!(result.contains("GROUP"));
    assert!(result.contains("BY"));
    assert!(result.contains("dept"));
}

#[test]
fn test_format_with_order_by() {
    let sql = "select name, salary from employees order by salary desc";
    let result = format_sql(sql).expect("format failed");

    eprintln!("Formatted:\n{}", result);

    assert!(result.contains("SELECT"));
    assert!(result.contains("ORDER"));
    assert!(result.contains("BY"));
    assert!(result.contains("salary"));
    assert!(result.contains("DESC"));
}

#[test]
fn test_format_with_limit() {
    let sql = "select * from users limit 10";
    let result = format_sql(sql).expect("format failed");

    assert!(result.contains("SELECT"));
    assert!(result.contains("LIMIT"));
    assert!(result.contains("10"));
}

#[test]
fn test_format_complex_select() {
    let sql = "select id, name, salary from employees where dept = 'eng' and salary > 50000 order by salary desc limit 5";
    let result = format_sql(sql).expect("format failed");

    assert!(result.contains("SELECT"));
    assert!(result.contains("FROM"));
    assert!(result.contains("WHERE"));
    assert!(result.contains("ORDER"));
    assert!(result.contains("LIMIT"));

    // Verify expressions are preserved
    assert!(result.contains("dept = 'eng'"));
    assert!(result.contains("salary > 50000"));
    assert!(result.contains("5"));
}

#[test]
fn test_format_preserves_expression_logic() {
    let sql = "select price * quantity as total from orders where status in ('pending', 'shipped')";
    let result = format_sql(sql).expect("format failed");

    eprintln!("Formatted:\n{}", result);

    // Complex expressions should be preserved from source
    assert!(result.contains("price * quantity"));
    // NOTE: Currently the IN expression span doesn't include the left operand
    // This is a known limitation
    // Check that IN is uppercased and has the list
    assert!(result.contains("IN ("));
    assert!(result.contains("'pending'"));
    assert!(result.contains("'shipped'"));
}

#[test]
fn test_format_select_star() {
    let sql = "select * from users";
    let result = format_sql(sql).expect("format failed");

    // Default config has clauses_on_newlines = true
    assert!(result.contains("SELECT *"));
    assert!(result.contains("\nFROM"));
}
