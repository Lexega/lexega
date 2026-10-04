// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for CAST, TRY_CAST, and :: operator
use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_cast_basic() {
    let sql = "SELECT CAST(id AS VARCHAR) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse basic CAST");
}

#[test]
fn test_cast_with_precision() {
    let sql = "SELECT CAST(id AS VARCHAR(50)) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST with precision");
}

#[test]
fn test_cast_with_precision_and_scale() {
    let sql = "SELECT CAST('9.8765' AS NUMBER(5,2)) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST with precision and scale"
    );
}

#[test]
fn test_cast_to_integer() {
    let sql = "SELECT CAST(amount AS INTEGER) FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST to INTEGER");
}

#[test]
fn test_cast_to_date() {
    let sql = "SELECT CAST('2024-05-09' AS DATE) FROM events;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST to DATE");
}

#[test]
fn test_cast_to_timestamp() {
    let sql = "SELECT CAST(date_col AS TIMESTAMP) FROM logs;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST to TIMESTAMP");
}

#[test]
fn test_cast_to_decimal() {
    let sql = "SELECT CAST(price AS DECIMAL(10,2)) FROM products;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST to DECIMAL with precision and scale"
    );
}

#[test]
fn test_cast_nested_expression() {
    let sql = "SELECT CAST(amount * 1.1 AS NUMBER(10,2)) FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST with nested expression"
    );
}

#[test]
fn test_try_cast_basic() {
    let sql = "SELECT TRY_CAST(value AS INTEGER) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse basic TRY_CAST");
}

#[test]
fn test_try_cast_with_precision() {
    let sql = "SELECT TRY_CAST(text AS VARCHAR(100)) FROM strings;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse TRY_CAST with precision");
}

#[test]
fn test_try_cast_with_precision_and_scale() {
    let sql = "SELECT TRY_CAST(value AS NUMBER(10,4)) FROM measurements;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse TRY_CAST with precision and scale"
    );
}

#[test]
fn test_try_cast_returns_null_on_failure() {
    let sql = "SELECT TRY_CAST('invalid' AS DATE) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse TRY_CAST that would return NULL"
    );
}

#[test]
fn test_double_colon_cast_basic() {
    let sql = "SELECT id::VARCHAR FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast operator");
}

#[test]
fn test_double_colon_cast_with_precision() {
    let sql = "SELECT id::VARCHAR(50) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast with precision");
}

#[test]
fn test_double_colon_cast_with_precision_and_scale() {
    let sql = "SELECT amount::NUMBER(10,2) FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse :: cast with precision and scale"
    );
}

#[test]
fn test_double_colon_cast_to_date() {
    let sql = "SELECT '2024-05-09'::DATE FROM events;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast to DATE");
}

#[test]
fn test_double_colon_cast_to_integer() {
    let sql = "SELECT value::INTEGER FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast to INTEGER");
}

#[test]
fn test_double_colon_cast_column_reference() {
    let sql = "SELECT users.id::VARCHAR FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse :: cast on qualified column"
    );
}

#[test]
fn test_cast_in_where_clause() {
    let sql = "SELECT * FROM users WHERE CAST(age AS VARCHAR) = '25';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST in WHERE clause");
}

#[test]
fn test_double_colon_in_where_clause() {
    let sql = "SELECT * FROM orders WHERE amount::VARCHAR LIKE '100%';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast in WHERE clause");
}

#[test]
fn test_cast_with_function_call() {
    let sql = "SELECT CAST(COUNT(*) AS VARCHAR) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST with function call");
}

#[test]
fn test_try_cast_with_coalesce() {
    let sql =
        "SELECT TRY_CAST(value AS INTEGER) FROM data WHERE TRY_CAST(value AS INTEGER) IS NOT NULL;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse TRY_CAST in WHERE with IS NOT NULL"
    );
}

#[test]
fn test_multiple_casts_in_select() {
    let sql = "SELECT CAST(id AS VARCHAR), amount::NUMBER(10,2), TRY_CAST(date AS DATE) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse multiple different cast types in SELECT"
    );
}

#[test]
fn test_cast_in_comparison() {
    let sql = "SELECT * FROM users WHERE CAST(age AS INTEGER) > 18;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST in comparison expression"
    );
}

#[test]
fn test_double_colon_in_arithmetic() {
    let sql = "SELECT amount::NUMBER(10,2) * 1.1 FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse :: cast in arithmetic expression"
    );
}

// Note: CAST with scalar subquery requires careful parenthesis handling
// Example that works: SELECT CAST(COUNT(*) AS VARCHAR) FROM users;

#[test]
fn test_cast_case_expression() {
    let sql =
        "SELECT CAST(CASE WHEN age > 18 THEN 'adult' ELSE 'minor' END AS VARCHAR(10)) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST with CASE expression"
    );
}
