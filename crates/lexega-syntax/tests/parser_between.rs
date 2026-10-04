// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for BETWEEN and NOT BETWEEN operators
use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_between_basic_numbers() {
    let sql = "SELECT * FROM orders WHERE amount BETWEEN 100 AND 500;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse basic BETWEEN with numbers"
    );
}

#[test]
fn test_between_column_references() {
    let sql = "SELECT * FROM ranges WHERE value BETWEEN min_val AND max_val;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with column references"
    );
}

#[test]
fn test_not_between_numbers() {
    let sql = "SELECT * FROM products WHERE price NOT BETWEEN 10 AND 20;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse NOT BETWEEN with numbers");
}

#[test]
fn test_between_dates() {
    let sql = "SELECT * FROM events WHERE date BETWEEN '2024-01-01' AND '2024-12-31';";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with date strings"
    );
}

#[test]
fn test_not_between_dates() {
    let sql = "SELECT * FROM logs WHERE timestamp NOT BETWEEN '2024-01-01' AND '2024-03-31';";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse NOT BETWEEN with timestamps"
    );
}

#[test]
fn test_between_strings() {
    let sql = "SELECT * FROM users WHERE name BETWEEN 'A' AND 'M';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse BETWEEN with strings");
}

#[test]
fn test_not_between_strings() {
    let sql = "SELECT * FROM products WHERE category NOT BETWEEN 'Electronics' AND 'Furniture';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse NOT BETWEEN with strings");
}

#[test]
fn test_between_with_expressions() {
    let sql = "SELECT * FROM sales WHERE total BETWEEN amount * 0.9 AND amount * 1.1;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with arithmetic expressions"
    );
}

#[test]
fn test_between_decimal_values() {
    let sql = "SELECT * FROM measurements WHERE value BETWEEN 1.5 AND 2.5;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with decimal values"
    );
}

#[test]
fn test_between_negative_numbers() {
    let sql = "SELECT * FROM temperatures WHERE celsius BETWEEN -10 AND 10;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with negative numbers"
    );
}

#[test]
fn test_between_in_select_with_alias() {
    let sql = "SELECT id, amount BETWEEN 100 AND 500 AS in_range FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN in SELECT list with alias"
    );
}

#[test]
fn test_multiple_between_conditions() {
    let sql = "SELECT * FROM data WHERE x BETWEEN 0 AND 10 AND y BETWEEN 20 AND 30;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse multiple BETWEEN conditions with AND"
    );
}

#[test]
fn test_between_or_condition() {
    let sql = "SELECT * FROM data WHERE x BETWEEN 0 AND 10 OR x BETWEEN 90 AND 100;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with OR condition"
    );
}

#[test]
fn test_between_with_not_operator() {
    let sql = "SELECT * FROM users WHERE age NOT BETWEEN 18 AND 65;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse NOT BETWEEN");
}

#[test]
fn test_between_qualified_column() {
    let sql = "SELECT * FROM orders o WHERE o.amount BETWEEN 100 AND 500;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with qualified column name"
    );
}

#[test]
fn test_between_with_function_call() {
    let sql = "SELECT * FROM data WHERE LENGTH(name) BETWEEN 5 AND 20;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with function call"
    );
}

#[test]
fn test_between_with_cast() {
    let sql = "SELECT * FROM data WHERE CAST(value AS INTEGER) BETWEEN 10 AND 100;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with CAST expression"
    );
}

// Note: Scalar subqueries in BETWEEN bounds are complex because they require
// parentheses that conflict with expression grouping. This is a known limitation.
// Example that may not parse: WHERE x BETWEEN (SELECT MIN(y) FROM t) AND (SELECT MAX(y) FROM t)

#[test]
fn test_between_in_having_clause() {
    let sql = "SELECT category, COUNT(*) as cnt FROM products GROUP BY category HAVING COUNT(*) BETWEEN 5 AND 20;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse BETWEEN in HAVING clause");
}

#[test]
fn test_between_with_and_in_expression() {
    let sql = "SELECT * FROM data WHERE (x + y) BETWEEN 10 AND 50;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with parenthesized expression"
    );
}

#[test]
fn test_not_between_with_zero() {
    let sql = "SELECT * FROM scores WHERE value NOT BETWEEN 0 AND 0;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse NOT BETWEEN with same bounds"
    );
}

#[test]
fn test_between_case_insensitive() {
    let sql = "SELECT * FROM data WHERE val between 1 and 10;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse lowercase between keyword"
    );
}

#[test]
fn test_between_with_qualify() {
    let sql = "SELECT * FROM sales QUALIFY ROW_NUMBER() OVER (ORDER BY amount) BETWEEN 1 AND 10;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN in QUALIFY clause"
    );
}

#[test]
fn test_between_timestamp_literals() {
    let sql = "SELECT * FROM events WHERE created_at BETWEEN '2024-01-01 00:00:00' AND '2024-12-31 23:59:59';";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN with timestamp literals"
    );
}

#[test]
fn test_between_combined_with_other_predicates() {
    let sql =
        "SELECT * FROM users WHERE age BETWEEN 18 AND 65 AND status = 'active' AND name LIKE 'J%';";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse BETWEEN combined with other WHERE predicates"
    );
}
