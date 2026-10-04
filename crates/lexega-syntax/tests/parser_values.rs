// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::parse_stmt_from_str;

/// Basic VALUES with simple integers
#[test]
fn test_values_basic_integers() {
    let sql = "SELECT * FROM (VALUES (1, 2), (3, 4));";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse basic VALUES with integers"
    );
}

/// VALUES with string literals
#[test]
fn test_values_with_strings() {
    let sql = "SELECT * FROM (VALUES (1, 'one'), (2, 'two'), (3, 'three'));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with strings");
}

/// VALUES with table alias
#[test]
fn test_values_with_table_alias() {
    let sql = "SELECT * FROM (VALUES (1, 'one'), (2, 'two')) AS v1;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with table alias");
}

/// VALUES with table and column aliases
#[test]
fn test_values_with_column_aliases() {
    let sql = "SELECT c1, c2 FROM (VALUES (1, 'one'), (2, 'two')) AS v1 (c1, c2);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse VALUES with column aliases"
    );
}

/// VALUES with positional column reference
#[test]
fn test_values_with_positional_reference() {
    let sql = "SELECT column1, $2 FROM (VALUES (1, 'one'), (2, 'two'), (3, 'three'));";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse VALUES with positional reference"
    );
}

/// VALUES with JOIN
#[test]
fn test_values_with_join() {
    let sql = "SELECT v1.$2, v2.$2 FROM (VALUES (1, 'one'), (2, 'two')) AS v1 INNER JOIN (VALUES (1, 'One'), (3, 'three')) AS v2 WHERE v2.$1 = v1.$1;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with JOIN");
}

/// Single row VALUES
#[test]
fn test_values_single_row() {
    let sql = "SELECT * FROM (VALUES (42, 'answer'));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse single row VALUES");
}

/// Single column VALUES
#[test]
fn test_values_single_column() {
    let sql = "SELECT * FROM (VALUES (1), (2), (3));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse single column VALUES");
}

/// VALUES with NULL
#[test]
fn test_values_with_null() {
    let sql = "SELECT * FROM (VALUES (1, NULL), (2, 'two'), (NULL, 'three'));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with NULL");
}

/// VALUES with boolean literals
#[test]
fn test_values_with_booleans() {
    let sql = "SELECT * FROM (VALUES (1, TRUE), (2, FALSE), (3, TRUE));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with booleans");
}

/// VALUES with decimal numbers
#[test]
fn test_values_with_decimals() {
    let sql = "SELECT * FROM (VALUES (1.5, 2.7), (3.14, 2.71));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with decimals");
}

/// VALUES with negative numbers
#[test]
fn test_values_with_negative_numbers() {
    let sql = "SELECT * FROM (VALUES (-1, -2), (3, -4), (-5, 6));";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse VALUES with negative numbers"
    );
}

/// VALUES with expressions
#[test]
fn test_values_with_expressions() {
    let sql = "SELECT * FROM (VALUES (1+1, 2*3), (5-2, 10/2));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with expressions");
}

/// VALUES in a CTE
#[test]
fn test_values_in_cte() {
    let sql =
        "WITH numbers AS (SELECT * FROM (VALUES (1), (2), (3)) AS t(n)) SELECT * FROM numbers;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES in CTE");
}

/// VALUES with WHERE clause
#[test]
fn test_values_with_where() {
    let sql = "SELECT * FROM (VALUES (1, 'a'), (2, 'b'), (3, 'c')) AS v WHERE column1 > 1;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with WHERE clause");
}

/// VALUES with ORDER BY
#[test]
fn test_values_with_order_by() {
    let sql = "SELECT * FROM (VALUES (3, 'c'), (1, 'a'), (2, 'b')) AS v ORDER BY column1;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with ORDER BY");
}

/// VALUES with LIMIT
#[test]
fn test_values_with_limit() {
    let sql = "SELECT * FROM (VALUES (1), (2), (3), (4), (5)) AS v LIMIT 3;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with LIMIT");
}

/// Multiple VALUES in UNION
#[test]
fn test_values_with_union() {
    let sql = "SELECT * FROM (VALUES (1, 'a')) UNION SELECT * FROM (VALUES (2, 'b'));";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse multiple VALUES with UNION"
    );
}

/// VALUES with CAST
#[test]
fn test_values_with_cast() {
    let sql = "SELECT * FROM (VALUES (CAST('2024-01-01' AS DATE), 100), (CAST('2024-01-02' AS DATE), 200));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with CAST");
}

/// VALUES with function calls
#[test]
fn test_values_with_functions() {
    let sql = "SELECT * FROM (VALUES (UPPER('hello'), LOWER('WORLD')), (LEFT('test', 2), RIGHT('test', 2)));";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse VALUES with function calls"
    );
}

/// VALUES with mixed types
#[test]
fn test_values_mixed_types() {
    let sql = "SELECT * FROM (VALUES (1, 'text', 3.14, TRUE, NULL));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with mixed types");
}

/// VALUES with date literals
#[test]
fn test_values_with_date_literals() {
    let sql = "SELECT * FROM (VALUES ('2024-01-01', 100), ('2024-01-02', 200)) AS sales(sale_date, amount);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse VALUES with date literals"
    );
}

/// VALUES with LEFT JOIN
#[test]
fn test_values_with_left_join() {
    let sql = "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS v1 LEFT JOIN (VALUES (1, 'x'), (3, 'y')) AS v2 ON v1.column1 = v2.column1;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with LEFT JOIN");
}

/// VALUES with aggregation
#[test]
fn test_values_with_aggregation() {
    let sql = "SELECT column1, SUM(column2) FROM (VALUES (1, 10), (1, 20), (2, 30)) AS v GROUP BY column1;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with aggregation");
}

/// Large VALUES (many rows)
#[test]
fn test_values_many_rows() {
    let sql =
        "SELECT * FROM (VALUES (1), (2), (3), (4), (5), (6), (7), (8), (9), (10)) AS numbers;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VALUES with many rows");
}
