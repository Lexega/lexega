// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for semi-structured data access: array subscripts and object field access.
/// Based on Snowflake documentation: https://docs.snowflake.com/en/user-guide/querying-semistructured
use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_array_subscript_simple() {
    let sql = "SELECT arr[0] FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse array subscript");
}

#[test]
fn test_array_subscript_expression_index() {
    let sql = "SELECT arr[i + 1] FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse array subscript with expression index"
    );
}

#[test]
fn test_array_subscript_negative() {
    let sql = "SELECT arr[-1] FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse array subscript with negative index"
    );
}

#[test]
fn test_object_field_colon_simple() {
    let sql = "SELECT src:dealership FROM car_sales";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse object field access with colon"
    );
}

#[test]
fn test_object_field_colon_nested() {
    let sql = "SELECT src:salesperson FROM car_sales";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse nested object field access");
}

#[test]
fn test_object_field_bracket_simple() {
    let sql = "SELECT src['salesperson'] FROM car_sales";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse object field access with brackets"
    );
}

#[test]
fn test_object_field_bracket_nested() {
    let sql = "SELECT src['salesperson']['name'] FROM car_sales";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse nested bracket field access"
    );
}

#[test]
fn test_chained_array_and_object() {
    let sql = "SELECT src:customer[0] FROM car_sales";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse chained object and array access"
    );
}

#[test]
fn test_complex_chaining() {
    let sql = "SELECT data:items[0]:price FROM products";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse complex chained access");
}

#[test]
fn test_array_access_in_where() {
    let sql = "SELECT * FROM table1 WHERE arr[0] > 10";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse array access in WHERE clause"
    );
}

#[test]
fn test_object_field_in_where() {
    let sql = "SELECT * FROM table1 WHERE data:status = 'active'";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse object field in WHERE clause"
    );
}

#[test]
fn test_nested_array_subscript() {
    let sql = "SELECT arr[arr[0]] FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse nested array subscript");
}

#[test]
fn test_cast_with_array_access() {
    let sql = "SELECT src:vehicle[0]::VARCHAR FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse type cast with array access"
    );
}

#[test]
fn test_multiple_fields_with_access() {
    let sql = "SELECT src:customer[0]:name, src:vehicle[0]:price FROM car_sales";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse multiple fields with chained access"
    );
}

#[test]
fn test_array_in_function_call() {
    let sql = "SELECT UPPER(data:name[0]) FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse array access in function call"
    );
}

#[test]
fn test_object_field_with_spaces() {
    let sql = "SELECT obj['field with spaces'] FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse field with spaces");
}

#[test]
fn test_get_path_equivalent() {
    let sql = "SELECT src:vehicle[0]:make FROM car_sales";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse GET_PATH equivalent");
}

#[test]
fn test_arithmetic_with_array_access() {
    let sql = "SELECT arr[0] + arr[1] FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse arithmetic with array access"
    );
}

#[test]
fn test_comparison_with_object_field() {
    let sql = "SELECT * FROM table1 WHERE obj:field1 = obj:field2";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse comparison with object fields"
    );
}

#[test]
fn test_deeply_nested_chaining() {
    let sql = "SELECT data:level1:level2:level3[0][1]:field FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse deeply nested chaining");
}

#[test]
fn test_mixed_bracket_and_colon() {
    let sql = "SELECT obj['field1']:field2['field3'] FROM table1";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse mixed bracket and colon notation"
    );
}
