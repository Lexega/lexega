// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for TABLE() function syntax
use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_table_function_simple() {
    let sql = "SELECT * FROM TABLE(my_udtf(10))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse TABLE() function");
}

#[test]
fn test_table_function_with_alias() {
    let sql = "SELECT * FROM TABLE(Fibonacci_Sequence_UDTF(6.0)) AS t";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse TABLE() function with alias"
    );
}

#[test]
fn test_table_function_lateral() {
    let sql = "SELECT * FROM orders, LATERAL TABLE(get_order_items(orders.order_id))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse LATERAL TABLE() function");
}
