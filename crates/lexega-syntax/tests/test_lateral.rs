// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for LATERAL support
//
// IMPORTANT: PostgreSQL LATERAL vs Snowflake LATERAL are ENTIRELY DIFFERENT features!
//
// PostgreSQL LATERAL:
// - Used with subqueries and table functions in FROM clause
// - Allows the subquery/function to reference columns from PRECEDING FROM items
// - Enables correlated operations in FROM clause
// - Example: FROM table1 t1, LATERAL (SELECT * FROM table2 WHERE table2.id = t1.id) t2
//
// Snowflake LATERAL:
// - Primarily used with FLATTEN() function for array/object processing
// - Different syntax and semantics
// - Example: FROM table, LATERAL FLATTEN(input => table.array_column)
//
// These tests focus on PostgreSQL LATERAL semantics (correlated subqueries and table functions).
// For Snowflake LATERAL FLATTEN, see separate Snowflake-specific tests.

use lexega_syntax::dialect::PostgresDialect;
use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::sync::Arc;

fn postgres_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = Arc::new(PostgresDialect);
    config
}

#[test]
fn test_lateral_subquery_basic() {
    let sql = r#"
        SELECT *
        FROM orders o,
        LATERAL (SELECT * FROM order_items WHERE order_id = o.id) oi;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format LATERAL subquery");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
}

#[test]
fn test_lateral_join() {
    let sql = r#"
        SELECT *
        FROM users u
        LEFT JOIN LATERAL (
            SELECT * FROM orders WHERE user_id = u.id ORDER BY created_at DESC LIMIT 5
        ) o ON true;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format LATERAL JOIN");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(formatted.contains("LEFT JOIN"), "Should preserve LEFT JOIN");
}

#[test]
fn test_lateral_function_call() {
    // PostgreSQL: LATERAL with table-returning function (no TABLE() wrapper in PostgreSQL)
    let sql = r#"
        SELECT *
        FROM documents d,
        LATERAL unnest(d.tags) AS tag;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format LATERAL function");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(
        formatted.contains("unnest"),
        "Should preserve function call"
    );
}

#[test]
fn test_lateral_generate_series() {
    // PostgreSQL: LATERAL with generate_series
    let sql = r#"
        SELECT *
        FROM orders o,
        LATERAL generate_series(1, o.quantity) AS item_number;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format LATERAL with generate_series");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(
        formatted.contains("generate_series"),
        "Should preserve function"
    );
}

#[test]
fn test_lateral_with_cross_join() {
    let sql = r#"
        SELECT *
        FROM employees e
        CROSS JOIN LATERAL (
            SELECT * FROM salaries WHERE employee_id = e.id
        ) s;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format LATERAL with CROSS JOIN");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(
        formatted.contains("CROSS JOIN"),
        "Should preserve CROSS JOIN"
    );
}

#[test]
fn test_multiple_lateral_joins() {
    let sql = r#"
        SELECT *
        FROM customers c
        LEFT JOIN LATERAL (SELECT * FROM orders WHERE customer_id = c.id) o ON true
        LEFT JOIN LATERAL (SELECT * FROM shipments WHERE order_id = o.id) s ON true;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format multiple LATERAL joins");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    // Count LATERAL occurrences
    let lateral_count = formatted.matches("LATERAL").count();
    assert_eq!(lateral_count, 2, "Should have 2 LATERAL keywords");
}

#[test]
fn test_lateral_flatten_snowflake_style() {
    // While LATERAL is PostgreSQL, Snowflake also uses it with FLATTEN
    let sql = r#"
        SELECT *
        FROM data d,
        LATERAL FLATTEN(input => d.array_column) f;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format LATERAL FLATTEN");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(
        formatted.contains("FLATTEN"),
        "Should preserve FLATTEN function"
    );
}

#[test]
fn test_lateral_normalizes_whitespace() {
    // If LATERAL is actually parsed (not opaque), it should normalize whitespace
    let sql_with_extra_spaces = "SELECT * FROM t1, LATERAL func(   t1.col   ) t2;";
    let _sql_normalized = "SELECT * FROM t1, LATERAL func(t1.col) t2;";

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql_with_extra_spaces, &config).expect("should parse and format");

    // If formatting is working (not opaque), extra spaces inside function should be normalized
    assert!(
        !formatted.contains("   "),
        "Should normalize extra spaces (not preserve as opaque)"
    );
    assert!(
        formatted.contains("func(t1.col)"),
        "Should normalize to single spaces"
    );
}

#[test]
fn test_lateral_correlated_subquery() {
    // PostgreSQL: LATERAL with correlated subquery
    // This is the PRIMARY use case for LATERAL in PostgreSQL
    let sql = r#"
        SELECT p.product_name, recent_sales.sale_date
        FROM products p,
        LATERAL (
            SELECT sale_date
            FROM sales s
            WHERE s.product_id = p.id
            ORDER BY sale_date DESC
            LIMIT 5
        ) AS recent_sales;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse LATERAL correlated subquery");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.to_uppercase().contains("LATERAL"),
        "Should preserve LATERAL"
    );
    assert!(
        formatted.contains("WHERE"),
        "Should preserve correlation predicate"
    );
}

#[test]
fn test_lateral_left_join_subquery() {
    // PostgreSQL: LATERAL in LEFT JOIN - very common pattern
    let sql = r#"
        SELECT m.name, la.amount
        FROM manufacturers m
        LEFT JOIN LATERAL (
            SELECT amount
            FROM products p
            WHERE p.manufacturer_id = m.id
            ORDER BY amount DESC
            LIMIT 5
        ) AS la ON true;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse LATERAL in LEFT JOIN");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.to_uppercase().contains("LATERAL"),
        "Should preserve LATERAL"
    );
    assert!(
        formatted.to_uppercase().contains("LEFT JOIN"),
        "Should preserve LEFT JOIN"
    );
}

#[test]
fn test_non_lateral_subquery_still_works() {
    let sql = r#"
        SELECT *
        FROM orders o
        JOIN (SELECT * FROM order_items WHERE price > 100) oi ON o.id = oi.order_id;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format non-LATERAL subquery");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        !formatted.contains("LATERAL"),
        "Should not contain LATERAL keyword"
    );
}

#[test]
fn test_lateral_with_where_clause() {
    let sql = r#"
        SELECT u.name, o.total
        FROM users u
        LEFT JOIN LATERAL (
            SELECT SUM(amount) as total
            FROM orders
            WHERE user_id = u.id AND status = 'completed'
        ) o ON true
        WHERE u.active = true;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format LATERAL with WHERE clause");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(formatted.contains("WHERE"), "Should preserve WHERE clauses");
}

#[test]
fn test_lateral_inner_join() {
    let sql = r#"
        SELECT *
        FROM departments d
        INNER JOIN LATERAL (
            SELECT * FROM employees WHERE department_id = d.id
        ) e ON true;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format LATERAL with INNER JOIN");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(
        formatted.contains("INNER JOIN"),
        "Should preserve INNER JOIN"
    );
}

#[test]
fn test_lateral_with_alias() {
    let sql = r#"
        SELECT *
        FROM users u,
        LATERAL (SELECT * FROM orders WHERE user_id = u.id) AS user_orders;
    "#;

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format LATERAL with alias");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(formatted.contains("user_orders"), "Should preserve alias");
}

#[test]
fn test_lateral_complex_correlation() {
    let sql = r#"
        SELECT *
        FROM projects p
        LEFT JOIN LATERAL (
            SELECT t.*, u.name as assignee_name
            FROM tasks t
            JOIN users u ON t.assignee_id = u.id
            WHERE t.project_id = p.id
            ORDER BY t.priority DESC
            LIMIT 10
        ) recent_tasks ON true;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format complex LATERAL query");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(formatted.contains("ORDER BY"), "Should preserve ORDER BY");
    assert!(formatted.contains("LIMIT"), "Should preserve LIMIT");
}

#[test]
fn test_lateral_with_distance_operator() {
    // PostgreSQL docs example using geometric distance operator <->
    let sql = r#"
        SELECT p1.id, p2.id, v1, v2
        FROM polygons p1, polygons p2,
             LATERAL vertices(p1.poly) v1,
             LATERAL vertices(p2.poly) v2
        WHERE (v1 <-> v2) < 10 AND p1.id != p2.id;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format LATERAL with distance operator");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("LATERAL"),
        "Should preserve LATERAL keyword"
    );
    assert!(
        formatted.contains("<->"),
        "Should preserve distance operator"
    );

    // Test that whitespace is normalized (proves it's NOT opaque)
    let sql_with_extra_whitespace = r#"
        SELECT    p1.id,    p2.id,    v1,    v2
        FROM    polygons    p1,    polygons    p2,
             LATERAL    vertices(p1.poly)    v1,
             LATERAL    vertices(p2.poly)    v2
        WHERE    (v1    <->    v2)    <    10    AND    p1.id    !=    p2.id;
    "#;

    let formatted_whitespace = format_sql_with_config(sql_with_extra_whitespace, &config)
        .expect("should parse and format with extra whitespace");

    // If the query parses correctly, extra whitespace should be normalized
    // If it's opaque, whitespace will be preserved exactly
    assert!(
        !formatted_whitespace.contains("    p1.id,    "),
        "Whitespace should be normalized, not preserved exactly (if preserved, query is opaque)"
    );
}
