// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::parse_stmt_from_str;

/// Basic LATERAL with subquery in comma syntax
#[test]
fn test_lateral_comma_syntax() {
    let sql = "SELECT * FROM t1, LATERAL (SELECT * FROM t2 WHERE t2.id = t1.id);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse LATERAL with comma syntax"
    );
}

/// LATERAL with explicit INNER JOIN
#[test]
fn test_lateral_inner_join() {
    let sql =
        "SELECT * FROM t1 INNER JOIN LATERAL (SELECT * FROM t2 WHERE t2.id = t1.id) AS sq ON TRUE;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse LATERAL with INNER JOIN");
}

/// LATERAL with LEFT JOIN
#[test]
fn test_lateral_left_join() {
    let sql = "SELECT * FROM customers c LEFT JOIN LATERAL (SELECT * FROM orders WHERE customer_id = c.id LIMIT 3) AS recent_orders ON TRUE;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse LATERAL with LEFT JOIN");
}

/// LATERAL with aliased subquery
#[test]
fn test_lateral_aliased_subquery() {
    let sql = "SELECT * FROM employees e, LATERAL (SELECT * FROM projects p WHERE p.manager_id = e.id) AS emp_projects;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse LATERAL with aliased subquery"
    );
}

/// LATERAL with table function (table function not yet implemented, but parser should handle keyword)
#[test]
fn test_lateral_table_function_syntax() {
    let sql = "SELECT * FROM t1, LATERAL flatten(input => t1.json_col);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse LATERAL with table function syntax"
    );
}

/// LATERAL with correlated WHERE clause
#[test]
fn test_lateral_correlated_where() {
    let sql = "SELECT * FROM regions r, LATERAL (SELECT * FROM stores WHERE region = r.name) AS regional_stores;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse LATERAL with correlated WHERE"
    );
}

/// Multiple LATERAL joins in sequence
#[test]
fn test_multiple_lateral_joins() {
    let sql = "SELECT * FROM t1, LATERAL (SELECT * FROM t2 WHERE t2.id = t1.id) AS sq1, LATERAL (SELECT * FROM t3 WHERE t3.id = sq1.id) AS sq2;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse multiple LATERAL joins");
}

/// LATERAL with complex subquery including ORDER BY and LIMIT
#[test]
fn test_lateral_complex_subquery() {
    let sql = "SELECT * FROM accounts a LEFT JOIN LATERAL (SELECT * FROM transactions WHERE account_id = a.id ORDER BY transaction_date DESC LIMIT 5) AS recent_txns ON TRUE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse LATERAL with complex subquery"
    );
}

/// LATERAL with aggregation in subquery
#[test]
fn test_lateral_with_aggregation() {
    let sql = "SELECT * FROM products p, LATERAL (SELECT COUNT(*) AS review_count FROM reviews WHERE product_id = p.id) AS stats;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse LATERAL with aggregation");
}

/// LATERAL RIGHT JOIN
#[test]
fn test_lateral_right_join() {
    let sql = "SELECT * FROM t1 RIGHT JOIN LATERAL (SELECT * FROM t2) AS sq ON t1.id = sq.id;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse LATERAL with RIGHT JOIN");
}

/// LATERAL with FULL OUTER JOIN
#[test]
fn test_lateral_full_outer_join() {
    let sql = "SELECT * FROM t1 FULL OUTER JOIN LATERAL (SELECT * FROM t2) AS sq ON t1.id = sq.id;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse LATERAL with FULL OUTER JOIN"
    );
}

/// LATERAL with CROSS JOIN (comma syntax is equivalent to CROSS JOIN)
#[test]
fn test_lateral_cross_join_explicit() {
    let sql =
        "SELECT * FROM t1 CROSS JOIN LATERAL (SELECT * FROM t2 WHERE t2.val > t1.val) AS filtered;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse LATERAL with CROSS JOIN");
}

/// LATERAL with nested subqueries
#[test]
fn test_lateral_nested_subqueries() {
    let sql = "SELECT * FROM t1, LATERAL (SELECT * FROM (SELECT * FROM t2 WHERE t2.x = t1.x) WHERE y > 10) AS nested;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse LATERAL with nested subqueries"
    );
}

/// LATERAL with USING clause (should work with explicit joins)
#[test]
fn test_lateral_with_using() {
    let sql = "SELECT * FROM t1 INNER JOIN LATERAL (SELECT id, data FROM t2 WHERE t2.fk = t1.id) AS sq USING (id);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse LATERAL with USING");
}

/// LATERAL in a more complex FROM clause with multiple tables
#[test]
fn test_lateral_mixed_joins() {
    let sql = "SELECT * FROM t1 JOIN t2 ON t1.id = t2.id, LATERAL (SELECT * FROM t3 WHERE t3.x = t1.x) AS sq;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse LATERAL with mixed joins");
}
