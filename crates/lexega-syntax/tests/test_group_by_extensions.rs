// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql, parse_sql, parse_stmt_from_str};

#[test]
fn test_group_by_all() {
    let sql = "SELECT name, COUNT(*) FROM users GROUP BY ALL";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY ALL");

    // Should also format correctly
    let formatted = format_sql(sql);
    assert!(formatted.is_ok());
}

#[test]
fn test_group_by_cube_simple() {
    let sql = "SELECT state, city, SUM(profit) FROM sales GROUP BY CUBE(state, city)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY CUBE");
}

#[test]
fn test_group_by_rollup_simple() {
    let sql = "SELECT state, city, SUM(profit) FROM sales GROUP BY ROLLUP(state, city)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY ROLLUP");
}

#[test]
fn test_group_by_grouping_sets_simple() {
    let sql = "SELECT medical_license, radio_license, COUNT(*) FROM nurses GROUP BY GROUPING SETS(medical_license, radio_license)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY GROUPING SETS");
}

#[test]
fn test_group_by_grouping_sets_nested() {
    let sql = "SELECT a, b, c, COUNT(*) FROM t GROUP BY GROUPING SETS((a, b), (c), ())";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY GROUPING SETS with nested groups"
    );
}

#[test]
fn test_group_by_position_ref() {
    let sql = "SELECT name, age, COUNT(*) FROM users GROUP BY 1, 2";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY with positional references"
    );
}

#[test]
fn test_group_by_mixed() {
    let sql = "SELECT name, age, COUNT(*) FROM users GROUP BY name, 2";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY with mixed column and position"
    );
}

#[test]
fn test_group_by_cube_max_elements() {
    // 7 elements is the max for CUBE (generates 128 grouping sets)
    let sql = "SELECT a, b, c, d, e, f, g, COUNT(*) FROM t GROUP BY CUBE(a, b, c, d, e, f, g)";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY CUBE with 7 elements"
    );
}

#[test]
fn test_group_by_cube_too_many_elements() {
    // Parser should accept CUBE with any number of elements
    // Snowflake will reject this at runtime (max 7 elements), but that's not the parser's job
    let sql =
        "SELECT a, b, c, d, e, f, g, h, COUNT(*) FROM t GROUP BY CUBE(a, b, c, d, e, f, g, h)";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Parser should accept CUBE with 8 elements (Snowflake runtime will validate)"
    );
}

#[test]
fn test_group_by_grouping_sets_max() {
    // Generate SQL with exactly 128 grouping sets
    let mut sets = Vec::new();
    for i in 0..128 {
        sets.push(format!("(col{})", i));
    }
    let sql = format!(
        "SELECT COUNT(*) FROM t GROUP BY GROUPING SETS({})",
        sets.join(", ")
    );
    let result = parse_stmt_from_str(&sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY GROUPING SETS with 128 sets"
    );
}

#[test]
fn test_group_by_grouping_sets_too_many() {
    // Parser should accept GROUPING SETS with any number of sets
    // Snowflake will reject this at runtime (max 128 sets), but that's not the parser's job
    let mut sets = vec![];
    for i in 0..129 {
        sets.push(format!("(col{})", i));
    }
    let sql = format!(
        "SELECT COUNT(*) FROM t GROUP BY GROUPING SETS({})",
        sets.join(", ")
    );

    let result = parse_sql(&sql);
    assert!(
        result.is_ok(),
        "Parser should accept GROUPING SETS with 129 sets (Snowflake runtime will validate)"
    );
}

#[test]
fn test_group_by_standard() {
    let sql = "SELECT name, age, COUNT(*) FROM users GROUP BY name, age";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse standard GROUP BY");
}

#[test]
fn test_group_by_with_having() {
    let sql = "SELECT name, COUNT(*) FROM users GROUP BY name HAVING COUNT(*) > 5";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY with HAVING");
}

#[test]
fn test_group_by_cube_with_having() {
    let sql = "SELECT state, city, SUM(profit) FROM sales GROUP BY CUBE(state, city) HAVING SUM(profit) > 1000";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY CUBE with HAVING");
}

#[test]
fn test_group_by_all_with_order() {
    let sql = "SELECT name, COUNT(*) FROM users GROUP BY ALL ORDER BY COUNT(*) DESC";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY ALL with ORDER BY");
}

#[test]
fn test_group_by_expression() {
    let sql = "SELECT YEAR(created_at), COUNT(*) FROM users GROUP BY YEAR(created_at)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY with expression");
}

#[test]
fn test_group_by_case_expression() {
    let sql = "SELECT CASE WHEN age < 18 THEN 'minor' ELSE 'adult' END, COUNT(*) FROM users GROUP BY CASE WHEN age < 18 THEN 'minor' ELSE 'adult' END";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY with CASE expression"
    );
}
