// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test PIVOT and UNPIVOT formatting

use lexega_syntax::{format_sql, parse_stmt_from_str};

#[test]
fn test_pivot_explicit_values() {
    let sql =
        "SELECT * FROM sales PIVOT(SUM(amount) FOR quarter IN ('2023_Q1', '2023_Q2', '2023_Q3'))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("SUM"));
    assert!(formatted.contains("FOR"));
    assert!(formatted.contains("IN"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_pivot_with_aliases() {
    let sql = "SELECT * FROM sales PIVOT(SUM(amount) FOR quarter IN ('Q1' AS q1, 'Q2' AS q2, 'Q3' AS q3))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    println!("Formatted:\n{}", formatted);
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("AS"));
}

#[test]
fn test_pivot_any() {
    let sql = "SELECT * FROM sales PIVOT(AVG(price) FOR product IN (ANY))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    println!("Formatted:\n{}", formatted);
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("ANY"));
}

#[test]
fn test_pivot_with_aggregate_alias() {
    let sql = "SELECT * FROM sales PIVOT(SUM(amount) AS total_sales FOR quarter IN ('Q1', 'Q2'))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("AS"));
    assert!(formatted.contains("total_sales"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_unpivot_basic() {
    let sql = "SELECT * FROM quarterly_sales UNPIVOT EXCLUDE NULLS (sales FOR quarter IN (q1, q2, q3, q4))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("UNPIVOT"));
    assert!(formatted.contains("EXCLUDE"));
    assert!(formatted.contains("NULLS"));
    assert!(formatted.contains("FOR"));
    assert!(formatted.contains("IN"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_unpivot_include_nulls() {
    let sql = "SELECT * FROM data UNPIVOT INCLUDE NULLS (value FOR name IN (col1, col2, col3))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("UNPIVOT"));
    assert!(formatted.contains("INCLUDE"));
    assert!(formatted.contains("NULLS"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_unpivot_with_aliases() {
    let sql = "SELECT * FROM data UNPIVOT EXCLUDE NULLS (value FOR name IN (jan AS January, feb AS February))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("UNPIVOT"));
    assert!(formatted.contains("AS"));
    assert!(formatted.contains("January"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_pivot_unpivot_combination() {
    // Test that we can parse queries with both PIVOT and complex features
    let test_cases = vec![
        "SELECT * FROM t PIVOT(MAX(val) FOR cat IN ('A', 'B')) WHERE id > 10",
        "SELECT * FROM t UNPIVOT EXCLUDE NULLS (v FOR n IN (a, b, c)) ORDER BY v",
    ];

    for sql in test_cases {
        let ast = parse_stmt_from_str(sql);
        assert!(ast.is_some(), "Failed to parse: {}", sql);

        let formatted = format_sql(sql).expect(&format!("Failed to format: {}", sql));
        println!("Input:  {}", sql);
        println!("Output: {}\n", formatted);
    }
}
