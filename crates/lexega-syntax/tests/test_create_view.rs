// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! UNIT TESTS: CREATE VIEW parsing and formatting with inline SQL.
//!
//! NOTE: These are unit tests with inline SQL strings for quick validation.
//! For fixture-based testing, see test_fixtures_ddl.rs

use lexega_syntax::{format_sql, try_parse_stmt_from_str};

#[test]
fn test_basic_view() {
    let sql = "CREATE VIEW my_view AS SELECT * FROM my_table";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    // Format it
    let formatted = format_sql(sql);
    assert!(formatted.is_ok(), "Failed to format: {:?}", formatted.err());

    println!("Formatted:\n{}", formatted.unwrap());
}

#[test]
fn test_secure_view() {
    let sql = "CREATE OR REPLACE SECURE VIEW my_secure_view AS SELECT id, name FROM users";
    let result = try_parse_stmt_from_str(sql);
    assert!(
        result.is_ok(),
        "Failed to parse secure view: {:?}",
        result.err()
    );

    let formatted = format_sql(sql);
    assert!(formatted.is_ok());

    println!("Formatted secure view:\n{}", formatted.unwrap());
}

#[test]
fn test_recursive_view() {
    let sql = r#"
        CREATE RECURSIVE VIEW employee_hierarchy (title, employee_id, manager_id) AS (
            SELECT title, employee_id, manager_id FROM employees WHERE title = 'President'
            UNION ALL
            SELECT e.title, e.employee_id, e.manager_id 
            FROM employees e
            INNER JOIN employee_hierarchy eh ON eh.employee_id = e.manager_id
        )
    "#;

    let result = try_parse_stmt_from_str(sql);
    assert!(
        result.is_ok(),
        "Failed to parse recursive view: {:?}",
        result.err()
    );

    let formatted = format_sql(sql);
    assert!(formatted.is_ok());

    println!("Formatted recursive view:\n{}", formatted.unwrap());
}

#[test]
fn test_view_with_column_list() {
    let sql = "CREATE VIEW sales_summary (year, total_sales) AS SELECT YEAR(date), SUM(amount) FROM sales GROUP BY YEAR(date)";

    let result = try_parse_stmt_from_str(sql);
    assert!(
        result.is_ok(),
        "Failed to parse view with columns: {:?}",
        result.err()
    );

    let formatted = format_sql(sql);
    assert!(formatted.is_ok());

    println!("Formatted view with columns:\n{}", formatted.unwrap());
}

#[test]
fn test_temp_view() {
    let sql = "CREATE TEMPORARY VIEW temp_view AS SELECT * FROM data";

    let result = try_parse_stmt_from_str(sql);
    assert!(
        result.is_ok(),
        "Failed to parse temp view: {:?}",
        result.err()
    );

    let formatted = format_sql(sql);
    assert!(formatted.is_ok());

    println!("Formatted temp view:\n{}", formatted.unwrap());
}

#[test]
fn test_view_with_comment() {
    let sql = "CREATE VIEW commented_view COMMENT = 'This is a test view' AS SELECT 1 AS col1";

    let result = try_parse_stmt_from_str(sql);
    assert!(
        result.is_ok(),
        "Failed to parse view with comment: {:?}",
        result.err()
    );

    let formatted = format_sql(sql);
    assert!(formatted.is_ok());

    println!("Formatted view with comment:\n{}", formatted.unwrap());
}
