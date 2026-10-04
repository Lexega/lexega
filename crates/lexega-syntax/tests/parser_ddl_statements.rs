// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// DDL (Data Definition Language) statement tests
// Tests for CREATE TABLE, DROP TABLE, and other DDL operations
use lexega_syntax::parse_sql;
use lexega_syntax::parse_stmt_from_str;

// CREATE TABLE with table type modifiers

#[test]
fn test_create_temp_table() {
    let sql = "CREATE TEMP TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE TEMP TABLE");
}

#[test]
fn test_create_temporary_table() {
    let sql = "CREATE TEMPORARY TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE TEMPORARY TABLE");
}

#[test]
fn test_create_local_temp_table() {
    let sql = "CREATE LOCAL TEMP TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE LOCAL TEMP TABLE");
}

#[test]
fn test_create_global_temporary_table() {
    let sql = "CREATE GLOBAL TEMPORARY TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CREATE GLOBAL TEMPORARY TABLE"
    );
}

#[test]
fn test_create_volatile_table() {
    let sql = "CREATE VOLATILE TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE VOLATILE TABLE");
}

#[test]
fn test_create_transient_table() {
    let sql = "CREATE TRANSIENT TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE TRANSIENT TABLE");
}

#[test]
fn test_create_or_replace_temp_table() {
    let sql = "CREATE OR REPLACE TEMP TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CREATE OR REPLACE TEMP TABLE"
    );
}

#[test]
fn test_create_or_replace_local_temporary_table() {
    let sql = "CREATE OR REPLACE LOCAL TEMPORARY TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CREATE OR REPLACE LOCAL TEMPORARY TABLE"
    );
}

// CREATE TABLE in scripting context

#[test]
fn test_create_temporary_table_in_block() {
    let src = r#"
BEGIN
    CREATE TEMPORARY TABLE staging (id INTEGER);
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CREATE TEMPORARY TABLE in block"
    );
}

#[test]
fn test_create_temp_table_as_select() {
    let src = r#"
BEGIN
    CREATE TEMPORARY TABLE staging AS SELECT * FROM source WHERE 1=0;
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CREATE TEMPORARY TABLE AS SELECT"
    );
}

#[test]
fn test_create_temporary_table_as_select_full() {
    let src = r#"
BEGIN
    CREATE TEMPORARY TABLE staging AS SELECT * FROM employees;
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CREATE TEMPORARY TABLE AS SELECT (full)"
    );
}

#[test]
fn test_create_temp_table_with_cte() {
    let src = r#"
BEGIN
    CREATE TEMP TABLE my_temp_tbl AS
    WITH MY_CTE AS (
        SELECT id, name, salary
        FROM employees
        WHERE salary > 50000
    )
    SELECT id, name, salary * 1.1 AS new_salary
    FROM MY_CTE
    WHERE name LIKE 'A%';
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse CREATE TEMP TABLE with CTE");
}

// DROP TABLE statements

#[test]
fn test_drop_table_if_exists() {
    let src = r#"
BEGIN
    DROP TABLE IF EXISTS staging;
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse DROP TABLE IF EXISTS");
}
