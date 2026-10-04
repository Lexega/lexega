// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for SAMPLE/TABLESAMPLE clause
/// Based on Snowflake documentation: https://docs.snowflake.com/en/sql-reference/constructs/sample
use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_sample_simple_probability() {
    let sql = "SELECT * FROM testtable SAMPLE (10)";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse SAMPLE with simple probability"
    );
}

#[test]
fn test_sample_decimal_probability() {
    let sql = "SELECT * FROM testtable TABLESAMPLE BERNOULLI (20.3)";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse TABLESAMPLE BERNOULLI with decimal"
    );
}

#[test]
fn test_sample_full_table() {
    let sql = "SELECT * FROM testtable TABLESAMPLE (100)";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE with 100%");
}

#[test]
fn test_sample_empty() {
    let sql = "SELECT * FROM testtable SAMPLE ROW (0)";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE ROW with 0%");
}

#[test]
fn test_sample_system_with_seed() {
    let sql = "SELECT * FROM testtable SAMPLE SYSTEM (3) SEED (82)";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE SYSTEM with SEED");
}

#[test]
fn test_sample_block_with_repeatable() {
    let sql = "SELECT * FROM testtable SAMPLE BLOCK (0.012) REPEATABLE (99992)";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse SAMPLE BLOCK with REPEATABLE"
    );
}

#[test]
fn test_sample_fixed_rows() {
    let sql = "SELECT * FROM testtable SAMPLE (10 ROWS)";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE with fixed ROWS");
}

#[test]
fn test_sample_multiple_tables_join() {
    let sql = "SELECT i, j FROM table1 AS t1 SAMPLE (25) INNER JOIN table2 AS t2 SAMPLE (50) WHERE t2.j = t1.i";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse SAMPLE on both sides of JOIN"
    );
}

#[test]
fn test_sample_one_table_in_join() {
    let sql = "SELECT i, j FROM table1 AS t1 INNER JOIN table2 AS t2 SAMPLE (50) WHERE t2.j = t1.i";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse SAMPLE on one table in JOIN"
    );
}

#[test]
fn test_sample_on_subquery_result() {
    let sql = "SELECT * FROM (SELECT * FROM t1 JOIN t2 ON t1.a = t2.c) SAMPLE (1)";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE on subquery result");
}

#[test]
fn test_sample_with_alias() {
    let sql = "SELECT * FROM testtable AS t SAMPLE (10)";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE with table alias");
}

#[test]
fn test_sample_with_where() {
    let sql = "SELECT * FROM testtable SAMPLE (50) WHERE id > 100";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE with WHERE clause");
}

#[test]
fn test_sample_with_order_by() {
    let sql = "SELECT * FROM testtable SAMPLE (25) ORDER BY id";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE with ORDER BY");
}

#[test]
fn test_sample_bernoulli_synonym() {
    let sql = "SELECT * FROM testtable SAMPLE ROW (15)";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse ROW as synonym for BERNOULLI"
    );
}

#[test]
fn test_sample_system_synonym() {
    let sql = "SELECT * FROM testtable SAMPLE BLOCK (20)";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse BLOCK as synonym for SYSTEM"
    );
}

#[test]
fn test_sample_with_time_travel() {
    let sql = "SELECT * FROM testtable AT (TIMESTAMP => '2024-01-01'::TIMESTAMP) SAMPLE (10)";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse SAMPLE with time travel");
}

#[test]
fn test_sample_expression_probability() {
    // Snowflake allows session/bind variables for probability
    let sql = "SELECT * FROM testtable SAMPLE (10 + 5)";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse SAMPLE with expression probability"
    );
}

#[test]
fn test_sample_expression_rows() {
    let sql = "SELECT * FROM testtable SAMPLE ((100 * 2) ROWS)";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse SAMPLE with expression for ROWS"
    );
}
