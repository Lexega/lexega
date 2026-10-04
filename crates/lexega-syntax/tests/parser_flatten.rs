// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for FLATTEN() table function
/// Based on Snowflake documentation: https://docs.snowflake.com/en/sql-reference/functions/flatten
use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_flatten_simple() {
    let sql = "SELECT * FROM TABLE(FLATTEN(INPUT => PARSE_JSON('[1, ,77]'))) f";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse simple FLATTEN");
}

#[test]
fn test_flatten_with_path() {
    let sql = "SELECT * FROM TABLE(FLATTEN(INPUT => data, PATH => 'contact'))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse FLATTEN with PATH");
}

#[test]
fn test_flatten_with_outer() {
    let sql = "SELECT * FROM TABLE(FLATTEN(INPUT => PARSE_JSON('[]'), OUTER => TRUE))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse FLATTEN with OUTER");
}

#[test]
fn test_flatten_with_recursive() {
    let sql = "SELECT * FROM TABLE(FLATTEN(INPUT => data, RECURSIVE => TRUE))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse FLATTEN with RECURSIVE");
}

#[test]
fn test_flatten_with_mode() {
    let sql = "SELECT * FROM TABLE(FLATTEN(INPUT => data, RECURSIVE => TRUE, MODE => 'OBJECT'))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse FLATTEN with MODE");
}

#[test]
fn test_flatten_lateral() {
    let sql = "SELECT * FROM persons p, LATERAL FLATTEN(INPUT => p.c, PATH => 'contact') f";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse LATERAL FLATTEN");
}

#[test]
fn test_flatten_multiple_lateral() {
    let sql = "SELECT id, f.value FROM persons p, LATERAL FLATTEN(INPUT => p.c, PATH => 'contact') f, LATERAL FLATTEN(INPUT => f.value:business) f1";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse multiple LATERAL FLATTEN");
}

#[test]
fn test_flatten_in_where() {
    let sql = "SELECT * FROM pets a, LATERAL FLATTEN(INPUT => a.v) b WHERE b.value LIKE '%dog%'";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse FLATTEN in WHERE");
}

#[test]
fn test_flatten_all_params() {
    let sql = "SELECT * FROM TABLE(FLATTEN(INPUT => data, PATH => 'items', OUTER => FALSE, RECURSIVE => TRUE, MODE => 'BOTH'))";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse FLATTEN with all parameters"
    );
}
