// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// LIMIT and OFFSET clause tests
// Based on https://docs.snowflake.com/en/sql-reference/constructs/limit
use lexega_syntax::ast::AstStmt;
use lexega_syntax::parse_sql;

#[test]
fn test_limit_basic() {
    let src = "SELECT col FROM t LIMIT 10;";
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse LIMIT");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            assert!(select.limit.is_some(), "should have LIMIT");
        }
    }
}

#[test]
fn test_limit_with_offset() {
    let src = "SELECT c1 FROM testtable LIMIT 3 OFFSET 3;";
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse LIMIT with OFFSET");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            assert!(select.limit.is_some(), "should have LIMIT");
            assert!(select.offset.is_some(), "should have OFFSET");
        }
    }
}

#[test]
fn test_limit_with_order_by() {
    let src = "SELECT c1 FROM testtable ORDER BY c1 LIMIT 3 OFFSET 3;";
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse LIMIT with ORDER BY");
}

#[test]
fn test_limit_null_unlimited() {
    // NULL means unlimited per docs
    let src = "SELECT * FROM demo1 ORDER BY i LIMIT NULL OFFSET NULL;";
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse LIMIT NULL");
}

#[test]
fn test_fetch_first_ansi_syntax() {
    // ANSI syntax: FETCH FIRST n ROWS ONLY
    let src = "SELECT col FROM t OFFSET 10 ROWS FETCH FIRST 5 ROWS ONLY;";
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse FETCH FIRST");
}

#[test]
fn test_fetch_next_syntax() {
    // FETCH NEXT is synonym for FETCH FIRST
    let src = "SELECT col FROM t FETCH NEXT 10 ROWS ONLY;";
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse FETCH NEXT");
}

#[test]
fn test_offset_row_singular() {
    // OFFSET can use ROW (singular) or ROWS (plural)
    let src = "SELECT col FROM t OFFSET 1 ROW FETCH FIRST 10 ROWS ONLY;";
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse OFFSET ROW");
}
