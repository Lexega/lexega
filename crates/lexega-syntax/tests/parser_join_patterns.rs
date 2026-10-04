// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test various JOIN pattern recognition including edge cases
//! Verifies that keywords can be used as identifiers except when they start join patterns

use lexega_syntax::{ast::*, format_sql, parse_stmt_from_str};

fn parse_select(sql: &str) -> AstSelect {
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse");
    match stmt {
        AstStmt::Select(select) => select.as_ref().clone(),
        _ => panic!("Expected SELECT statement"),
    }
}

#[test]
fn test_asof_join() {
    // Basic ASOF JOIN without MATCH_CONDITION
    let sql = "SELECT * FROM t1 ASOF JOIN t2 ON t1.id = t2.id";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    assert!(select.from[0].joins[0].asof_keyword_span.is_some());
    assert!(select.from[0].joins[0].match_condition.is_none());
}

#[test]
fn test_asof_join_with_match_condition() {
    // ASOF JOIN with MATCH_CONDITION - the full syntax
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts >= t2.ts) ON t1.id = t2.id";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    let join = &select.from[0].joins[0];
    assert!(join.asof_keyword_span.is_some());
    assert!(join.match_condition.is_some());
}

#[test]
fn test_asof_join_match_condition_using() {
    // ASOF JOIN with MATCH_CONDITION and USING clause
    let sql =
        "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.timestamp >= t2.timestamp) USING (id)";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    let join = &select.from[0].joins[0];
    assert!(join.asof_keyword_span.is_some());
    assert!(join.match_condition.is_some());
}

#[test]
fn test_asof_join_match_condition_only() {
    // ASOF JOIN with only MATCH_CONDITION (no ON or USING)
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts > t2.ts)";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
    let join = &select.from[0].joins[0];
    assert!(join.asof_keyword_span.is_some());
    assert!(join.match_condition.is_some());
}

#[test]
fn test_match_condition_case_insensitive() {
    // MATCH_CONDITION should be case-insensitive
    let sql = "SELECT * FROM t1 ASOF JOIN t2 match_condition(t1.x <= t2.x)";
    let select = parse_select(sql);
    let join = &select.from[0].joins[0];
    assert!(join.match_condition.is_some());
}

#[test]
fn test_asof_as_alias() {
    // ASOF should work as an alias when not followed by JOIN
    let sql = "SELECT * FROM table1 AS asof";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_outer_as_alias() {
    // OUTER should work as an alias
    // Note: Standalone "OUTER JOIN" (without LEFT/RIGHT/FULL) is NOT valid Snowflake syntax
    let sql = "SELECT * FROM table1 AS outer";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_natural_left_outer_join() {
    // NATURAL LEFT OUTER JOIN should parse correctly
    let sql = "SELECT * FROM t1 NATURAL LEFT OUTER JOIN t2";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
}

#[test]
fn test_left_directed_join() {
    // LEFT DIRECTED JOIN should parse
    let sql = "SELECT * FROM t1 LEFT DIRECTED JOIN t2 ON t1.id = t2.id";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert_eq!(select.from[0].joins.len(), 1);
}

#[test]
fn test_inner_as_alias() {
    // INNER should work as alias when not followed by JOIN
    let sql = "SELECT * FROM table1 AS inner";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_left_as_alias() {
    // LEFT should work as alias when not followed by JOIN/OUTER/DIRECTED
    let sql = "SELECT * FROM table1 AS left";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_natural_as_alias() {
    // NATURAL should work as alias when not followed by join patterns
    let sql = "SELECT * FROM table1 AS natural";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_cross_as_alias() {
    // CROSS should work as alias when not followed by JOIN
    let sql = "SELECT * FROM table1 AS cross";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_connect_as_alias() {
    // CONNECT should work as alias when not followed by BY
    let sql = "SELECT * FROM table1 AS connect";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_start_as_alias() {
    // START should work as alias when not followed by WITH
    let sql = "SELECT * FROM table1 AS start";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].alias.is_some());
}

#[test]
fn test_asof_match_condition_formatter() {
    // Test that formatter outputs MATCH_CONDITION correctly
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.ts >= t2.ts) ON t1.id = t2.id";
    let formatted = format_sql(sql).expect("Failed to format");
    assert!(formatted.contains("MATCH_CONDITION"));
    assert!(formatted.contains(">="));
    assert!(formatted.contains("ASOF"));
    println!("Formatted SQL:\n{}", formatted);
}

#[test]
fn test_match_condition_not_consumed_as_alias() {
    // Ensure MATCH_CONDITION(expr) is not treated as a table alias
    let sql = "SELECT * FROM t1 ASOF JOIN t2 MATCH_CONDITION(t1.x >= t2.x) ON t1.id = t2.id";
    let select = parse_select(sql);
    let join = &select.from[0].joins[0];

    // The right table should NOT have MATCH_CONDITION as its alias
    assert!(
        select.from[0].joins[0].right.alias.is_none(),
        "MATCH_CONDITION should not be consumed as table alias"
    );

    // Instead, it should be in the match_condition field
    assert!(
        join.match_condition.is_some(),
        "MATCH_CONDITION should be parsed as join condition"
    );
}
