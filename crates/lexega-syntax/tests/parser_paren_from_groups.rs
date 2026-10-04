// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parenthesised FROM-item groups (standard SQL `joined_table` production).
//!
//! Tests for the `(t1 a JOIN t2 b ON …)` shape common in tool-generated SQL
//! (Tableau, Power BI, dbt macros, migrated Oracle/Sybase code). The parser
//! must promote the inner joined-table into the outer AstTableRef carrying
//! `paren_group_*` spans; the formatter must round-trip the parens.

use lexega_syntax::{
    ast::*, format_sql_with_config, parse_stmt_from_str, verify_formatting_safe_with_dialect,
    FormatterConfig,
};

fn parse_select(sql: &str) -> AstSelect {
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse");
    match stmt {
        AstStmt::Select(select) => select.as_ref().clone(),
        _ => panic!(
            "Expected SELECT statement, got {:?}",
            std::mem::discriminant(&stmt)
        ),
    }
}

fn fmt_default() -> FormatterConfig {
    FormatterConfig::default()
}

#[test]
fn paren_group_two_table_join_no_alias() {
    let sql = "SELECT a.x, b.y FROM (tbl1 a JOIN tbl2 b ON a.id = b.id) WHERE a.x > 0";
    let select = parse_select(sql);
    assert_eq!(select.from.len(), 1);
    let tbl = select.from[0]
        .as_table_ref()
        .expect("expected table-ref FROM item");
    let pg = tbl
        .paren_group
        .as_deref()
        .expect("paren_group should be set");
    assert_eq!(
        pg.inner_join_count, 1,
        "exactly one inner JOIN should be inside the parens"
    );
    assert_eq!(tbl.joins.len(), 1);
}

#[test]
fn paren_group_round_trips_byte_safe() {
    let sql = "SELECT a.x, b.y FROM (tbl1 a JOIN tbl2 b ON a.id = b.id) WHERE a.x > 0";
    let formatted = format_sql_with_config(sql, &fmt_default()).expect("format");
    verify_formatting_safe_with_dialect(sql, &formatted, fmt_default().dialect.as_ref())
        .expect("paren-grouped FROM should preserve semantics");
}

#[test]
fn paren_group_three_table_chain() {
    // All three joins should be inside the paren group; no outer joins.
    let sql = "SELECT * FROM (tbl1 a JOIN tbl2 b ON a.id = b.id JOIN tbl3 c ON b.id = c.b_id)";
    let select = parse_select(sql);
    let tbl = select.from[0].as_table_ref().expect("expected table-ref");
    let pg = tbl
        .paren_group
        .as_deref()
        .expect("paren_group should be set");
    assert_eq!(pg.inner_join_count, 2);
    assert_eq!(tbl.joins.len(), 2);
}

#[test]
fn paren_group_cross_join() {
    let sql = "SELECT * FROM (tbl1 a CROSS JOIN tbl2 b) WHERE a.x = b.y";
    let select = parse_select(sql);
    let tbl = select.from[0].as_table_ref().expect("expected table-ref");
    let pg = tbl
        .paren_group
        .as_deref()
        .expect("paren_group should be set");
    assert_eq!(pg.inner_join_count, 1);
    assert!(matches!(tbl.joins[0].kind, AstJoinKind::Cross));
}

#[test]
fn paren_group_nested_parens() {
    // Outer (t1 a LEFT JOIN (t2 b INNER JOIN t3 c ON …) ON …)
    let sql = "SELECT * FROM (tbl1 a LEFT JOIN (tbl2 b INNER JOIN tbl3 c ON b.id = c.b_id) ON a.id = b.a_id)";
    let select = parse_select(sql);
    let outer = select.from[0].as_table_ref().expect("expected table-ref");
    let outer_pg = outer.paren_group.as_deref().expect("outer paren_group");
    assert_eq!(outer_pg.inner_join_count, 1);
    assert_eq!(outer.joins.len(), 1);
    // The right side of the LEFT JOIN must itself be a paren-grouped table-ref.
    let inner_right = &outer.joins[0].right;
    let inner_pg = inner_right
        .paren_group
        .as_deref()
        .expect("nested paren group on JOIN.right should preserve its parens");
    assert_eq!(inner_pg.inner_join_count, 1);
}

#[test]
fn paren_group_nested_round_trips() {
    let sql = "SELECT * FROM (tbl1 a LEFT JOIN (tbl2 b INNER JOIN tbl3 c ON b.id = c.b_id) ON a.id = b.a_id)";
    let formatted = format_sql_with_config(sql, &fmt_default()).expect("format");
    verify_formatting_safe_with_dialect(sql, &formatted, fmt_default().dialect.as_ref())
        .expect("nested paren-group should preserve semantics");
}

#[test]
fn paren_group_single_table_inside_parens() {
    // Degenerate: just `(tbl)` with no joins inside.
    let sql = "SELECT * FROM (tbl1 a) WHERE a.x = 1";
    let select = parse_select(sql);
    let tbl = select.from[0].as_table_ref().expect("expected table-ref");
    let pg = tbl
        .paren_group
        .as_deref()
        .expect("paren_group should be set");
    assert_eq!(pg.inner_join_count, 0);
    assert_eq!(tbl.joins.len(), 0);
}

#[test]
fn paren_group_with_outer_join_after_paren() {
    // Combined: paren-grouped inner joins + a post-paren JOIN.
    // (a JOIN b ON …) JOIN c ON …
    // Inner count = 1 (b JOIN), outer joins = [c JOIN] appended.
    let sql = "SELECT * FROM (tbl1 a JOIN tbl2 b ON a.id = b.id) JOIN tbl3 c ON a.cid = c.id";
    let select = parse_select(sql);
    let tbl = select.from[0].as_table_ref().expect("expected table-ref");
    let pg = tbl
        .paren_group
        .as_deref()
        .expect("paren_group should be set");
    assert_eq!(pg.inner_join_count, 1);
    assert_eq!(tbl.joins.len(), 2);
}
