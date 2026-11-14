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

/// The table names of the one `SELECT`'s FROM items `sql` parses to under
/// `dialect`, each with whether parentheses enclose it; `None` where the
/// script is not one parsed `SELECT`.
fn from_tables(sql: &str, dialect: &str) -> Option<Vec<(Vec<String>, bool)>> {
    let dialect = lexega_syntax::dialect::dialect_from_name(dialect).expect("a dialect");
    let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).ok()?;
    let [AstStmt::Select(select)] = script.stmts.as_slice() else {
        return None;
    };
    select
        .from
        .iter()
        .map(|item| {
            let table = item.as_table_ref()?;
            let parts = table.name.parts.as_ref()?;
            let names = parts
                .iter()
                .map(|p| {
                    p.as_ref().map(|part| {
                        sql[part.span().start as usize..part.span().end as usize].to_string()
                    })
                })
                .collect::<Option<Vec<String>>>()?;
            Some((names, table.paren_group.is_some()))
        })
        .collect()
}

#[test]
fn a_parenthesised_table_is_the_table() {
    let users = || Some(vec![(vec!["users".to_string()], true)]);
    let mut wrong = Vec::new();
    for dialect in [
        "mysql",
        "postgres",
        "snowflake",
        "mssql",
        "bigquery",
        "databricks",
    ] {
        let sql = "SELECT * FROM (users) WHERE email = NULL";
        let read = from_tables(sql, dialect);
        if read != users() {
            wrong.push(format!("[{dialect}] {sql}: {read:?}"));
        }
    }
    for (dialect, sql, expected) in [
        (
            "mysql",
            "SELECT * FROM ((users)) WHERE email = NULL",
            users(),
        ),
        (
            "mysql",
            "SELECT * FROM (analytics.users) WHERE email = NULL",
            Some(vec![(
                vec!["analytics".to_string(), "users".to_string()],
                true,
            )]),
        ),
        (
            "mysql",
            "SELECT u.id FROM (users u JOIN orders o ON o.user_id = u.id) WHERE u.email = NULL",
            users(),
        ),
        (
            "mysql",
            "SELECT * FROM (users), (orders) WHERE users.id = orders.user_id",
            Some(vec![
                (vec!["users".to_string()], true),
                (vec!["orders".to_string()], true),
            ]),
        ),
        // A FROM naming no table, or a subquery that does not parse, is no table.
        ("snowflake", "SELECT 1 FROM WHERE 1 = 1", None),
        ("snowflake", "SELECT * FROM (SELECT FROM) t", None),
        ("mysql", "SELECT * FROM (SELECT FROM) t", None),
        ("mysql", "SELECT * FROM (users WHERE) t", None),
        ("postgres", "SELECT id FROM users, WHERE id = 1", None),
    ] {
        let read = from_tables(sql, dialect);
        if read != expected {
            wrong.push(format!("[{dialect}] {sql}: {read:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A FROM item as [`first_from_item`] reads it: its table name parts,
/// alias, alias columns, whether a sample clause is read, and how many
/// joins it has.
type FromItem = (Vec<String>, Option<String>, Vec<String>, bool, usize);

/// The first FROM item of the one `SELECT` `sql` parses to under `dialect`;
/// `None` where the script is not one parsed `SELECT`.
fn first_from_item(sql: &str, dialect: &str) -> Option<FromItem> {
    let dialect = lexega_syntax::dialect::dialect_from_name(dialect).expect("a dialect");
    let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).ok()?;
    let [AstStmt::Select(select)] = script.stmts.as_slice() else {
        return None;
    };
    let table = select.from.first()?.as_table_ref()?;
    let text =
        |span: lexega_syntax::lexer::Span| sql[span.start as usize..span.end as usize].to_string();
    let parts = table
        .name
        .parts
        .as_ref()?
        .iter()
        .map(|p| p.as_ref().map(|part| text(part.span())))
        .collect::<Option<Vec<String>>>()?;
    Some((
        parts,
        table.alias.as_ref().map(|alias| text(alias.span)),
        table
            .alias_columns
            .iter()
            .flat_map(|columns| columns.iter().map(|c| text(c.span)))
            .collect(),
        table.sample.is_some(),
        table.joins.len(),
    ))
}

#[test]
fn a_parenthesised_table_takes_the_alias_and_sample_written_after_it() {
    let users = |alias: Option<&str>, columns: &[&str], sample: bool, joins: usize| {
        Some((
            vec!["users".to_string()],
            alias.map(str::to_string),
            columns.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            sample,
            joins,
        ))
    };
    let mut wrong = Vec::new();
    for dialect in [
        "databricks",
        "mysql",
        "postgres",
        "snowflake",
        "mssql",
        "bigquery",
    ] {
        for (sql, expected) in [
            (
                "SELECT * FROM (users) u WHERE u.email = NULL",
                users(Some("u"), &[], false, 0),
            ),
            (
                "SELECT * FROM (users) AS u WHERE u.email = NULL",
                users(Some("u"), &[], false, 0),
            ),
            (
                "SELECT * FROM ((users)) u WHERE u.email = NULL",
                users(Some("u"), &[], false, 0),
            ),
            (
                "SELECT * FROM (users) AS u (a, b) WHERE u.a = NULL",
                users(Some("u"), &["a", "b"], false, 0),
            ),
            (
                "SELECT * FROM (users) u JOIN orders o ON o.user_id = u.id",
                users(Some("u"), &[], false, 1),
            ),
            (
                "SELECT * FROM (users) TABLESAMPLE (10 PERCENT) WHERE email = NULL",
                users(None, &[], true, 0),
            ),
            (
                "SELECT * FROM (users) TABLESAMPLE (10 PERCENT) u WHERE u.email = NULL",
                users(Some("u"), &[], true, 0),
            ),
            // A FROM naming no table, or a subquery that does not parse, is no table.
            ("SELECT * FROM (SELECT FROM) t", None),
            ("SELECT * FROM (users WHERE) t", None),
        ] {
            let read = first_from_item(sql, dialect);
            if read != expected {
                wrong.push(format!("[{dialect}] {sql}: {read:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
