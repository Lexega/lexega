// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Regression tests for Databricks/Spark `LATERAL VIEW [OUTER] explode(...)` parsing.

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect, AstStmt,
    DatabricksDialect, FormatterConfig,
};

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::databricks(),
        ..Default::default()
    }
}

#[test]
fn parse_lateral_view_outer_explode_not_opaque() {
    let sql = r#"
SELECT
  f.id,
  f.item.col AS item_col,
  f.item.val AS item_val
FROM main.analytics.events_raw f,
LATERAL VIEW OUTER explode(from_json(f.payload, 'array<struct<col:string,val:string>>')) exploded AS item
WHERE f.event_date >= DATE '2024-06-01';
"#;

    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");

    assert_eq!(script.stmts.len(), 1, "expected single statement");
    assert!(
        !matches!(script.stmts[0], AstStmt::OpaqueContent { .. }),
        "LATERAL VIEW OUTER explode should not fall back to OpaqueContent"
    );
}

#[test]
fn format_lateral_view_outer_explode_roundtrip_safe() {
    let sql = r#"
SELECT
  f.id,
  f.item.col AS item_col,
  f.item.val AS item_val
FROM main.analytics.events_raw f,
LATERAL VIEW OUTER explode(from_json(f.payload, 'array<struct<col:string,val:string>>')) exploded AS item
WHERE f.event_date >= DATE '2024-06-01';
"#;

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("format should succeed");

    verify_formatting_safe_with_dialect(sql, &formatted, &DatabricksDialect)
        .expect("formatting should be safe under Databricks dialect");

    assert!(
        formatted
            .to_ascii_uppercase()
            .contains("LATERAL VIEW OUTER"),
        "formatted SQL should preserve LATERAL VIEW OUTER construct: {}",
        formatted
    );
}

#[test]
fn a_lateral_view_after_a_from_item_is_a_lateral_join_to_the_generator() {
    use lexega_syntax::ast::{AstJoinConstraint, FromItemKind};
    let text = |sql: &str, span: lexega_syntax::lexer::Span| {
        sql[span.start as usize..span.end as usize].to_string()
    };
    // Each case: the joins' kinds, and each generator's call, table alias
    // and column aliases.
    type Expected<'e> = &'e [(&'e str, &'e str, Option<&'e str>, &'e [&'e str])];
    let cases: [(&str, Expected); 6] = [
        (
            "SELECT x FROM db.t r LATERAL VIEW explode(r.c) v AS x",
            &[("Cross", "explode(r.c)", Some("v"), &["x"])],
        ),
        (
            "SELECT x FROM db.t r LATERAL VIEW OUTER explode(r.c) v AS x WHERE x > 1",
            &[("LeftOuter", "explode(r.c)", Some("v"), &["x"])],
        ),
        (
            "SELECT p, v FROM db.t r LATERAL VIEW posexplode(r.c) t AS p, v",
            &[("Cross", "posexplode(r.c)", Some("t"), &["p", "v"])],
        ),
        (
            "SELECT a, b FROM db.t r LATERAL VIEW inline(r.c) AS a, b",
            &[("Cross", "inline(r.c)", None, &["a", "b"])],
        ),
        (
            "SELECT s.col0 FROM db.t r LATERAL VIEW stack(2, r.id, r.c) s",
            &[("Cross", "stack(2, r.id, r.c)", Some("s"), &[])],
        ),
        (
            "SELECT y FROM db.t r LATERAL VIEW explode(r.c) t1 AS x \
             LATERAL VIEW OUTER explode(x) t2 AS y",
            &[
                ("Cross", "explode(r.c)", Some("t1"), &["x"]),
                ("LeftOuter", "explode(x)", Some("t2"), &["y"]),
            ],
        ),
    ];
    for (sql, expected) in cases {
        let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("parses");
        assert_eq!(script.stmts.len(), 1, "{sql}: {:?}", script.stmts);
        let AstStmt::Select(select) = &script.stmts[0] else {
            panic!("not a SELECT: {sql}");
        };
        assert_eq!(select.from.len(), 1, "{sql}");
        let FromItemKind::TableRef(table) = &select.from[0].kind else {
            panic!("not a table: {sql}");
        };
        assert_eq!(table.joins.len(), expected.len(), "{sql}");
        for (join, (kind, call, alias, columns)) in table.joins.iter().zip(expected) {
            assert_eq!(format!("{:?}", join.kind), *kind, "{sql}");
            assert!(join.lateral_keyword_span.is_some(), "{sql}");
            assert!(matches!(join.constraint, AstJoinConstraint::None), "{sql}");
            let generator = join.right.table_function.as_ref().expect("a call");
            assert_eq!(text(sql, generator.span()), *call, "{sql}");
            assert_eq!(
                join.right
                    .alias
                    .as_ref()
                    .map(|a| text(sql, a.span))
                    .as_deref(),
                *alias,
                "{sql}"
            );
            let found: Vec<String> = join
                .right
                .alias_columns
                .iter()
                .flat_map(|cols| cols.iter().map(|c| text(sql, c.span)))
                .collect();
            assert_eq!(found, *columns, "{sql}");
        }
    }
    // After a join's condition, the generator joins the joined rows.
    let sql = "SELECT r.id FROM db.t r JOIN db.u u ON u.id = r.id LATERAL VIEW explode(r.c) v AS x";
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("parses");
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT");
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("not a table");
    };
    let kinds: Vec<String> = table
        .joins
        .iter()
        .map(|j| format!("{:?}", j.kind))
        .collect();
    assert_eq!(kinds, ["Inner", "Cross"], "{sql}");
}
