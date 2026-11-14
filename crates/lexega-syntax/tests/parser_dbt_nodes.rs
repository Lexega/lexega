// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for dbt node parsing: ref(), source(), var(), config(), this
//! Verifies that the parser creates first-class AST nodes for dbt functions.

use lexega_syntax::ast::{
    AstExpr, AstNamePart, AstNamePiece, AstObjectRef, AstProjectionKind, AstSelectIntoTarget,
    AstStmt, AstTableNameKind, AstTemplatedName, CteItem, FromItemKind, ProjectionItemKind,
};
use lexega_syntax::{parse_sql, parse_sql_with_dialect};

/// Helper to extract the first expression from a SELECT statement
fn parse_expr(sql: &str) -> Option<AstExpr> {
    let result = parse_sql(sql).ok()?;
    let stmt = result.stmts.first()?;

    if let AstStmt::Select(select) = stmt {
        if let AstProjectionKind::Columns(items) = &select.projection.kind {
            if let Some(item) = items.first() {
                if let ProjectionItemKind::SelectItem(select_item) = &item.kind {
                    return Some(select_item.expr.clone());
                }
            }
        }
    }
    None
}

#[test]
fn test_parse_dbt_ref_single_arg() {
    let sql = "SELECT ref('orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtRef {
            model_name,
            package_name,
            ..
        } => {
            assert_eq!(model_name, "orders");
            assert!(package_name.is_none());
        }
        other => panic!("Expected DbtRef, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_ref_two_args() {
    let sql = "SELECT ref('my_package', 'orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtRef {
            model_name,
            package_name,
            ..
        } => {
            assert_eq!(model_name, "orders");
            assert_eq!(package_name.as_deref(), Some("my_package"));
        }
        other => panic!("Expected DbtRef, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_source() {
    let sql = "SELECT source('raw_data', 'customers')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtSource {
            source_name,
            table_name,
            ..
        } => {
            assert_eq!(source_name, "raw_data");
            assert_eq!(table_name, "customers");
        }
        other => panic!("Expected DbtSource, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_var_single_arg() {
    let sql = "SELECT var('my_var')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtVar {
            var_name,
            default_value,
            ..
        } => {
            assert_eq!(var_name, "my_var");
            assert!(default_value.is_none());
        }
        other => panic!("Expected DbtVar, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_this_bare() {
    let sql = "SELECT this";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtThis { parens, .. } => {
            assert!(parens.is_none(), "Bare 'this' should have no parens");
        }
        other => panic!("Expected DbtThis, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_this_with_parens() {
    let sql = "SELECT this()";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtThis { parens, .. } => {
            assert!(parens.is_some(), "this() should have parens");
        }
        other => panic!("Expected DbtThis, got {:?}", other),
    }
}

#[test]
fn test_dbt_ref_inner_spans() {
    let sql = "SELECT ref('orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtRef {
            func_name_span,
            lparen_span,
            model_name_span,
            rparen_span,
            span,
            ..
        } => {
            // Verify spans are captured and in correct order
            assert!(func_name_span.start < lparen_span.start);
            assert!(lparen_span.start < model_name_span.start);
            assert!(model_name_span.end < rparen_span.end);
            assert!(span.start == func_name_span.start);
            assert!(span.end == rparen_span.end);
        }
        other => panic!("Expected DbtRef, got {:?}", other),
    }
}

#[test]
fn test_dbt_source_inner_spans() {
    let sql = "SELECT source('raw', 'orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtSource {
            source_name_span,
            table_name_span,
            ..
        } => {
            // source_name comes before table_name
            assert!(source_name_span.end < table_name_span.start);
        }
        other => panic!("Expected DbtSource, got {:?}", other),
    }
}

/// A templated name's pieces as `w:<text>` / `t:<text>`.
fn pieces(sql: &str, name: &AstTemplatedName) -> Vec<String> {
    let text = |span: lexega_syntax::lexer::Span| &sql[span.start as usize..span.end as usize];
    name.pieces
        .iter()
        .map(|piece| match piece {
            AstNamePiece::Word(span) => format!("w:{}", text(*span)),
            AstNamePiece::Template(span) => format!("t:{}", text(*span)),
            AstNamePiece::Rendered(span) => format!("r:{}", text(*span)),
        })
        .collect()
}

/// The object a statement names first: a query's first table, a write's
/// target, a created table.
fn first_object(stmt: &AstStmt) -> &AstObjectRef {
    match stmt {
        AstStmt::Select(select) => match &select.from[0].kind {
            FromItemKind::TableRef(table) => &table.name,
            other => panic!("not a table: {other:?}"),
        },
        AstStmt::Delete(delete) => &delete.target_table.as_ref().expect("target").name,
        AstStmt::Update(update) => &update.target_table.as_ref().expect("target").name,
        AstStmt::Insert(insert) => insert.target_table.as_ref().expect("target"),
        AstStmt::CreateTable(create) => &create.name,
        other => panic!("unexpected statement: {other:?}"),
    }
}

/// Each part of `name` as written: a word as its text, a part a template
/// writes some of as its text and its pieces (`t_{{ s }}=w:t_ t:{{ s }}`).
fn parts_of(sql: &str, name: &AstObjectRef) -> Vec<String> {
    let text = |span: lexega_syntax::lexer::Span| &sql[span.start as usize..span.end as usize];
    name.parts
        .as_ref()
        .expect("parts")
        .iter()
        .map(|part| match part.as_ref().expect("written part") {
            AstNamePart::Word(span) => text(*span).to_string(),
            AstNamePart::Templated { span, name } => {
                format!("{}={}", text(*span), pieces(sql, name).join(" "))
            }
        })
        .collect()
}

#[test]
fn a_name_a_template_writes_part_of_is_one_name() {
    // (statement, its object's parts)
    let cases: &[(&str, &[&str])] = &[
        (
            "SELECT id FROM {{ s }}_t WHERE id = 1",
            &["{{ s }}_t=t:{{ s }} w:_t"],
        ),
        (
            "SELECT id FROM t_{{ s }} WHERE id = 1",
            &["t_{{ s }}=w:t_ t:{{ s }}"],
        ),
        (
            "SELECT id FROM {{ db }}.{{ s }}_t",
            &["{{ db }}=t:{{ db }}", "{{ s }}_t=t:{{ s }} w:_t"],
        ),
        (
            "SELECT a.id FROM zz.dbo.t_{{ s }}_x AS a",
            &["zz", "dbo", "t_{{ s }}_x=w:t_ t:{{ s }} w:_x"],
        ),
        (
            "SELECT id FROM {{ ref('m') }}{{ v }}",
            &["{{ ref('m') }}{{ v }}=t:{{ ref('m') }} t:{{ v }}"],
        ),
        (
            "DELETE FROM t_{{ s }} WHERE id = 1",
            &["t_{{ s }}=w:t_ t:{{ s }}"],
        ),
        (
            "UPDATE t_{{ s }} SET c = 1 WHERE id = 1",
            &["t_{{ s }}=w:t_ t:{{ s }}"],
        ),
        (
            "INSERT INTO t_{{ s }} SELECT id FROM u",
            &["t_{{ s }}=w:t_ t:{{ s }}"],
        ),
        (
            "CREATE TABLE t_{{ s }} (id INT)",
            &["t_{{ s }}=w:t_ t:{{ s }}"],
        ),
        // A name written as one template expression, which may render any
        // relation, is one part made of one template piece.
        (
            "SELECT id FROM {{ ref('m') }} AS m WHERE id = 1",
            &["{{ ref('m') }}=t:{{ ref('m') }}"],
        ),
        (
            "INSERT INTO {{ this }} SELECT id FROM u",
            &["{{ this }}=t:{{ this }}"],
        ),
        (
            "SELECT id FROM {% if p %}a{% else %}b{% endif %}.t",
            &["{% if p %}a{% else %}b{% endif %}.t=t:{% if p %}a{% else %}b{% endif %}.t"],
        ),
        // A name that holds a block, wherever it is read.
        (
            "INSERT INTO {% if p %}a{% else %}b{% endif %}.t SELECT id FROM u",
            &["{% if p %}a{% else %}b{% endif %}.t=t:{% if p %}a{% else %}b{% endif %}.t"],
        ),
        (
            "DELETE FROM {% if p %}a{% endif %}_t WHERE id = 1",
            &["{% if p %}a{% endif %}_t=t:{% if p %}a{% endif %}_t"],
        ),
    ];
    for (sql, parts) in cases {
        let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        assert_eq!(script.stmts.len(), 1, "{sql}: {:?}", script.stmts);
        let name = first_object(&script.stmts[0]);
        assert_eq!(name.name_kind, AstTableNameKind::Templated, "{sql}");
        assert_eq!(&parts_of(sql, name), parts, "{sql}");
    }

    // A name written whole is a catalog name of words.
    let sql = "SELECT id FROM zz.t_x a";
    let script = parse_sql(sql).expect("parses");
    let name = first_object(&script.stmts[0]);
    assert_eq!(name.name_kind, AstTableNameKind::Catalog);
    assert_eq!(parts_of(sql, name), ["zz", "t_x"]);
}

#[test]
fn a_name_a_block_begins_ends_where_the_name_does() {
    // (statement, the table's name, its alias)
    let cases: &[(&str, &str, Option<&str>)] = &[
        (
            "SELECT o.id FROM {% if p %}a{% else %}b{% endif %}.orders o",
            "{% if p %}a{% else %}b{% endif %}.orders",
            Some("o"),
        ),
        (
            "SELECT o.id FROM {% if p %}a{% else %}b{% endif %}.orders AS o",
            "{% if p %}a{% else %}b{% endif %}.orders",
            Some("o"),
        ),
        (
            "SELECT id FROM {% if p %}a{% endif %}_orders WHERE id = 1",
            "{% if p %}a{% endif %}_orders",
            None,
        ),
        (
            "SELECT id FROM {% if p %}a{% endif %}{% if q %}b{% endif %}.t x",
            "{% if p %}a{% endif %}{% if q %}b{% endif %}.t",
            Some("x"),
        ),
    ];
    for (sql, name, alias) in cases {
        let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let [AstStmt::Select(select)] = script.stmts.as_slice() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let FromItemKind::TableRef(table) = &select.from[0].kind else {
            panic!("{sql}: not a table");
        };
        let text = |span: lexega_syntax::lexer::Span| &sql[span.start as usize..span.end as usize];
        assert_eq!(text(table.name.span), *name, "{sql}");
        assert_eq!(table.alias.as_ref().map(|a| text(a.span)), *alias, "{sql}");
        assert_eq!(
            parts_of(sql, &table.name),
            [format!("{name}=t:{name}")],
            "{sql}"
        );
    }

    // A block written after a name's word ends the name: it may wrap a clause.
    let sql = "SELECT a FROM t1{% if p %} JOIN u ON t1.id = u.id {% endif %} WHERE a > 1";
    let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let name = first_object(&script.stmts[0]);
    assert_eq!(name.name_kind, AstTableNameKind::Catalog, "{sql}");
    assert_eq!(parts_of(sql, name), ["t1"], "{sql}");
}

#[test]
fn a_stage_or_stream_name_a_template_writes_part_of_is_read() {
    let text = |sql: &str, span: lexega_syntax::lexer::Span| {
        sql[span.start as usize..span.end as usize].to_string()
    };
    // A stage's name, then its path.
    let sql = "SELECT $1 FROM @{{ target.schema }}.stg/f.csv s";
    let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [AstStmt::Select(select)] = script.stmts.as_slice() else {
        panic!("{sql}: {:?}", script.stmts);
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("{sql}: not a table");
    };
    assert_eq!(text(sql, table.name.span), "@{{ target.schema }}.stg/f.csv");
    assert_eq!(table.name.name_kind, AstTableNameKind::Stage);

    // A streaming read of a table whose name a template writes some of.
    let sql = "SELECT * FROM STREAM s1.{{ var('t') }}";
    let script = parse_sql_with_dialect(sql, &*lexega_syntax::dialect::databricks())
        .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [AstStmt::Select(select)] = script.stmts.as_slice() else {
        panic!("{sql}: {:?}", script.stmts);
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("{sql}: not a table");
    };
    assert!(table.stream_span.is_some(), "{sql}: not a stream");
    assert_eq!(text(sql, table.name.span), "s1.{{ var('t') }}");
}

#[test]
fn a_table_function_a_template_names_some_of_is_one_call() {
    for (sql, call) in [
        (
            "SELECT * FROM {{ schema }}.fn(1) AS f WHERE f.c = 1",
            "{{ schema }}.fn(1)",
        ),
        ("SELECT * FROM t_{{ s }}(1) WHERE c = 1", "t_{{ s }}(1)"),
        (
            "SELECT * FROM {{ my_tvf }}(1) WHERE c = 1",
            "{{ my_tvf }}(1)",
        ),
    ] {
        let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        assert_eq!(script.stmts.len(), 1, "{sql}: {:?}", script.stmts);
        let name = first_object(&script.stmts[0]);
        assert_eq!(name.name_kind, AstTableNameKind::Templated, "{sql}");
        assert_eq!(
            &sql[name.span.start as usize..name.span.end as usize],
            call,
            "{sql}"
        );
    }
}

#[test]
fn a_column_or_alias_a_template_writes_part_of_is_one_name() {
    let sql = "SELECT c_{{ s }}, {{ s }}_c, a.c_{{ s }}, id AS d_{{ s }}, id e_{{ s }}, \
               '{{ s }}_lit', id {{ s }}_f, a.{{ c }} FROM t AS a";
    let script = parse_sql(sql).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{:?}", script.stmts);
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT");
    };
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("not a column list");
    };
    let items: Vec<_> = items
        .iter()
        .map(|item| match &item.kind {
            ProjectionItemKind::SelectItem(item) => item,
            other => panic!("not a select item: {other:?}"),
        })
        .collect();
    let column = |i: usize| match &items[i].expr {
        AstExpr::Ident { column_ref, .. } => column_ref.clone(),
        other => panic!("item {i} is not a column: {other:?}"),
    };
    let templated_column = |i: usize| {
        pieces(
            sql,
            column(i)
                .name
                .templated
                .as_deref()
                .expect("templated column"),
        )
    };
    assert_eq!(templated_column(0), ["w:c_", "t:{{ s }}"]);
    assert_eq!(templated_column(1), ["t:{{ s }}", "w:_c"]);
    assert_eq!(templated_column(2), ["w:c_", "t:{{ s }}"]);
    assert!(column(2).qualifier.is_some());
    let alias = |i: usize| {
        let alias = items[i].alias.as_ref().expect("alias");
        pieces(
            sql,
            alias.ident.templated.as_deref().expect("templated alias"),
        )
    };
    assert_eq!(alias(3), ["w:d_", "t:{{ s }}"]);
    assert_eq!(alias(4), ["w:e_", "t:{{ s }}"]);
    // A template inside a string is no name.
    assert!(
        matches!(items[5].expr, AstExpr::Literal { .. }),
        "{:?}",
        items[5].expr
    );
    assert_eq!(alias(6), ["t:{{ s }}", "w:_f"]);
    assert_eq!(templated_column(7), ["t:{{ c }}"]);

    let sql = "SELECT a.id FROM t AS a_{{ s }} JOIN u {{ s }}_b ON a.id = 1";
    let script = parse_sql(sql).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{:?}", script.stmts);
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT");
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("not a table");
    };
    let alias = table.alias.as_ref().expect("alias");
    assert_eq!(
        pieces(sql, alias.templated.as_deref().expect("templated alias")),
        ["w:a_", "t:{{ s }}"]
    );
    let joined = table.joins[0].right.alias.as_ref().expect("joined alias");
    assert_eq!(
        pieces(sql, joined.templated.as_deref().expect("templated alias")),
        ["t:{{ s }}", "w:_b"]
    );
}

#[test]
fn a_derived_table_alias_a_cte_name_and_a_new_table_a_template_writes_part_of_are_one_name() {
    let sql = "SELECT a.id FROM (SELECT 1 AS id) AS a_{{ s }} WHERE a_{{ s }}.id = 1";
    let script = parse_sql(sql).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{:?}", script.stmts);
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT");
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("not a table");
    };
    let alias = table.alias.as_ref().expect("alias");
    assert_eq!(
        pieces(sql, alias.templated.as_deref().expect("templated alias")),
        ["w:a_", "t:{{ s }}"]
    );
    // The alias qualifies a column as written.
    let where_clause = select.where_clause.as_deref().expect("WHERE");
    let AstExpr::BinaryOp { left, .. } = &where_clause.expr else {
        panic!("not a comparison: {:?}", where_clause.expr);
    };
    let AstExpr::Ident { column_ref, .. } = left.as_ref() else {
        panic!("not a column: {left:?}");
    };
    let text = |span: lexega_syntax::lexer::Span| &sql[span.start as usize..span.end as usize];
    let qualifier = column_ref.qualifier.as_ref().expect("qualifier");
    assert_eq!(text(qualifier.span), "a_{{ s }}");
    assert_eq!(text(column_ref.name.span), "id");

    let sql = "WITH c_{{ s }} AS (SELECT 1 AS id) SELECT id FROM c_{{ s }}";
    let script = parse_sql(sql).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{:?}", script.stmts);
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT");
    };
    let with = select.with_clause.as_ref().expect("WITH");
    let CteItem::Cte(cte) = &with.ctes[0] else {
        panic!("not a CTE");
    };
    assert_eq!(
        pieces(sql, cte.name.templated.as_deref().expect("templated name")),
        ["w:c_", "t:{{ s }}"]
    );
    assert_eq!(
        parts_of(sql, first_object(&script.stmts[0])),
        ["c_{{ s }}=w:c_ t:{{ s }}"]
    );

    let sql = "SELECT id INTO #t_{{ s }} FROM zz.dbo.t";
    let script = parse_sql_with_dialect(sql, &*lexega_syntax::dialect::mssql()).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{:?}", script.stmts);
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT");
    };
    let Some(AstSelectIntoTarget::NewTable(into)) = select.into_target.as_deref() else {
        panic!("not a new table: {:?}", select.into_target);
    };
    assert_eq!(into.name.name_kind, AstTableNameKind::Templated);
    assert_eq!(parts_of(sql, &into.name), ["#t_{{ s }}=w:#t_ t:{{ s }}"]);
}

#[test]
fn test_dbt_in_from_clause() {
    // dbt functions in FROM clause should be wrapped in Jinja braces
    let sql = "SELECT * FROM {{ ref('orders') }}";
    let result = parse_sql(sql);

    // Verify it parses without error
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
}
