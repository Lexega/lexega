// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::ast::{AstSetModifier, AstSetOpKind, AstSetSelect};
use lexega_syntax::dialect::{bigquery, databricks, mssql, mysql, postgres, snowflake, DialectRef};
use lexega_syntax::{parse_sql_with_dialect, AstStmt};

/// Every statement of every body below `stmts`, outermost first.
fn flatten<'a>(stmts: &'a [AstStmt], out: &mut Vec<&'a AstStmt>) {
    for stmt in stmts {
        out.push(stmt);
        for body in stmt.bodies() {
            flatten(body.stmts, out);
        }
    }
}

/// The one set operation a block body holds, with nothing cut off beside it.
fn body_set_select(src: &str, dialect: DialectRef) -> AstSetSelect {
    let script = parse_sql_with_dialect(src, dialect.as_ref())
        .unwrap_or_else(|e| panic!("did not parse: {e:?}\n{src}"));
    let mut all = Vec::new();
    flatten(&script.stmts, &mut all);
    assert!(
        script.cut_statements.is_empty(),
        "statements cut short: {:#?}\n{src}",
        script.cut_statements
    );
    assert!(
        !all.iter().any(|s| matches!(
            s,
            AstStmt::Select(_) | AstStmt::OpaqueContent { .. } | AstStmt::Error { .. }
        )),
        "a SELECT or an unread statement stands in the body: {all:#?}\n{src}"
    );
    let sets: Vec<&AstSetSelect> = all
        .iter()
        .filter_map(|s| match s {
            AstStmt::SetSelect(set) => Some(set),
            _ => None,
        })
        .collect();
    assert_eq!(sets.len(), 1, "set operations in the body: {all:#?}\n{src}");
    sets[0].clone()
}

#[test]
fn snowflake_block_union() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a UNION SELECT 2 FROM b; END;",
        snowflake(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
}

#[test]
fn snowflake_block_union_all() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a UNION ALL SELECT 2 FROM b; END;",
        snowflake(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
    assert!(matches!(set.modifier, AstSetModifier::All));
}

#[test]
fn snowflake_block_intersect() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a INTERSECT SELECT 2 FROM b; END;",
        snowflake(),
    );
    assert!(matches!(set.op, AstSetOpKind::Intersect));
}

#[test]
fn snowflake_block_except() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a EXCEPT SELECT 2 FROM b; END;",
        snowflake(),
    );
    assert!(matches!(set.op, AstSetOpKind::Except));
}

#[test]
fn snowflake_block_minus() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a MINUS SELECT 2 FROM b; END;",
        snowflake(),
    );
    assert!(matches!(set.op, AstSetOpKind::Minus));
}

#[test]
fn snowflake_block_parenthesised_branch() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a UNION (SELECT 2 FROM b); END;",
        snowflake(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
}

#[test]
fn snowflake_block_trailing_order_by_and_limit() {
    let set = body_set_select(
        "BEGIN SELECT x FROM a UNION SELECT x FROM b ORDER BY x LIMIT 5; END;",
        snowflake(),
    );
    assert!(set.order_by.is_some());
    assert!(set.limit.is_some());
}

#[test]
fn snowflake_block_chain_of_three() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a UNION SELECT 2 FROM b UNION ALL SELECT 3 FROM c; END;",
        snowflake(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
    assert!(matches!(&*set.left, AstStmt::SetSelect(_)));
}

#[test]
fn snowflake_loop_body_union() {
    body_set_select(
        "BEGIN WHILE (x < 3) DO SELECT 1 FROM a UNION SELECT 2 FROM b; x := x + 1; END WHILE; END;",
        snowflake(),
    );
}

#[test]
fn postgres_do_block_union() {
    let set = body_set_select(
        "DO $$ BEGIN SELECT 1 FROM a UNION ALL SELECT 2 FROM b; END $$;",
        postgres(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
}

#[test]
fn postgres_do_block_except_with_order_by() {
    let set = body_set_select(
        "DO $$ BEGIN SELECT x FROM a EXCEPT SELECT x FROM b ORDER BY x; END $$;",
        postgres(),
    );
    assert!(matches!(set.op, AstSetOpKind::Except));
    assert!(set.order_by.is_some());
}

#[test]
fn bigquery_block_union() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a UNION ALL SELECT 2 FROM b; END;",
        bigquery(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
}

#[test]
fn bigquery_block_intersect_distinct() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a INTERSECT DISTINCT SELECT 2 FROM b; END;",
        bigquery(),
    );
    assert!(matches!(set.op, AstSetOpKind::Intersect));
}

#[test]
fn databricks_block_union() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a UNION SELECT 2 FROM b; END;",
        databricks(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
}

#[test]
fn databricks_block_except() {
    let set = body_set_select(
        "BEGIN SELECT 1 FROM a EXCEPT SELECT 2 FROM b; END;",
        databricks(),
    );
    assert!(matches!(set.op, AstSetOpKind::Except));
}

#[test]
fn mysql_routine_body_union() {
    let set = body_set_select(
        "CREATE PROCEDURE p() BEGIN SELECT 1 FROM a UNION SELECT 2 FROM b; END;",
        mysql(),
    );
    assert!(matches!(set.op, AstSetOpKind::Union));
}

#[test]
fn mysql_routine_body_union_all_limit() {
    let set = body_set_select(
        "CREATE PROCEDURE p() BEGIN SELECT x FROM a UNION ALL SELECT x FROM b ORDER BY x LIMIT 3; END;",
        mysql(),
    );
    assert!(set.limit.is_some());
}

#[test]
fn mssql_begin_end_union() {
    let set = body_set_select("BEGIN SELECT 1 FROM a UNION SELECT 2 FROM b; END", mssql());
    assert!(matches!(set.op, AstSetOpKind::Union));
}

#[test]
fn mssql_procedure_body_except() {
    let set = body_set_select(
        "CREATE PROCEDURE p AS BEGIN SELECT 1 FROM a EXCEPT SELECT 2 FROM b; END",
        mssql(),
    );
    assert!(matches!(set.op, AstSetOpKind::Except));
}
