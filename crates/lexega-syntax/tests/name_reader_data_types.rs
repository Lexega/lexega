// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A data type's name is read as a name of parts, but never with a dashed
//! part: a `-` after a type is a subtraction.

use lexega_syntax::{parse_sql_with_dialect, AstStmt};

/// The one statement `sql` holds, as its tree prints.
fn tree(sql: &str) -> String {
    let script = parse_sql_with_dialect(sql, &*lexega_syntax::dialect::postgres())
        .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [stmt @ AstStmt::Select(_)] = script.stmts.as_slice() else {
        panic!("{sql}: expected one SELECT, got {:?}", script.stmts);
    };
    format!("{stmt:?}")
}

/// How the tree prints a type named by `sql[name]`.
fn type_named(sql: &str, name: &str) -> String {
    let start = sql
        .find(name)
        .unwrap_or_else(|| panic!("{sql}: no `{name}`"));
    format!(
        "Simple {{ name_span: Span {{ start: {start}, end: {} }} }}",
        start + name.len()
    )
}

#[test]
fn a_dash_after_a_cast_type_subtracts() {
    for (sql, type_name) in [
        ("SELECT x::integer-1 FROM t", "integer"),
        ("SELECT x::numeric-y FROM t", "numeric"),
    ] {
        let tree = tree(sql);
        assert!(tree.contains("BinaryOp"), "{sql}: no subtraction: {tree}");
        assert!(
            tree.contains(&type_named(sql, type_name)),
            "{sql}: the type is not `{type_name}`: {tree}"
        );
    }
}

#[test]
fn a_cast_type_takes_a_qualified_name() {
    for (sql, type_name) in [
        ("SELECT CAST('a' AS s1.status_t) FROM t", "s1.status_t"),
        ("SELECT x::s1.status_t FROM t", "s1.status_t"),
    ] {
        let tree = tree(sql);
        assert!(
            tree.contains(&type_named(sql, type_name)),
            "{sql}: the type is not `{type_name}`: {tree}"
        );
    }
}
