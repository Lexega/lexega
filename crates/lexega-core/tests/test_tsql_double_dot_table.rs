// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL omitted-component (double-dot) table names: `master..sysobjects`
//! means database `master`, default schema, object `sysobjects`. The
//! parser records the omitted middle component as `None` in
//! `AstObjectRef::parts` so the positional db/schema/name decomposition
//! stays correct downstream.

use lexega_core::{
    ast::{AstStmt, FromItemKind},
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect,
    FormatterConfig, MsSqlDialect,
};

fn mssql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::mssql(),
        ..Default::default()
    }
}

#[test]
fn double_dot_table_parses_with_omitted_middle_part() {
    let sql = "SELECT * FROM master..sysobjects;";
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("should parse");
    let select = script
        .stmts
        .iter()
        .find_map(|s| match s {
            AstStmt::Select(sel) => Some(sel),
            _ => None,
        })
        .expect("a SELECT statement, not OpaqueContent");

    let tref = match &select.from[0].kind {
        FromItemKind::TableRef(t) => t,
        other => panic!("expected TableRef, got {other:?}"),
    };
    let parts = tref.name.parts.as_ref().expect("structurally dotted parts");
    assert_eq!(parts.len(), 3, "db..table is three positional slots");
    assert!(parts[0].is_some(), "database component present");
    assert!(parts[1].is_none(), "schema component omitted");
    assert!(parts[2].is_some(), "object component present");
}

#[test]
fn double_dot_table_roundtrips_byte_exact() {
    let sql = "SELECT * FROM master..sysobjects;";
    let formatted = format_sql_with_config(sql, &mssql_config()).expect("should format");
    verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
        .expect("formatting should be safe");
}
