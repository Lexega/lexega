// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `SELECT … INTO …` parsing tests covering both shapes:
//!
//! - MSSQL: `SELECT * INTO new_tbl FROM src` (also `#tmp` / `##global` /
//!   schema-qualified / `ON [PRIMARY]` filegroup).
//! - PostgreSQL: `SELECT * INTO [TEMP|TEMPORARY|UNLOGGED] new_tbl FROM src`.
//! - Snowflake / others: scripting form `INTO :var, :var2` preserved.
//!
//! Disambiguation is dialect-driven at parse time. PL/pgSQL bodies live
//! inside `$$…$$` literals so the main parser never sees that path.

use lexega_syntax::{
    ast::*, format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect,
    FormatterConfig,
};

fn parse_select_with_dialect(sql: &str, dialect_name: &str) -> AstSelect {
    let dialect =
        lexega_syntax::dialect::dialect_from_name(dialect_name).expect("known dialect name");
    let script = parse_sql_with_dialect(sql, dialect.as_ref()).expect("parse should succeed");
    let stmt = script
        .stmts
        .into_iter()
        .next()
        .expect("at least one statement");
    match stmt {
        AstStmt::Select(s) => s.as_ref().clone(),
        other => panic!(
            "expected AstStmt::Select, got variant: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

fn config_for(dialect_name: &str) -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect =
        lexega_syntax::dialect::dialect_from_name(dialect_name).expect("known dialect name");
    config
}

fn roundtrip(sql: &str, dialect_name: &str) {
    let config = config_for(dialect_name);
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("round-trip failed for {dialect_name}: {e}\nSQL: {sql}"));
}

// ─── MSSQL: SELECT … INTO new_tbl ────────────────────────────────────────

#[test]
fn mssql_select_into_persistent_table() {
    let sql = "SELECT * INTO new_tbl FROM old_tbl";
    let sel = parse_select_with_dialect(sql, "mssql");
    let target = sel
        .into_target
        .as_deref()
        .expect("into_target should be set");
    match target {
        AstSelectIntoTarget::NewTable(nt) => {
            assert_eq!(nt.temp_kind, AstSelectIntoTempKind::None);
            assert!(nt.temp_keyword_span.is_none());
            assert!(nt.on_filegroup.is_none());
        }
        AstSelectIntoTarget::ScriptingVars(_) | AstSelectIntoTarget::OutFile(_) => {
            panic!("MSSQL should parse SELECT INTO as NewTable")
        }
    }
    roundtrip(sql, "mssql");
}

#[test]
fn mssql_select_into_local_temp_table() {
    let sql = "SELECT col1, col2 INTO #tmp_local FROM src";
    let sel = parse_select_with_dialect(sql, "mssql");
    let target = sel.into_target.as_deref().expect("into_target");
    match target {
        AstSelectIntoTarget::NewTable(nt) => {
            assert_eq!(nt.temp_kind, AstSelectIntoTempKind::LocalTemp);
        }
        _ => panic!("expected NewTable"),
    }
    roundtrip(sql, "mssql");
}

#[test]
fn mssql_select_into_global_temp_table() {
    let sql = "SELECT col1 INTO ##tmp_global FROM src";
    let sel = parse_select_with_dialect(sql, "mssql");
    let target = sel.into_target.as_deref().expect("into_target");
    match target {
        AstSelectIntoTarget::NewTable(nt) => {
            assert_eq!(nt.temp_kind, AstSelectIntoTempKind::GlobalTemp);
        }
        _ => panic!("expected NewTable"),
    }
    roundtrip(sql, "mssql");
}

#[test]
fn mssql_select_into_qualified_bracketed_name() {
    let sql = "SELECT * INTO [dbo].[new_tbl] FROM [dbo].[src]";
    let sel = parse_select_with_dialect(sql, "mssql");
    assert!(matches!(
        sel.into_target.as_deref(),
        Some(AstSelectIntoTarget::NewTable(_))
    ));
    roundtrip(sql, "mssql");
}

#[test]
fn mssql_select_into_three_part_name() {
    let sql = "SELECT * INTO tempdb.dbo.staging FROM live.dbo.orders";
    let sel = parse_select_with_dialect(sql, "mssql");
    assert!(matches!(
        sel.into_target.as_deref(),
        Some(AstSelectIntoTarget::NewTable(_))
    ));
    roundtrip(sql, "mssql");
}

#[test]
fn mssql_select_into_with_on_filegroup() {
    let sql = "SELECT * INTO new_tbl ON [PRIMARY] FROM src";
    let sel = parse_select_with_dialect(sql, "mssql");
    let target = sel.into_target.as_deref().expect("into_target");
    match target {
        AstSelectIntoTarget::NewTable(nt) => {
            let fg = nt
                .on_filegroup
                .as_ref()
                .expect("filegroup should be parsed");
            assert!(fg.filegroup_span.end > fg.filegroup_span.start);
        }
        _ => panic!("expected NewTable"),
    }
    roundtrip(sql, "mssql");
}

#[test]
fn mssql_select_into_with_where() {
    let sql = "SELECT id, name INTO archive_2024 FROM users WHERE created_at < '2024-01-01'";
    let sel = parse_select_with_dialect(sql, "mssql");
    assert!(matches!(
        sel.into_target.as_deref(),
        Some(AstSelectIntoTarget::NewTable(_))
    ));
    assert!(
        sel.where_clause.is_some(),
        "WHERE clause should follow INTO"
    );
    roundtrip(sql, "mssql");
}

// ─── PostgreSQL: SELECT … INTO [TEMP|TEMPORARY|UNLOGGED] new_tbl ──────────

#[test]
fn pg_select_into_persistent_table() {
    let sql = "SELECT * INTO new_tbl FROM old_tbl";
    let sel = parse_select_with_dialect(sql, "postgresql");
    match sel.into_target.as_deref() {
        Some(AstSelectIntoTarget::NewTable(nt)) => {
            assert_eq!(nt.temp_kind, AstSelectIntoTempKind::None);
            assert!(nt.temp_keyword_span.is_none());
        }
        other => panic!("expected NewTable, got {other:?}"),
    }
    roundtrip(sql, "postgresql");
}

#[test]
fn pg_select_into_temp_qualifier() {
    let sql = "SELECT * INTO TEMP tmp_tbl FROM src";
    let sel = parse_select_with_dialect(sql, "postgresql");
    match sel.into_target.as_deref() {
        Some(AstSelectIntoTarget::NewTable(nt)) => {
            assert_eq!(nt.temp_kind, AstSelectIntoTempKind::Temp);
            assert!(nt.temp_keyword_span.is_some());
        }
        _ => panic!("expected NewTable with Temp"),
    }
    roundtrip(sql, "postgresql");
}

#[test]
fn pg_select_into_temporary_qualifier() {
    let sql = "SELECT * INTO TEMPORARY tmp_tbl FROM src";
    let sel = parse_select_with_dialect(sql, "postgresql");
    match sel.into_target.as_deref() {
        Some(AstSelectIntoTarget::NewTable(nt)) => {
            assert_eq!(nt.temp_kind, AstSelectIntoTempKind::Temp);
        }
        _ => panic!("expected NewTable with Temp"),
    }
    roundtrip(sql, "postgresql");
}

#[test]
fn pg_select_into_unlogged_qualifier() {
    let sql = "SELECT * INTO UNLOGGED log_tbl FROM src";
    let sel = parse_select_with_dialect(sql, "postgresql");
    match sel.into_target.as_deref() {
        Some(AstSelectIntoTarget::NewTable(nt)) => {
            assert_eq!(nt.temp_kind, AstSelectIntoTempKind::Unlogged);
            assert!(nt.temp_keyword_span.is_some());
        }
        _ => panic!("expected NewTable with Unlogged"),
    }
    roundtrip(sql, "postgresql");
}

#[test]
fn pg_select_into_qualified_name() {
    let sql = "SELECT id, name INTO public.archive FROM users WHERE created_at < '2024-01-01'";
    let sel = parse_select_with_dialect(sql, "postgresql");
    assert!(matches!(
        sel.into_target.as_deref(),
        Some(AstSelectIntoTarget::NewTable(_))
    ));
    roundtrip(sql, "postgresql");
}

// ─── Snowflake / other dialects: scripting form unchanged ─────────────────

#[test]
fn snowflake_select_into_scripting_var_preserved() {
    // Snowflake Scripting: bare `INTO var` (no colon) — must remain ScriptingVars.
    let sql = "SELECT col INTO my_var FROM tbl";
    let sel = parse_select_with_dialect(sql, "snowflake");
    match sel.into_target.as_deref() {
        Some(AstSelectIntoTarget::ScriptingVars(vars)) => {
            assert_eq!(vars.len(), 1);
        }
        other => panic!("Snowflake INTO must stay ScriptingVars, got {other:?}"),
    }
}

#[test]
fn snowflake_select_into_multiple_scripting_vars() {
    let sql = "SELECT a, b INTO :v1, :v2 FROM tbl";
    let sel = parse_select_with_dialect(sql, "snowflake");
    match sel.into_target.as_deref() {
        Some(AstSelectIntoTarget::ScriptingVars(vars)) => {
            assert_eq!(vars.len(), 2);
        }
        _ => panic!("expected ScriptingVars with 2 entries"),
    }
}
