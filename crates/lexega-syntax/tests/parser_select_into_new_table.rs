// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `SELECT … INTO …` parsing tests covering both shapes:
//!
//! - MSSQL: `SELECT * INTO new_tbl FROM src` (also `#tmp` / `##global` /
//!   schema-qualified / `ON [PRIMARY]` filegroup).
//! - PostgreSQL: `SELECT * INTO [TEMP|TEMPORARY|UNLOGGED] new_tbl FROM src`.
//! - Snowflake / others: scripting form `INTO :var, :var2` preserved.
//! - PL/pgSQL (a block inside a dollar-quoted body): `INTO [STRICT] v, …`
//!   is the scripting form.

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
    FormatterConfig {
        dialect: lexega_syntax::dialect::dialect_from_name(dialect_name)
            .expect("known dialect name"),
        ..Default::default()
    }
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
        AstSelectIntoTarget::ScriptingVars { .. } | AstSelectIntoTarget::OutFile(_) => {
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
        Some(AstSelectIntoTarget::ScriptingVars { vars, .. }) => {
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
        Some(AstSelectIntoTarget::ScriptingVars { vars, .. }) => {
            assert_eq!(vars.len(), 2);
        }
        _ => panic!("expected ScriptingVars with 2 entries"),
    }
}

// ─── PL/pgSQL: a block inside a dollar-quoted body ───────────────────────

/// Every `SELECT` a statement's dollar-quoted body block holds, with the
/// statement count of the script.
fn body_selects(sql: &str, dialect_name: &str) -> (usize, Vec<AstSelect>) {
    // Statements holding no SELECT (DECLARE, RETURN) are passed over.
    fn walk(stmt: &AstStmt, out: &mut Vec<AstSelect>) {
        if let AstStmt::Select(s) = stmt {
            out.push(s.as_ref().clone());
        } else if let AstStmt::Block(b) = stmt {
            for s in b.decls.iter().chain(&b.body) {
                walk(s, out);
            }
        } else if let AstStmt::DoBlock(d) = stmt {
            d.body_stmt.iter().for_each(|s| walk(s, out));
        } else if let AstStmt::CreateFunction(f) = stmt {
            f.body_stmt.iter().for_each(|s| walk(s, out));
        } else if let AstStmt::CreateProcedure(p) = stmt {
            p.body_stmt.iter().for_each(|s| walk(s, out));
        }
    }
    let dialect =
        lexega_syntax::dialect::dialect_from_name(dialect_name).expect("known dialect name");
    let script = parse_sql_with_dialect(sql, dialect.as_ref()).expect("parse should succeed");
    let mut out = Vec::new();
    for stmt in &script.stmts {
        walk(stmt, &mut out);
    }
    (script.stmts.len(), out)
}

/// The target names (as written) and the `STRICT` text of a scripting INTO.
fn into_vars(sql: &str, sel: &AstSelect) -> (Vec<String>, Option<String>) {
    match sel.into_target.as_deref() {
        Some(AstSelectIntoTarget::ScriptingVars { vars, strict_span }) => (
            vars.iter()
                .map(|s| sql[s.start as usize..s.end as usize].to_string())
                .collect(),
            strict_span.map(|s| sql[s.start as usize..s.end as usize].to_string()),
        ),
        other => panic!("expected ScriptingVars in {sql}, got {other:?}"),
    }
}

#[test]
fn plpgsql_select_into_is_a_variable_target_list() {
    let bodies = [
        (
            "SELECT c INTO STRICT v FROM t WHERE id = 1;",
            vec!["v"],
            Some("STRICT"),
        ),
        ("SELECT c, d INTO n, v FROM t;", vec!["n", "v"], None),
        ("SELECT c INTO v FROM t;", vec!["v"], None),
        (
            "SELECT c, d INTO strict n, v FROM t;",
            vec!["n", "v"],
            Some("strict"),
        ),
        (
            "SELECT c, d INTO r.a, total FROM t;",
            vec!["r.a", "total"],
            None,
        ),
        // The targets may come before the select list.
        ("SELECT INTO v c FROM t LIMIT 1;", vec!["v"], None),
        (
            "SELECT INTO STRICT n, v c, d FROM t;",
            vec!["n", "v"],
            Some("STRICT"),
        ),
    ];
    let shapes = [
        ("postgresql", "DO $$ DECLARE n int; v int; BEGIN {} END $$;"),
        ("postgresql", "DO $$ BEGIN {} END $$;"),
        (
            "postgresql",
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ DECLARE n int; v int; BEGIN {} RETURN v; END $$;",
        ),
        (
            "postgresql",
            "CREATE FUNCTION f() RETURNS int AS $$ BEGIN {} RETURN v; END $$ LANGUAGE plpgsql;",
        ),
        (
            "postgresql",
            "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ DECLARE n int; v int; BEGIN {} END $$;",
        ),
        (
            "redshift",
            "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ DECLARE n int; v int; BEGIN {} END $$;",
        ),
    ];
    for (dialect, shape) in shapes {
        for (body, vars, strict) in &bodies {
            let sql = shape.replace("{}", body);
            let (count, selects) = body_selects(&sql, dialect);
            assert_eq!(count, 1, "one statement in {sql}");
            assert_eq!(selects.len(), 1, "one SELECT in {sql}");
            let sel = &selects[0];
            assert!(!sel.from.is_empty(), "the read is kept in {sql}");
            let (got_vars, got_strict) = into_vars(&sql, sel);
            assert_eq!(&got_vars, vars, "targets of {sql}");
            assert_eq!(got_strict.as_deref(), *strict, "STRICT of {sql}");
            if body.contains("WHERE") {
                assert!(sel.where_clause.is_some(), "WHERE kept in {sql}");
            }
            roundtrip(&sql, dialect);
        }
    }
}

#[test]
fn select_into_outside_a_dollar_body_block_still_names_a_table() {
    // Top level, a `LANGUAGE sql` body that is not a block, and T-SQL
    // procedure blocks keep the new-table reading.
    let cases = [
        ("postgresql", "SELECT c INTO new_t FROM t;"),
        ("postgresql", "SELECT c INTO strict FROM t;"),
        ("redshift", "SELECT c INTO new_t FROM t;"),
        (
            "postgresql",
            "CREATE FUNCTION g() RETURNS void LANGUAGE sql AS $$ SELECT c INTO new_t FROM t $$;",
        ),
        (
            "mssql",
            "CREATE PROCEDURE p AS BEGIN SELECT c INTO #t FROM t; END;",
        ),
        ("mssql", "SELECT c INTO dbo.new_t FROM t;"),
    ];
    for (dialect, sql) in cases {
        let (_, selects) = body_selects(sql, dialect);
        assert_eq!(selects.len(), 1, "one SELECT in {sql}");
        assert!(
            matches!(
                selects[0].into_target.as_deref(),
                Some(AstSelectIntoTarget::NewTable(_))
            ),
            "{sql} must read INTO as a new table, got {:?}",
            selects[0].into_target
        );
        roundtrip(sql, dialect);
    }
}

#[test]
fn a_routine_nested_in_a_plpgsql_block_reads_into_by_its_own_body() {
    // Each case: the INTO of every SELECT in walk order, `None` for a new
    // table, else the variable targets.
    let cases: [(&str, Vec<Option<Vec<&str>>>); 5] = [
        (
            "DO $$ BEGIN CREATE FUNCTION g() RETURNS void LANGUAGE sql AS $g$ SELECT c INTO new_t FROM t $g$; END $$;",
            vec![None],
        ),
        (
            "DO $$ DECLARE v int; BEGIN CREATE FUNCTION g() RETURNS void LANGUAGE sql AS $g$ SELECT c INTO new_t FROM t $g$; SELECT c INTO STRICT v FROM t WHERE id = 1; END $$;",
            vec![None, Some(vec!["v"])],
        ),
        (
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ DECLARE v int; BEGIN CREATE FUNCTION g() RETURNS void LANGUAGE sql AS $g$ SELECT c INTO new_t FROM t $g$; SELECT c INTO v FROM t; RETURN v; END $$;",
            vec![None, Some(vec!["v"])],
        ),
        (
            "DO $$ BEGIN CREATE PROCEDURE g() LANGUAGE sql BEGIN ATOMIC SELECT c INTO new_t FROM t; END; END $$;",
            vec![None],
        ),
        (
            "DO $$ BEGIN CREATE FUNCTION g() RETURNS int LANGUAGE plpgsql AS $g$ DECLARE v int; BEGIN SELECT c INTO v FROM t; RETURN v; END $g$; END $$;",
            vec![Some(vec!["v"])],
        ),
    ];
    for (sql, expected) in &cases {
        let (_, selects) = body_selects(sql, "postgresql");
        let got: Vec<Option<Vec<String>>> = selects
            .iter()
            .map(|sel| match sel.into_target.as_deref() {
                Some(AstSelectIntoTarget::NewTable(_)) => None,
                Some(AstSelectIntoTarget::ScriptingVars { .. }) => Some(into_vars(sql, sel).0),
                Some(AstSelectIntoTarget::OutFile(_)) | None => {
                    panic!("no table or variable INTO read in {sql}")
                }
            })
            .collect();
        let expected: Vec<Option<Vec<String>>> = expected
            .iter()
            .map(|e| {
                e.as_ref()
                    .map(|vars| vars.iter().map(|v| v.to_string()).collect())
            })
            .collect();
        assert_eq!(got, expected, "INTO readings of {sql}");
    }
}

#[test]
fn snowflake_procedure_body_into_a_variable_named_strict_is_a_target() {
    let sql = "CREATE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ DECLARE strict INT; BEGIN SELECT c INTO strict FROM t; RETURN strict; END $$;";
    let (_, selects) = body_selects(sql, "snowflake");
    assert_eq!(selects.len(), 1);
    let (vars, strict) = into_vars(sql, &selects[0]);
    assert_eq!(vars, vec!["strict".to_string()]);
    assert_eq!(strict, None);
}
