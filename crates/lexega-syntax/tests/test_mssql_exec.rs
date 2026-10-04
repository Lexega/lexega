// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for MSSQL EXEC/EXECUTE procedure call and dynamic SQL parsing.

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect, AstStmt,
    FormatterConfig, MsSqlDialect,
};

fn mssql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::mssql(),
        ..Default::default()
    }
}

/// Helper: parse with MSSQL dialect and assert it produces an MssqlExec AST node (not OpaqueContent).
fn assert_parses_as_exec(sql: &str) {
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("should parse");
    let stmts: Vec<_> = script.stmts.iter().collect();
    assert!(
        !stmts.is_empty(),
        "Expected at least one statement for:\n{}",
        sql
    );
    for stmt in &stmts {
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "MSSQL EXEC parsed as OpaqueContent (parser fallback):\n{}",
            sql
        );
    }
    // At least one statement should be MssqlExec
    let has_exec = stmts.iter().any(|s| matches!(s, AstStmt::MssqlExec(_)));
    assert!(
        has_exec,
        "Expected MssqlExec variant but got: {:?}\nSQL: {}",
        stmts
            .iter()
            .map(|s| std::mem::discriminant(*s))
            .collect::<Vec<_>>(),
        sql
    );
}

/// Helper: parse, format, and verify round-trip safety under MSSQL dialect.
fn assert_format_roundtrip(sql: &str) {
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
        .expect("formatting should be safe");
}

// ─── Basic EXEC (Identifier form) ───────────────────────────────────────────

#[test]
fn test_exec_simple_proc() {
    assert_parses_as_exec("EXEC sp_help;");
}

#[test]
fn test_exec_simple_proc_no_semi() {
    assert_parses_as_exec("EXEC sp_help");
}

#[test]
fn test_execute_keyword_form() {
    assert_parses_as_exec("EXECUTE sp_help;");
}

// ─── Qualified procedure names ──────────────────────────────────────────────

#[test]
fn test_exec_schema_qualified() {
    assert_parses_as_exec("EXEC dbo.sp_helpdb;");
}

#[test]
fn test_exec_fully_qualified() {
    assert_parses_as_exec("EXEC master.dbo.sp_helpdb;");
}

// ─── Positional arguments ───────────────────────────────────────────────────

#[test]
fn test_exec_positional_args() {
    assert_parses_as_exec("EXEC sp_adduser 'testuser', 'db_datareader';");
}

#[test]
fn test_exec_single_positional_arg() {
    assert_parses_as_exec("EXEC sp_helpdb 'master';");
}

// ─── Named parameters ──────────────────────────────────────────────────────

#[test]
fn test_exec_named_params() {
    assert_parses_as_exec("EXEC sp_rename @objname = 'old_tbl', @newname = 'new_tbl';");
}

#[test]
fn test_exec_mixed_positional_and_named() {
    assert_parses_as_exec("EXEC dbo.my_proc 42, @name = 'foo', @flag = 1;");
}

// ─── OUTPUT parameter ───────────────────────────────────────────────────────

#[test]
fn test_exec_output_param() {
    assert_parses_as_exec("EXEC dbo.sp_get_count @result = @cnt OUTPUT;");
}

// ─── DEFAULT keyword ────────────────────────────────────────────────────────

#[test]
fn test_exec_default_keyword() {
    assert_parses_as_exec("EXEC dbo.my_proc @p1 = DEFAULT;");
}

// ─── Return value capture ───────────────────────────────────────────────────

#[test]
fn test_exec_return_capture() {
    assert_parses_as_exec("EXEC @ret = dbo.sp_calculate 10, 20;");
}

#[test]
fn test_execute_return_capture() {
    assert_parses_as_exec("EXECUTE @rc = sp_procedure;");
}

// ─── Dynamic SQL ────────────────────────────────────────────────────────────

#[test]
fn test_exec_dynamic_sql_simple() {
    assert_parses_as_exec("EXEC ('SELECT 1');");
}

#[test]
fn test_exec_dynamic_sql_concat() {
    assert_parses_as_exec("EXEC ('SELECT * FROM ' + @table_name);");
}

#[test]
fn test_execute_dynamic_sql() {
    assert_parses_as_exec("EXECUTE ('DROP TABLE ' + @t);");
}

// ─── Formatting round-trip ──────────────────────────────────────────────────

#[test]
fn test_format_roundtrip_exec_simple() {
    assert_format_roundtrip("EXEC sp_help;");
}

#[test]
fn test_format_roundtrip_execute_keyword() {
    assert_format_roundtrip("EXECUTE sp_helpdb;");
}

#[test]
fn test_format_roundtrip_exec_qualified() {
    assert_format_roundtrip("EXEC master.dbo.sp_helpdb;");
}

#[test]
fn test_format_roundtrip_exec_named_params() {
    assert_format_roundtrip("EXEC sp_rename @objname = 'old', @newname = 'new';");
}

#[test]
fn test_format_roundtrip_exec_return_capture() {
    assert_format_roundtrip("EXEC @ret = dbo.sp_calc 10, 20;");
}

#[test]
fn test_format_roundtrip_exec_dynamic_sql() {
    assert_format_roundtrip("EXEC ('SELECT 1');");
}

#[test]
fn test_format_roundtrip_exec_output_param() {
    assert_format_roundtrip("EXEC dbo.sp_get @result = @cnt OUTPUT;");
}

// ─── Multi-statement ────────────────────────────────────────────────────────

#[test]
fn test_multi_exec_statements() {
    let sql = "EXEC sp_help;\nEXEC dbo.sp_helpdb 'master';";
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("should parse");
    let exec_count = script
        .stmts
        .iter()
        .filter(|s| matches!(s, AstStmt::MssqlExec(_)))
        .count();
    assert_eq!(exec_count, 2, "Should parse two EXEC statements");
}

// ─── Non-MSSQL dialect should NOT parse EXEC as MssqlExec ───────────────────

#[test]
fn test_exec_not_mssql_dialect_is_not_exec_node() {
    // Under Snowflake dialect, "EXEC sp_help" should NOT produce MssqlExec
    let result = parse_sql_with_dialect("EXEC sp_help;", &lexega_syntax::SnowflakeDialect);
    if let Ok(script) = result {
        let has_mssql_exec = script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::MssqlExec(_)));
        assert!(
            !has_mssql_exec,
            "Snowflake dialect should NOT produce MssqlExec variant"
        );
    }
    // If it errors, that's fine too — Snowflake doesn't need to parse EXEC
}

// ─── T-SQL omitted-component (double-dot) procedure names ────────────────────

#[test]
fn test_exec_double_dot_omitted_schema() {
    assert_parses_as_exec("EXEC master..xp_cmdshell 'whoami';");
}

#[test]
fn test_exec_double_dot_bracket_quoted() {
    assert_parses_as_exec("EXEC [master]..[xp_cmdshell] 'whoami';");
}

#[test]
fn test_exec_double_dot_roundtrip() {
    assert_format_roundtrip("EXEC master..xp_cmdshell 'whoami';");
    assert_format_roundtrip("EXEC [master]..[xp_cmdshell] 'whoami';");
}

// ─── EXEC(...) AT linked_server ─────────────────────────────────────────────

#[test]
fn test_exec_dynamic_at_linked_server() {
    let sql = "EXEC ('SELECT * FROM payroll.dbo.t') AT PAYROLL_LINK;";
    assert_parses_as_exec(sql);
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("should parse");
    let exec = script
        .stmts
        .iter()
        .find_map(|s| match s {
            AstStmt::MssqlExec(e) => Some(e),
            _ => None,
        })
        .expect("MssqlExec node");
    assert!(
        exec.at_linked_server_span.is_some(),
        "AT linked-server clause should be captured"
    );
}

#[test]
fn test_exec_dynamic_at_bracket_server() {
    assert_parses_as_exec("EXECUTE ('SELECT 1') AT [PAYROLL_LINK];");
}

#[test]
fn test_exec_dynamic_at_with_params() {
    assert_parses_as_exec("EXEC ('SELECT ?', 42) AT PAYROLL_LINK;");
}

#[test]
fn test_exec_at_linked_server_roundtrip() {
    assert_format_roundtrip("EXEC ('SELECT * FROM payroll.dbo.t') AT PAYROLL_LINK;");
    assert_format_roundtrip("EXECUTE ('SELECT 1') AT [PAYROLL_LINK];");
}

// ─── RECONFIGURE ────────────────────────────────────────────────────────────

#[test]
fn test_reconfigure_parses() {
    let script = parse_sql_with_dialect("RECONFIGURE;", &MsSqlDialect).expect("should parse");
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::Reconfigure { .. })),
        "RECONFIGURE should parse to AstStmt::Reconfigure, got: {:?}",
        script.stmts
    );
}

#[test]
fn test_reconfigure_with_override_parses() {
    let script =
        parse_sql_with_dialect("RECONFIGURE WITH OVERRIDE;", &MsSqlDialect).expect("should parse");
    let has = script.stmts.iter().any(|s| {
        matches!(
            s,
            AstStmt::Reconfigure {
                with_override_span: Some(_),
                ..
            }
        )
    });
    assert!(has, "RECONFIGURE WITH OVERRIDE should capture the clause");
}

#[test]
fn test_reconfigure_roundtrip() {
    assert_format_roundtrip("RECONFIGURE;");
    assert_format_roundtrip("RECONFIGURE WITH OVERRIDE;");
}

#[test]
fn test_reconfigure_not_mssql_dialect() {
    // Under Snowflake, RECONFIGURE is a bare identifier, not this statement.
    let result = parse_sql_with_dialect("RECONFIGURE;", &lexega_syntax::SnowflakeDialect);
    if let Ok(script) = result {
        assert!(
            !script
                .stmts
                .iter()
                .any(|s| matches!(s, AstStmt::Reconfigure { .. })),
            "Snowflake should not produce a Reconfigure statement"
        );
    }
}
