// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `OUT` and `OUTPUT` after an `EXEC` argument are read alike.

use lexega_syntax::ast::AstMssqlExec;
use lexega_syntax::{parse_sql_with_dialect, AstStmt, MsSqlDialect};

/// The `EXEC` of `sql` and the number of statements the script holds.
fn exec_of(sql: &str) -> (AstMssqlExec, usize) {
    let script = parse_sql_with_dialect(sql, &MsSqlDialect)
        .unwrap_or_else(|e| panic!("did not parse: {e:?}\n{sql}"));
    let exec = script
        .stmts
        .iter()
        .find_map(|s| match s {
            AstStmt::MssqlExec(e) => Some((**e).clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no EXEC in {:#?}\n{sql}", script.stmts));
    (exec, script.stmts.len())
}

fn arg_texts<'a>(exec: &AstMssqlExec, sql: &'a str) -> Vec<&'a str> {
    exec.args
        .iter()
        .map(|a| &sql[a.span.start as usize..a.span.end as usize])
        .collect()
}

#[test]
fn positional_out() {
    let sql = "EXEC p @q OUT;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert_eq!(arg_texts(&exec, sql), ["@q OUT"]);
}

#[test]
fn positional_output() {
    let sql = "EXEC p @q OUTPUT;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert_eq!(arg_texts(&exec, sql), ["@q OUTPUT"]);
}

#[test]
fn named_out() {
    let sql = "EXEC p @o = @q OUT;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert_eq!(arg_texts(&exec, sql), ["@o = @q OUT"]);
}

#[test]
fn named_output() {
    let sql = "EXEC p @o = @q OUTPUT;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert_eq!(arg_texts(&exec, sql), ["@o = @q OUTPUT"]);
}

#[test]
fn return_variable_with_out_argument() {
    let sql = "EXEC @rc = p @a, @b OUT;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert!(exec.return_var_span.is_some());
    assert_eq!(arg_texts(&exec, sql), ["@a", "@b OUT"]);
}

#[test]
fn out_argument_before_another_argument() {
    let sql = "EXEC p @a OUT, @b OUT, @c = 1;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert_eq!(arg_texts(&exec, sql), ["@a OUT", "@b OUT", "@c = 1"]);
}

#[test]
fn out_argument_without_semicolon_before_next_statement() {
    let sql = "EXEC p @q OUT\nSELECT 1";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 2);
    assert_eq!(arg_texts(&exec, sql), ["@q OUT"]);
}

#[test]
fn sp_executesql_with_output_declaration_and_out_argument() {
    let sql = "EXEC sp_executesql N'SELECT @x = COUNT(*) FROM t', N'@x INT OUTPUT', @x = @y OUT;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert_eq!(
        arg_texts(&exec, sql),
        [
            "N'SELECT @x = COUNT(*) FROM t'",
            "N'@x INT OUTPUT'",
            "@x = @y OUT"
        ]
    );
}

#[test]
fn execute_keyword_form() {
    let sql = "EXECUTE dbo.p @o = @q OUT;";
    let (exec, count) = exec_of(sql);
    assert_eq!(count, 1);
    assert_eq!(arg_texts(&exec, sql), ["@o = @q OUT"]);
}
