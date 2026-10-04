// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The trailing `;` of the LAST statement in a scripting body survives
//! formatting.
//!
//! Statement spans EXCLUDE their `;` terminator; the `;` lives in the gap
//! between a statement's span end and the body's terminating boundary
//! (END / EXCEPTION / UNTIL / next branch). The block-body and loop/branch
//! formatters emit the gap after the LAST statement as well as the
//! inter-statement gaps, so a body whose final statement does not
//! self-terminate (DDL/DML like DROP/SELECT) keeps its `;`.
//! `verify_formatting_safe*` is token-stream equivalence, so a dropped `;`
//! fails verification.
//!
//! Covers every body-loop site: BEGIN/END block, `$$` procedure/function body
//! (Snowflake + PostgreSQL + Redshift), FOR, WHILE, LOOP, REPEAT, IF/ELSEIF/ELSE,
//! CASE branch + ELSE, and EXCEPTION handlers.

use lexega_syntax::dialect::{mysql, postgres, redshift, snowflake};
use lexega_syntax::{
    format_sql_with_config, verify_formatting_safe_with_dialect, DialectRef, FormatterConfig,
};

fn roundtrip(dialect: DialectRef, sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect;
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("format failed: {}\nSQL:\n{}", e, sql));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref()).unwrap_or_else(
        |e| {
            panic!(
                "round-trip dropped a token: {}\nformatted:\n{}\nSQL:\n{}",
                e, formatted, sql
            )
        },
    );
}

#[test]
fn block_body_last_stmt_semicolon() {
    roundtrip(
        snowflake(),
        "BEGIN\n  DROP TABLE a;\n  DROP TABLE b;\nEND;\n",
    );
}

#[test]
fn snowflake_dollar_body_ending_in_ddl() {
    roundtrip(
        snowflake(),
        "CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS $$\nBEGIN\n  DROP TABLE a;\nEND;\n$$;\n",
    );
}

#[test]
fn postgres_dollar_body_ending_in_ddl() {
    roundtrip(
        postgres(),
        "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n  DROP TABLE a;\n  DROP TABLE b;\nEND;\n$$;\n",
    );
}

#[test]
fn redshift_dollar_body_ending_in_ddl() {
    roundtrip(
        redshift(),
        "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$\nBEGIN\n  DROP TABLE a;\n  DROP TABLE b;\nEND;\n$$;\n",
    );
}

#[test]
fn for_body_last_stmt_semicolon() {
    roundtrip(
        snowflake(),
        "BEGIN\n  FOR i IN 1 TO 3 DO\n    DROP TABLE a;\n    DROP TABLE b;\n  END FOR;\nEND;\n",
    );
}

#[test]
fn while_body_last_stmt_semicolon() {
    roundtrip(
        snowflake(),
        "BEGIN\n  WHILE (x < 3) DO\n    DROP TABLE a;\n    DROP TABLE b;\n  END WHILE;\nEND;\n",
    );
}

#[test]
fn loop_body_last_stmt_semicolon() {
    roundtrip(
        snowflake(),
        "BEGIN\n  LOOP\n    DROP TABLE a;\n    BREAK;\n  END LOOP;\nEND;\n",
    );
}

#[test]
fn repeat_body_last_stmt_semicolon() {
    roundtrip(
        mysql(),
        "BEGIN\n  REPEAT\n    DROP TABLE a;\n    DROP TABLE b;\n  UNTIL x > 3 END REPEAT;\nEND;\n",
    );
}

#[test]
fn if_elseif_else_body_last_stmt_semicolon() {
    roundtrip(
        snowflake(),
        "BEGIN\n  IF (x = 1) THEN\n    DROP TABLE a;\n  ELSEIF (x = 2) THEN\n    DROP TABLE b;\n  ELSE\n    DROP TABLE c;\n  END IF;\nEND;\n",
    );
}

#[test]
fn case_branch_and_else_body_last_stmt_semicolon() {
    roundtrip(
        snowflake(),
        "CASE (x)\n  WHEN 1 THEN\n    DROP TABLE a;\n    DROP TABLE b;\n  ELSE\n    DROP TABLE c;\nEND CASE;\n",
    );
}

#[test]
fn exception_handler_body_last_stmt_semicolon() {
    roundtrip(
        snowflake(),
        "BEGIN\n  DROP TABLE a;\nEXCEPTION\n  WHEN foo THEN\n    DROP TABLE b;\n  WHEN OTHER THEN\n    DROP TABLE c;\n    DROP TABLE d;\nEND;\n",
    );
}
