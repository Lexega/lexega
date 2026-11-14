// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL's `EXECUTE st` runs a prepared statement in a routine's, an
//! event's or a trigger's body as it does at the top level; a PL/pgSQL
//! body's `EXECUTE <expr>` stays dynamic SQL.

use lexega_syntax::{dialect, parse_sql_with_dialect, AstStmt, DialectRef};

/// The one statement `sql` holds, read whole under `dialect`.
fn one_statement(dialect: &DialectRef, sql: &str) -> AstStmt {
    let script = parse_sql_with_dialect(sql, &**dialect).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [stmt] = script.stmts.as_slice() else {
        panic!("{sql}: expected one statement, got {:?}", script.stmts);
    };
    assert!(
        !matches!(stmt, AstStmt::OpaqueContent { .. }),
        "{sql}: not read: {stmt:?}"
    );
    stmt.clone()
}

/// Every statement `stmt` holds, at any depth, itself first.
fn all_statements(stmt: &AstStmt) -> Vec<AstStmt> {
    let mut out = vec![stmt.clone()];
    for body in stmt.bodies() {
        for inner in body.stmts {
            out.extend(all_statements(inner));
        }
    }
    out
}

#[test]
fn a_mysql_body_runs_a_prepared_statement() {
    for sql in [
        "CREATE PROCEDURE p() BEGIN PREPARE s FROM 'SELECT 1'; EXECUTE s; DEALLOCATE PREPARE s; END",
        "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO BEGIN SET @s = CONCAT('DELETE FROM o WHERE id = ', @v); PREPARE st FROM @s; EXECUTE st; END",
        "CREATE TRIGGER tr BEFORE INSERT ON o FOR EACH ROW BEGIN PREPARE st FROM @s; EXECUTE st USING @a, @b; END",
    ] {
        let stmt = one_statement(&dialect::mysql(), sql);
        let inner = all_statements(&stmt);
        assert!(
            inner.iter().any(|s| matches!(s, AstStmt::PgExecute(_))),
            "{sql}: no EXECUTE of a prepared statement in {inner:?}"
        );
        assert!(
            !inner.iter().any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
            "{sql}: a body statement not read in {inner:?}"
        );
    }
}

#[test]
fn a_plpgsql_body_executes_dynamic_sql() {
    let sql = "DO $$ BEGIN EXECUTE 'DELETE FROM o'; END $$;";
    let stmt = one_statement(&dialect::postgres(), sql);
    let inner = all_statements(&stmt);
    assert!(
        inner
            .iter()
            .any(|s| matches!(s, AstStmt::ExecuteImmediate { .. })),
        "{sql}: {inner:?}"
    );
    assert!(
        !inner.iter().any(|s| matches!(s, AstStmt::PgExecute(_))),
        "{sql}: {inner:?}"
    );
}

/// `REPEAT('a', 2)` is MySQL's string function, read as a call; `REPEAT …
/// UNTIL … END REPEAT` in a body stays the loop.
#[test]
fn repeat_followed_by_a_parenthesis_is_a_call() {
    for sql in [
        "SELECT REPEAT('a', 2)",
        "SELECT REPEAT(status, 3) AS r FROM orders",
        "CREATE PROCEDURE p() BEGIN DECLARE s TEXT; SET s = REPEAT('-', 3); END",
        "CREATE PROCEDURE p() BEGIN DECLARE i INT DEFAULT 0; REPEAT SET i = i + 1; UNTIL i > 3 END REPEAT; END",
    ] {
        let stmt = one_statement(&dialect::mysql(), sql);
        let inner = all_statements(&stmt);
        assert!(
            !inner.iter().any(|s| matches!(s, AstStmt::OpaqueContent { .. } | AstStmt::Error { .. })),
            "{sql}: a statement not read in {inner:?}"
        );
    }
}
