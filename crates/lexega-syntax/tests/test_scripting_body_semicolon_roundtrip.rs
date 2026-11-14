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
    let config = FormatterConfig {
        dialect,
        ..Default::default()
    };
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

#[test]
fn a_statement_in_a_body_formats_as_at_the_top_of_a_script() {
    use lexega_syntax::dialect::mssql;

    let bulk = "BULK INSERT dbo.zz_t FROM 'c:\\f.csv'";
    let mysql_bodies = [
        "CREATE PROCEDURE p() BEGIN SET @a = 1; SELECT @a; END",
        "CREATE PROCEDURE p() BEGIN DECLARE x INT; SET x = 1; END",
        "CREATE PROCEDURE p() BEGIN SET PASSWORD = 'x'; END",
        "CREATE PROCEDURE p() BEGIN SET NAMES utf8mb4; END",
        "CREATE PROCEDURE p() BEGIN IF 1 = 1 THEN SET @a = 1; END IF; END",
    ];
    for sql in mysql_bodies {
        roundtrip(mysql(), sql);
    }
    let tsql_bodies = [
        format!("CREATE PROCEDURE dbo.p AS\nBEGIN\n  DELETE FROM dbo.zz_t\n  {bulk}\nEND\nGO\n"),
        format!("CREATE PROCEDURE dbo.p AS\nBEGIN\n  DELETE FROM dbo.zz_t;\n  {bulk};\nEND\nGO\n"),
        format!("CREATE PROCEDURE dbo.p AS\nBEGIN\n  EXEC dbo.q\n  {bulk}\nEND\nGO\n"),
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n  EXECUTE AS USER = 'zz_u' WITH NO REVERT\n  TRUNCATE TABLE dbo.zz_t\nEND\nGO\n".to_string(),
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n  EXECUTE AS USER = 'zz_u'\n  TRUNCATE TABLE dbo.zz_t;\nEND\nGO\n".to_string(),
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n  DISABLE TRIGGER trg ON dbo.zz_t\n  DELETE FROM dbo.zz_t\nEND\nGO\n".to_string(),
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n  BEGIN TRAN\n  DELETE FROM dbo.zz_t\n  COMMIT TRAN\nEND\nGO\n".to_string(),
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n  SAVE TRANSACTION sp\n  DELETE FROM dbo.zz_t\nEND\nGO\n".to_string(),
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n  REVERT\n  ADD SIGNATURE TO dbo.q BY CERTIFICATE c\nEND\nGO\n".to_string(),
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n  GRANT SELECT ON dbo.zz_t TO u\n  DELETE FROM dbo.zz_t\nEND\nGO\n".to_string(),
    ];
    for sql in &tsql_bodies {
        roundtrip(mssql(), sql);
    }
    roundtrip(
        snowflake(),
        "BEGIN\n  CREATE SCHEMA s;\n  USE SCHEMA s;\n  ALTER SESSION SET QUERY_TAG = 'x';\nEND;\n",
    );
}

/// PL/pgSQL assigns an element or a slice of a value by its subscripts: the
/// assignment is read as one and kept whole.
#[test]
fn subscript_assignments_round_trip() {
    for body in [
        "arr[1] := arr[1] + 1;",
        "a[cnt] = 7;",
        "x[1:2] := ARRAY[1, 2];",
        "js['a'] := '1';",
        "m[i][j] := 0;",
        "NEW.tags[1] := 'x';",
    ] {
        roundtrip(
            postgres(),
            &format!("CREATE FUNCTION f(arr int[]) RETURNS int LANGUAGE plpgsql AS $$\nBEGIN\n  {body}\n  RETURN 1;\nEND $$;\n"),
        );
    }
}

/// MySQL's index definitions in a table's list, after its columns or its keys,
/// are items of the table and format as written.
#[test]
fn mysql_index_definitions_round_trip() {
    for sql in [
        "CREATE TABLE k (id INT PRIMARY KEY, v INT, KEY ix_v (v));",
        "CREATE TABLE k (id INT, v INT, KEY (v));",
        "CREATE TABLE k (id INT, v INT, PRIMARY KEY (id), KEY ix_v (v), INDEX ix_w (v), FULLTEXT ft (v), SPATIAL INDEX sp (v), UNIQUE KEY uq (id));",
        "CREATE TABLE k (id INT, v INT, UNIQUE INDEX uq USING BTREE (id), KEY ix (v) USING HASH, FULLTEXT KEY ft (v));",
        "CREATE TABLE `k` (\n  `id` int NOT NULL AUTO_INCREMENT,\n  `v` int DEFAULT NULL,\n  PRIMARY KEY (`id`),\n  KEY `ix_v` (`v`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
    ] {
        roundtrip(mysql(), sql);
    }
}

/// The items of a table's list, columns, keys, index definitions and
/// constraints, format in the order written, whatever it is, with or
/// without `AS SELECT`; formatting twice changes nothing.
#[test]
fn table_items_format_in_the_order_written() {
    let items = [
        "id INT",
        "v INT",
        "g GEOMETRY NOT NULL",
        "KEY k1 (v)",
        "INDEX i1 (id)",
        "UNIQUE KEY u1 (id)",
        "UNIQUE INDEX u2 (v)",
        "FULLTEXT f1 (v)",
        "SPATIAL INDEX s1 (g)",
        "PRIMARY KEY (id)",
        "FOREIGN KEY (v) REFERENCES p (id)",
        "CHECK (v > 0)",
        "CONSTRAINT c1 UNIQUE (v)",
    ];
    let config = FormatterConfig {
        dialect: mysql(),
        ..Default::default()
    };
    let mut wrong = Vec::new();
    let mut check = |sql: String| {
        let once = match format_sql_with_config(&sql, &config) {
            Ok(once) => once,
            Err(e) => return wrong.push(format!("{sql}\n  format failed: {e}")),
        };
        if let Err(e) = verify_formatting_safe_with_dialect(&sql, &once, config.dialect.as_ref()) {
            return wrong.push(format!("{sql}\n  {e}\n{once}"));
        }
        match format_sql_with_config(&once, &config) {
            Ok(twice) if twice == once => {}
            Ok(twice) => wrong.push(format!("{sql}\n  not stable:\n{once}\n{twice}")),
            Err(e) => wrong.push(format!("{sql}\n  second format failed: {e}")),
        }
    };
    // Each pair of items first, in either order, the rest after.
    for first in 0..items.len() {
        for second in 0..items.len() {
            if first == second {
                continue;
            }
            let mut order = vec![items[first], items[second]];
            order.extend(
                (0..items.len())
                    .filter(|at| *at != first && *at != second)
                    .map(|at| items[at]),
            );
            check(format!("CREATE TABLE k ({});", order.join(", ")));
            check(format!(
                "CREATE TABLE k ({}) AS SELECT id, v, g FROM orders;",
                order.join(", ")
            ));
        }
    }
    // Items alone, and keys alone before a query.
    for item in items {
        check(format!("CREATE TABLE k ({item});"));
        check(format!(
            "CREATE TABLE k ({item}) AS SELECT id, v, g FROM orders;"
        ));
    }
    check("CREATE TABLE k (KEY ix (id), INDEX iv (v)) AS SELECT id, v FROM orders;".to_string());
    assert!(wrong.is_empty(), "{}", wrong.join("\n\n"));
    // A key before a column in PostgreSQL and T-SQL too.
    roundtrip(
        postgres(),
        "CREATE TABLE k (PRIMARY KEY (id), id int, v int);",
    );
    roundtrip(
        lexega_syntax::dialect::mssql(),
        "CREATE TABLE k (CONSTRAINT pk PRIMARY KEY (id), id INT, v INT);",
    );
}

/// PostgreSQL's `LIKE table` items of a table's list, and `ONLY` before the
/// target of a `MERGE` or a `TRUNCATE`, format as written; formatting twice
/// changes nothing.
#[test]
fn like_items_and_only_targets_format_as_written() {
    let config = FormatterConfig {
        dialect: postgres(),
        ..Default::default()
    };
    let mut wrong = Vec::new();
    for sql in [
        "CREATE TABLE t (LIKE src);",
        "CREATE TABLE t (LIKE src INCLUDING ALL, id int, CONSTRAINT ck CHECK (id > 0));",
        "CREATE TABLE t (id int, LIKE src, v int);",
        "CREATE TABLE t (id int, LIKE s1.src EXCLUDING INDEXES INCLUDING DEFAULTS /* c */, LIKE \"Other\", PRIMARY KEY (id));",
        "CREATE TEMPORARY TABLE IF NOT EXISTS t (LIKE src INCLUDING ALL) ON COMMIT DROP;",
        "MERGE INTO ONLY t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET v = s.v;",
        "MERGE INTO ONLY app.t AS x USING s ON x.id = s.id WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id);",
        "TRUNCATE ONLY t;",
        "TRUNCATE TABLE ONLY app.t RESTART IDENTITY CASCADE;",
        "TRUNCATE ONLY t *;",
        "TRUNCATE ONLY a, b;",
    ] {
        let once = match format_sql_with_config(sql, &config) {
            Ok(once) => once,
            Err(e) => {
                wrong.push(format!("{sql}\n  format failed: {e}"));
                continue;
            }
        };
        if let Err(e) = verify_formatting_safe_with_dialect(sql, &once, config.dialect.as_ref()) {
            wrong.push(format!("{sql}\n  {e}\n{once}"));
            continue;
        }
        match format_sql_with_config(&once, &config) {
            Ok(twice) if twice == once => {}
            Ok(twice) => wrong.push(format!("{sql}\n  not stable:\n{once}\n{twice}")),
            Err(e) => wrong.push(format!("{sql}\n  second format failed: {e}")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n\n"));
}
