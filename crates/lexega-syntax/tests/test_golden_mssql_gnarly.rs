// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Golden and gap-inventory test for MSSQL/T-SQL.
//!
//! The fixture holds both syntax the parser covers and syntax it does not, so
//! the test pins parser/formatter coverage.

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, span_to_line_col, AstStmt, CommaStyle,
    FormatterConfig, MsSqlDialect,
};

const INPUT: &str = include_str!("fixtures/mssql_golden_gnarly.sql");
const EXPECTED: &str = include_str!("fixtures/mssql_golden_gnarly_formatted.sql");
const SEMICOLONLESS_BOUNDARIES: &str = include_str!("fixtures/mssql_semicolonless_boundaries.sql");

fn mssql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::mssql(),
        ..Default::default()
    }
}

#[test]
fn test_mssql_gnarly_golden_default() {
    let formatted = format_sql_with_config(INPUT, &mssql_config())
        .expect("formatting should succeed for gnarly MSSQL fixture");

    assert_eq!(
        formatted.trim(),
        EXPECTED.trim(),
        "Formatted output should match mssql_golden_gnarly_formatted.sql"
    );
}

#[test]
fn test_mssql_gnarly_idempotent() {
    let formatted_once =
        format_sql_with_config(INPUT, &mssql_config()).expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &mssql_config())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Formatting should be idempotent for gnarly MSSQL fixture"
    );
}

#[test]
fn test_mssql_gnarly_known_opaque_inventory() {
    let script = parse_sql_with_dialect(INPUT, &MsSqlDialect)
        .expect("script parsing should return an AstScript");

    assert!(
        script
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, AstStmt::GoBatchSeparator { .. })),
        "Expected GO batch separator to parse as AstStmt::GoBatchSeparator"
    );

    let mut opaque_reports = Vec::new();
    let mut opaque_snippets = Vec::new();

    for (index, stmt) in script.stmts.iter().enumerate() {
        if matches!(stmt, AstStmt::OpaqueContent { .. }) {
            let span = stmt.span();
            let (start, end) = span_to_line_col(INPUT, span);
            let start_idx = span.start as usize;
            let end_idx = (span.end as usize).min(INPUT.len());
            let raw_snippet = if start_idx < end_idx {
                &INPUT[start_idx..end_idx]
            } else {
                "<empty-span>"
            };
            let snippet = raw_snippet.lines().next().unwrap_or("<empty>").trim();
            opaque_snippets.push(snippet.to_string());

            opaque_reports.push(format!(
                "stmt#{idx} lines {l1}:{c1}-{l2}:{c2} => {snip}",
                idx = index,
                l1 = start.line,
                c1 = start.col,
                l2 = end.line,
                c2 = end.col,
                snip = snippet
            ));
        }
    }

    assert_eq!(
        opaque_snippets.len(),
        0,
        "Unexpected MSSQL opaque inventory size:\n{}",
        opaque_reports.join("\n")
    );
}

#[test]
fn test_mssql_semicolonless_select_go_boundary() {
    let script = parse_sql_with_dialect(SEMICOLONLESS_BOUNDARIES, &MsSqlDialect)
        .expect("semicolonless MSSQL boundary fixture should parse");

    assert!(
        script.stmts.len() >= 5,
        "Expected fixture to contain at least 5 statements"
    );
    assert!(matches!(script.stmts[0], AstStmt::Select(_)));
    assert!(matches!(script.stmts[1], AstStmt::GoBatchSeparator { .. }));
    assert!(matches!(script.stmts[2], AstStmt::Select(_)));
}

#[test]
fn test_mssql_semicolonless_create_view_query_boundary() {
    let script = parse_sql_with_dialect(SEMICOLONLESS_BOUNDARIES, &MsSqlDialect)
        .expect("semicolonless MSSQL boundary fixture should parse");

    assert!(matches!(script.stmts[3], AstStmt::CreateView(_)));
    assert!(matches!(script.stmts[4], AstStmt::Select(_)));
}

fn kinds(sql: &str) -> Vec<&'static str> {
    parse_sql_with_dialect(sql, &MsSqlDialect)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .stmts
        .iter()
        .map(|stmt| {
            if matches!(stmt, AstStmt::Select(_)) {
                "select"
            } else if matches!(stmt, AstStmt::Update(_)) {
                "update"
            } else if matches!(stmt, AstStmt::GoBatchSeparator { .. }) {
                "go"
            } else if matches!(stmt, AstStmt::OpaqueContent { .. } | AstStmt::Error { .. }) {
                "unparsed"
            } else {
                "other"
            }
        })
        .collect()
}

// `GO` ends a batch only alone on its line, as sqlcmd and SSMS read it;
// anywhere else `go` is a name, in a statement that parses or one that
// does not.
#[test]
fn go_ends_a_batch_only_alone_on_its_line() {
    for (sql, expected) in [
        (
            "SELECT go.a FROM dbo.t go JOIN dbo.u u ON u.id = go.id;",
            vec!["select"],
        ),
        ("SELECT go.a FROM dbo.t go WHERE go.k = 1;", vec!["select"]),
        (
            "SELECT go.a FROM dbo.t go LEFT JOIN dbo.u u ON u.id = go.id;",
            vec!["select"],
        ),
        ("SELECT go.a FROM dbo.t go ORDER BY go.a;", vec!["select"]),
        ("SELECT a, go FROM dbo.t;", vec!["select"]),
        ("SELECT a FROM dbo.t AS go WHERE ;", vec!["unparsed"]),
        ("SELECT COUNT(* FROM dbo.t GO", vec!["unparsed"]),
        (
            "SELECT p.a FROM sales.go AS p WHERE p.b = (SELECT MAX(x FROM dbo.s);",
            vec!["unparsed"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t AS go;\nEXEC (@sql);",
            vec!["unparsed", "other"],
        ),
        (
            "UPDATE dbo.t SET go = (SELECT MAX(x FROM dbo.s) WHERE id = 1;\nEXEC sp_executesql @sql;",
            vec!["unparsed", "other"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t\nGO 5\nUPDATE dbo.s SET a = 1;",
            vec!["unparsed", "go", "update"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t\nGO -- end of batch\nUPDATE dbo.s SET a = 1;",
            vec!["unparsed", "go", "update"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t\n   go\nUPDATE dbo.s SET a = 1;",
            vec!["unparsed", "go", "update"],
        ),
        (
            "SELECT 1\r\nGO\r\nSELECT 2\r\n\tgo 3 -- x\r\nSELECT 3",
            vec!["select", "go", "select", "go", "select"],
        ),
    ] {
        assert_eq!(kinds(sql), expected, "{sql}");
    }
    // A count belongs to the separator only on its line.
    let script = parse_sql_with_dialect("SELECT 1\nGO\n5", &MsSqlDialect).expect("parse");
    assert!(
        matches!(
            script.stmts[1],
            AstStmt::GoBatchSeparator {
                count_span: None,
                ..
            }
        ),
        "{:?}",
        script.stmts
    );
}

// `GO` with comments of either kind before or after it, and nothing else on
// its line, ends the batch; anything else on its line makes it a name.
#[test]
fn go_with_comments_on_its_line_ends_a_batch() {
    for (sql, expected) in [
        (
            "SELECT 1\nGO /* c */\nSELECT 2",
            vec!["select", "go", "select"],
        ),
        (
            "SELECT 1\n/* c */ GO\nSELECT 2",
            vec!["select", "go", "select"],
        ),
        (
            "SELECT 1\nGO /* a */ -- b\nSELECT 2",
            vec!["select", "go", "select"],
        ),
        (
            "SELECT 1\n/* a */ go 5 /* b */ /* c */\nSELECT 2",
            vec!["select", "go", "select"],
        ),
        (
            "SELECT 1\nGO /* runs\n   on */\nSELECT 2",
            vec!["select", "go", "select"],
        ),
        (
            "SELECT 1 /* runs\n   on */ GO\nSELECT 2",
            vec!["select", "go", "select"],
        ),
        (
            "CREATE TABLE dbo.a (id INT);\nGO /* a */\nDROP TABLE dbo.b;",
            vec!["other", "go", "other"],
        ),
        (
            "SELECT 1;\nGO /* deploy step 2 */\nUPDATE dbo.Orders SET Status = 0 WHERE id = 1;",
            vec!["select", "go", "update"],
        ),
        (
            "DECLARE @sql NVARCHAR(MAX) = N'SELECT 1';\nGO /* batch 1 */\nEXEC (@sql);",
            vec!["other", "go", "other"],
        ),
    ] {
        assert_eq!(kinds(sql), expected, "{sql}");
    }
    for sql in [
        "SELECT 1\nGO;\nSELECT 2",
        "SELECT 1\nGO 5 x\nSELECT 2",
        "SELECT 1\nGO /* c */ x\nSELECT 2",
        "SELECT 1\nx /* c */ GO\nSELECT 2",
        "SELECT 1\nGO 5.5\nSELECT 2",
    ] {
        assert!(!kinds(sql).contains(&"go"), "{sql}: {:?}", kinds(sql));
    }
}

// A separator ends the batch after a statement written without `;`,
// whatever clause the statement ends with.
#[test]
fn go_ends_a_batch_after_a_statement_without_a_semicolon() {
    for stmt in [
        "SELECT a FROM dbo.t ORDER BY c0",
        "SELECT a FROM dbo.t ORDER BY c0 DESC",
        "SELECT a FROM dbo.t ORDER BY c0, go",
        "SELECT a FROM dbo.t GROUP BY c0",
        "SELECT a FROM dbo.t WHERE c0 = 1",
        "SELECT a FROM dbo.t ORDER BY a OFFSET 5 ROWS FETCH NEXT 5 ROWS ONLY",
        "SELECT a FROM dbo.t OPTION (RECOMPILE)",
        "INSERT INTO dbo.t (a) SELECT b FROM dbo.u ORDER BY b",
        "UPDATE dbo.t SET a = 1 WHERE b = 2",
        "CREATE PROCEDURE dbo.p AS SELECT a FROM dbo.t ORDER BY a",
        "IF @x = 1 SELECT a FROM dbo.t ORDER BY a",
        "WITH c AS (SELECT a FROM dbo.t) SELECT a FROM c ORDER BY a",
        "SELECT a INTO #x FROM dbo.t ORDER BY a",
        "EXEC dbo.p @a = 1",
        "PRINT 'x'",
    ] {
        let sql = format!("{stmt}\nGO\nSELECT 1");
        let kinds = kinds(&sql);
        assert!(kinds.ends_with(&["go", "select"]), "{sql}: {kinds:?}");
    }
}

/// Statement shapes written without `;` that end in an `ORDER BY` list.
const ORDER_BY_ENDERS: &[&str] = &[
    "SELECT a FROM dbo.t ORDER BY a",
    "SELECT a FROM dbo.t ORDER BY a, b",
    "SELECT a FROM dbo.t ORDER BY a DESC",
    "SELECT t.a FROM dbo.t t ORDER BY t.a ASC",
    "SELECT [a] FROM dbo.t ORDER BY [a]",
    "SELECT a FROM dbo.t ORDER BY 1",
    "SELECT a FROM dbo.t ORDER BY LEN(a)",
    "SELECT a FROM dbo.t ORDER BY CASE WHEN a = 1 THEN 0 ELSE 1 END",
    "SELECT a FROM dbo.t ORDER BY a COLLATE Latin1_General_CI_AS",
    "SELECT TOP (5) WITH TIES a FROM dbo.t ORDER BY a",
    "SELECT a FROM dbo.t UNION ALL SELECT a FROM dbo.u ORDER BY a",
    "WITH c AS (SELECT a FROM dbo.t) SELECT a FROM c ORDER BY a",
    "INSERT INTO dbo.t (a) SELECT a FROM dbo.u ORDER BY a",
    "SELECT a INTO #x FROM dbo.t ORDER BY a",
    "IF @x = 1 SELECT a FROM dbo.t ORDER BY a",
    "IF @x = 1 SELECT a FROM dbo.t ELSE SELECT b FROM dbo.u ORDER BY b",
    "WHILE @x < 5 SELECT a FROM dbo.t ORDER BY a",
    "CREATE VIEW dbo.v AS SELECT TOP 10 a FROM dbo.t ORDER BY a",
    "DECLARE cur CURSOR FOR SELECT a FROM dbo.t ORDER BY a",
];

/// Statements that may follow one written without `;`.
const NEXT_STATEMENTS: &[&str] = &[
    "PRINT 'x'",
    "EXEC dbo.p @a = 1",
    "EXEC (@sql)",
    "EXEC sp_executesql @sql",
    "EXECUTE dbo.p",
    "DROP TABLE dbo.Orders",
    "DROP TABLE [dbo].[Orders]",
    "TRUNCATE TABLE dbo.Orders",
    "truncate table dbo.Orders",
    "ALTER TABLE dbo.t DROP COLUMN c",
    "GRANT CONTROL ON SCHEMA::dbo TO app_user",
    "REVOKE SELECT ON dbo.t FROM app_user",
    "DENY SELECT ON dbo.t TO app_user",
    "USE master",
    "RAISERROR('x', 16, 1)",
    "WAITFOR DELAY '00:00:01'",
    "GOTO lbl",
    "DEALLOCATE cur",
    "DBCC CHECKDB",
    "KILL 52",
    "CHECKPOINT",
    "RECONFIGURE",
    "BACKUP DATABASE db TO DISK = 'x'",
    "BULK INSERT dbo.t FROM 'c:\\x.csv'",
    "ENABLE TRIGGER tr ON dbo.t",
    "SAVE TRANSACTION sp1",
    "REVERT",
    "DELETE FROM dbo.Orders",
    "UPDATE dbo.Orders SET s = 0",
    "SET NOCOUNT ON",
    "DECLARE @y INT = 1",
    "IF @x = 1 DELETE FROM dbo.Orders",
    "BEGIN TRANSACTION",
    "COMMIT",
    "RETURN",
    "SELECT 1",
    "CREATE TABLE dbo.n (id INT)",
    "lbl:",
    "OPEN cur",
    "FETCH NEXT FROM cur INTO @x",
    "CLOSE cur",
];

/// The kind of each statement, by its variant.
fn variants(sql: &str) -> Vec<std::mem::Discriminant<AstStmt>> {
    parse_sql_with_dialect(sql, &MsSqlDialect)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .stmts
        .iter()
        .map(std::mem::discriminant)
        .collect()
}

// After a statement written without `;` that ends in an `ORDER BY` list, a
// statement on the next line is its own, as with `;`: the list ends at a
// word that leads a statement.
#[test]
fn an_order_by_list_ends_where_the_next_statement_starts() {
    for ender in ORDER_BY_ENDERS {
        for next in NEXT_STATEMENTS {
            let sql = format!("{ender}\n{next}\n");
            let control = format!("{ender};\n{next}\n");
            assert_eq!(variants(&sql), variants(&control), "{sql}");
        }
    }
}

// A `RETURN`, `BREAK` or `CONTINUE` written without `;` takes no word that
// leads a statement as its value or label: the next statement is its own.
#[test]
fn a_statement_after_a_return_or_loop_control_stands_alone() {
    for ender in [
        "RETURN",
        "IF @x = 1 RETURN",
        "IF @x = 1\n    RETURN",
        "WHILE 1 = 1 BREAK",
        "WHILE 1 = 1 CONTINUE",
        "CREATE PROCEDURE dbo.p AS RETURN",
    ] {
        for next in NEXT_STATEMENTS.iter().chain(&["GO\nDROP TABLE dbo.Orders"]) {
            let sql = format!("{ender}\n{next}\n");
            let control = format!("{ender};\n{next}\n");
            assert_eq!(variants(&sql), variants(&control), "{sql}");
        }
    }
    // `CASE` starts a returned value.
    for sql in [
        "CREATE FUNCTION dbo.f() RETURNS INT AS BEGIN RETURN CASE WHEN 1 = 1 THEN 0 ELSE 1 END END",
        "CREATE FUNCTION dbo.f() RETURNS INT AS BEGIN RETURN\n    CASE WHEN 1 = 1 THEN 0 ELSE 1 END\nEND",
    ] {
        let script = parse_sql_with_dialect(sql, &MsSqlDialect).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(script.stmts.len(), 1, "{sql}: {:?}", script.stmts);
        assert!(
            !matches!(
                script.stmts[0],
                AstStmt::OpaqueContent { .. } | AstStmt::Error { .. }
            ),
            "{sql}: {:?}",
            script.stmts
        );
    }
}

// A principal's `ENABLE` / `DISABLE` clause is not the start of an
// `{ ENABLE | DISABLE } TRIGGER` statement on the next line.
#[test]
fn a_trigger_state_statement_after_a_principal_statement_stands_alone() {
    for ender in [
        "ALTER ROLE db_owner ADD MEMBER u",
        "CREATE USER u FOR LOGIN l",
        "CREATE LOGIN l WITH PASSWORD = 'x'",
        "ALTER LOGIN l ENABLE",
        "ALTER LOGIN l DISABLE",
    ] {
        for next in [
            "ENABLE TRIGGER tr ON dbo.t",
            "DISABLE TRIGGER tr ON dbo.t",
            "DISABLE TRIGGER ALL ON DATABASE",
        ] {
            let sql = format!("{ender}\n{next}\n");
            let control = format!("{ender};\n{next}\n");
            assert_eq!(variants(&sql), variants(&control), "{sql}");
        }
    }
}

// `fmt` keeps the statement after such an `ORDER BY` a statement of its own.
#[test]
fn fmt_keeps_the_statement_after_an_order_by_without_a_semicolon() {
    for ender in ORDER_BY_ENDERS {
        for next in ["TRUNCATE TABLE dbo.Orders", "EXEC (@sql)", "PRINT 'x'"] {
            let sql = format!("{ender}\n{next}\n");
            let formatted = format_sql_with_config(&sql, &mssql_config())
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            lexega_syntax::verify_formatting_safe_with_dialect(&sql, &formatted, &MsSqlDialect)
                .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
            assert_eq!(variants(&formatted), variants(&sql), "{formatted}");
            assert!(
                formatted.lines().any(|l| l.trim() == next),
                "{sql}\n---\n{formatted}"
            );
            let again = format_sql_with_config(&formatted, &mssql_config())
                .unwrap_or_else(|e| panic!("{formatted}: {e}"));
            assert_eq!(again, formatted, "{sql}");
        }
    }
}

// `fmt` keeps every line that starts with `GO` on its own line as written:
// a separator with its comments, and a `GO` line that is not one.
#[test]
fn fmt_keeps_every_go_line_as_written() {
    for (sql, line) in [
        (
            "CREATE VIEW dbo.v AS SELECT a FROM dbo.t\nGO /* v */\nCREATE VIEW dbo.w AS SELECT b FROM dbo.u\nGO\n",
            "GO /* v */",
        ),
        ("SELECT 1\nGO /* c */\nSELECT 2\n", "GO /* c */"),
        ("SELECT 1\n/* c */ GO\nSELECT 2\n", "/* c */ GO"),
        ("SELECT 1\nGO /* a */ -- b\nSELECT 2\n", "GO /* a */ -- b"),
        (
            "SELECT alpha_one, beta_two, gamma_three FROM dbo.t\nGO /* next */\nSELECT 2\n",
            "GO /* next */",
        ),
        (
            "CREATE VIEW dbo.v AS SELECT a FROM dbo.t\nGO;\nCREATE VIEW dbo.w AS SELECT b FROM dbo.u\n",
            "GO;",
        ),
        ("SELECT 1\nGO;\nSELECT 2\n", "GO;"),
        ("SELECT 1\nGO 5 x\nSELECT 2\n", "GO 5 x"),
        // A `go` after a statement on its line is no GO line, and fmt
        // makes none of it.
        ("SELECT 1; GO\nSELECT 2;\n", "SELECT 1; GO"),
        ("SELECT 1;GO\nSELECT 2;\n", "SELECT 1; GO"),
        ("SELECT a, b, c FROM dbo.t\ngo  /* c */  x\n", "go  /* c */  x"),
        // A `GO` after the end of a comment a statement's line opened:
        // sqlcmd reads the line as part of the statement, so fmt never
        // sets the `GO` at a line's start.
        ("SELECT 1 /* runs\n   on */ GO\nSELECT 2\n", "   on */ GO"),
        ("SELECT 1; /* runs\n   on */ GO\nSELECT 2;\n", "   on */ GO"),
        (
            "DECLARE @x INT = 1 /* set\n */ GO\nSELECT @x\n",
            " */ GO",
        ),
        ("SELECT 1 /* runs\n   on */ GO;\nSELECT 2\n", "   on */ GO;"),
    ] {
        let formatted =
            format_sql_with_config(sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        assert!(
            formatted.lines().any(|l| l.trim_end() == line),
            "{sql}\n---\n{formatted}"
        );
        assert_eq!(kinds(&formatted), kinds(sql), "{formatted}");
        let again = format_sql_with_config(&formatted, &mssql_config())
            .unwrap_or_else(|e| panic!("{formatted}: {e}"));
        assert_eq!(again, formatted, "{sql}");
    }
}

// Verification refuses output that joins a line starting with `GO` to the
// line before it.
#[test]
fn verification_refuses_a_go_line_joined_to_the_line_before() {
    for (sql, joined) in [
        ("SELECT 1\nGO;\nSELECT 2", "SELECT 1 GO;\n\nSELECT 2"),
        ("SELECT 1\nGO 5 x\nSELECT 2", "SELECT 1 GO\n5 x\nSELECT 2"),
    ] {
        let err = lexega_syntax::verify_formatting_safe_with_dialect(sql, joined, &MsSqlDialect)
            .expect_err("a GO line joined to the line before");
        assert!(err.contains("GO line"), "{err}");
    }
}

// A bare `go` name is never set alone on a formatted line, in any list and
// any style: it stays on the line of the item before it.
#[test]
fn fmt_never_sets_a_go_name_alone_on_its_line() {
    let l = "customer_identifier_value, order_identifier_value, shipping_address_line";
    let shapes = [
        format!("SELECT {l}, go FROM dbo.t"),
        format!("SELECT go, {l} FROM dbo.t"),
        "SELECT a AS x, b AS y, c AS z, go FROM dbo.t".to_string(),
        format!("SELECT {l}, go /* c */ FROM dbo.t"),
        format!("SELECT {l}, -- c\n  go FROM dbo.t"),
        format!("SELECT COUNT(*) FROM dbo.t GROUP BY {l}, go"),
        format!("SELECT COUNT(*) FROM dbo.t GROUP BY go, {l}"),
        "SELECT COUNT(*) FROM dbo.t GROUP BY c0, go".to_string(),
        format!("SELECT a FROM dbo.t ORDER BY {l}, go"),
        format!("SELECT a FROM dbo.t ORDER BY go, {l}"),
        "SELECT a FROM dbo.t ORDER BY c0, go".to_string(),
        "SELECT a FROM dbo.customer_identifier_value, dbo.order_identifier_value, go".to_string(),
        format!("INSERT INTO dbo.t (a, b, go) SELECT {l}, go FROM dbo.s"),
        format!("INSERT INTO dbo.t (a, b, c, d) VALUES ({l}, go)"),
        "SELECT a FROM dbo.t WHERE x IN (alpha_value_one, beta_value_two, gamma_value_three, delta_value_four, epsilon_value_five, zeta_value_six, eta_value_seven, go)".to_string(),
        format!("SELECT {l}, go FROM dbo.t UNION ALL SELECT {l}, go FROM dbo.u"),
        format!("SELECT x FROM (SELECT {l}, go FROM dbo.t) AS q"),
        format!("SELECT a FROM dbo.t WHERE EXISTS (SELECT {l}, go FROM dbo.u)"),
        format!("CREATE PROCEDURE dbo.p AS\nBEGIN\n  SELECT {l}, go FROM dbo.t\nEND"),
    ];
    let styles = [
        FormatterConfig::readable(),
        FormatterConfig::compact(),
        FormatterConfig::ultra_readable(),
    ];
    for shape in &shapes {
        for end in ["", ";"] {
            let sql = format!("{shape}{end}\n");
            for style in &styles {
                for comma_style in [CommaStyle::Trailing, CommaStyle::Leading] {
                    let config = FormatterConfig {
                        dialect: lexega_syntax::dialect::mssql(),
                        comma_style,
                        ..style.clone()
                    };
                    let formatted = format_sql_with_config(&sql, &config)
                        .unwrap_or_else(|e| panic!("{sql}: {e}"));
                    lexega_syntax::verify_formatting_safe_with_dialect(
                        &sql,
                        &formatted,
                        &MsSqlDialect,
                    )
                    .unwrap_or_else(|e| panic!("{sql} ({comma_style:?}): {e}\n{formatted}"));
                    assert!(!kinds(&formatted).contains(&"go"), "{formatted}");
                    let again = format_sql_with_config(&formatted, &config)
                        .unwrap_or_else(|e| panic!("{formatted}: {e}"));
                    assert_eq!(again, formatted, "{sql} ({comma_style:?})");
                }
            }
        }
    }
}

// The item before a bare `go` keeps it on its line.
#[test]
fn fmt_keeps_a_go_name_with_the_item_before_it() {
    for (sql, comma_style, line) in [
        (
            "SELECT alpha, beta, gamma, go FROM dbo.t",
            CommaStyle::Trailing,
            "    gamma, go",
        ),
        (
            "SELECT COUNT(*) FROM dbo.t GROUP BY alpha, go",
            CommaStyle::Trailing,
            "    alpha, go",
        ),
        (
            "SELECT a FROM dbo.t ORDER BY alpha, go",
            CommaStyle::Trailing,
            "    alpha, go",
        ),
        (
            "INSERT INTO dbo.t (a, b, c) VALUES (alpha, beta, go)",
            CommaStyle::Trailing,
            "    beta, go",
        ),
        (
            "SELECT go, alpha, beta FROM dbo.t",
            CommaStyle::Leading,
            "      go, alpha",
        ),
        (
            "SELECT COUNT(*) FROM dbo.t GROUP BY go, alpha",
            CommaStyle::Leading,
            "      go, alpha",
        ),
    ] {
        let config = FormatterConfig {
            comma_style,
            ..mssql_config()
        };
        let formatted =
            format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e}"));
        assert!(
            formatted.lines().any(|l| l == line),
            "{sql}\n---\n{formatted}"
        );
    }
}

// `fmt` prints an unparsed statement's text as written: a `go` in it stays
// where it is.
#[test]
fn fmt_keeps_a_go_name_in_place() {
    for sql in [
        "SELECT go.name, STRING_AGG(p2.name, '->') WITHIN GROUP (GRAPH PATH) AS friends FROM dbo.Person AS go, dbo.friendOf FOR PATH AS fo, dbo.Person FOR PATH AS p2 WHERE MATCH(SHORTEST_PATH(go(-(fo)->p2)+)) AND go.name = 'Alice';",
        "SELECT p.a FROM sales.go AS p WHERE p.b = (SELECT MAX(x FROM dbo.s);",
        "SELECT a FROM dbo.t AS go WHERE ;",
        "SELECT COUNT(* FROM dbo.t GO",
    ] {
        let formatted =
            format_sql_with_config(sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        // Only a line break between two statements is added.
        assert_eq!(formatted.trim_end().replace('\n', ""), sql, "{formatted}");
    }
    for sql in [
        "SELECT go.a FROM dbo.t go JOIN dbo.u u ON u.id = go.id;",
        "SELECT go.a FROM dbo.t go ORDER BY go.a;",
    ] {
        let formatted =
            format_sql_with_config(sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        assert_eq!(kinds(&formatted), vec!["select"], "{formatted}");
    }
}

// Verification refuses output where a `go` name stands alone on its line,
// where sqlcmd and SSMS end the batch, or a separator has left its line.
#[test]
fn verification_refuses_a_batch_separator_the_original_does_not_have() {
    let sql = "SELECT a, go FROM dbo.t;";
    let moved = "SELECT\n    a,\n    go\nFROM dbo.t;";
    let err = lexega_syntax::verify_formatting_safe_with_dialect(sql, moved, &MsSqlDialect)
        .expect_err("a go name moved alone onto its line");
    assert!(err.contains("Batch separator added"), "{err}");
    let err = lexega_syntax::verify_formatting_safe_with_dialect(
        "SELECT 1\nGO\nSELECT 2",
        "SELECT 1 GO SELECT 2",
        &MsSqlDialect,
    )
    .expect_err("a separator moved off its line");
    assert!(err.contains("Batch separator lost"), "{err}");
    // A dialect without batch separators reads `go` as a name anywhere.
    lexega_syntax::verify_formatting_safe_with_dialect(
        sql,
        moved,
        &lexega_syntax::dialect::SnowflakeDialect,
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

/// Statements written without `;` whose clauses a scan reads to the next
/// statement: table options, an `ALTER TABLE` action, an `OUTPUT` list, a
/// declaration, a call's arguments.
const CLAUSE_ENDERS: &[&str] = &[
    "CREATE TABLE #t (id INT)",
    "CREATE TABLE #results (db SYSNAME, rows_deleted INT)",
    "CREATE TABLE dbo.t (id INT) WITH (DATA_COMPRESSION = PAGE)",
    "ALTER TABLE dbo.t ADD c INT",
    "UPDATE dbo.t SET a = 1 OUTPUT inserted.id",
    "DELETE FROM dbo.Q OUTPUT deleted.id INTO @ids",
    "DECLARE @x INT",
    "DECLARE c CURSOR FOR SELECT a FROM dbo.t",
    "EXEC dbo.p @a = 1",
];

/// Cursor statements, each a statement wherever one may start.
const CURSOR_STATEMENTS: &[&str] = &[
    "OPEN cur",
    "FETCH NEXT FROM cur INTO @x",
    "FETCH cur",
    "FETCH PRIOR FROM cur INTO @x",
    "FETCH ABSOLUTE 5 FROM cur INTO @x",
    "FETCH NEXT FROM GLOBAL cur INTO @x",
    "FETCH GLOBAL cur INTO @x",
    "FETCH GLOBAL cur",
    "FETCH NEXT FROM @cur INTO @x",
    "CLOSE cur",
    "DEALLOCATE cur",
];

// A cursor statement after a statement written without `;` is its own, as
// with `;`, and so is the statement after it.
#[test]
fn a_cursor_statement_after_a_statement_without_a_semicolon_stands_alone() {
    for ender in CLAUSE_ENDERS.iter().chain(ORDER_BY_ENDERS) {
        for cursor in CURSOR_STATEMENTS {
            for next in ["DROP TABLE dbo.Old", "EXEC xp_cmdshell 'dir'"] {
                let sql = format!("{ender}\n{cursor}\n{next}\n");
                let control = format!("{ender};\n{cursor}\n{next}\n");
                assert_eq!(variants(&sql), variants(&control), "{sql}");
            }
        }
    }
    // A query's row limit is its own: `FETCH NEXT 5 ROWS ONLY` leads none.
    for sql in [
        "SELECT a FROM dbo.t ORDER BY a OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY\nDROP TABLE dbo.x\n",
        "CREATE VIEW dbo.v AS SELECT a FROM dbo.t ORDER BY a OFFSET 0 ROWS FETCH FIRST 5 ROWS ONLY\nGO\nDROP TABLE dbo.x\n",
    ] {
        assert_eq!(kinds(sql).len(), sql.lines().count(), "{sql}: {:?}", kinds(sql));
        assert!(!kinds(sql).contains(&"unparsed"), "{sql}");
    }
}

// One check tells a cursor's `FETCH` from a query's row limit, in every
// dialect: a signed count before `FROM` / `IN` is a cursor's position, and
// a row limit's count of any shape ends the query.
#[test]
fn a_cursor_fetch_and_a_row_limit_are_told_apart_once() {
    let parse = |sql: &str, dialect: &dyn lexega_syntax::dialect::Dialect| {
        parse_sql_with_dialect(sql, dialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .stmts
            .iter()
            .map(std::mem::discriminant)
            .collect::<Vec<_>>()
    };
    let pg = lexega_syntax::dialect::postgres();
    let fetch_then_delete = parse("FETCH NEXT FROM c; DELETE FROM o;", pg.as_ref());
    for sql in [
        "FETCH -1 FROM c; DELETE FROM o;",
        "FETCH +2 IN c; DELETE FROM o;",
        "FETCH RELATIVE -1 FROM c; DELETE FROM o;",
        "FETCH 3 FROM c; DELETE FROM o;",
    ] {
        assert_eq!(parse(sql, pg.as_ref()), fetch_then_delete, "{sql}");
    }
    let select_then_delete = parse("SELECT a FROM t; DELETE FROM o;", pg.as_ref());
    for sql in [
        "SELECT a FROM t FETCH FIRST 5 ROWS ONLY; DELETE FROM o;",
        "SELECT a FROM t FETCH NEXT ROW ONLY; DELETE FROM o;",
        "SELECT a FROM t OFFSET 1 FETCH FIRST (2 + 3) ROWS ONLY; DELETE FROM o;",
    ] {
        assert_eq!(parse(sql, pg.as_ref()), select_then_delete, "{sql}");
    }
    // `INTO` is no row limit's: T-SQL's `FETCH @c INTO @x`, read as
    // PostgreSQL, is no query's tail, and `fmt` keeps it.
    let config = FormatterConfig {
        dialect: pg.clone(),
        ..Default::default()
    };
    for sql in [
        "SELECT a FROM t ORDER BY a\nFETCH @cur INTO @x\nDROP TABLE o\n",
        "DECLARE c CURSOR FOR SELECT a FROM t\nFETCH @cur INTO @x\nDROP TABLE o\n",
    ] {
        let formatted =
            format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e}"));
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, pg.as_ref())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
    let sf = lexega_syntax::dialect::snowflake();
    for sql in [
        "SELECT a FROM t FETCH 10; DELETE FROM o;",
        "SELECT a FROM t FETCH :n; DELETE FROM o;",
        "SELECT a FROM t FETCH $1; DELETE FROM o;",
    ] {
        assert_eq!(parse(sql, sf.as_ref()), select_then_delete, "{sql}");
    }
}

// A parenthesised query after a statement that ends in a name or a literal
// is a statement of its own, as with `;`: no call or table hint takes a
// query.
#[test]
fn a_parenthesised_query_after_a_statement_without_a_semicolon_stands_alone() {
    for ender in [
        "SELECT a FROM dbo.t ORDER BY a",
        "SELECT a FROM dbo.t WHERE a = 1",
        "SELECT a FROM dbo.t",
        "SET @a = @b",
        "EXEC dbo.p",
    ] {
        for next in [
            "(SELECT b FROM dbo.u)",
            "(SELECT b FROM dbo.u) UNION (SELECT c FROM dbo.v)",
        ] {
            let sql = format!("{ender}\n{next}\nDROP TABLE dbo.Old\n");
            let control = format!("{ender};\n{next}\nDROP TABLE dbo.Old\n");
            assert_eq!(variants(&sql), variants(&control), "{sql}");
        }
    }
    // A call, a table hint, a table function and a subquery are unchanged.
    for sql in [
        "SELECT COUNT (*) FROM dbo.t (NOLOCK)",
        "SELECT a FROM dbo.tvf (1) x",
        "SELECT a FROM dbo.t WHERE b = (SELECT 1)",
        "SELECT a FROM dbo.t WHERE b IN (SELECT 1)",
        "SELECT COALESCE((SELECT MAX(a) FROM dbo.t), 0) AS m FROM dbo.t",
        "SELECT a FROM dbo.t WHERE ISNULL((SELECT 1), 0) = 1",
        "INSERT INTO dbo.t (SELECT a FROM dbo.u)",
        "INSERT INTO dbo.t (a)\n(SELECT a FROM dbo.u)",
        "WITH c AS (SELECT 1 AS a)\n(SELECT a FROM c)",
    ] {
        assert_eq!(kinds(sql).len(), 1, "{sql}: {:?}", kinds(sql));
    }
}

// A parenthesised query stands wherever a query may: as a view's or a
// table's body, as a set operation's branches, inside more parentheses and
// after `WITH`. It is read whole, and `fmt` writes it once, each comment
// where it is written, in every dialect.
#[test]
fn a_parenthesised_query_stands_wherever_a_query_may() {
    let read_whole = [
        "CREATE VIEW v AS (SELECT a FROM t);\n",
        "CREATE OR REPLACE VIEW v AS (\n  SELECT a FROM t\n);\n",
        "CREATE VIEW v AS (SELECT a FROM t) UNION ALL (SELECT a FROM u);\n",
        "CREATE VIEW v AS\n(SELECT a FROM t)\nUNION ALL\n(SELECT a FROM u);\n",
        "CREATE VIEW v AS (WITH c AS (SELECT a FROM t) SELECT a FROM c);\n",
        "CREATE VIEW v AS ((SELECT a FROM t));\n",
        "CREATE VIEW v AS ((SELECT a FROM t) UNION (SELECT a FROM u));\n",
        "CREATE VIEW v (x) AS (SELECT a FROM t);\n",
        "CREATE TABLE t2 AS (WITH c AS (SELECT a FROM t) SELECT a FROM c);\n",
        "CREATE TABLE t2 AS (SELECT a FROM t) UNION ALL (SELECT a FROM u);\n",
        "(((SELECT 1)));\n",
        "((SELECT 1)) UNION (SELECT 2);\n",
        "(WITH c AS (SELECT a FROM t) SELECT a FROM c);\n",
        "(WITH c AS (SELECT a FROM t) SELECT a FROM c) UNION (SELECT 2);\n",
        "INSERT INTO t2 (SELECT a FROM t) UNION ALL (SELECT a FROM u);\n",
    ];
    let commented = [
        "(/* first */ SELECT 1) UNION (SELECT 2);\n",
        "( /* c */ SELECT 1 /* d */ );\n",
        "(\n  -- first branch\n  SELECT 1\n) UNION (\n  -- second\n  SELECT 2\n);\n",
        "CREATE VIEW v AS (/* body */ SELECT a FROM t);\n",
        "CREATE VIEW v AS (\n  -- body\n  SELECT a FROM t\n);\n",
        "( /* outer */ ( /* inner */ SELECT 1));\n",
        "(/* w */ WITH c AS (SELECT 1 AS a) SELECT a FROM c);\n",
    ];
    for dialect in [
        lexega_syntax::dialect::mssql(),
        lexega_syntax::dialect::snowflake(),
        lexega_syntax::dialect::postgres(),
        lexega_syntax::dialect::mysql(),
        lexega_syntax::dialect::bigquery(),
        lexega_syntax::dialect::databricks(),
        lexega_syntax::dialect::redshift(),
    ] {
        let config = FormatterConfig {
            dialect: dialect.clone(),
            ..Default::default()
        };
        for sql in read_whole.iter().chain(&commented) {
            let parsed = parse_sql_with_dialect(sql, dialect.as_ref())
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            assert_eq!(parsed.stmts.len(), 1, "{sql}: {:?}", parsed.stmts);
            assert!(
                !matches!(
                    parsed.stmts[0],
                    AstStmt::OpaqueContent { .. } | AstStmt::Error { .. }
                ),
                "{sql}"
            );
            if let AstStmt::CreateView(view) = &parsed.stmts[0] {
                assert!(view.query.is_ok(), "{sql}");
            }
            let formatted =
                format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e}"));
            lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
                .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
            let again =
                format_sql_with_config(&formatted, &config).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(again, formatted, "{sql}");
        }
        // The comment stays inside the parentheses it is written in.
        let formatted = format_sql_with_config(commented[0], &config)
            .unwrap_or_else(|e| panic!("{}: {e}", commented[0]));
        let first_line = formatted.lines().next().unwrap_or_default();
        assert!(
            first_line.starts_with('(')
                && first_line.find("/* first */") < first_line.find("SELECT 1"),
            "{formatted}"
        );
    }
}

// `fmt` writes a statement that starts with a parenthesised query once,
// parentheses and all, in every dialect.
#[test]
fn fmt_keeps_a_statement_that_starts_with_a_parenthesised_query() {
    for dialect in [
        lexega_syntax::dialect::mssql(),
        lexega_syntax::dialect::snowflake(),
        lexega_syntax::dialect::postgres(),
        lexega_syntax::dialect::mysql(),
        lexega_syntax::dialect::bigquery(),
        lexega_syntax::dialect::databricks(),
        lexega_syntax::dialect::redshift(),
    ] {
        let config = FormatterConfig {
            dialect: dialect.clone(),
            ..Default::default()
        };
        for sql in [
            "(SELECT 1);\n",
            "(SELECT 1) UNION (SELECT 2);\n",
            "(SELECT 1) ORDER BY 1;\n",
            "(SELECT id FROM u) UNION ALL (SELECT id FROM v) ORDER BY 1;\n",
            "SELECT 1;\n(SELECT 1);\n",
            "((SELECT 1) UNION (SELECT 2)) ORDER BY 1;\n",
            "(VALUES (1), (2));\n",
            "WITH c AS (SELECT 1 AS a) (SELECT a FROM c);\n",
        ] {
            let formatted =
                format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e}"));
            lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
                .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
            let again =
                format_sql_with_config(&formatted, &config).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(again, formatted, "{sql}");
        }
    }
    for ender in ["SELECT a FROM dbo.t WHERE a = 1", "RETURN;", "SELECT 1"] {
        let sql = format!("{ender}\n(SELECT b FROM dbo.u)\nDROP TABLE dbo.Old\n");
        let formatted =
            format_sql_with_config(&sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        lexega_syntax::verify_formatting_safe_with_dialect(&sql, &formatted, &MsSqlDialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
}

// `fmt` writes a label on a line of its own before the statement it
// labels, whatever ends the statement before it.
#[test]
fn fmt_writes_a_label_on_its_own_line() {
    for before in [
        "SELECT 1",
        "SELECT 1;",
        "SELECT a FROM dbo.t",
        "SELECT a FROM dbo.t ORDER BY a",
        "SELECT a x FROM dbo.t y",
        "SET @i = 0",
        "DECLARE @i INT = 0",
        "UPDATE dbo.t SET a = 1 WHERE id = 2",
        "PRINT 'x'",
        "EXEC dbo.p",
    ] {
        for (label, labelled) in [
            (
                "top_loop:",
                "top_loop:\nWHILE @i < 10\nBEGIN\n  SET @i = @i + 1\nEND",
            ),
            ("lbl:", "lbl:\nBEGIN\n  DELETE FROM dbo.t\nEND"),
            ("finish:", "finish:\nPRINT 'done'"),
        ] {
            let sql = format!(
                "{before}\n{labelled}\nGOTO {}\n",
                label.trim_end_matches(':')
            );
            let formatted = format_sql_with_config(&sql, &mssql_config())
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            lexega_syntax::verify_formatting_safe_with_dialect(&sql, &formatted, &MsSqlDialect)
                .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
            assert!(
                formatted.lines().any(|l| l.trim() == label),
                "{sql}\n---\n{formatted}"
            );
            assert_eq!(variants(&formatted), variants(&sql), "{formatted}");
            let again = format_sql_with_config(&formatted, &mssql_config())
                .unwrap_or_else(|e| panic!("{formatted}: {e}"));
            assert_eq!(again, formatted, "{sql}");
        }
    }
    let sql = "CREATE PROCEDURE dbo.p AS\nBEGIN\n  DECLARE @i INT = 0\n  SELECT @i = COUNT(*) FROM dbo.t\nretry_loop:\n  WHILE @i > 0\n  BEGIN\n    DELETE TOP (10) FROM dbo.t\n    SET @i = @i - 10\n  END\nEND\nGO\n";
    let formatted =
        format_sql_with_config(sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
        .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    assert!(
        formatted.lines().any(|l| l.trim() == "retry_loop:"),
        "{formatted}"
    );
}

// `fmt` writes an `INSERT … VALUES` without `;` in a block or a procedure
// body with the row's own parentheses.
#[test]
fn fmt_keeps_the_rows_of_an_insert_without_a_semicolon_in_a_block() {
    for sql in [
        "CREATE PROCEDURE dbo.p AS\nBEGIN\n    INSERT INTO dbo.ReportLog (ReportName, RunAt) VALUES ('TopCustomers', GETDATE())\n    EXEC dbo.usp_NotifyReport 'TopCustomers'\nEND\nGO\n",
        "BEGIN\n    INSERT INTO dbo.t (a) VALUES (1)\n    EXEC dbo.p\nEND\n",
        "BEGIN\n    EXEC dbo.p\n    INSERT INTO dbo.t (a) VALUES (1), (2)\nEND\n",
        "BEGIN\n    INSERT INTO dbo.t (a) VALUES (1), /* c */ (2)\n    SELECT 1\nEND\n",
    ] {
        let formatted =
            format_sql_with_config(sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        let again = format_sql_with_config(&formatted, &mssql_config())
            .unwrap_or_else(|e| panic!("{formatted}: {e}"));
        assert_eq!(again, formatted, "{sql}");
    }
}

// A sqlcmd command line is a statement of the client's: no name before it
// is a label, no statement takes it, and `fmt` keeps it as written on its
// own line.
#[test]
fn a_sqlcmd_command_line_is_kept_as_written() {
    for (before, line) in [
        ("SELECT a FROM dbo.t t", ":r .\\Tables\\Orders.sql"),
        ("UPDATE t SET a = 1 FROM dbo.t t", ":r .\\next.sql"),
        ("SELECT a FROM dbo.t x", ":setvar Db Prod"),
        ("PRINT 'Deploying'", ":r .\\next.sql"),
        ("SELECT a FROM dbo.t ORDER BY a", ":r .\\next.sql"),
        ("SELECT @@SERVERNAME AS server_name", ":CONNECT server2"),
        ("SELECT 1", ":on error exit"),
        ("SELECT 1", ":setvar a b -- note"),
        ("lbl:", ":setvar x 1"),
        ("SELECT a FROM dbo.t t", ":List"),
        ("SELECT a FROM dbo.t t", ":LIST"),
        ("SELECT a FROM dbo.t t", ":!! dir"),
        ("SELECT a FROM dbo.t t", "!! dir"),
        ("SELECT a FROM dbo.t t", "!!dir c:\\x"),
        ("SELECT a FROM dbo.t t", ":Exit(SELECT @@ROWCOUNT)"),
        ("SELECT a FROM dbo.t t", ":ServerList"),
    ] {
        let sql = format!("{before}\n{line}\nDROP TABLE dbo.x\n");
        let parsed = parse_sql_with_dialect(&sql, &MsSqlDialect).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed
                .stmts
                .iter()
                .filter(|s| matches!(s, AstStmt::SqlcmdCommand { .. }))
                .count(),
            1,
            "{sql}: {:?}",
            parsed.stmts
        );
        assert!(
            !kinds(&sql).contains(&"unparsed"),
            "{sql}: {:?}",
            kinds(&sql)
        );
        assert!(
            !parsed
                .stmts
                .iter()
                .any(|s| matches!(s, AstStmt::MssqlLabel(_)) && !before.ends_with(':')),
            "{sql}: {:?}",
            parsed.stmts
        );
        let formatted =
            format_sql_with_config(&sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        lexega_syntax::verify_formatting_safe_with_dialect(&sql, &formatted, &MsSqlDialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        assert!(
            formatted.lines().any(|l| l == line),
            "{sql}\n---\n{formatted}"
        );
        let again = format_sql_with_config(&formatted, &mssql_config())
            .unwrap_or_else(|e| panic!("{formatted}: {e}"));
        assert_eq!(again, formatted, "{sql}");
    }
    // In a procedure body too.
    let sql = "CREATE PROCEDURE dbo.p AS\nBEGIN\n    SELECT a FROM dbo.t t\n:setvar x 1\n    DELETE FROM dbo.t\nEND\nGO\n";
    let formatted =
        format_sql_with_config(sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
        .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    assert!(
        formatted.lines().any(|l| l.trim() == ":setvar x 1"),
        "{formatted}"
    );
    // Not at a line's start, or with a space after `:`, it is no command.
    for sql in [
        "SELECT a :r FROM dbo.t\n",
        "SELECT 1\n: r x\n",
        "SELECT 1\n: !! dir\n",
        "SELECT 1\n! ! dir\n",
    ] {
        let parsed = parse_sql_with_dialect(sql, &MsSqlDialect).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !parsed
                .stmts
                .iter()
                .any(|s| matches!(s, AstStmt::SqlcmdCommand { .. })),
            "{sql}"
        );
    }
    // Verification refuses a command line `fmt` would change.
    let err = lexega_syntax::verify_formatting_safe_with_dialect(
        "SELECT 1\n:r .\\x.sql\n",
        "SELECT 1\n:r\n.\\x.sql\n",
        &MsSqlDialect,
    )
    .expect_err("a sqlcmd line split");
    assert!(err.contains("sqlcmd"), "{err}");
}

// Each sqlcmd command is read for what it does: an include, a connection,
// an operating-system command, the editor and `:exit(query)` run what the
// line does not hold; every other command sets the client's state.
#[test]
fn a_sqlcmd_command_line_is_read_for_what_it_does() {
    use lexega_syntax::ast::SqlcmdAction;
    #[derive(Debug, PartialEq)]
    enum Does {
        Client(Option<&'static str>),
        Include(Option<&'static str>),
        Connect(Option<&'static str>),
        OsCommand,
        Edit,
        ExitQuery(&'static str),
    }
    for (line, does) in [
        (
            ":r .\\Tables\\Orders.sql",
            Does::Include(Some(".\\Tables\\Orders.sql")),
        ),
        (
            ":R \"C:\\Some Folder\\x.sql\"",
            Does::Include(Some("\"C:\\Some Folder\\x.sql\"")),
        ),
        (":r $(Path)\\x.sql", Does::Include(Some("$(Path)\\x.sql"))),
        (":r", Does::Include(None)),
        (
            ":connect myserver\\instance1",
            Does::Connect(Some("myserver\\instance1")),
        ),
        (":CONNECT srv -U sa -P secret", Does::Connect(Some("srv"))),
        (":connect -Psecret srv", Does::Connect(None)),
        (":connect srv,1433;Password=secret", Does::Connect(None)),
        (":setvar Pw secret value", Does::Client(Some("Pw"))),
        (
            ":connect $(Server) $(User)",
            Does::Connect(Some("$(Server)")),
        ),
        (
            ":connect tcp:srv,1433 -l 30",
            Does::Connect(Some("tcp:srv,1433")),
        ),
        ("!! dir", Does::OsCommand),
        (":!! del c:\\x", Does::OsCommand),
        (":ED", Does::Edit),
        (
            ":EXIT(SELECT @@ROWCOUNT)",
            Does::ExitQuery("SELECT @@ROWCOUNT"),
        ),
        (":exit (SELECT 1)", Does::ExitQuery("SELECT 1")),
        (":exit", Does::Client(None)),
        (":EXIT()", Does::Client(None)),
        (":exit( )", Does::Client(None)),
        (":setvar Db \"Prod\"", Does::Client(Some("Db"))),
        (":listvar", Does::Client(None)),
        (":on error exit", Does::Client(Some("error exit"))),
        (":out C:\\out.txt", Does::Client(Some("C:\\out.txt"))),
        (":error STDOUT", Does::Client(Some("STDOUT"))),
        (":perftrace STDERR", Does::Client(Some("STDERR"))),
        (":xml ON", Does::Client(Some("ON"))),
        (":help", Does::Client(None)),
        (":List", Does::Client(None)),
        (":reset", Does::Client(None)),
        (":serverlist", Does::Client(None)),
        (":quit", Does::Client(None)),
    ] {
        let sql = format!("SELECT 1\n{line}\nGO\n");
        let parsed = parse_sql_with_dialect(&sql, &MsSqlDialect).unwrap_or_else(|e| panic!("{e}"));
        let found: Vec<Does> = parsed
            .stmts
            .iter()
            .filter_map(|s| {
                if let AstStmt::SqlcmdCommand { action, .. } = s {
                    Some(*action)
                } else {
                    None
                }
            })
            .map(|action| {
                let text = |span: lexega_syntax::Span| {
                    &*String::leak(sql[span.start as usize..span.end as usize].to_string())
                };
                match action {
                    SqlcmdAction::Client { named } => Does::Client(named.map(text)),
                    SqlcmdAction::Include { file_span } => Does::Include(file_span.map(text)),
                    SqlcmdAction::Connect { server_span } => Does::Connect(server_span.map(text)),
                    SqlcmdAction::OsCommand => Does::OsCommand,
                    SqlcmdAction::Edit => Does::Edit,
                    SqlcmdAction::ExitQuery { query_span } => Does::ExitQuery(text(query_span)),
                }
            })
            .collect();
        assert_eq!(found, vec![does], "{line}");
    }
}

// Between two sqlcmd lines `fmt` breaks lines as the source does:
// consecutive lines stay consecutive and a blank line stays one, with the
// comments between them where they are written.
#[test]
fn consecutive_sqlcmd_lines_keep_their_line_breaks() {
    let includes: String = (1..=12)
        .map(|n| format!(":r .\\Tables\\T{n:02}.sql\n"))
        .collect();
    let ssdt = format!(
        ":setvar DatabaseName \"MyDb\"\n:on error exit\nGO\nUSE [$(DatabaseName)]\nGO\n{includes}GO\nPRINT N'done'\nGO\n"
    );
    let ssdt_formatted = format!(
        ":setvar DatabaseName \"MyDb\"\n:on error exit\nGO\n\nUSE [$(DatabaseName)]\nGO\n\n{includes}GO\n\nPRINT N'done'\nGO\n"
    );
    for (sql, expected) in [
        (ssdt.as_str(), ssdt_formatted.as_str()),
        (
            ":r a.sql\n\n:r b.sql\n:r c.sql\n",
            ":r a.sql\n\n:r b.sql\n:r c.sql\n",
        ),
        (":r a.sql\n\n\n\n:r b.sql\n", ":r a.sql\n\n:r b.sql\n"),
        (
            ":r a.sql\n-- c\n:r b.sql\n\n-- d\n\n:r c.sql\n/* e */\n:r d.sql\n",
            ":r a.sql\n-- c\n:r b.sql\n\n-- d\n\n:r c.sql\n/* e */\n:r d.sql\n",
        ),
        (
            ":setvar a b -- note\n:r c.sql\n",
            ":setvar a b -- note\n:r c.sql\n",
        ),
        (
            ":r a.sql\r\n:r b.sql\r\n\r\n:r c.sql\r\n",
            ":r a.sql\r\n:r b.sql\r\n\r\n:r c.sql\r\n",
        ),
        // A comment before a command on its line stays on that line:
        // sqlcmd reads a command only at a line's start.
        (
            ":r a.sql\n/* c */ :r b.sql\n:r c.sql\n",
            ":r a.sql\n/* c */ :r b.sql\n:r c.sql\n",
        ),
        (
            ":r a.sql\n/* c\n d */ :setvar x y\n:r c.sql\n",
            ":r a.sql\n/* c\n d */ :setvar x y\n:r c.sql\n",
        ),
    ] {
        let formatted =
            format_sql_with_config(sql, &mssql_config()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        assert_eq!(formatted.trim_end(), expected.trim_end(), "{sql:?}");
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        let again = format_sql_with_config(&formatted, &mssql_config())
            .unwrap_or_else(|e| panic!("{formatted}: {e}"));
        assert_eq!(again, formatted, "{sql:?}");
    }
}

// T-SQL writes a select item's alias before the expression, with an `=`
// between them: the alias is the item's, the expression its value, and the
// formatter keeps the order.
#[test]
fn a_select_item_alias_written_first_is_the_items_alias() {
    use lexega_syntax::ast::{AstProjectionKind, ProjectionItemKind};
    use lexega_syntax::verify_formatting_safe_with_dialect;
    for (sql, alias, value) in [
        ("SELECT body = N'x', id FROM dbo.src;", "body", "N'x'"),
        ("SELECT FORMAT = N'CSV' FROM dbo.src;", "FORMAT", "N'CSV'"),
        (
            "SELECT [Total Due] = a + b FROM dbo.t;",
            "[Total Due]",
            "a + b",
        ),
    ] {
        let parsed = parse_sql_with_dialect(sql, &MsSqlDialect).unwrap_or_else(|e| panic!("{e}"));
        let AstStmt::Select(select) = &parsed.stmts[0] else {
            panic!("{sql}: not a SELECT");
        };
        let AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("{sql}: no columns");
        };
        let ProjectionItemKind::SelectItem(item) = &items[0].kind else {
            panic!("{sql}: no select item");
        };
        let text = |span: lexega_syntax::Span| &sql[span.start as usize..span.end as usize];
        let written = item.alias.as_ref().map(|alias| text(alias.ident.span));
        assert_eq!(written, Some(alias), "{sql}");
        assert!(item.alias_first.is_some(), "{sql}");
        assert_eq!(text(item.expr.span()), value, "{sql}");
        let formatted = format_sql_with_config(sql, &mssql_config()).expect("formats");
        verify_formatting_safe_with_dialect(sql, &formatted, &MsSqlDialect)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
        assert!(
            formatted.contains(&format!("{alias} = {value}")),
            "{sql}: {formatted}"
        );
    }
}
