// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for TABLE() function syntax
use lexega_syntax::ast::{AstStmt, AstTableHintKind, AstTableRef, FromItemKind};
use lexega_syntax::lexer::Span;
use lexega_syntax::{parse_sql_with_dialect, parse_stmt_from_str};

#[test]
fn test_table_function_simple() {
    let sql = "SELECT * FROM TABLE(my_udtf(10))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse TABLE() function");
}

#[test]
fn test_table_function_with_alias() {
    let sql = "SELECT * FROM TABLE(Fibonacci_Sequence_UDTF(6.0)) AS t";
    let stmt = parse_stmt_from_str(sql);
    assert!(
        stmt.is_some(),
        "Failed to parse TABLE() function with alias"
    );
}

#[test]
fn test_table_function_lateral() {
    let sql = "SELECT * FROM orders, LATERAL TABLE(get_order_items(orders.order_id))";
    let stmt = parse_stmt_from_str(sql);
    assert!(stmt.is_some(), "Failed to parse LATERAL TABLE() function");
}

/// The first table of the one SELECT `sql` parses to under `dialect`.
fn first_table(sql: &str, dialect: &dyn lexega_syntax::dialect::Dialect) -> AstTableRef {
    let script = parse_sql_with_dialect(sql, dialect).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{sql}: {:?}", script.stmts);
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT: {sql}");
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("not a table: {sql}");
    };
    (**table).clone()
}

#[test]
fn a_tsql_hint_list_written_without_with_is_the_tables_hints() {
    let mssql = lexega_syntax::dialect::mssql();
    let text = |sql: &str, span: Span| sql[span.start as usize..span.end as usize].to_string();
    for (sql, list) in [
        ("SELECT * FROM zz.dbo.t (NOLOCK) WHERE c = 1", "(NOLOCK)"),
        (
            "SELECT * FROM zz.dbo.t a (NOLOCK) WHERE a.c = 1",
            "(NOLOCK)",
        ),
        ("SELECT * FROM zz.dbo.t AS a (nolock)", "(nolock)"),
        (
            "SELECT * FROM zz.dbo.t (NOLOCK, ROWLOCK)",
            "(NOLOCK, ROWLOCK)",
        ),
    ] {
        let table = first_table(sql, &*mssql);
        assert_eq!(text(sql, table.name.span), "zz.dbo.t", "{sql}");
        assert_eq!(table.name.parts.as_ref().map(Vec::len), Some(3), "{sql}");
        let hints = table.table_hints.as_ref().expect("hints");
        assert!(
            matches!(hints.hints[0].kind, AstTableHintKind::NoLock),
            "{sql}"
        );
        assert_eq!(text(sql, hints.span), list, "{sql}");
        assert_eq!(hints.with_keyword_span, None, "{sql}");
    }
    let sql = "SELECT * FROM zz.dbo.t WITH (NOLOCK)";
    let hints = first_table(sql, &*mssql).table_hints.expect("hints");
    let with = hints.with_keyword_span.expect("WITH written");
    assert_eq!(text(sql, with), "WITH");
    assert_eq!(hints.span.start, with.start);
    // A call stays a call: an argument, a hint taken only after `WITH`, and
    // a dialect without table hints.
    let postgres = lexega_syntax::dialect::postgres();
    for (sql, dialect, call) in [
        ("SELECT * FROM dbo.fn(1) f", &*mssql, "dbo.fn(1)"),
        (
            "SELECT * FROM dbo.fn(HOLDLOCK) f",
            &*mssql,
            "dbo.fn(HOLDLOCK)",
        ),
        ("SELECT * FROM fn(nolock) f", &*postgres, "fn(nolock)"),
    ] {
        let table = first_table(sql, dialect);
        assert_eq!(text(sql, table.name.span), call, "{sql}");
        assert!(table.table_hints.is_none(), "{sql}");
    }
    // An INSERT's column list is no hint list.
    let sql = "INSERT INTO t (snapshot) VALUES (1)";
    let script = parse_sql_with_dialect(sql, &*mssql).expect("parses");
    let AstStmt::Insert(insert) = &script.stmts[0] else {
        panic!("not an INSERT");
    };
    assert!(insert.table_hints.is_none());
}

#[test]
fn a_table_functions_table_argument_is_read_as_a_table() {
    use lexega_syntax::ast::{AstExpr, AstFunctionArg};
    let text = |sql: &str, span: Span| sql[span.start as usize..span.end as usize].to_string();
    let bigquery = lexega_syntax::dialect::bigquery();
    let databricks = lexega_syntax::dialect::databricks();
    // (sql, dialect, the argument's text, its table, PARTITION BY, ORDER BY)
    let cases: [(
        &str,
        &dyn lexega_syntax::dialect::Dialect,
        &str,
        &str,
        usize,
        usize,
    ); 3] = [
        (
            "SELECT * FROM ML.PREDICT(MODEL d.m, TABLE d.t)",
            &*bigquery,
            "TABLE d.t",
            "d.t",
            0,
            0,
        ),
        (
            "SELECT * FROM my_udtf(TABLE(a.t))",
            &*databricks,
            "TABLE(a.t)",
            "a.t",
            0,
            0,
        ),
        (
            "SELECT * FROM my_udtf(TABLE(a.t) PARTITION BY k, LENGTH(j) ORDER BY o DESC)",
            &*databricks,
            "TABLE(a.t) PARTITION BY k, LENGTH(j) ORDER BY o DESC",
            "a.t",
            2,
            1,
        ),
    ];
    for (sql, dialect, arg_text, table, partitions, orders) in cases {
        let table_ref = first_table(sql, dialect);
        let Some(AstExpr::FunctionCall { args, .. }) = table_ref.table_function.as_deref() else {
            panic!("no call: {sql}");
        };
        let found = args.iter().find_map(|arg| match arg.as_ref() {
            AstFunctionArg::Table {
                table_keyword,
                name,
                partition_by,
                order_by,
                span,
            } => Some((
                table_keyword.map(|k| text(sql, k)),
                text(sql, name.span),
                partition_by.len(),
                order_by.len(),
                text(sql, *span),
            )),
            AstFunctionArg::Positional(_)
            | AstFunctionArg::Introduced { .. }
            | AstFunctionArg::Named { .. }
            | AstFunctionArg::Lambda { .. }
            | AstFunctionArg::AliasedArg { .. }
            | AstFunctionArg::BulkArg { .. }
            | AstFunctionArg::Unparsed { .. }
            | AstFunctionArg::DataType { .. }
            | AstFunctionArg::NonValue { .. } => None,
        });
        assert_eq!(
            found,
            Some((
                Some("TABLE".to_string()),
                table.to_string(),
                partitions,
                orders,
                arg_text.to_string()
            )),
            "{sql}"
        );
    }
    // A form outside the shape is kept as written.
    let sql = "SELECT * FROM my_udtf(TABLE(a.t) WITH SINGLE PARTITION ORDER BY o)";
    let table_ref = first_table(sql, &*databricks);
    let Some(AstExpr::FunctionCall { args, .. }) = table_ref.table_function.as_deref() else {
        panic!("no call: {sql}");
    };
    assert!(
        matches!(args[0].as_ref(), AstFunctionArg::Unparsed { .. }),
        "{sql}: {args:?}"
    );
}

#[test]
fn a_databricks_stream_reads_its_table() {
    let databricks = lexega_syntax::dialect::databricks();
    let text = |sql: &str, span: Span| sql[span.start as usize..span.end as usize].to_string();
    for (sql, stream, table, alias) in [
        (
            "SELECT * FROM STREAM(live.events_raw) e WHERE e.id = 1",
            "STREAM(live.events_raw)",
            "live.events_raw",
            Some("e"),
        ),
        (
            "SELECT * FROM STREAM ( a.t ) AS s",
            "STREAM ( a.t )",
            "a.t",
            Some("s"),
        ),
        ("SELECT * FROM stream a.t", "stream a.t", "a.t", None),
    ] {
        let table_ref = first_table(sql, &*databricks);
        assert_eq!(
            table_ref.stream_span.map(|s| text(sql, s)).as_deref(),
            Some(stream),
            "{sql}"
        );
        assert_eq!(text(sql, table_ref.name.span), table, "{sql}");
        assert!(table_ref.table_function.is_none(), "{sql}");
        assert_eq!(
            table_ref
                .alias
                .as_ref()
                .map(|a| text(sql, a.span))
                .as_deref(),
            alias,
            "{sql}"
        );
        let config = lexega_syntax::FormatterConfig {
            dialect: lexega_syntax::dialect::databricks(),
            ..Default::default()
        };
        let formatted = lexega_syntax::format_sql_with_config(sql, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &*databricks)
            .expect("formatting keeps the statement");
    }
    // A table named `stream`, and `STREAM(…)` where the dialect has no such read.
    let table_ref = first_table("SELECT * FROM stream WHERE id = 1", &*databricks);
    assert!(table_ref.stream_span.is_none());
    let snowflake = lexega_syntax::dialect::snowflake();
    let table_ref = first_table("SELECT * FROM STREAM(a.t)", &*snowflake);
    assert!(table_ref.stream_span.is_none());
}

#[test]
fn a_table_function_named_in_from_is_read_as_its_call() {
    use lexega_syntax::ast::{AstExpr, AstFunctionArg};
    let text = |sql: &str, span: Span| sql[span.start as usize..span.end as usize].to_string();
    // (sql, dialect, the call, the function's parts, each argument as text
    // with whether it is unparsed)
    let mssql = lexega_syntax::dialect::mssql();
    let bigquery = lexega_syntax::dialect::bigquery();
    let mysql = lexega_syntax::dialect::mysql();
    let postgres = lexega_syntax::dialect::postgres();
    type Case<'a> = (
        &'a str,
        &'a dyn lexega_syntax::dialect::Dialect,
        &'a str,
        usize,
        Vec<(&'a str, bool)>,
    );
    let cases: [Case<'_>; 4] = [
        (
            "SELECT * FROM dbo.fn(1, 'a') AS f",
            &*mssql,
            "dbo.fn(1, 'a')",
            2,
            vec![("1", false), ("'a'", false)],
        ),
        (
            "SELECT * FROM public.dblink('host=h', 'SELECT 1') AS t",
            &*postgres,
            "public.dblink('host=h', 'SELECT 1')",
            2,
            vec![("'host=h'", false), ("'SELECT 1'", false)],
        ),
        (
            "SELECT * FROM ML.PREDICT(MODEL d.m, TABLE d.t)",
            &*bigquery,
            "ML.PREDICT(MODEL d.m, TABLE d.t)",
            2,
            vec![("MODEL d.m", true), ("TABLE d.t", false)],
        ),
        (
            "SELECT j.a FROM JSON_TABLE(@doc, '$[*]' COLUMNS (a INT PATH '$.a')) AS j",
            &*mysql,
            "JSON_TABLE(@doc, '$[*]' COLUMNS (a INT PATH '$.a'))",
            1,
            vec![("@doc", false), ("'$[*]' COLUMNS (a INT PATH '$.a')", true)],
        ),
    ];
    for (sql, dialect, call, parts, args) in cases {
        let table = first_table(sql, dialect);
        assert_eq!(text(sql, table.name.span), call, "{sql}");
        assert_eq!(
            table.name.parts.as_ref().map(Vec::len),
            Some(parts),
            "{sql}"
        );
        let Some(AstExpr::FunctionCall { args: read, .. }) = table.table_function.as_deref() else {
            panic!("no call: {sql}");
        };
        let read: Vec<(String, bool)> = read
            .iter()
            .map(|arg| match arg.as_ref() {
                AstFunctionArg::Unparsed { span } => (text(sql, *span), true),
                AstFunctionArg::Positional(e) => (text(sql, e.span()), false),
                AstFunctionArg::Table { span, .. } => (text(sql, *span), false),
                other => panic!("{sql}: {other:?}"),
            })
            .collect();
        let expected: Vec<(String, bool)> = args.iter().map(|(a, u)| (a.to_string(), *u)).collect();
        assert_eq!(read, expected, "{sql}");
    }
    // An alias's column list names the call's columns; a list whose items
    // carry a type (PostgreSQL's column definition list) declares them. A
    // list that mixes the two is neither, and is not read.
    for (sql, columns, declared) in [
        (
            "SELECT * FROM dblink('host=h', 'SELECT 1, 2') AS t(a, b)",
            Some(vec!["a", "b"]),
            None,
        ),
        (
            "SELECT * FROM dblink('host=h', 'SELECT 1, 2') AS t(a int, b text)",
            None,
            Some(vec!["a", "b"]),
        ),
        (
            "SELECT * FROM json_to_record(t.j) AS x(a int)",
            None,
            Some(vec!["a"]),
        ),
        (
            "SELECT * FROM fn(1) AS f(a, b double precision)",
            None,
            None,
        ),
        (
            "SELECT * FROM generate_series(1, 3) AS g(v int)",
            None,
            Some(vec!["v"]),
        ),
    ] {
        let script = parse_sql_with_dialect(sql, &*postgres).expect("parses");
        let AstStmt::Select(select) = &script.stmts[0] else {
            panic!("not a SELECT: {sql}");
        };
        let FromItemKind::TableRef(table) = &select.from[0].kind else {
            panic!("not a table: {sql}");
        };
        let read = table
            .alias_columns
            .as_ref()
            .map(|cols| cols.iter().map(|c| text(sql, c.span)).collect::<Vec<_>>());
        let expected = columns.map(|cols| cols.iter().map(|c| c.to_string()).collect());
        assert_eq!(read, expected, "{sql}");
        let defined = table
            .column_definitions_span
            .and(table.table_function_columns.as_deref())
            .map(|cols| {
                cols.iter()
                    .map(|c| text(sql, c.name.span))
                    .collect::<Vec<_>>()
            });
        let declared_expected = declared.map(|cols| cols.iter().map(|c| c.to_string()).collect());
        assert_eq!(defined, declared_expected, "{sql}");
        assert_eq!(
            text(sql, table.alias.as_ref().expect("alias").span).len(),
            1
        );
        // An unread list is left after the statement, as text no statement reads.
        assert_eq!(
            script.stmts.len() == 1,
            read.is_some() || defined.is_some(),
            "{sql}"
        );
    }
    // Only a table function's call takes an argument in another grammar.
    assert!(
        parse_sql_with_dialect("SELECT f(MODEL d.m)", &*bigquery).map_or(true, |s| {
            !matches!(s.stmts.first(), Some(AstStmt::Select(_)))
        })
    );
}

/// The first table-valued function source of the one SELECT `sql` parses
/// to under `dialect`: a FROM item, or the right side of a join.
fn first_call(sql: &str, dialect: &dyn lexega_syntax::dialect::Dialect) -> AstTableRef {
    let script = parse_sql_with_dialect(sql, dialect).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{sql}: {:?}", script.stmts);
    let AstStmt::Select(select) = &script.stmts[0] else {
        panic!("not a SELECT: {sql}");
    };
    select
        .from
        .iter()
        .filter_map(|item| {
            if let FromItemKind::TableRef(table) = &item.kind {
                Some(table)
            } else {
                None
            }
        })
        .flat_map(|table| {
            std::iter::once((**table).clone())
                .chain(table.joins.iter().map(|join| (*join.right).clone()))
        })
        .find(|table| table.table_function.is_some())
        .unwrap_or_else(|| panic!("no call: {sql}"))
}

#[test]
fn a_table_functions_declared_columns_are_read() {
    let text = |sql: &str, span: Span| sql[span.start as usize..span.end as usize].to_string();
    let mssql = lexega_syntax::dialect::mssql();
    let mysql = lexega_syntax::dialect::mysql();
    let postgres = lexega_syntax::dialect::postgres();
    // (sql, dialect, each column: name, kind, type, path)
    type Case<'a> = (
        &'a str,
        &'a dyn lexega_syntax::dialect::Dialect,
        &'a [(&'a str, &'a str, &'a str, &'a str)],
    );
    let cases: [Case<'_>; 7] = [
        (
            "SELECT a FROM t CROSS APPLY OPENJSON(t.c) WITH (a INT '$.a', b NVARCHAR(MAX) AS JSON) j",
            &*mssql,
            &[
                ("a", "value", "INT", "'$.a'"),
                ("b", "json", "NVARCHAR", ""),
            ],
        ),
        (
            "SELECT a FROM OPENJSON(@j) WITH ([Order] NVARCHAR(100) 'strict $.o', a int, \
             o NVARCHAR(MAX) '$.o' AS JSON)",
            &*mssql,
            &[
                ("[Order]", "value", "NVARCHAR", "'strict $.o'"),
                ("a", "value", "int", ""),
                ("o", "json", "NVARCHAR", "'$.o'"),
            ],
        ),
        (
            "SELECT a FROM t, JSON_TABLE(t.c, '$[*]' COLUMNS (a INT PATH '$')) AS j",
            &*mysql,
            &[("a", "value", "INT", "'$'")],
        ),
        (
            "SELECT * FROM t, JSON_TABLE(t.c, '$[*]' COLUMNS (id FOR ORDINALITY, \
             a VARCHAR(10) PATH '$.a' NULL ON EMPTY DEFAULT '0' ON ERROR, \
             e INT EXISTS PATH '$.e', \
             NESTED PATH '$.n[*]' COLUMNS (x INT PATH '$'))) AS j",
            &*mysql,
            &[
                ("id", "ordinality", "", ""),
                ("a", "value", "VARCHAR", "'$.a'"),
                ("e", "exists", "INT", "'$.e'"),
                ("x", "value", "INT", "'$'"),
            ],
        ),
        (
            "SELECT * FROM t, JSON_TABLE(t.c, '$[*]' COLUMNS (NESTED '$.n' COLUMNS (x INT PATH '$'), y INT PATH '$.y')) j",
            &*mysql,
            &[("x", "value", "INT", "'$'"), ("y", "value", "INT", "'$.y'")],
        ),
        (
            "SELECT * FROM t, JSON_TABLE(t.c, '$[*]' COLUMNS (a int PATH '$.a', b text FORMAT JSON PATH '$.b', \
             e boolean EXISTS)) j",
            &*postgres,
            &[
                ("a", "value", "int", "'$.a'"),
                ("b", "json", "text", "'$.b'"),
                ("e", "exists", "boolean", ""),
            ],
        ),
        (
            "SELECT * FROM t, JSON_TABLE(t.c, '$[*]' AS p COLUMNS (a int PATH '$')) j",
            &*postgres,
            &[("a", "value", "int", "'$'")],
        ),
    ];
    for (sql, dialect, expected) in cases {
        let table = first_call(sql, dialect);
        let columns = table.table_function_columns.as_deref().expect("declared");
        let found: Vec<(String, String, String, String)> = columns
            .iter()
            .map(|column| {
                use lexega_syntax::ast::AstTableFunctionColumnKind as Kind;
                let (kind, typed) = match &column.kind {
                    Kind::Value { data_type, path } => ("value", Some((data_type, path))),
                    Kind::Json { data_type, path } => ("json", Some((data_type, path))),
                    Kind::Exists { data_type, path } => ("exists", Some((data_type, path))),
                    Kind::Ordinality => ("ordinality", None),
                };
                // The type's name and the path.
                let (data_type, path) =
                    typed.map_or((String::new(), String::new()), |(t, path)| {
                        let name = match t {
                            lexega_syntax::ast::AstDataType::Simple { name_span }
                            | lexega_syntax::ast::AstDataType::WithPrecision {
                                name_span, ..
                            }
                            | lexega_syntax::ast::AstDataType::WithPrecisionScale {
                                name_span,
                                ..
                            } => text(sql, *name_span),
                            lexega_syntax::ast::AstDataType::Parameterized { span, .. }
                            | lexega_syntax::ast::AstDataType::CompoundInterval { span, .. } => {
                                text(sql, *span)
                            }
                        };
                        (name, path.map_or(String::new(), |path| text(sql, path)))
                    });
                (
                    text(sql, column.name.span),
                    kind.to_string(),
                    data_type,
                    path,
                )
            })
            .collect();
        let expected: Vec<(String, String, String, String)> = expected
            .iter()
            .map(|(n, k, t, p)| (n.to_string(), k.to_string(), t.to_string(), p.to_string()))
            .collect();
        assert_eq!(found, expected, "{sql}");
    }
    // A call declaring no columns, and a list in a grammar not read.
    for (sql, dialect) in [
        (
            "SELECT * FROM t CROSS APPLY OPENJSON(t.c) j",
            &*mssql as &dyn lexega_syntax::dialect::Dialect,
        ),
        ("SELECT * FROM t CROSS APPLY dbo.fn(t.c) f", &*mssql),
        (
            "SELECT * FROM t, JSON_TABLE(t.c, '$[*]' COLUMNS (a)) j",
            &*mysql,
        ),
        (
            "SELECT * FROM t, JSON_TABLE(t.c, '$[*]' COLUMNS (a int PATH '$') ERROR ON ERROR) j",
            &*postgres,
        ),
        (
            "SELECT * FROM t CROSS APPLY OPENJSON(t.c) WITH (a INT, 'b' INT, c INT) j",
            &*mssql,
        ),
    ] {
        let table = first_call(sql, dialect);
        assert!(table.table_function_columns.is_none(), "{sql}");
    }
}

#[test]
fn an_openrowset_data_source_user_and_password_run_is_one_argument() {
    use lexega_syntax::ast::{AstExpr, AstFunctionArg};
    let mssql = lexega_syntax::dialect::mssql();
    for (sql, run) in [
        (
            "SELECT a.* FROM OPENROWSET('MSDASQL', 's';'u';'pw', 'SELECT 1') AS a",
            "'s';'u';'pw'",
        ),
        (
            "SELECT a.* FROM OPENROWSET('MSDASQL', 's' ; 'u' ; N'pw', 'SELECT 1') AS a",
            "'s' ; 'u' ; N'pw'",
        ),
    ] {
        let table = first_call(sql, &*mssql);
        let Some(AstExpr::FunctionCall { args, .. }) = table.table_function.as_deref() else {
            panic!("no call: {sql}");
        };
        let texts: Vec<&str> = args
            .iter()
            .map(|arg| match arg.as_ref() {
                AstFunctionArg::Unparsed { span } => &sql[span.start as usize..span.end as usize],
                AstFunctionArg::Positional(value) => {
                    &sql[value.span().start as usize..value.span().end as usize]
                }
                other => panic!("unexpected argument: {other:?}"),
            })
            .collect();
        assert_eq!(texts, ["'MSDASQL'", run, "'SELECT 1'"], "{sql}");
    }
}
