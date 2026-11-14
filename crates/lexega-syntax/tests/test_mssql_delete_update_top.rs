// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL DELETE TOP / UPDATE TOP support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
///
/// Covers:
///   - DELETE TOP (n) FROM table
///   - DELETE TOP (n) PERCENT FROM table
///   - DELETE TOP n FROM table (bare number)
///   - UPDATE TOP (n) table SET ...
///   - UPDATE TOP (n) PERCENT table SET ...
///   - UPDATE TOP n table SET ... (bare number)
///   - Multi-statement scripts
///   - SELECT TOP still works (regression)
use lexega_syntax::ast::AstStmt;
use lexega_syntax::dialect::mssql;
use lexega_syntax::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

// ============================================================================
// Helpers
// ============================================================================

fn mssql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: mssql(),
        ..Default::default()
    }
}

fn parse_mssql(sql: &str) -> Vec<AstStmt> {
    let dialect = mssql();
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    script.stmts
}

fn ast_variant_name(stmt: &AstStmt) -> &'static str {
    match stmt {
        AstStmt::Delete(_) => "Delete",
        AstStmt::Update(_) => "Update",
        AstStmt::Select(_) => "Select",
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

fn format_and_verify(sql: &str) {
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for MSSQL: {}\nSQL: {}", e, sql));

    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
}

// ============================================================================
// DELETE TOP
// ============================================================================

#[test]
fn test_delete_top_parenthesized() {
    let sql = "DELETE TOP (10) FROM dbo.MyTable WHERE Status = 'old';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_delete_top_percent() {
    let sql = "DELETE TOP (10) PERCENT FROM dbo.MyTable WHERE Active = 0;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_delete_top_bare_number() {
    let sql = "DELETE TOP 5 FROM MyTable;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_delete_top_no_where() {
    let sql = "DELETE TOP (100) FROM staging.temp_data;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

// ============================================================================
// UPDATE TOP
// ============================================================================

#[test]
fn test_update_top_parenthesized() {
    let sql = "UPDATE TOP (10) dbo.MyTable SET Status = 'active' WHERE Id > 100;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

#[test]
fn test_update_top_percent() {
    let sql = "UPDATE TOP (25) PERCENT dbo.Employees SET Bonus = 500;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

#[test]
fn test_update_top_bare_number() {
    let sql = "UPDATE TOP 5 MyTable SET col1 = 1;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

#[test]
fn test_update_top_with_from_join() {
    let sql = "UPDATE TOP (10) t SET t.Status = 'done' FROM dbo.Tasks t JOIN dbo.Projects p ON t.ProjectId = p.Id WHERE p.Active = 1;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

// ============================================================================
// Multi-statement
// ============================================================================

#[test]
fn test_multi_statement_top() {
    let sql = "\
DELETE TOP (10) FROM dbo.OldData;
UPDATE TOP (5) dbo.Records SET Processed = 1;
SELECT TOP 3 * FROM dbo.Results;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Expected 3 statements");
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    assert_eq!(ast_variant_name(&stmts[1]), "Update");
    assert_eq!(ast_variant_name(&stmts[2]), "Select");
    format_and_verify(sql);
}

// ============================================================================
// SELECT TOP still parses alongside DELETE/UPDATE TOP
// ============================================================================

#[test]
fn test_select_top_still_works() {
    let sql = "SELECT TOP 10 * FROM MyTable;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Select");
    format_and_verify(sql);
}

#[test]
fn test_select_top_percent_with_ties() {
    let sql = "SELECT TOP 10 PERCENT WITH TIES col1 FROM MyTable ORDER BY col1;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Select");
    format_and_verify(sql);
}

#[test]
fn test_select_top_parenthesized() {
    let sql = "SELECT TOP (5) a, b FROM t;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Select");
    format_and_verify(sql);
}

// ============================================================================
// Mixed case
// ============================================================================

#[test]
fn test_delete_top_mixed_case() {
    let sql = "delete top (10) from MyTable where id > 5;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_update_top_mixed_case() {
    let sql = "update Top (3) MyTable set col1 = 'x';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

// ============================================================================
// OPTION (…) query hints
// ============================================================================

// A DELETE, UPDATE or MERGE ends after its `OPTION (…)` hints, which are
// kept as written and printed back unchanged.
#[test]
fn dml_option_hints_belong_to_their_statement() {
    let text = |sql: &str, span: lexega_syntax::lexer::Span| {
        sql[span.start as usize..span.end as usize].to_string()
    };
    for (sql, hints) in [
        ("DELETE FROM users OPTION (MAXDOP 1)", vec!["OPTION (MAXDOP 1)"]),
        (
            "DELETE FROM users WHERE id = 1 OPTION (MAXDOP 1, RECOMPILE);",
            vec!["OPTION (MAXDOP 1, RECOMPILE)"],
        ),
        ("UPDATE users SET a = 1 OPTION (RECOMPILE)", vec!["OPTION (RECOMPILE)"]),
        (
            "UPDATE u SET a = 1 FROM users u JOIN orders o ON o.id = u.id OPTION (RECOMPILE)",
            vec!["OPTION (RECOMPILE)"],
        ),
        (
            "MERGE users AS t USING orders AS s ON t.id = s.id WHEN MATCHED THEN DELETE OPTION (MAXDOP 1);",
            vec!["OPTION (MAXDOP 1)"],
        ),
    ] {
        let stmts = parse_mssql(sql);
        assert_eq!(stmts.len(), 1, "{sql}");
        let (span, clauses) = match &stmts[0] {
            AstStmt::Delete(d) => (d.span, &d.option_clauses),
            AstStmt::Update(u) => (u.span, &u.option_clauses),
            AstStmt::Merge(m) => (m.span, &m.option_clauses),
            other => panic!("{sql}: {other:?}"),
        };
        let read: Vec<String> = clauses.iter().map(|c| text(sql, c.span)).collect();
        assert_eq!(read, hints, "{sql}");
        assert_eq!(span.end, clauses.last().map_or(0, |c| c.span.end), "{sql}");

        format_and_verify(sql);
        let formatted = format_sql_with_config(sql, &mssql_config()).expect("formats");
        for hint in &hints {
            assert!(formatted.contains(hint), "{sql}\n{formatted}");
        }
        let again = format_sql_with_config(&formatted, &mssql_config()).expect("formats");
        assert_eq!(again, formatted, "{sql}");
    }
}

// An OUTPUT clause is printed where T-SQL writes it: after an UPDATE's SET,
// after a DELETE's target, before an INSERT's source, after a MERGE's WHEN
// clauses; the statement ends with its last clause.
#[test]
fn an_output_clause_formats_where_it_is_written() {
    for sql in [
        "DELETE dbo.Orders OUTPUT deleted.Id WHERE Id = 1;",
        "DELETE dbo.Orders WHERE Id = 1;",
        "DELETE FROM dbo.Orders OUTPUT deleted.Id WHERE Id = 1;",
        "DELETE FROM dbo.Orders OUTPUT deleted.Id INTO dbo.Log (Id) WHERE Id = 1;",
        "DELETE FROM dbo.Orders OUTPUT deleted.Id INTO @t WHERE Id = 1;",
        "DELETE FROM o OUTPUT deleted.Id FROM dbo.Orders o JOIN stg.S s ON s.Id = o.Id;",
        "DELETE o OUTPUT deleted.Id FROM dbo.Orders o JOIN stg.S s ON s.Id = o.Id;",
        "DELETE TOP (10) FROM dbo.Orders OUTPUT deleted.* WHERE Id > 1;",
        "DELETE FROM dbo.Orders WITH (TABLOCK) OUTPUT deleted.Id WHERE Id = 1;",
        "DELETE FROM dbo.Orders OUTPUT deleted.Id WHERE Id = 1 OPTION (MAXDOP 1);",
        "UPDATE dbo.Orders SET Status = 1 OUTPUT inserted.Id WHERE Id = 1;",
        "UPDATE dbo.Orders SET Status = 1 OUTPUT inserted.Id, deleted.Status INTO @t WHERE Id = 1;",
        "UPDATE o SET Status = 1 OUTPUT inserted.Id FROM dbo.Orders o JOIN stg.S s ON s.Id = o.Id WHERE s.Flag = 1;",
        "UPDATE TOP (5) dbo.Orders SET Status = 1 OUTPUT inserted.Id;",
        "INSERT INTO dbo.Orders (Id) OUTPUT inserted.Id VALUES (1);",
        "INSERT INTO dbo.Orders (Id) OUTPUT inserted.Id INTO @t SELECT Id FROM stg.S;",
        "MERGE dbo.Orders AS t USING stg.S AS s ON t.Id = s.Id WHEN MATCHED THEN DELETE OUTPUT $action, deleted.Id;",
        "MERGE dbo.Orders AS t USING stg.S AS s ON t.Id = s.Id WHEN MATCHED THEN DELETE OUTPUT deleted.Id INTO @t;",
        "DELETE FROM dbo.Orders OUTPUT deleted.* INTO @t OUTPUT deleted.Id WHERE Id = 1;",
        "UPDATE o SET Status = 1 OUTPUT inserted.* INTO @t OUTPUT inserted.Id FROM dbo.Orders o WHERE o.Id = 1;",
        "INSERT INTO dbo.Orders (Id) OUTPUT inserted.Id INTO @a OUTPUT inserted.Id VALUES (1);",
        "MERGE dbo.Orders AS t USING stg.S AS s ON t.Id = s.Id WHEN MATCHED THEN DELETE OUTPUT deleted.Id INTO @a OUTPUT deleted.Id;",
    ] {
        let stmts = parse_mssql(sql);
        assert_eq!(stmts.len(), 1, "{sql}");
        let span = stmts[0].span();
        assert_eq!(
            &sql[span.start as usize..span.end as usize],
            sql.trim_end_matches(';'),
            "{sql}"
        );
        format_and_verify(sql);
        let formatted = format_sql_with_config(sql, &mssql_config()).expect("formats");
        let again = format_sql_with_config(&formatted, &mssql_config()).expect("formats");
        assert_eq!(again, formatted, "{sql}");
    }
}

// A join hint in a join or in a query's `OPTION (…)` is read as one, in every
// statement that joins, and the statement is printed back as written.
#[test]
fn join_hints_are_read_in_joins_and_query_options() {
    use lexega_syntax::ast::{AstJoinHintKind, AstQueryHintKind, AstQueryOptions};
    let options_of = |stmt: &AstStmt| -> Vec<AstQueryOptions> {
        match stmt {
            AstStmt::Select(s) => s.post_locking_extension_clauses.to_vec(),
            AstStmt::Delete(d) => d.option_clauses.clone(),
            AstStmt::Update(u) => u.option_clauses.clone(),
            AstStmt::Merge(m) => m.option_clauses.clone(),
            other => panic!("{other:?}"),
        }
    };
    for (sql, join_hints) in [
        (
            "SELECT s.c FROM dbo.S s JOIN dbo.T t ON t.id = s.id OPTION (HASH JOIN);",
            vec![AstJoinHintKind::Hash],
        ),
        (
            "SELECT s.c FROM dbo.S s JOIN dbo.T t ON t.id = s.id OPTION (LOOP JOIN, MERGE JOIN);",
            vec![AstJoinHintKind::Loop, AstJoinHintKind::Merge],
        ),
        (
            "SELECT s.c FROM dbo.S s JOIN dbo.T t ON t.id = s.id OPTION (MERGE JOIN, FORCE ORDER, MAXDOP 1);",
            vec![AstJoinHintKind::Merge],
        ),
        (
            "SELECT s.c FROM dbo.S s INNER HASH JOIN dbo.T t ON t.id = s.id OPTION (RECOMPILE);",
            vec![],
        ),
        (
            "UPDATE t SET a = 1 FROM dbo.t t INNER HASH JOIN dbo.s s ON s.id = t.id WHERE t.k = 1;",
            vec![],
        ),
        (
            "DELETE t FROM dbo.t t INNER LOOP JOIN dbo.s s ON s.id = t.id WHERE t.k = 1;",
            vec![],
        ),
        (
            "UPDATE t SET a = 1 FROM dbo.t t INNER HASH JOIN dbo.s s ON s.id = t.id OPTION (hash join);",
            vec![AstJoinHintKind::Hash],
        ),
        (
            "DELETE t FROM dbo.t t INNER LOOP JOIN dbo.s s ON s.id = t.id OPTION (LOOP JOIN, MAXDOP 2);",
            vec![AstJoinHintKind::Loop],
        ),
        (
            "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER MERGE JOIN dbo.T t ON t.id = s.id) v;",
            vec![],
        ),
        (
            "UPDATE dbo.E SET x = 1 FROM (SELECT s.id FROM dbo.S s LEFT OUTER LOOP JOIN dbo.T t ON t.id = s.id) v;",
            vec![],
        ),
        (
            "MERGE dbo.Orders AS t USING (SELECT s.Id FROM stg.S s INNER LOOP JOIN stg.U u ON u.Id = s.Id) AS s ON t.Id = s.Id WHEN MATCHED THEN DELETE OPTION (LOOP JOIN);",
            vec![AstJoinHintKind::Loop],
        ),
    ] {
        let stmts = parse_mssql(sql);
        assert_eq!(stmts.len(), 1, "{sql}: {stmts:?}");
        let read: Vec<AstJoinHintKind> = options_of(&stmts[0])
            .iter()
            .flat_map(|options| &options.hints)
            .filter_map(|hint| match hint.kind {
                AstQueryHintKind::Join(kind) => Some(kind),
                AstQueryHintKind::Other => None,
            })
            .collect();
        assert_eq!(read, join_hints, "{sql}");
        format_and_verify(sql);
        let formatted = format_sql_with_config(sql, &mssql_config()).expect("formats");
        let again = format_sql_with_config(&formatted, &mssql_config()).expect("formats");
        assert_eq!(again, formatted, "{sql}");
    }
    for sql in [
        "INSERT INTO dbo.X (c) SELECT s.c FROM dbo.S s INNER HASH JOIN dbo.T t ON t.id = s.id OPTION (HASH JOIN);",
        "WITH c AS (SELECT s.c FROM dbo.S s INNER HASH JOIN dbo.T t ON t.id = s.id) SELECT * FROM c OPTION (HASH JOIN);",
    ] {
        let stmts = parse_mssql(sql);
        assert_eq!(stmts.len(), 1, "{sql}: {stmts:?}");
        assert!(
            !matches!(stmts[0], AstStmt::OpaqueContent { .. }),
            "{sql}: {:?}",
            stmts[0]
        );
        format_and_verify(sql);
    }
}
