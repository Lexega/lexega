// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql, parse_sql, parse_stmt_from_str};

#[test]
fn test_group_by_all() {
    let sql = "SELECT name, COUNT(*) FROM users GROUP BY ALL";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY ALL");

    // Should also format correctly
    let formatted = format_sql(sql);
    assert!(formatted.is_ok());
}

#[test]
fn test_group_by_cube_simple() {
    let sql = "SELECT state, city, SUM(profit) FROM sales GROUP BY CUBE(state, city)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY CUBE");
}

#[test]
fn test_group_by_rollup_simple() {
    let sql = "SELECT state, city, SUM(profit) FROM sales GROUP BY ROLLUP(state, city)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY ROLLUP");
}

#[test]
fn test_group_by_grouping_sets_simple() {
    let sql = "SELECT medical_license, radio_license, COUNT(*) FROM nurses GROUP BY GROUPING SETS(medical_license, radio_license)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY GROUPING SETS");
}

#[test]
fn test_group_by_grouping_sets_nested() {
    let sql = "SELECT a, b, c, COUNT(*) FROM t GROUP BY GROUPING SETS((a, b), (c), ())";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY GROUPING SETS with nested groups"
    );
}

#[test]
fn test_group_by_position_ref() {
    let sql = "SELECT name, age, COUNT(*) FROM users GROUP BY 1, 2";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY with positional references"
    );
}

#[test]
fn test_group_by_mixed() {
    let sql = "SELECT name, age, COUNT(*) FROM users GROUP BY name, 2";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY with mixed column and position"
    );
}

#[test]
fn test_group_by_cube_max_elements() {
    // 7 elements is the max for CUBE (generates 128 grouping sets)
    let sql = "SELECT a, b, c, d, e, f, g, COUNT(*) FROM t GROUP BY CUBE(a, b, c, d, e, f, g)";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY CUBE with 7 elements"
    );
}

#[test]
fn test_group_by_cube_too_many_elements() {
    // Parser should accept CUBE with any number of elements
    // Snowflake will reject this at runtime (max 7 elements), but that's not the parser's job
    let sql =
        "SELECT a, b, c, d, e, f, g, h, COUNT(*) FROM t GROUP BY CUBE(a, b, c, d, e, f, g, h)";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Parser should accept CUBE with 8 elements (Snowflake runtime will validate)"
    );
}

#[test]
fn test_group_by_grouping_sets_max() {
    // Generate SQL with exactly 128 grouping sets
    let mut sets = Vec::new();
    for i in 0..128 {
        sets.push(format!("(col{})", i));
    }
    let sql = format!(
        "SELECT COUNT(*) FROM t GROUP BY GROUPING SETS({})",
        sets.join(", ")
    );
    let result = parse_stmt_from_str(&sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY GROUPING SETS with 128 sets"
    );
}

#[test]
fn test_group_by_grouping_sets_too_many() {
    // Parser should accept GROUPING SETS with any number of sets
    // Snowflake will reject this at runtime (max 128 sets), but that's not the parser's job
    let mut sets = vec![];
    for i in 0..129 {
        sets.push(format!("(col{})", i));
    }
    let sql = format!(
        "SELECT COUNT(*) FROM t GROUP BY GROUPING SETS({})",
        sets.join(", ")
    );

    let result = parse_sql(&sql);
    assert!(
        result.is_ok(),
        "Parser should accept GROUPING SETS with 129 sets (Snowflake runtime will validate)"
    );
}

#[test]
fn test_group_by_standard() {
    let sql = "SELECT name, age, COUNT(*) FROM users GROUP BY name, age";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse standard GROUP BY");
}

#[test]
fn test_group_by_with_having() {
    let sql = "SELECT name, COUNT(*) FROM users GROUP BY name HAVING COUNT(*) > 5";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY with HAVING");
}

#[test]
fn test_group_by_cube_with_having() {
    let sql = "SELECT state, city, SUM(profit) FROM sales GROUP BY CUBE(state, city) HAVING SUM(profit) > 1000";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY CUBE with HAVING");
}

#[test]
fn test_group_by_all_with_order() {
    let sql = "SELECT name, COUNT(*) FROM users GROUP BY ALL ORDER BY COUNT(*) DESC";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY ALL with ORDER BY");
}

#[test]
fn test_group_by_expression() {
    let sql = "SELECT YEAR(created_at), COUNT(*) FROM users GROUP BY YEAR(created_at)";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Should parse GROUP BY with expression");
}

/// A GROUP BY key may be a constant or an ODBC escape: the statement is read
/// whole, none of it skipped.
#[test]
fn test_group_by_literal_and_odbc_escape_keys() {
    use lexega_syntax::{dialect, parse_sql_with_dialect, AstStmt};
    for (dialect, sql) in [
        (dialect::snowflake(), "SELECT 'x' AS v, COUNT(*) AS n FROM u GROUP BY 'x'"),
        (dialect::snowflake(), "SELECT TRUE AS v, COUNT(*) AS n FROM u GROUP BY TRUE"),
        (
            dialect::mssql(),
            "SELECT {fn CONVERT(email, SQL_VARCHAR)} AS k, COUNT(*) AS n FROM u GROUP BY {fn CONVERT(email, SQL_VARCHAR)}",
        ),
    ] {
        let script = parse_sql_with_dialect(sql, &*dialect).expect("parses");
        assert_eq!(script.stmts.len(), 1, "{sql}");
        assert!(
            !matches!(script.stmts[0], AstStmt::OpaqueContent { .. }),
            "{sql}: {:?}",
            script.stmts[0]
        );
    }
}

#[test]
fn test_group_by_case_expression() {
    let sql = "SELECT CASE WHEN age < 18 THEN 'minor' ELSE 'adult' END, COUNT(*) FROM users GROUP BY CASE WHEN age < 18 THEN 'minor' ELSE 'adult' END";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Should parse GROUP BY with CASE expression"
    );
}

/// The kinds of the statements `sql` parses into under `dialect`.
fn statement_kinds(sql: &str, dialect: lexega_syntax::dialect::DialectRef) -> Vec<&'static str> {
    use lexega_syntax::ast::AstStmt;
    let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
    script
        .stmts
        .iter()
        .map(|stmt| {
            if matches!(stmt, AstStmt::Select(_)) {
                "select"
            } else if matches!(stmt, AstStmt::Update(_)) {
                "update"
            } else if matches!(stmt, AstStmt::Delete(_)) {
                "delete"
            } else if matches!(stmt, AstStmt::OpaqueContent { .. } | AstStmt::Error { .. }) {
                "unparsed"
            } else {
                "other"
            }
        })
        .collect()
}

// `GROUP BY ()`, the empty grouping set, groups every row into one group.
#[test]
fn the_empty_grouping_set_parses_and_formats_as_written() {
    use lexega_syntax::dialect;
    for sql in [
        "SELECT COUNT(*) FROM t GROUP BY ()",
        "SELECT COUNT(*) FROM t GROUP BY ();",
        "SELECT a, COUNT(*) FROM t GROUP BY a, ()",
        "SELECT a, COUNT(*) FROM t GROUP BY ROLLUP(a), ()",
        "SELECT m FROM (SELECT MAX(c) AS m FROM s GROUP BY ( )) v",
        "SELECT COUNT(*) FROM t GROUP BY () HAVING COUNT(*) > 1",
    ] {
        for dialect in [
            dialect::mssql(),
            dialect::postgres(),
            dialect::redshift(),
            dialect::snowflake(),
            dialect::bigquery(),
            dialect::databricks(),
            dialect::mysql(),
        ] {
            assert_eq!(
                statement_kinds(sql, dialect.clone()),
                vec!["select"],
                "{sql}"
            );
            let config = lexega_syntax::FormatterConfig {
                dialect: dialect.clone(),
                ..Default::default()
            };
            let formatted = lexega_syntax::format_sql_with_config(sql, &config)
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
                .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
            let again = lexega_syntax::format_sql_with_config(&formatted, &config)
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            assert_eq!(again, formatted, "{sql}");
        }
    }
}

// A grouping set written bare is printed bare, one in parentheses in them.
#[test]
fn grouping_sets_format_as_written() {
    use lexega_syntax::dialect;
    for sql in [
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS (a, ());",
        "SELECT a, b, COUNT(*) FROM t GROUP BY GROUPING SETS (a, b);",
        "SELECT a, b, COUNT(*) FROM t GROUP BY GROUPING SETS ((a), b, (a, b), ());",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS ((a), ());",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS ( /* c */ a , ( b ) );",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS ( /* c */ (a), ());",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS ((a) /* c */, ());",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS (( /* c */ a), ( /* d */ ));",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS (a /* c */, b);",
        "SELECT a + 1, COUNT(*) FROM t GROUP BY GROUPING SETS (a + 1, (a + 1));",
        "SELECT a, COUNT(*) FROM t GROUP BY a, GROUPING SETS (b, (c));",
        "SELECT a, b, COUNT(*) FROM t GROUP BY GROUPING SETS (a, b) /* x */;",
        "SELECT a, COUNT(*) FROM t GROUP BY CUBE (a) /* x */;",
        "SELECT a, COUNT(*) FROM t GROUP BY ROLLUP (a) /* x */;",
        "SELECT a, COUNT(*) FROM t GROUP BY ROLLUP (a) /* x */ HAVING COUNT(*) > 1;",
        "SELECT a, COUNT(*) FROM t GROUP BY CUBE (a, b) /* x */ ORDER BY a;",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS /* y */ ((a), ()) /* x */ ORDER BY a;",
        "SELECT a, COUNT(*) FROM t GROUP BY ROLLUP /* y */ (a, b), c;",
        "SELECT a, COUNT(*) FROM t GROUP BY GROUPING SETS (ROLLUP (a) /* r */, CUBE (b) /* c */) /* x */;",
        "SELECT a, COUNT(*) FROM t GROUP BY CUBE ( /* c */ a /* d */ );",
    ] {
        for dialect in [
            dialect::mssql(),
            dialect::postgres(),
            dialect::redshift(),
            dialect::snowflake(),
            dialect::bigquery(),
            dialect::databricks(),
            dialect::mysql(),
        ] {
            assert_eq!(
                statement_kinds(sql, dialect.clone()),
                vec!["select"],
                "{sql}"
            );
            let config = lexega_syntax::FormatterConfig {
                dialect: dialect.clone(),
                ..Default::default()
            };
            let formatted = lexega_syntax::format_sql_with_config(sql, &config)
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
                .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
            let again = lexega_syntax::format_sql_with_config(&formatted, &config)
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            assert_eq!(again, formatted, "{sql}");
        }
    }
}

// After an opening parenthesis never closed, what does not parse ends at a
// `;` any statement follows, and at a T-SQL batch separator at any depth:
// the statements after it are read.
#[test]
fn an_unparsed_statement_ends_where_a_statement_or_a_batch_starts() {
    use lexega_syntax::dialect::{mssql, postgres, snowflake};
    for (sql, dialect, kinds) in [
        (
            "SELECT COUNT(* FROM dbo.t;\nGRANT CONTROL ON SCHEMA::dbo TO public;\nDELETE FROM dbo.z;",
            mssql(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t;\nEXEC dbo.p;\nDELETE FROM dbo.z;",
            mssql(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t;\nEXECUTE dbo.p;\nDELETE FROM dbo.z;",
            mssql(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t;\nWITH c AS (SELECT * FROM dbo.Orders) SELECT * FROM c;\nDELETE FROM dbo.z;",
            mssql(),
            vec!["unparsed", "select", "delete"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t;\nSET @x = 2;\nDELETE FROM dbo.z;",
            mssql(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t;\nGO\nUPDATE dbo.mid SET a = 1;",
            mssql(),
            vec!["unparsed", "other", "update"],
        ),
        (
            "SELECT a FROM dbo.t WHERE a IN (1, 2;\nGO\nUPDATE dbo.mid SET a = 1;\nGO",
            mssql(),
            vec!["unparsed", "other", "update", "other"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t\nGO\nUPDATE dbo.mid SET a = 1\nGO",
            mssql(),
            vec!["unparsed", "other", "update", "other"],
        ),
        (
            "SELECT COUNT(* FROM dbo.t\nUPDATE dbo.s1 SET a = 1\nGO\nDELETE FROM dbo.s2",
            mssql(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM t;\nWITH d AS (DELETE FROM q RETURNING *) SELECT * FROM d;\nDELETE FROM z;",
            postgres(),
            vec!["unparsed", "select", "delete"],
        ),
        (
            "SELECT COUNT(* FROM t;\nCALL p();\nDELETE FROM z;",
            postgres(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM t;\nEXECUTE IMMEDIATE 'DELETE FROM q';\nDELETE FROM z;",
            snowflake(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM t;\nCOPY INTO t FROM @s;\nDELETE FROM z;",
            snowflake(),
            vec!["unparsed", "other", "delete"],
        ),
        (
            "SELECT COUNT(* FROM t;\nGRANT SELECT ON t TO ROLE r;\nDELETE FROM z;",
            snowflake(),
            vec!["unparsed", "other", "delete"],
        ),
    ] {
        assert_eq!(statement_kinds(sql, dialect), kinds, "{sql}");
    }
    // Text after a `;` that starts no statement stays in the skip.
    assert_eq!(
        statement_kinds("SELECT COUNT(* FROM t; junk;\nDELETE FROM z;", snowflake()),
        vec!["unparsed", "delete"]
    );
}

// What does not parse ends at its statement's `;`: the statements after it
// are read.
#[test]
fn an_unparsed_statement_ends_at_its_semicolon() {
    let mssql = lexega_syntax::dialect::mssql;
    assert_eq!(
        statement_kinds(
            "UPDATE e SET x = v.m FROM dbo.E e CROSS APPLY (SELECT MAX(s.c) AS m FROM dbo.S s WHERE s.Id = e.Id GROUP BY ()) v;\nUPDATE dbo.T SET a = 1;\nDELETE FROM dbo.T;",
            mssql()
        ),
        vec!["update", "update", "delete"]
    );
    // A FROM list that does not parse leaves its UPDATE unparsed, to the `;`.
    assert_eq!(
        statement_kinds(
            "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT 1 AS one FROM dbo.S WHERE ) v;\nDELETE FROM dbo.T;",
            mssql()
        ),
        vec!["unparsed", "delete"]
    );
    // A stray closing parenthesis opens no nesting.
    assert_eq!(
        statement_kinds("SELECT 1;\n) junk;\nDELETE FROM dbo.T;", mssql()),
        vec!["select", "unparsed", "delete"]
    );
    // An opening parenthesis never closed ends at the `;` a statement
    // follows.
    assert_eq!(
        statement_kinds("SELECT COUNT(* FROM t;\nDELETE FROM dbo.T;", mssql()),
        vec!["unparsed", "delete"]
    );
}
