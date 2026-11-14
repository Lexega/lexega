// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test PIVOT and UNPIVOT formatting

use lexega_syntax::{format_sql, parse_stmt_from_str};

#[test]
fn test_pivot_explicit_values() {
    let sql =
        "SELECT * FROM sales PIVOT(SUM(amount) FOR quarter IN ('2023_Q1', '2023_Q2', '2023_Q3'))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("SUM"));
    assert!(formatted.contains("FOR"));
    assert!(formatted.contains("IN"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_pivot_with_aliases() {
    let sql = "SELECT * FROM sales PIVOT(SUM(amount) FOR quarter IN ('Q1' AS q1, 'Q2' AS q2, 'Q3' AS q3))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    println!("Formatted:\n{}", formatted);
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("AS"));
}

#[test]
fn test_pivot_any() {
    let sql = "SELECT * FROM sales PIVOT(AVG(price) FOR product IN (ANY))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    println!("Formatted:\n{}", formatted);
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("ANY"));
}

#[test]
fn test_pivot_with_aggregate_alias() {
    let sql = "SELECT * FROM sales PIVOT(SUM(amount) AS total_sales FOR quarter IN ('Q1', 'Q2'))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("PIVOT"));
    assert!(formatted.contains("AS"));
    assert!(formatted.contains("total_sales"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_unpivot_basic() {
    let sql = "SELECT * FROM quarterly_sales UNPIVOT EXCLUDE NULLS (sales FOR quarter IN (q1, q2, q3, q4))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("UNPIVOT"));
    assert!(formatted.contains("EXCLUDE"));
    assert!(formatted.contains("NULLS"));
    assert!(formatted.contains("FOR"));
    assert!(formatted.contains("IN"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_unpivot_include_nulls() {
    let sql = "SELECT * FROM data UNPIVOT INCLUDE NULLS (value FOR name IN (col1, col2, col3))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("UNPIVOT"));
    assert!(formatted.contains("INCLUDE"));
    assert!(formatted.contains("NULLS"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_unpivot_with_aliases() {
    let sql = "SELECT * FROM data UNPIVOT EXCLUDE NULLS (value FOR name IN (jan AS January, feb AS February))";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("UNPIVOT"));
    assert!(formatted.contains("AS"));
    assert!(formatted.contains("January"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_pivot_unpivot_combination() {
    // Test that we can parse queries with both PIVOT and complex features
    let test_cases = vec![
        "SELECT * FROM t PIVOT(MAX(val) FOR cat IN ('A', 'B')) WHERE id > 10",
        "SELECT * FROM t UNPIVOT EXCLUDE NULLS (v FOR n IN (a, b, c)) ORDER BY v",
    ];

    for sql in test_cases {
        let ast = parse_stmt_from_str(sql);
        assert!(ast.is_some(), "Failed to parse: {}", sql);

        let formatted = format_sql(sql).unwrap_or_else(|_| panic!("Failed to format: {}", sql));
        println!("Input:  {}", sql);
        println!("Output: {}\n", formatted);
    }
}

/// Formats `sql` in `dialect` with the default and the compact style and
/// checks each output: the same significant tokens as the source (case
/// aside), formatting it again changes nothing, and the formatter's own
/// safety check passes it.
fn assert_formats_to_source_tokens(sql: &str, dialect: lexega_syntax::DialectRef) {
    use lexega_syntax::lexer::tokenize_with_dialect;
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };
    let lexemes = |text: &str| -> Vec<String> {
        tokenize_with_dialect(text, dialect.as_ref())
            .tokens
            .iter()
            .map(|t| t.lexeme(text).to_ascii_uppercase())
            .collect()
    };
    for base in [FormatterConfig::default(), FormatterConfig::compact()] {
        let config = FormatterConfig {
            dialect: dialect.clone(),
            ..base
        };
        let formatted = format_sql_with_config(sql, &config)
            .unwrap_or_else(|e| panic!("format failed for {sql:?}: {e:?}"));
        assert_eq!(
            lexemes(&formatted),
            lexemes(sql),
            "formatted text holds other tokens than the source:\n{formatted}"
        );
        let again = format_sql_with_config(&formatted, &config)
            .unwrap_or_else(|e| panic!("reformat failed for {formatted:?}: {e:?}"));
        assert_eq!(again, formatted, "formatting is not idempotent");
        verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
            .unwrap_or_else(|e| panic!("safety check refused {formatted:?}: {e}"));
    }
}

#[test]
fn unpivot_prints_only_the_null_handling_written() {
    use lexega_syntax::dialect;
    let bare = "SELECT * FROM t UNPIVOT (v FOR n IN (a, b));";
    let include = "SELECT * FROM t UNPIVOT INCLUDE NULLS (v FOR n IN (a, b));";
    let exclude = "SELECT * FROM t UNPIVOT EXCLUDE NULLS (v FOR n IN (a, b));";
    for d in [
        dialect::snowflake(),
        dialect::bigquery(),
        dialect::databricks(),
    ] {
        for sql in [bare, include, exclude] {
            assert_formats_to_source_tokens(sql, d.clone());
        }
    }
    let tsql = "SELECT CustomerID, Phone\n\
                FROM (SELECT CustomerID, Phone1, Phone2 FROM dbo.Customers) AS cp\n\
                UNPIVOT (Phone FOR Phones IN (Phone1, Phone2)) AS up;";
    assert_formats_to_source_tokens(tsql, dialect::mssql());
    assert_formats_to_source_tokens(bare, dialect::mssql());
}

#[test]
fn safety_check_refuses_an_added_null_handling_clause() {
    let original = "SELECT * FROM t UNPIVOT (v FOR n IN (a, b));";
    let changed = "SELECT * FROM t UNPIVOT EXCLUDE NULLS (v FOR n IN (a, b));";
    for d in [
        lexega_syntax::dialect::snowflake(),
        lexega_syntax::dialect::mssql(),
    ] {
        assert!(
            lexega_syntax::verify_formatting_safe_with_dialect(original, changed, d.as_ref())
                .is_err(),
            "the safety check passed words the source does not have"
        );
    }
}

#[test]
fn pivot_prints_only_the_clauses_written() {
    use lexega_syntax::dialect;
    let forms = [
        "SELECT * FROM s PIVOT (SUM(amount) FOR q IN ('Q1', 'Q2'));",
        "SELECT * FROM s PIVOT (SUM(amount) AS total FOR q IN ('Q1' AS q1, 'Q2'));",
    ];
    for d in [
        dialect::snowflake(),
        dialect::bigquery(),
        dialect::databricks(),
    ] {
        for sql in forms {
            assert_formats_to_source_tokens(sql, d.clone());
        }
    }
    let snowflake_only = [
        "SELECT * FROM s PIVOT (SUM(amount) FOR q IN (ANY ORDER BY q DESC));",
        "SELECT * FROM s PIVOT (SUM(amount) FOR q IN (ANY) DEFAULT ON NULL (0));",
    ];
    for sql in snowflake_only {
        assert_formats_to_source_tokens(sql, dialect::snowflake());
    }
    assert_formats_to_source_tokens(
        "SELECT * FROM s PIVOT (SUM(amount) FOR q IN ([Q1], [Q2])) AS p;",
        dialect::mssql(),
    );
}
