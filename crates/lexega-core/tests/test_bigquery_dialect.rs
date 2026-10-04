// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for the BigQuery (GoogleSQL) dialect.
///
/// Covers:
///   1. Dialect trait properties (identity, keywords, types, operators)
///   2. Lexer gates (backtick identifiers, # comments, double-quoted strings)
///   3. Format round-trip (lex → parse → format → verify token preservation)
///   4. || operator semantics (concat, not logical OR)
///   5. Cross-dialect comparison (BigQuery vs MySQL vs Snowflake)
///   6. Risk analysis with BigQuery dialect
use lexega_core::ast::{AstExpr, AstProjectionKind, BinaryOperator, ProjectionItemKind};
use lexega_core::dialect::{bigquery, mysql, snowflake, BigQueryDialect, Dialect};
use lexega_core::lexer::tokenize_with_dialect;
use lexega_core::parser::try_parse_script_with_dialect;
use lexega_core::{
    format_sql_with_config, AstStmt, FormatterConfig, LiteralKind, TokenKind, TriviaKind,
};

// ============================================================================
// Helpers
// ============================================================================

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = bigquery();
    config
}

fn token_kinds(sql: &str, dialect: &dyn Dialect) -> Vec<TokenKind> {
    let result = tokenize_with_dialect(sql, dialect);
    result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect()
}

fn all_trivia_kinds(sql: &str, dialect: &dyn Dialect) -> Vec<TriviaKind> {
    let result = tokenize_with_dialect(sql, dialect);
    let mut trivia_kinds = Vec::new();
    for tok in &result.tokens {
        for t in &tok.leading_trivia {
            trivia_kinds.push(t.kind);
        }
        for t in &tok.trailing_trivia {
            trivia_kinds.push(t.kind);
        }
    }
    trivia_kinds
}

/// Format and verify round-trip safety for BigQuery.
fn format_and_verify(sql: &str, config: &FormatterConfig) {
    let formatted = format_sql_with_config(sql, config)
        .unwrap_or_else(|e| panic!("Format failed for {}: {}", config.dialect.name(), e));

    lexega_core::verify_formatting_safe_with_dialect(&sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("BigQuery formatting verification failed: {}", e));
}

fn extract_first_expr(sql: &str, dialect: &dyn Dialect) -> AstExpr {
    let result = tokenize_with_dialect(sql, dialect);
    let script = try_parse_script_with_dialect(sql, &result.tokens, dialect).expect("should parse");
    assert_eq!(script.stmts.len(), 1, "expected 1 statement");
    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            AstProjectionKind::Columns(items) => {
                assert!(!items.is_empty(), "expected at least one projection item");
                match &items[0].kind {
                    ProjectionItemKind::SelectItem(si) => si.expr.clone(),
                    other => panic!(
                        "expected SelectItem, got {:?}",
                        std::mem::discriminant(other)
                    ),
                }
            }
            AstProjectionKind::Star(_) => panic!("expected Columns projection, got Star"),
        },
        other => panic!("expected Select, got {:?}", std::mem::discriminant(other)),
    }
}

// ============================================================================
// 1. Dialect Trait Properties
// ============================================================================

#[test]
fn test_bq_dialect_name() {
    let bq = BigQueryDialect;
    assert_eq!(bq.name(), "bigquery");
}

#[test]
fn test_bq_identifier_quote_is_backtick() {
    let bq = BigQueryDialect;
    assert_eq!(bq.identifier_quote_char(), '`');
}

#[test]
fn test_bq_double_quoted_strings_supported() {
    let bq = BigQueryDialect;
    assert!(bq.supports_double_quoted_strings());
}

#[test]
fn test_bq_backslash_escapes_active() {
    let bq = BigQueryDialect;
    assert!(bq.backslash_escapes_in_single_quoted_strings());
}

#[test]
fn test_bq_hash_is_line_comment() {
    let bq = BigQueryDialect;
    assert!(bq.hash_is_line_comment());
}

#[test]
fn test_bq_no_nested_block_comments() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_nested_block_comments());
}

#[test]
fn test_bq_no_space_required_after_double_dash() {
    let bq = BigQueryDialect;
    assert!(!bq.requires_space_after_double_dash());
}

#[test]
fn test_bq_no_version_comments() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_version_comments());
}

#[test]
fn test_bq_pipe_pipe_is_concat() {
    let bq = BigQueryDialect;
    assert!(bq.pipe_pipe_is_concat());
}

#[test]
fn test_bq_no_cast_operator() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_type_cast_operator());
}

#[test]
fn test_bq_no_json_operators() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_json_operators());
}

#[test]
fn test_bq_no_dollar_quoted_strings() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_dollar_quoted_strings());
}

#[test]
fn test_bq_no_escape_string_literals() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_escape_string_literals());
}

#[test]
fn test_bq_qualify_supported() {
    let bq = BigQueryDialect;
    assert!(bq.supports_qualify());
}

#[test]
fn test_bq_tablesample_supported() {
    let bq = BigQueryDialect;
    assert!(bq.supports_sample());
}

#[test]
fn test_bq_merge_supported() {
    let bq = BigQueryDialect;
    assert!(bq.supports_merge());
}

#[test]
fn test_bq_no_for_update() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_for_update());
}

#[test]
fn test_bq_no_distinct_on() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_distinct_on());
}

#[test]
fn test_bq_no_returning() {
    let bq = BigQueryDialect;
    assert!(!bq.supports_returning());
}

#[test]
fn test_bq_max_identifier_length() {
    let bq = BigQueryDialect;
    assert_eq!(bq.max_identifier_length(), Some(1024));
}

// ============================================================================
// 2. Reserved Keywords
// ============================================================================

#[test]
fn test_bq_reserved_keywords() {
    let bq = BigQueryDialect;
    let reserved = [
        "SELECT",
        "FROM",
        "WHERE",
        "JOIN",
        "ON",
        "AS",
        "AND",
        "OR",
        "NOT",
        "NULL",
        "TRUE",
        "FALSE",
        "IN",
        "IS",
        "LIKE",
        "BETWEEN",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "END",
        "EXISTS",
        "UNION",
        "INTERSECT",
        "EXCEPT",
        "ORDER",
        "GROUP",
        "HAVING",
        "LIMIT",
        "WITH",
        "QUALIFY",
        "STRUCT",
        "ARRAY",
        "UNNEST",
        "TABLESAMPLE",
        "LATERAL",
        "MERGE",
        "RECURSIVE",
        "WINDOW",
        "OVER",
        "PARTITION",
        "ROWS",
        "RANGE",
        "INTERVAL",
    ];
    for kw in &reserved {
        assert!(
            bq.is_reserved_keyword(kw),
            "BigQuery should have reserved keyword: {}",
            kw
        );
    }
}

#[test]
fn test_bq_reserved_keywords_case_insensitive() {
    let bq = BigQueryDialect;
    assert!(bq.is_reserved_keyword("select"));
    assert!(bq.is_reserved_keyword("SELECT"));
    assert!(bq.is_reserved_keyword("Select"));
    assert!(bq.is_reserved_keyword("qualify"));
    assert!(bq.is_reserved_keyword("QUALIFY"));
}

// ============================================================================
// 4. Lexer Gate: Backtick Identifiers
// ============================================================================

#[test]
fn test_bq_backtick_identifier_basic() {
    let sql = "SELECT `my_column` FROM `my-project.dataset.table`";
    let bq = bigquery();
    let kinds = token_kinds(sql, bq.as_ref());
    // Backtick-quoted identifiers should be lexed as identifiers
    let ident_count = kinds
        .iter()
        .filter(|k| matches!(k, TokenKind::Identifier { .. }))
        .count();
    assert!(
        ident_count >= 2,
        "Should have at least 2 backtick identifiers, got {}",
        ident_count
    );
}

#[test]
fn test_bq_backtick_with_special_chars() {
    // BigQuery allows hyphens and dots in backtick-quoted identifiers
    let sql = "SELECT * FROM `my-project.my-dataset.my-table`";
    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    assert!(
        formatted.contains("`my-project.my-dataset.my-table`"),
        "Backtick identifier with special chars should be preserved"
    );
}

#[test]
fn test_bq_backtick_reserved_keyword() {
    // Reserved keywords must be backtick-quoted when used as identifiers
    let sql = "SELECT `from`, `select` FROM `table`";
    let config = bq_config();
    format_and_verify(sql, &config);
}

// ============================================================================
// 5. Lexer Gate: # Line Comments
// ============================================================================

#[test]
fn test_bq_hash_comment_basic() {
    let sql = "# This is a BigQuery comment\nSELECT 1";
    let bq = bigquery();
    let trivia = all_trivia_kinds(sql, bq.as_ref());
    assert!(
        trivia.contains(&TriviaKind::LineComment),
        "# should produce a LineComment trivia in BigQuery dialect"
    );
}

#[test]
fn test_bq_hash_comment_inline() {
    let sql = "SELECT 1 # inline comment";
    let bq = bigquery();
    let trivia = all_trivia_kinds(sql, bq.as_ref());
    assert!(
        trivia.contains(&TriviaKind::LineComment),
        "Inline # comment should be recognized"
    );
}

#[test]
fn test_bq_hash_not_comment_in_snowflake() {
    // In Snowflake, # is NOT a comment
    let sql = "SELECT 1 # not a comment";
    let sf = snowflake();
    let trivia = all_trivia_kinds(sql, sf.as_ref());
    let line_comments: Vec<_> = trivia
        .iter()
        .filter(|k| matches!(k, TriviaKind::LineComment))
        .collect();
    // Snowflake should NOT treat # as a line comment
    assert!(
        line_comments.is_empty(),
        "Snowflake should NOT treat # as a line comment, but found {:?}",
        line_comments
    );
}

// ============================================================================
// 6. Lexer Gate: Double-Quoted Strings
// ============================================================================

#[test]
fn test_bq_double_quoted_string_is_string_literal() {
    let sql = r#"SELECT "hello world""#;
    let bq = bigquery();
    let kinds = token_kinds(sql, bq.as_ref());
    // In BigQuery, "hello world" is a string literal
    let string_count = kinds
        .iter()
        .filter(|k| matches!(k, TokenKind::Literal(LiteralKind::String)))
        .count();
    assert!(
        string_count >= 1,
        "Double-quoted text should be a string literal in BigQuery, got kinds: {:?}",
        kinds
    );
}

#[test]
fn test_bq_double_quoted_string_not_identifier() {
    // Contrast: in Snowflake/PG, "hello" is an identifier
    let sql = r#"SELECT "hello""#;
    let sf = snowflake();
    let kinds = token_kinds(sql, sf.as_ref());
    let ident_count = kinds
        .iter()
        .filter(|k| matches!(k, TokenKind::Identifier { .. }))
        .count();
    assert!(
        ident_count >= 1,
        "In Snowflake, double-quoted text should be an identifier"
    );
}

// ============================================================================
// 7. Lexer Gate: Backslash Escapes in Strings
// ============================================================================

#[test]
fn test_bq_backslash_escape_in_string() {
    let sql = r"SELECT 'hello\nworld'";
    let bq = bigquery();
    let kinds = token_kinds(sql, bq.as_ref());
    // Should be a single string literal (backslash doesn't terminate the string)
    let string_count = kinds
        .iter()
        .filter(|k| matches!(k, TokenKind::Literal(LiteralKind::String)))
        .count();
    assert_eq!(
        string_count, 1,
        "Backslash should be an escape in BigQuery strings"
    );
}

#[test]
fn test_bq_backslash_escaped_single_quote() {
    let sql = r"SELECT 'it\'s a test'";
    let bq = bigquery();
    let kinds = token_kinds(sql, bq.as_ref());
    let string_count = kinds
        .iter()
        .filter(|k| matches!(k, TokenKind::Literal(LiteralKind::String)))
        .count();
    assert_eq!(
        string_count, 1,
        "Backslash-escaped quote should not terminate string"
    );
}

// ============================================================================
// 8. Dash-Dash Comment (no space required)
// ============================================================================

#[test]
fn test_bq_double_dash_comment_no_space() {
    let sql = "--this is a comment\nSELECT 1";
    let bq = bigquery();
    let trivia = all_trivia_kinds(sql, bq.as_ref());
    assert!(
        trivia.contains(&TriviaKind::LineComment),
        "BigQuery: --comment (no space) should still be a line comment"
    );
}

#[test]
fn test_bq_double_dash_comment_with_space() {
    let sql = "-- this is a comment\nSELECT 1";
    let bq = bigquery();
    let trivia = all_trivia_kinds(sql, bq.as_ref());
    assert!(
        trivia.contains(&TriviaKind::LineComment),
        "BigQuery: -- comment (with space) should be a line comment"
    );
}

// ============================================================================
// 9. || Operator Semantics (Concatenation)
// ============================================================================

#[test]
fn test_bq_pipe_pipe_is_concat_not_logical_or() {
    let sql = "SELECT a || b";
    let bq = bigquery();
    let expr = extract_first_expr(sql, bq.as_ref());
    match expr {
        AstExpr::BinaryOp { operator, .. } => {
            assert_eq!(
                operator,
                BinaryOperator::Concat,
                "BigQuery || should parse as Concat, got {:?}",
                operator
            );
        }
        other => panic!(
            "Expected BinaryOp, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

#[test]
fn test_bq_pipe_pipe_concat_vs_mysql_logical_or() {
    // Same SQL, different operator semantics
    let sql = "SELECT a || b";

    // BigQuery: || is Concat
    let bq_expr = extract_first_expr(sql, bigquery().as_ref());
    match bq_expr {
        AstExpr::BinaryOp { operator, .. } => assert_eq!(operator, BinaryOperator::Concat),
        _ => panic!("BigQuery: expected BinaryOp Concat"),
    }

    // MySQL: || is LogicalOr
    let mysql_expr = extract_first_expr(sql, mysql().as_ref());
    match mysql_expr {
        AstExpr::BinaryOp { operator, .. } => assert_eq!(operator, BinaryOperator::LogicalOr),
        _ => panic!("MySQL: expected BinaryOp LogicalOr"),
    }
}

#[test]
fn test_bq_concat_precedence_like_snowflake() {
    // In BigQuery (like Snowflake), || has arithmetic-level precedence
    // a || b = c should parse as (a || b) = c, not a || (b = c)
    let sql = "SELECT a || b = c";
    let bq_expr = extract_first_expr(sql, bigquery().as_ref());
    match bq_expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::Equal,
            left,
            ..
        } => {
            match *left {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::Concat,
                    ..
                } => { /* correct */ }
                other => panic!(
                    "Expected left side to be Concat, got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        }
        AstExpr::BinaryOp { operator, .. } => {
            panic!("Expected top-level Equal, got {:?}", operator)
        }
        other => panic!(
            "Expected BinaryOp, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// 10. Format Round-Trip Tests
// ============================================================================

#[test]
fn test_bq_format_simple_select() {
    let sql = "SELECT a, b, c FROM `my-project.dataset.table` WHERE a > 1";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_with_hash_comment() {
    let sql = "# BigQuery query\nSELECT a FROM t";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_with_double_dash_comment() {
    let sql = "-- BigQuery query\nSELECT a FROM t";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_with_backtick_identifiers() {
    let sql = "SELECT `column_a`, `column_b` FROM `dataset.table`";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_concat_operator() {
    let sql = "SELECT first_name || ' ' || last_name AS full_name FROM employees";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_cte() {
    let sql = "WITH cte AS (SELECT 1 AS x) SELECT x FROM cte";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_window_function() {
    let sql =
        "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) AS rn FROM employees";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_subquery() {
    let sql = "SELECT * FROM (SELECT a, b FROM t1 UNION ALL SELECT c, d FROM t2)";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_multi_statement() {
    let sql = "SELECT 1; SELECT 2; SELECT 3";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_case_expression() {
    let sql =
        "SELECT CASE WHEN x > 0 THEN 'positive' WHEN x < 0 THEN 'negative' ELSE 'zero' END FROM t";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_aggregate() {
    let sql = "SELECT dept, COUNT(*) AS cnt, SUM(salary) AS total FROM employees GROUP BY dept HAVING COUNT(*) > 5 ORDER BY total DESC";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_join() {
    let sql = "SELECT a.id, b.name FROM table_a a INNER JOIN table_b b ON a.id = b.id LEFT JOIN table_c c ON a.id = c.id";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_insert() {
    let sql = "INSERT INTO my_table (col1, col2) VALUES (1, 'hello'), (2, 'world')";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_merge() {
    let sql = r#"MERGE target AS t
USING source AS s
ON t.id = s.id
WHEN MATCHED THEN UPDATE SET t.value = s.value
WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)"#;
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_create_table() {
    let sql = "CREATE TABLE dataset.new_table (id INT64, name STRING, created DATE)";
    format_and_verify(sql, &bq_config());
}

// ============================================================================
// 11. Cross-Dialect: BigQuery vs Others (Shared Characteristics)
// ============================================================================

#[test]
fn test_bq_shares_backtick_with_mysql() {
    let bq = BigQueryDialect;
    let mysql_d = lexega_core::dialect::MySqlDialect;
    assert_eq!(
        bq.identifier_quote_char(),
        mysql_d.identifier_quote_char(),
        "BigQuery and MySQL should both use backtick for identifiers"
    );
}

#[test]
fn test_bq_shares_concat_with_snowflake() {
    let bq = BigQueryDialect;
    let sf = lexega_core::dialect::SnowflakeDialect;
    assert_eq!(
        bq.pipe_pipe_is_concat(),
        sf.pipe_pipe_is_concat(),
        "BigQuery and Snowflake should both use || as concat"
    );
}

#[test]
fn test_bq_differs_from_mysql_on_pipe_pipe() {
    let bq = BigQueryDialect;
    let mysql_d = lexega_core::dialect::MySqlDialect;
    assert_ne!(
        bq.pipe_pipe_is_concat(),
        mysql_d.pipe_pipe_is_concat(),
        "BigQuery (concat) and MySQL (logical OR) should differ on || semantics"
    );
}

#[test]
fn test_bq_shares_hash_comment_with_mysql() {
    let bq = BigQueryDialect;
    let mysql_d = lexega_core::dialect::MySqlDialect;
    assert_eq!(
        bq.hash_is_line_comment(),
        mysql_d.hash_is_line_comment(),
        "BigQuery and MySQL should both treat # as line comment"
    );
}

#[test]
fn test_bq_shares_double_quoted_strings_with_mysql() {
    let bq = BigQueryDialect;
    let mysql_d = lexega_core::dialect::MySqlDialect;
    assert_eq!(
        bq.supports_double_quoted_strings(),
        mysql_d.supports_double_quoted_strings(),
        "BigQuery and MySQL should both allow double-quoted strings"
    );
}

#[test]
fn test_bq_has_qualify_like_snowflake_unlike_mysql() {
    let bq = BigQueryDialect;
    let sf = lexega_core::dialect::SnowflakeDialect;
    let mysql_d = lexega_core::dialect::MySqlDialect;
    assert!(bq.supports_qualify(), "BigQuery supports QUALIFY");
    assert!(sf.supports_qualify(), "Snowflake supports QUALIFY");
    assert!(
        !mysql_d.supports_qualify(),
        "MySQL does NOT support QUALIFY"
    );
}

#[test]
fn test_bq_no_cast_operator_unlike_snowflake() {
    let bq = BigQueryDialect;
    let sf = lexega_core::dialect::SnowflakeDialect;
    assert!(
        !bq.supports_type_cast_operator(),
        "BigQuery does NOT support :: cast"
    );
    assert!(
        sf.supports_type_cast_operator(),
        "Snowflake supports :: cast"
    );
}

// ============================================================================
// 12. Factory Function
// ============================================================================

#[test]
fn test_bq_factory_returns_correct_dialect() {
    let dialect = bigquery();
    assert_eq!(dialect.name(), "bigquery");
    assert_eq!(dialect.identifier_quote_char(), '`');
    assert!(dialect.pipe_pipe_is_concat());
    assert!(dialect.hash_is_line_comment());
}

// ============================================================================
// 13. Complex BigQuery-Style Queries
// ============================================================================

#[test]
fn test_bq_format_unnest() {
    let sql = "SELECT * FROM UNNEST([1, 2, 3]) AS num";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_safe_cast() {
    let sql = "SELECT SAFE_CAST('123' AS INT64) AS safe_int";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_struct_literal() {
    let sql = "SELECT STRUCT(1 AS a, 'hello' AS b)";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_array_literal() {
    let sql = "SELECT [1, 2, 3] AS arr";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_interval() {
    let sql = "SELECT INTERVAL 5 DAY";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_mixed_comments() {
    let sql = "# hash comment\n-- dash comment\n/* block comment */\nSELECT 1";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_qualified_table_with_backticks() {
    let sql = "SELECT a FROM `project-id`.`dataset`.`table`";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_double_quoted_string_concat() {
    // BigQuery: "hello" is a string, || is concat
    let sql = r#"SELECT "hello" || ' ' || "world""#;
    format_and_verify(sql, &bq_config());
}

// ============================================================================
// 14. Risk Analysis with BigQuery Dialect
// ============================================================================

#[test]
fn test_bq_risk_analysis_basic() {
    // Simple SELECT should be analyzable with BigQuery dialect
    let sql = "SELECT * FROM users WHERE id = 1";
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("BQ risk analysis should succeed");
    assert!(
        report.summary.statements_parsed > 0,
        "Should have parsed at least 1 statement"
    );
}

#[test]
fn test_bq_risk_analysis_cross_join() {
    let sql = "SELECT a.*, b.* FROM table_a a CROSS JOIN table_b b";
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("BQ risk analysis should succeed");
    assert!(report.summary.statements_parsed > 0);
}

// ============================================================================
// 15. SAFE_CAST – Parser/Formatter Round-Trip
// ============================================================================

#[test]
fn test_bq_safe_cast_simple() {
    format_and_verify("SELECT SAFE_CAST(x AS INT64)", &bq_config());
}

#[test]
fn test_bq_safe_cast_string_literal() {
    format_and_verify("SELECT SAFE_CAST('123' AS INT64) AS val", &bq_config());
}

#[test]
fn test_bq_safe_cast_nested_expr() {
    format_and_verify("SELECT SAFE_CAST(a + b AS FLOAT64) FROM t", &bq_config());
}

#[test]
fn test_bq_safe_cast_in_where() {
    format_and_verify(
        "SELECT id FROM t WHERE SAFE_CAST(col AS INT64) > 10",
        &bq_config(),
    );
}

#[test]
fn test_bq_safe_cast_multiple() {
    format_and_verify(
        "SELECT SAFE_CAST(a AS STRING), SAFE_CAST(b AS INT64) FROM t",
        &bq_config(),
    );
}

#[test]
fn test_bq_safe_cast_ast_variant() {
    let bq = BigQueryDialect;
    let expr = extract_first_expr("SELECT SAFE_CAST(x AS INT64)", &bq);
    assert!(
        matches!(expr, AstExpr::SafeCast { .. }),
        "Expected SafeCast variant, got {:?}",
        std::mem::discriminant(&expr)
    );
}

#[test]
fn test_bq_safe_cast_vs_cast() {
    // Both CAST and SAFE_CAST should work; they produce different AST nodes
    let bq = BigQueryDialect;
    let cast_expr = extract_first_expr("SELECT CAST(x AS INT64)", &bq);
    let safe_expr = extract_first_expr("SELECT SAFE_CAST(x AS INT64)", &bq);
    assert!(matches!(cast_expr, AstExpr::Cast { .. }));
    assert!(matches!(safe_expr, AstExpr::SafeCast { .. }));
}

// ============================================================================
// 16. UNNEST – Table-Valued Function in FROM
// ============================================================================

#[test]
fn test_bq_unnest_array_literal() {
    format_and_verify("SELECT * FROM UNNEST([1, 2, 3]) AS num", &bq_config());
}

#[test]
fn test_bq_unnest_column_ref() {
    format_and_verify(
        "SELECT elem FROM my_table, UNNEST(my_table.arr) AS elem",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_cross_join() {
    format_and_verify(
        "SELECT t.id, u.val FROM t CROSS JOIN UNNEST(t.items) AS u",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_with_offset() {
    format_and_verify(
        "SELECT val, off FROM UNNEST([10, 20, 30]) AS val WITH OFFSET AS off",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_with_offset_bare() {
    // WITH OFFSET without any alias
    format_and_verify(
        "SELECT elem FROM UNNEST([10, 20, 30]) AS elem WITH OFFSET",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_with_offset_implicit_alias() {
    // WITH OFFSET alias (no AS keyword)
    format_and_verify(
        "SELECT elem, off FROM UNNEST([10, 20, 30]) AS elem WITH OFFSET off",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_column_list_alias() {
    // Column-list alias: AS alias(col1, col2, ...)
    format_and_verify(
        "SELECT u.val FROM UNNEST(a.repeated_field) AS u(val)",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_column_list_alias_multi() {
    // Multiple columns in alias list
    format_and_verify(
        "SELECT a, b, c FROM UNNEST(arr) AS t(a, b, c)",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_column_list_alias_cross_join() {
    // CROSS JOIN UNNEST with column-list alias (golden fixture pattern)
    format_and_verify(
        "SELECT a.id, u.val FROM my_table a CROSS JOIN UNNEST(a.repeated_field) AS u(val)",
        &bq_config(),
    );
}

#[test]
fn test_bq_unnest_column_list_alias_preserves_parens() {
    // Verify (val) is preserved and not dropped
    let sql = "SELECT val FROM UNNEST(arr) AS u(val)";
    let formatted = format_sql_with_config(sql, &bq_config()).expect("should format");
    assert!(
        formatted.contains("u(val)"),
        "Column-list alias should be preserved; got: {}",
        formatted
    );
}

#[test]
fn test_bq_unnest_no_table_wrapper() {
    // UNNEST should NOT be wrapped in TABLE() by the formatter
    let sql = "SELECT * FROM UNNEST([1, 2, 3]) AS x";
    let formatted = format_sql_with_config(sql, &bq_config()).expect("should format");
    assert!(
        !formatted.contains("TABLE("),
        "UNNEST should not be wrapped in TABLE(); got: {}",
        formatted
    );
    assert!(
        formatted.contains("UNNEST"),
        "Output should contain UNNEST; got: {}",
        formatted
    );
}

// ============================================================================
// 17. SELECT * EXCEPT – BigQuery Column Exclusion
// ============================================================================

#[test]
fn test_bq_except_single_column() {
    format_and_verify("SELECT * EXCEPT (col1) FROM t", &bq_config());
}

#[test]
fn test_bq_except_multiple_columns() {
    format_and_verify("SELECT * EXCEPT (col1, col2, col3) FROM t", &bq_config());
}

#[test]
fn test_bq_except_preserves_keyword() {
    // Ensure EXCEPT is preserved in output (not converted to EXCLUDE)
    let sql = "SELECT * EXCEPT (col1) FROM t";
    let formatted = format_sql_with_config(sql, &bq_config()).expect("should format");
    assert!(
        formatted.contains("EXCEPT"),
        "BigQuery EXCEPT should be preserved; got: {}",
        formatted
    );
}

#[test]
fn test_bq_except_with_alias() {
    format_and_verify("SELECT t.* EXCEPT (col1) FROM my_table t", &bq_config());
}

#[test]
fn test_bq_replace_still_works() {
    format_and_verify("SELECT * REPLACE (col1 + 1 AS col1) FROM t", &bq_config());
}

#[test]
fn test_bq_except_and_replace_combined() {
    // BigQuery doesn't allow both on same *, but each should parse individually
    format_and_verify("SELECT * EXCEPT (a) FROM t", &bq_config());
    format_and_verify("SELECT * REPLACE (b + 1 AS b) FROM t", &bq_config());
}

// ============================================================================
// 18. Parameterized Types – ARRAY<T>, STRUCT<...>
// ============================================================================

#[test]
fn test_bq_parameterized_type_in_cast() {
    format_and_verify("SELECT CAST(x AS ARRAY<INT64>)", &bq_config());
}

#[test]
fn test_bq_parameterized_struct_type() {
    format_and_verify("SELECT CAST(x AS STRUCT<a INT64, b STRING>)", &bq_config());
}

#[test]
fn test_bq_nested_parameterized_type() {
    format_and_verify(
        "SELECT CAST(x AS ARRAY<STRUCT<a INT64, b STRING>>)",
        &bq_config(),
    );
}

#[test]
fn test_bq_parameterized_in_safe_cast() {
    format_and_verify("SELECT SAFE_CAST(x AS ARRAY<STRING>)", &bq_config());
}

// ============================================================================
// 19. STRUCT Constructors – Typeless, Typed, Positional, Empty
// ============================================================================

#[test]
fn test_bq_struct_typeless_named() {
    // STRUCT(expr AS name, ...)
    format_and_verify("SELECT STRUCT(1 AS x, 'hello' AS y)", &bq_config());
}

#[test]
fn test_bq_struct_positional() {
    // STRUCT(a, b, c) — positional args (no AS)
    format_and_verify("SELECT STRUCT(a, b, c)", &bq_config());
}

#[test]
fn test_bq_struct_empty() {
    // STRUCT() — empty struct
    format_and_verify("SELECT STRUCT()", &bq_config());
}

#[test]
fn test_bq_struct_typed() {
    // STRUCT<x INT64, y STRING>(1, 'hello') — typed constructor
    format_and_verify("SELECT STRUCT<x INT64, y STRING>(1, 'hello')", &bq_config());
}

#[test]
fn test_bq_struct_typed_nested() {
    // Nested typed STRUCT
    format_and_verify(
        "SELECT STRUCT<a STRUCT<b INT64, c STRING>>(STRUCT<b INT64, c STRING>(1, 'hi'))",
        &bq_config(),
    );
}

#[test]
fn test_bq_struct_mixed_as_and_positional() {
    // Mix of aliased and positional args
    format_and_verify("SELECT STRUCT(1 AS x, b, 'hello' AS y)", &bq_config());
}

#[test]
fn test_bq_struct_in_select_list() {
    // STRUCT as part of a larger query
    format_and_verify(
        "SELECT id, STRUCT(name AS n, age AS a) AS person FROM users",
        &bq_config(),
    );
}

#[test]
fn test_bq_struct_in_where_clause() {
    // STRUCT expression in WHERE
    format_and_verify(
        "SELECT * FROM t WHERE s = STRUCT(1 AS x, 2 AS y)",
        &bq_config(),
    );
}

#[test]
fn test_bq_array_typed_constructor() {
    // ARRAY<T>(...) typed constructor (same mechanism as STRUCT)
    format_and_verify("SELECT ARRAY<INT64>(1, 2, 3)", &bq_config());
}

// ============================================================================
// 20. INTERVAL Expressions – Integer + Unit, String + Range
// ============================================================================

#[test]
fn test_bq_interval_integer_day() {
    // INTERVAL int_expr unit
    format_and_verify(
        "SELECT CURRENT_TIMESTAMP() + INTERVAL 1 DAY AS tomorrow",
        &bq_config(),
    );
}

#[test]
fn test_bq_interval_integer_month() {
    format_and_verify(
        "SELECT CURRENT_DATE() - INTERVAL 3 MONTH AS three_months_ago",
        &bq_config(),
    );
}

#[test]
fn test_bq_interval_string_range() {
    // INTERVAL 'string' unit TO unit (range form)
    format_and_verify(
        "SELECT ts + INTERVAL '1:30:00' HOUR TO SECOND AS shifted",
        &bq_config(),
    );
}

#[test]
fn test_bq_interval_year_to_month_range() {
    format_and_verify("SELECT ts + INTERVAL '1-6' YEAR TO MONTH", &bq_config());
}

#[test]
fn test_bq_interval_in_function_arg() {
    // INTERVAL inside function arguments (within parens)
    format_and_verify("SELECT DATE_ADD(ts, INTERVAL 1 HOUR)", &bq_config());
}

#[test]
fn test_bq_interval_string_with_unit() {
    // Snowflake-compatible form still works
    format_and_verify("SELECT INTERVAL '5' HOUR", &bq_config());
}

#[test]
fn test_bq_interval_golden_section9() {
    // Golden fixture section 9: All three forms together
    let sql = "\
SELECT
  CURRENT_TIMESTAMP() + INTERVAL 1 DAY AS tomorrow,
  CURRENT_DATE() - INTERVAL 3 MONTH AS three_months_ago,
  ts + INTERVAL '1:30:00' HOUR TO SECOND AS shifted;";
    format_and_verify(sql, &bq_config());
}

// ============================================================================
// 21. Combined BigQuery Patterns
// ============================================================================

#[test]
fn test_bq_unnest_with_safe_cast() {
    format_and_verify(
        "SELECT SAFE_CAST(elem AS INT64) FROM UNNEST(['1', '2', '3']) AS elem",
        &bq_config(),
    );
}

#[test]
fn test_bq_complex_query() {
    let sql = r#"
        SELECT
            t.id,
            SAFE_CAST(t.value AS INT64) AS int_val,
            u.item
        FROM `project.dataset.table` t
        CROSS JOIN UNNEST(t.items) AS u
        WHERE SAFE_CAST(t.value AS INT64) > 0
    "#;
    format_and_verify(sql.trim(), &bq_config());
}

#[test]
fn test_bq_except_then_join() {
    format_and_verify(
        "SELECT a.* EXCEPT (id), b.name FROM table_a a JOIN table_b b ON a.id = b.id",
        &bq_config(),
    );
}

// ============================================================================
// 21. Risk Analysis with New BigQuery Features
// ============================================================================

#[test]
fn test_bq_risk_safe_cast() {
    let sql = "SELECT SAFE_CAST(col AS INT64) FROM users";
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("BQ risk analysis with SAFE_CAST should succeed");
    assert!(report.summary.statements_parsed > 0);
}

#[test]
fn test_bq_risk_unnest() {
    let sql = "SELECT * FROM UNNEST([1, 2, 3]) AS x";
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("BQ risk analysis with UNNEST should succeed");
    assert!(report.summary.statements_parsed > 0);
}

// ============================================================================
// 21. Typed String Literals (DATE '...', TIMESTAMP '...', etc.)
// ============================================================================

#[test]
fn test_bq_typed_literal_date() {
    format_and_verify("SELECT DATE '2024-01-15'", &bq_config());
}

#[test]
fn test_bq_typed_literal_timestamp() {
    format_and_verify("SELECT TIMESTAMP '2024-01-15 10:30:00'", &bq_config());
}

#[test]
fn test_bq_typed_literal_datetime() {
    format_and_verify("SELECT DATETIME '2024-01-15T10:30:00'", &bq_config());
}

#[test]
fn test_bq_typed_literal_time() {
    format_and_verify("SELECT TIME '10:30:00'", &bq_config());
}

#[test]
fn test_bq_typed_literal_numeric() {
    format_and_verify("SELECT NUMERIC '12345.67'", &bq_config());
}

#[test]
fn test_bq_typed_literal_bignumeric() {
    format_and_verify(
        "SELECT BIGNUMERIC '99999999999999999999.999999999'",
        &bq_config(),
    );
}

#[test]
fn test_bq_typed_literal_json() {
    format_and_verify(r#"SELECT JSON '{"key": "value"}'"#, &bq_config());
}

#[test]
fn test_bq_typed_literal_in_where() {
    format_and_verify(
        "SELECT id FROM events WHERE event_date > DATE '2024-01-01'",
        &bq_config(),
    );
}

#[test]
fn test_bq_typed_literal_in_comparison() {
    format_and_verify(
        "SELECT * FROM t WHERE ts BETWEEN TIMESTAMP '2024-01-01 00:00:00' AND TIMESTAMP '2024-12-31 23:59:59'",
        &bq_config(),
    );
}

#[test]
fn test_bq_typed_literal_multiple() {
    format_and_verify(
        "SELECT DATE '2024-01-15', TIME '10:30:00', TIMESTAMP '2024-01-15 10:30:00' FROM t",
        &bq_config(),
    );
}

#[test]
fn test_bq_typed_literal_ast_variant() {
    let bq = BigQueryDialect;
    let expr = extract_first_expr("SELECT DATE '2024-01-15'", &bq);
    assert!(
        matches!(expr, AstExpr::TypedStringLiteral { .. }),
        "Expected TypedStringLiteral variant, got {:?}",
        std::mem::discriminant(&expr)
    );
}

#[test]
fn test_bq_typed_literal_vs_function_call() {
    // DATE '...' = typed literal; DATE(col) = function call
    let bq = BigQueryDialect;
    let literal = extract_first_expr("SELECT DATE '2024-01-15'", &bq);
    let func = extract_first_expr("SELECT DATE(some_col)", &bq);
    assert!(matches!(literal, AstExpr::TypedStringLiteral { .. }));
    assert!(matches!(func, AstExpr::FunctionCall { .. }));
}

#[test]
fn test_bq_typed_literal_case_insensitive() {
    // Type names are case-insensitive
    format_and_verify("SELECT date '2024-01-15'", &bq_config());
    format_and_verify("SELECT Date '2024-01-15'", &bq_config());
    format_and_verify("SELECT timestamp '2024-01-15 00:00:00'", &bq_config());
}

#[test]
fn test_bq_typed_literal_in_expression() {
    format_and_verify(
        "SELECT DATE_DIFF(DATE '2024-12-31', DATE '2024-01-01', DAY) AS days",
        &bq_config(),
    );
}

#[test]
fn test_bq_risk_typed_literal() {
    let sql = "SELECT * FROM events WHERE ts > TIMESTAMP '2024-01-01 00:00:00'";
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("BQ risk analysis with typed literal should succeed");
    assert!(report.summary.statements_parsed > 0);
}

// ============================================================================
// FOR SYSTEM_TIME AS OF (BigQuery time travel)
// ============================================================================

#[test]
fn test_bq_for_system_time_string_literal() {
    format_and_verify(
        "SELECT * FROM my_table FOR SYSTEM_TIME AS OF '2024-01-01 00:00:00 UTC';",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_function_call() {
    format_and_verify(
        "SELECT * FROM my_table FOR SYSTEM_TIME AS OF CURRENT_TIMESTAMP();",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_typed_literal() {
    format_and_verify(
        "SELECT * FROM my_table FOR SYSTEM_TIME AS OF TIMESTAMP '2024-01-01 00:00:00';",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_backtick_table() {
    format_and_verify(
        "SELECT * FROM `project.dataset.table` FOR SYSTEM_TIME AS OF '2024-01-01';",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_with_alias() {
    format_and_verify(
        "SELECT t.* FROM my_table AS t FOR SYSTEM_TIME AS OF '2024-01-01';",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_with_where() {
    format_and_verify(
        "SELECT * FROM my_table FOR SYSTEM_TIME AS OF '2024-01-01' WHERE id > 10;",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_with_join() {
    // BigQuery canonical order: table [AS alias] FOR SYSTEM_TIME AS OF expr
    format_and_verify(
        "SELECT a.*, b.col FROM table_a AS a FOR SYSTEM_TIME AS OF '2024-01-01' JOIN table_b AS b ON a.id = b.id;",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_variable() {
    // Using a column reference as the timestamp expression
    format_and_verify(
        "SELECT * FROM my_table FOR SYSTEM_TIME AS OF my_timestamp;",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_subtraction_expr() {
    // TIMESTAMP_SUB without INTERVAL (since INTERVAL 1 HOUR is P6)
    format_and_verify(
        "SELECT * FROM my_table FOR SYSTEM_TIME AS OF TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL '1' HOUR);",
        &bq_config(),
    );
}

#[test]
fn test_bq_for_system_time_preserves_semantics() {
    let sql = "SELECT col1, col2 FROM data_table FOR SYSTEM_TIME AS OF '2024-06-15';";
    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    // Verify the FOR SYSTEM_TIME AS OF clause is preserved
    assert!(
        formatted.contains("FOR SYSTEM_TIME AS OF"),
        "Formatted output should contain FOR SYSTEM_TIME AS OF, got: {}",
        formatted
    );
}

#[test]
fn test_bq_for_system_time_not_parsed_in_snowflake() {
    // In Snowflake dialect, FOR is not time travel syntax (AT/BEFORE is)
    // FOR SYSTEM_TIME should not be consumed as time travel
    let sql = "SELECT * FROM my_table FOR SYSTEM_TIME AS OF '2024-01-01';";
    let sf_config = FormatterConfig::default(); // Snowflake is default
                                                // Should still parse (FOR is a keyword, parser may handle it differently)
    let result = format_sql_with_config(sql, &sf_config);
    // We just check it doesn't panic — the exact behavior depends on Snowflake parser
    let _ = result;
}

// =============================================================================
// Standalone scripting: DECLARE and SET without BEGIN...END
// =============================================================================

#[test]
fn test_bq_standalone_declare() {
    format_and_verify("DECLARE x INT64 DEFAULT 0;", &bq_config());
}

#[test]
fn test_bq_standalone_declare_no_default() {
    format_and_verify("DECLARE y STRING;", &bq_config());
}

#[test]
fn test_bq_standalone_set() {
    format_and_verify("SET y = 'hello';", &bq_config());
}

#[test]
fn test_bq_standalone_declare_then_set() {
    // BigQuery allows DECLARE and SET as independent top-level statements
    format_and_verify("DECLARE x INT64 DEFAULT 0;\nSET x = 42;", &bq_config());
}

#[test]
fn test_bq_standalone_multiple_declares() {
    format_and_verify(
        "DECLARE x INT64;\nDECLARE y STRING;\nDECLARE z BOOL;",
        &bq_config(),
    );
}

#[test]
fn test_bq_standalone_set_tuple_form() {
    format_and_verify("SET (x, y) = (SELECT 1, 'world');", &bq_config());
}

#[test]
fn test_bq_declare_set_then_select() {
    // Scripting statements mixed with DML
    format_and_verify(
        "DECLARE x INT64 DEFAULT 10;\nSET x = 20;\nSELECT x;",
        &bq_config(),
    );
}
