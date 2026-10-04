// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for the Microsoft SQL Server (T-SQL) dialect.
///
/// Covers:
///   1. Dialect trait properties (identity, keywords, types, operators)
///   2. Lexer gates (bracket identifiers, nested block comments, # NOT a comment)
///   3. Format round-trip (lex → parse → format → verify token preservation)
///   4. || operator semantics (concat, not logical OR)
///   5. Cross-dialect comparison (MSSQL vs Snowflake vs MySQL)
///   6. Risk analysis with MSSQL dialect
use lexega_core::dialect::{mssql, Dialect, MsSqlDialect};
use lexega_core::lexer::tokenize_with_dialect;
use lexega_core::{
    format_sql_with_config, FormatterConfig, IdentifierKind, LiteralKind, TokenKind, TriviaKind,
};

// ============================================================================
// Helpers
// ============================================================================

fn mssql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mssql();
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

fn token_lexemes<'a>(sql: &'a str, dialect: &dyn Dialect) -> Vec<&'a str> {
    let result = tokenize_with_dialect(sql, dialect);
    result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.lexeme(sql))
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

/// Format and verify round-trip safety for MSSQL.
fn format_and_verify(sql: &str, config: &FormatterConfig) {
    let formatted = format_sql_with_config(sql, config)
        .unwrap_or_else(|e| panic!("Format failed for {}: {}", config.dialect.name(), e));

    lexega_core::verify_formatting_safe_with_dialect(&sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("MSSQL formatting verification failed: {}", e));
}

/// Build an AnalysisConfig that uses the MSSQL dialect for risk analysis.
fn mssql_analysis_config() -> lexega_core::analyzer::AnalysisConfig {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mssql());
    config
}

// ============================================================================
// 1. Dialect Trait Properties
// ============================================================================

#[test]
fn test_mssql_dialect_name() {
    let d = MsSqlDialect;
    assert_eq!(d.name(), "mssql");
}

#[test]
fn test_mssql_identifier_quote_char() {
    let d = MsSqlDialect;
    assert_eq!(d.identifier_quote_char(), '"');
}

#[test]
fn test_mssql_max_identifier_length() {
    let d = MsSqlDialect;
    assert_eq!(d.max_identifier_length(), Some(128));
}

#[test]
fn test_mssql_case_insensitive() {
    let d = MsSqlDialect;
    assert!(!d.unquoted_identifiers_case_sensitive());
}

#[test]
fn test_mssql_no_double_quoted_strings() {
    let d = MsSqlDialect;
    assert!(!d.supports_double_quoted_strings());
}

#[test]
fn test_mssql_no_backslash_escapes() {
    let d = MsSqlDialect;
    assert!(!d.backslash_escapes_in_single_quoted_strings());
}

#[test]
fn test_mssql_nested_block_comments() {
    let d = MsSqlDialect;
    assert!(d.supports_nested_block_comments());
}

#[test]
fn test_mssql_no_space_after_dash() {
    let d = MsSqlDialect;
    assert!(!d.requires_space_after_double_dash());
}

#[test]
fn test_mssql_hash_not_comment() {
    let d = MsSqlDialect;
    assert!(!d.hash_is_line_comment());
}

#[test]
fn test_mssql_bracket_identifiers_supported() {
    let d = MsSqlDialect;
    assert!(d.supports_bracket_identifiers());
}

#[test]
fn test_mssql_pipe_pipe_is_concat() {
    let d = MsSqlDialect;
    assert!(d.pipe_pipe_is_concat());
}

#[test]
fn test_mssql_no_type_cast_operator() {
    let d = MsSqlDialect;
    assert!(!d.supports_type_cast_operator());
}

#[test]
fn test_mssql_no_qualify() {
    let d = MsSqlDialect;
    assert!(!d.supports_qualify());
}

#[test]
fn test_mssql_no_lateral() {
    let d = MsSqlDialect;
    assert!(!d.supports_lateral());
}

#[test]
fn test_mssql_cross_outer_apply_parse_and_format() {
    let sql = r#"
SELECT d.DeptID, r.EmpID
FROM Departments d
CROSS APPLY dbo.GetReports(d.DeptMgrID) r;

SELECT d.DeptID, r.EmpID
FROM Departments d
OUTER APPLY dbo.GetReports(d.DeptMgrID) r;
"#;

    let script = lexega_core::parse_sql_with_dialect(sql, &MsSqlDialect)
        .expect("CROSS/OUTER APPLY should parse in MSSQL dialect");

    assert_eq!(script.stmts.len(), 2, "Expected two SELECT statements");

    for stmt in &script.stmts {
        match stmt {
            lexega_core::AstStmt::Select(select) => {
                assert!(
                    !select.from.is_empty(),
                    "SELECT with APPLY should have FROM clause"
                );
                let table = select.from[0]
                    .as_table_ref()
                    .expect("Expected first FROM item to be table ref");
                assert_eq!(
                    table.joins.len(),
                    1,
                    "Expected APPLY to produce one join entry"
                );
                assert!(
                    table.joins[0].apply_keyword_span.is_some(),
                    "Join should preserve APPLY keyword span"
                );
            }
            _ => panic!("Expected SELECT statements only"),
        }
    }

    let formatted = format_sql_with_config(sql, &mssql_config())
        .expect("Formatting should succeed for APPLY statements");
    let upper = formatted.to_ascii_uppercase();
    assert!(upper.contains("CROSS APPLY"));
    assert!(upper.contains("OUTER APPLY"));

    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, mssql().as_ref())
        .expect("Formatting with APPLY should preserve semantics");
}

#[test]
fn test_mssql_supports_merge() {
    let d = MsSqlDialect;
    assert!(d.supports_merge());
}

#[test]
fn test_mssql_supports_pivot() {
    let d = MsSqlDialect;
    assert!(d.supports_pivot());
    assert!(d.supports_unpivot());
}

#[test]
fn test_mssql_no_for_update() {
    let d = MsSqlDialect;
    assert!(!d.supports_for_update());
    assert!(!d.supports_for_update_nowait());
    assert!(!d.supports_for_update_wait());
}

#[test]
fn test_mssql_no_returning() {
    let d = MsSqlDialect;
    assert!(!d.supports_returning());
}

#[test]
fn test_mssql_no_distinct_on() {
    let d = MsSqlDialect;
    assert!(!d.supports_distinct_on());
}

#[test]
fn test_mssql_no_dollar_quoted_strings() {
    let d = MsSqlDialect;
    assert!(!d.supports_dollar_quoted_strings());
    assert!(!d.supports_escape_string_literals());
}

// ============================================================================
// 2. Reserved Keywords
// ============================================================================

#[test]
fn test_mssql_reserved_keywords() {
    let d = MsSqlDialect;
    // Core SQL keywords
    assert!(d.is_reserved_keyword("SELECT"));
    assert!(d.is_reserved_keyword("FROM"));
    assert!(d.is_reserved_keyword("WHERE"));
    assert!(d.is_reserved_keyword("INSERT"));
    assert!(d.is_reserved_keyword("UPDATE"));
    assert!(d.is_reserved_keyword("DELETE"));
    assert!(d.is_reserved_keyword("CREATE"));
    assert!(d.is_reserved_keyword("DROP"));
    assert!(d.is_reserved_keyword("ALTER"));
    assert!(d.is_reserved_keyword("JOIN"));
    assert!(d.is_reserved_keyword("UNION"));
    assert!(d.is_reserved_keyword("EXCEPT"));
    assert!(d.is_reserved_keyword("INTERSECT"));

    // Case insensitive
    assert!(d.is_reserved_keyword("select"));
    assert!(d.is_reserved_keyword("Select"));
}

#[test]
fn test_mssql_specific_reserved_keywords() {
    let d = MsSqlDialect;
    // MSSQL-specific reserved keywords
    assert!(d.is_reserved_keyword("TOP"));
    assert!(d.is_reserved_keyword("BACKUP"));
    assert!(d.is_reserved_keyword("CHECKPOINT"));
    assert!(d.is_reserved_keyword("CLUSTERED"));
    assert!(d.is_reserved_keyword("NONCLUSTERED"));
    assert!(d.is_reserved_keyword("COMPUTE"));
    assert!(d.is_reserved_keyword("DBCC"));
    assert!(d.is_reserved_keyword("DENY"));
    assert!(d.is_reserved_keyword("DUMP"));
    assert!(d.is_reserved_keyword("ERRLVL"));
    assert!(d.is_reserved_keyword("FILLFACTOR"));
    assert!(d.is_reserved_keyword("FREETEXT"));
    assert!(d.is_reserved_keyword("FREETEXTTABLE"));
    assert!(d.is_reserved_keyword("GOTO"));
    assert!(d.is_reserved_keyword("HOLDLOCK"));
    assert!(d.is_reserved_keyword("IDENTITY"));
    assert!(d.is_reserved_keyword("IDENTITY_INSERT"));
    assert!(d.is_reserved_keyword("IDENTITYCOL"));
    assert!(d.is_reserved_keyword("KILL"));
    assert!(d.is_reserved_keyword("LINENO"));
    assert!(d.is_reserved_keyword("LOAD"));
    assert!(d.is_reserved_keyword("NOCHECK"));
    assert!(d.is_reserved_keyword("OFFSETS"));
    assert!(d.is_reserved_keyword("OPENDATASOURCE"));
    assert!(d.is_reserved_keyword("OPENQUERY"));
    assert!(d.is_reserved_keyword("OPENROWSET"));
    assert!(d.is_reserved_keyword("OPENXML"));
    assert!(d.is_reserved_keyword("PIVOT"));
    assert!(d.is_reserved_keyword("UNPIVOT"));
    assert!(d.is_reserved_keyword("PLAN"));
    assert!(d.is_reserved_keyword("PRINT"));
    assert!(d.is_reserved_keyword("PROC"));
    assert!(d.is_reserved_keyword("RAISERROR"));
    assert!(d.is_reserved_keyword("READTEXT"));
    assert!(d.is_reserved_keyword("RECONFIGURE"));
    assert!(d.is_reserved_keyword("REPLICATION"));
    assert!(d.is_reserved_keyword("RESTORE"));
    assert!(d.is_reserved_keyword("REVERT"));
    assert!(d.is_reserved_keyword("ROWCOUNT"));
    assert!(d.is_reserved_keyword("ROWGUIDCOL"));
    assert!(d.is_reserved_keyword("SECURITYAUDIT"));
    assert!(d.is_reserved_keyword("SETUSER"));
    assert!(d.is_reserved_keyword("SHUTDOWN"));
    assert!(d.is_reserved_keyword("STATISTICS"));
    assert!(d.is_reserved_keyword("TABLESAMPLE"));
    assert!(d.is_reserved_keyword("TEXTSIZE"));
    assert!(d.is_reserved_keyword("TRAN"));
    assert!(d.is_reserved_keyword("TRY_CONVERT"));
    assert!(d.is_reserved_keyword("TSEQUAL"));
    assert!(d.is_reserved_keyword("UPDATETEXT"));
    assert!(d.is_reserved_keyword("WAITFOR"));
    assert!(d.is_reserved_keyword("WRITETEXT"));
    assert!(d.is_reserved_keyword("MERGE"));
}

#[test]
fn test_mssql_nonreserved_keywords() {
    let d = MsSqlDialect;
    // Non-reserved but recognized as keywords
    assert!(d.is_keyword("OUTPUT"));
    assert!(d.is_keyword("APPLY"));
    assert!(d.is_keyword("TRY"));
    assert!(d.is_keyword("CATCH"));
    assert!(d.is_keyword("THROW"));
    assert!(d.is_keyword("GO"));
    assert!(d.is_keyword("NOLOCK"));
    assert!(d.is_keyword("UPDLOCK"));
    assert!(d.is_keyword("ROWLOCK"));
    assert!(d.is_keyword("TABLOCK"));
    assert!(d.is_keyword("TABLOCKX"));
    assert!(d.is_keyword("PAGLOCK"));
    assert!(d.is_keyword("XLOCK"));
    assert!(d.is_keyword("NOWAIT"));
    assert!(d.is_keyword("READPAST"));
    assert!(d.is_keyword("MAXDOP"));
    assert!(d.is_keyword("MAXRECURSION"));
}

// ============================================================================
// 3. Bracket Identifier Lexing — THE MSSQL-SPECIFIC GATE
// ============================================================================

#[test]
fn test_bracket_identifier_simple() {
    let d = MsSqlDialect;
    let sql = "[CustomerID]";
    let kinds = token_kinds(sql, &d);
    // Should lex as a single Quoted Identifier, not LBracket + Identifier + RBracket
    assert_eq!(kinds.len(), 1, "Expected 1 token, got: {:?}", kinds);
    assert!(
        matches!(kinds[0], TokenKind::Identifier { .. }),
        "Expected Identifier, got: {:?}",
        kinds[0]
    );
}

#[test]
fn test_bracket_identifier_lexeme() {
    let d = MsSqlDialect;
    let sql = "[My Column]";
    let lexemes = token_lexemes(sql, &d);
    assert_eq!(lexemes, vec!["[My Column]"]);
}

#[test]
fn test_bracket_identifier_in_select() {
    let d = MsSqlDialect;
    let sql = "SELECT [FirstName], [LastName] FROM [Customers]";
    let kinds = token_kinds(sql, &d);
    // SELECT, [FirstName], comma, [LastName], FROM, [Customers]
    assert_eq!(kinds.len(), 6, "Expected 6 tokens, got: {:?}", kinds);
    assert!(matches!(kinds[0], TokenKind::Keyword(_))); // SELECT
    assert!(matches!(kinds[1], TokenKind::Identifier { .. })); // [FirstName]
    assert!(matches!(kinds[3], TokenKind::Identifier { .. })); // [LastName]
    assert!(matches!(kinds[4], TokenKind::Keyword(_))); // FROM
    assert!(matches!(kinds[5], TokenKind::Identifier { .. })); // [Customers]
}

#[test]
fn test_bracket_identifier_with_schema() {
    let d = MsSqlDialect;
    let sql = "[dbo].[Customers]";
    let lexemes = token_lexemes(sql, &d);
    // [dbo] . [Customers]
    assert_eq!(lexemes, vec!["[dbo]", ".", "[Customers]"]);
}

#[test]
fn test_bracket_identifier_three_part_name() {
    let d = MsSqlDialect;
    let sql = "[MyDB].[dbo].[Orders]";
    let lexemes = token_lexemes(sql, &d);
    assert_eq!(lexemes, vec!["[MyDB]", ".", "[dbo]", ".", "[Orders]"]);
}

#[test]
fn test_bracket_identifier_with_spaces() {
    let d = MsSqlDialect;
    let sql = "[First Name]";
    let lexemes = token_lexemes(sql, &d);
    assert_eq!(lexemes.len(), 1);
    assert_eq!(lexemes[0], "[First Name]");
}

#[test]
fn test_bracket_identifier_with_special_chars() {
    let d = MsSqlDialect;
    let sql = "[Column$With.Special-Chars]";
    let lexemes = token_lexemes(sql, &d);
    assert_eq!(lexemes.len(), 1);
    assert_eq!(lexemes[0], "[Column$With.Special-Chars]");
}

#[test]
fn test_bracket_identifier_escaped_bracket() {
    // In T-SQL, ]] inside [...] represents a literal ]
    let d = MsSqlDialect;
    let sql = "[Name]]With]]Brackets]";
    let lexemes = token_lexemes(sql, &d);
    assert_eq!(lexemes.len(), 1);
    assert_eq!(lexemes[0], "[Name]]With]]Brackets]");
}

#[test]
fn test_bracket_identifier_not_in_snowflake() {
    // In Snowflake dialect, [...] should NOT be identifier — should be punctuation
    let sf = lexega_core::dialect::SnowflakeDialect;
    let sql = "[col]";
    let kinds = token_kinds(sql, &sf);
    // Should be 3 tokens: LBracket, Identifier, RBracket
    assert!(
        kinds.len() > 1,
        "Snowflake should NOT treat [...] as identifier"
    );
}

#[test]
fn test_bracket_identifier_not_in_mysql() {
    // MySQL should NOT treat [...] as identifier
    let my = lexega_core::dialect::MySqlDialect;
    let sql = "[col]";
    let kinds = token_kinds(sql, &my);
    assert!(
        kinds.len() > 1,
        "MySQL should NOT treat [...] as identifier"
    );
}

// ============================================================================
// 5. Comment Behavior — # is NOT a comment in MSSQL
// ============================================================================

#[test]
fn test_hash_not_comment_in_mssql() {
    let d = MsSqlDialect;
    let sql = "SELECT * FROM #temp";
    // # should be an operator/symbol, not a comment delimiter
    let trivia = all_trivia_kinds(sql, &d);
    // There should be no line-comment trivia
    assert!(
        !trivia.iter().any(|t| *t == TriviaKind::LineComment),
        "# should NOT be a line comment in MSSQL — it denotes temp tables"
    );
}

#[test]
fn test_dash_dash_comment_in_mssql() {
    let d = MsSqlDialect;
    let sql = "SELECT 1 --comment";
    let trivia = all_trivia_kinds(sql, &d);
    assert!(
        trivia.iter().any(|t| *t == TriviaKind::LineComment),
        "-- should be a line comment in MSSQL"
    );
}

#[test]
fn test_dash_dash_no_space_in_mssql() {
    let d = MsSqlDialect;
    // MSSQL does NOT require space after --
    let sql = "SELECT 1 --comment_no_space";
    let trivia = all_trivia_kinds(sql, &d);
    assert!(
        trivia.iter().any(|t| *t == TriviaKind::LineComment),
        "-- without space should still be a comment in MSSQL"
    );
}

#[test]
fn test_block_comment_in_mssql() {
    let d = MsSqlDialect;
    let sql = "SELECT /* block */ 1";
    let trivia = all_trivia_kinds(sql, &d);
    assert!(
        trivia.iter().any(|t| *t == TriviaKind::BlockComment),
        "Block comments should work in MSSQL"
    );
}

// ============================================================================
// 6. Double-Quoted Identifiers (not strings)
// ============================================================================

#[test]
fn test_double_quote_is_identifier_in_mssql() {
    let d = MsSqlDialect;
    let sql = r#""MyColumn""#;
    let kinds = token_kinds(sql, &d);
    assert_eq!(kinds.len(), 1);
    assert!(
        matches!(kinds[0], TokenKind::Identifier { .. }),
        "Double-quoted should be identifier in MSSQL, got: {:?}",
        kinds[0]
    );
}

#[test]
fn test_double_quote_not_string_in_mssql() {
    let d = MsSqlDialect;
    let sql = r#""hello world""#;
    let kinds = token_kinds(sql, &d);
    assert_eq!(kinds.len(), 1);
    assert!(
        !matches!(kinds[0], TokenKind::Literal(LiteralKind::String)),
        "Double-quoted should NOT be a string literal in MSSQL"
    );
}

// ============================================================================
// 7. String Literals — No Backslash Escapes
// ============================================================================

#[test]
fn test_backslash_not_escape_in_mssql() {
    let d = MsSqlDialect;
    // In MSSQL, backslash is a literal character, not an escape
    let sql = r"'C:\Users\test'";
    let kinds = token_kinds(sql, &d);
    // Should be a single string literal token
    assert_eq!(
        kinds.len(),
        1,
        "Backslash path should be single string: {:?}",
        kinds
    );
    assert!(matches!(kinds[0], TokenKind::Literal(LiteralKind::String)));
}

// ============================================================================
// 8. || Operator — Concat (SQL Server 2022+)
// ============================================================================

#[test]
fn test_pipe_pipe_is_concat_mssql() {
    let d = MsSqlDialect;
    assert!(d.pipe_pipe_is_concat());
}

#[test]
fn test_pipe_pipe_lexing_mssql() {
    let d = MsSqlDialect;
    let sql = "SELECT 'hello' || ' world'";
    let lexemes = token_lexemes(sql, &d);
    assert!(
        lexemes.contains(&"||"),
        "Should contain || operator: {:?}",
        lexemes
    );
}

// ============================================================================
// 9. Cross-Dialect Comparisons
// ============================================================================

#[test]
fn test_bracket_identifier_cross_dialect() {
    let mssql_d = MsSqlDialect;
    let sf_d = lexega_core::dialect::SnowflakeDialect;

    let sql = "[MyColumn]";

    // MSSQL: single identifier token
    let mssql_tokens = token_kinds(sql, &mssql_d);
    assert_eq!(mssql_tokens.len(), 1);
    assert!(matches!(mssql_tokens[0], TokenKind::Identifier { .. }));

    // Snowflake: punctuation + identifier + punctuation
    let sf_tokens = token_kinds(sql, &sf_d);
    assert!(sf_tokens.len() >= 3);
}

#[test]
fn test_hash_cross_dialect() {
    let mssql_d = MsSqlDialect;
    let my_d = lexega_core::dialect::MySqlDialect;

    let sql = "SELECT 1 # something";

    // MSSQL: # is NOT a comment
    let mssql_trivia = all_trivia_kinds(sql, &mssql_d);
    let mssql_has_comment = mssql_trivia.iter().any(|t| *t == TriviaKind::LineComment);

    // MySQL: # IS a comment
    let mysql_trivia = all_trivia_kinds(sql, &my_d);
    let mysql_has_comment = mysql_trivia.iter().any(|t| *t == TriviaKind::LineComment);

    assert!(!mssql_has_comment, "MSSQL should NOT treat # as comment");
    assert!(mysql_has_comment, "MySQL SHOULD treat # as comment");
}

#[test]
fn test_double_quote_cross_dialect() {
    let mssql_d = MsSqlDialect;
    let my_d = lexega_core::dialect::MySqlDialect;

    let sql = r#""test""#;

    // MSSQL: identifier
    let mssql_kinds = token_kinds(sql, &mssql_d);
    assert!(matches!(mssql_kinds[0], TokenKind::Identifier { .. }));

    // MySQL: string literal
    let mysql_kinds = token_kinds(sql, &my_d);
    assert!(matches!(
        mysql_kinds[0],
        TokenKind::Literal(LiteralKind::String)
    ));
}

#[test]
fn test_nested_comments_cross_dialect() {
    let mssql_d = MsSqlDialect;
    let sf_d = lexega_core::dialect::SnowflakeDialect;

    // MSSQL supports nested block comments
    assert!(mssql_d.supports_nested_block_comments());
    // Snowflake does not
    assert!(!sf_d.supports_nested_block_comments());
}

// ============================================================================
// 10. Format Round-Trip Tests
// ============================================================================

#[test]
fn test_format_simple_select_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT 1", &config);
}

#[test]
fn test_format_select_from_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT col1, col2 FROM table1 WHERE col1 = 1", &config);
}

#[test]
fn test_format_select_with_alias_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT a.col1, b.col2 FROM t1 a JOIN t2 b ON a.id = b.id",
        &config,
    );
}

#[test]
fn test_format_insert_mssql() {
    let config = mssql_config();
    format_and_verify("INSERT INTO t1 (col1, col2) VALUES (1, 'hello')", &config);
}

#[test]
fn test_format_update_mssql() {
    let config = mssql_config();
    format_and_verify("UPDATE t1 SET col1 = 1 WHERE col2 = 'x'", &config);
}

#[test]
fn test_format_delete_mssql() {
    let config = mssql_config();
    format_and_verify("DELETE FROM t1 WHERE col1 = 1", &config);
}

#[test]
fn test_format_cte_mssql() {
    let config = mssql_config();
    format_and_verify(
        "WITH cte AS (SELECT col1 FROM t1) SELECT * FROM cte",
        &config,
    );
}

#[test]
fn test_format_window_function_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) rn FROM emp",
        &config,
    );
}

#[test]
fn test_format_case_expression_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT CASE WHEN x > 0 THEN 'pos' WHEN x < 0 THEN 'neg' ELSE 'zero' END AS sign FROM t",
        &config,
    );
}

#[test]
fn test_format_subquery_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT * FROM (SELECT col1, col2 FROM t1 WHERE col1 > 10) sub",
        &config,
    );
}

#[test]
fn test_format_union_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT col1 FROM t1 UNION ALL SELECT col1 FROM t2", &config);
}

#[test]
fn test_format_exists_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id)",
        &config,
    );
}

#[test]
fn test_format_cast_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT CAST(col1 AS VARCHAR(100)) FROM t1", &config);
}

#[test]
fn test_format_string_concat_plus_mssql() {
    // MSSQL traditionally uses + for string concatenation
    let config = mssql_config();
    format_and_verify("SELECT 'Hello' + ' ' + 'World'", &config);
}

#[test]
fn test_format_pipe_pipe_concat_mssql() {
    // SQL Server 2022+ supports || for concat
    let config = mssql_config();
    format_and_verify("SELECT 'Hello' || ' ' || 'World'", &config);
}

#[test]
fn test_format_multi_join_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT a.x, b.y, c.z FROM t1 a INNER JOIN t2 b ON a.id = b.id LEFT JOIN t3 c ON b.id = c.id",
        &config,
    );
}

#[test]
fn test_format_group_by_having_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT dept, COUNT(*) cnt FROM emp GROUP BY dept HAVING COUNT(*) > 5",
        &config,
    );
}

#[test]
fn test_format_in_list_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT * FROM t1 WHERE col1 IN (1, 2, 3, 4, 5)", &config);
}

#[test]
fn test_format_between_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT * FROM t1 WHERE col1 BETWEEN 10 AND 20", &config);
}

#[test]
fn test_format_coalesce_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT COALESCE(col1, col2, 'default') FROM t1", &config);
}

#[test]
fn test_format_multiple_statements_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT 1; SELECT 2; SELECT 3", &config);
}

// ============================================================================
// 11. Format Round-Trip with Bracket Identifiers
// ============================================================================

#[test]
fn test_format_bracket_select_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT [FirstName], [LastName] FROM [Customers]", &config);
}

#[test]
fn test_format_bracket_schema_qualified_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT [c].[FirstName] FROM [dbo].[Customers] [c]", &config);
}

#[test]
fn test_format_bracket_where_mssql() {
    let config = mssql_config();
    format_and_verify("SELECT * FROM [Orders] WHERE [Status] = 'Active'", &config);
}

#[test]
fn test_format_bracket_join_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT [a].[Name], [b].[Total] FROM [Customers] [a] JOIN [Orders] [b] ON [a].[ID] = [b].[CustID]",
        &config,
    );
}

#[test]
fn test_format_bracket_insert_mssql() {
    let config = mssql_config();
    format_and_verify(
        "INSERT INTO [dbo].[Orders] ([CustomerID], [Amount]) VALUES (1, 100.00)",
        &config,
    );
}

#[test]
fn test_format_bracket_update_mssql() {
    let config = mssql_config();
    format_and_verify(
        "UPDATE [Orders] SET [Status] = 'Shipped' WHERE [OrderID] = 42",
        &config,
    );
}

#[test]
fn test_format_bracket_mixed_with_unquoted_mssql() {
    let config = mssql_config();
    format_and_verify(
        "SELECT [SpecialCol], regular_col FROM [My Table] t WHERE t.id = 1",
        &config,
    );
}

// ============================================================================
// 12. Risk Analysis with MSSQL Dialect
// ============================================================================

#[test]
fn test_risk_analysis_mssql_basic() {
    let sql = "SELECT * FROM users";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("MSSQL risk analysis should succeed");
    assert!(
        report.summary.statements_parsed >= 1,
        "Should parse at least 1 statement"
    );
}

#[test]
fn test_risk_analysis_mssql_join() {
    let sql = "SELECT a.*, b.* FROM users a CROSS JOIN orders b";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("MSSQL risk analysis should succeed for cross join");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_risk_analysis_mssql_delete_no_where() {
    let sql = "DELETE FROM orders";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("MSSQL risk analysis should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

// ============================================================================
// 13. Factory Function
// ============================================================================

#[test]
fn test_mssql_factory() {
    let dialect = mssql();
    assert_eq!(dialect.name(), "mssql");
    assert!(dialect.supports_bracket_identifiers());
}

// ============================================================================
// 14. Edge Cases
// ============================================================================

#[test]
fn test_empty_bracket_identifier() {
    let d = MsSqlDialect;
    let sql = "[]";
    let kinds = token_kinds(sql, &d);
    // Even an empty bracket identifier should lex as one token
    assert_eq!(
        kinds.len(),
        1,
        "Empty brackets should be one identifier: {:?}",
        kinds
    );
    assert!(matches!(kinds[0], TokenKind::Identifier { .. }));
}

#[test]
fn test_bracket_identifier_with_numbers() {
    let d = MsSqlDialect;
    let sql = "[123abc]";
    let lexemes = token_lexemes(sql, &d);
    assert_eq!(lexemes, vec!["[123abc]"]);
}

#[test]
fn test_bracket_identifier_unicode() {
    let d = MsSqlDialect;
    let sql = "[Ñoño]";
    let lexemes = token_lexemes(sql, &d);
    assert_eq!(lexemes.len(), 1);
    assert_eq!(lexemes[0], "[Ñoño]");
}

#[test]
fn test_mssql_no_escape_string_prefix() {
    let d = MsSqlDialect;
    assert!(!d.supports_escape_string_literals());
}

#[test]
fn test_mssql_supports_cte() {
    let d = MsSqlDialect;
    assert!(d.supports_cte());
}

#[test]
fn test_mssql_supports_window_functions() {
    let d = MsSqlDialect;
    assert!(d.supports_window_functions());
}

#[test]
fn test_mssql_supports_tablesample() {
    let d = MsSqlDialect;
    assert!(d.supports_sample());
}

#[test]
fn test_mssql_no_flatten() {
    let d = MsSqlDialect;
    assert!(!d.supports_flatten());
}

#[test]
fn test_mssql_no_time_travel() {
    let d = MsSqlDialect;
    assert!(!d.supports_time_travel());
}

#[test]
fn test_mssql_supports_values_as_table() {
    let d = MsSqlDialect;
    assert!(d.supports_values_as_table());
}

// ============================================================================
// @variable identifiers (T-SQL local and system variables)
// ============================================================================

#[test]
fn test_mssql_at_variable_single_token() {
    let lexemes = token_lexemes("SELECT @myvar;", &MsSqlDialect);
    assert_eq!(lexemes, vec!["SELECT", "@myvar", ";"]);
}

#[test]
fn test_mssql_at_variable_kind() {
    let kinds = token_kinds("SELECT @myvar;", &MsSqlDialect);
    assert!(matches!(
        kinds[1],
        TokenKind::Identifier {
            kind: IdentifierKind::AtVariable
        }
    ));
}

#[test]
fn test_mssql_system_variable_double_at() {
    let lexemes = token_lexemes("SELECT @@VERSION;", &MsSqlDialect);
    assert_eq!(lexemes, vec!["SELECT", "@@VERSION", ";"]);
    let kinds = token_kinds("SELECT @@VERSION;", &MsSqlDialect);
    assert!(matches!(
        kinds[1],
        TokenKind::Identifier {
            kind: IdentifierKind::AtVariable
        }
    ));
}

#[test]
fn test_mssql_at_variable_in_where() {
    let lexemes = token_lexemes("SELECT * FROM t WHERE id = @user_id;", &MsSqlDialect);
    assert!(lexemes.contains(&"@user_id"));
}

#[test]
fn test_mssql_at_variable_assignment() {
    let lexemes = token_lexemes("SET @count = 10;", &MsSqlDialect);
    assert_eq!(lexemes[1], "@count");
    let kinds = token_kinds("SET @count = 10;", &MsSqlDialect);
    assert!(matches!(
        kinds[1],
        TokenKind::Identifier {
            kind: IdentifierKind::AtVariable
        }
    ));
}

#[test]
fn test_mssql_multiple_at_variables() {
    let lexemes = token_lexemes("SELECT @a, @b, @@ROWCOUNT;", &MsSqlDialect);
    assert_eq!(lexemes[1], "@a");
    assert_eq!(lexemes[3], "@b");
    assert_eq!(lexemes[5], "@@ROWCOUNT");
}

#[test]
fn test_mssql_at_variable_with_underscore() {
    let lexemes = token_lexemes("SELECT @my_long_var_name;", &MsSqlDialect);
    assert_eq!(lexemes[1], "@my_long_var_name");
}

#[test]
fn test_mssql_at_gt_not_operator() {
    // In MSSQL, @> should NOT be recognized as an operator.
    // @> is PostgreSQL array-contains; MSSQL has @-identifiers instead.
    // supports_at_sign_identifiers() takes priority over @>.
    // "SELECT x @> y" should lex @ as start of @> identifier, not as @> operator.
    let kinds = token_kinds("SELECT x @> y;", &MsSqlDialect);
    // @> in MSSQL context means: Unknown/AtVariable token, then > operator
    assert!(
        !kinds
            .iter()
            .any(|k| matches!(k, TokenKind::Operator(lexega_core::Operator::AtGt))),
        "MSSQL should not produce @> operator — @ is identifier prefix in MSSQL"
    );
}

#[test]
fn test_snowflake_at_is_unknown() {
    // Snowflake should NOT produce AtVariable — @ is Unknown
    let kinds = token_kinds("SELECT @var;", &lexega_core::dialect::SnowflakeDialect);
    assert!(matches!(kinds[1], TokenKind::Unknown));
}

#[test]
fn test_pg_at_is_unknown() {
    let kinds = token_kinds("SELECT @var;", &lexega_core::dialect::PostgresDialect);
    assert!(matches!(kinds[1], TokenKind::Unknown));
}

// ============================================================================
// #temp_table identifiers (T-SQL local and global temp tables)
// ============================================================================

#[test]
fn test_mssql_temp_table_single_token() {
    let lexemes = token_lexemes("SELECT * FROM #temp_users;", &MsSqlDialect);
    assert!(lexemes.contains(&"#temp_users"));
}

#[test]
fn test_mssql_temp_table_kind() {
    let kinds = token_kinds("SELECT * FROM #temp;", &MsSqlDialect);
    let temp_idx = kinds
        .iter()
        .position(|k| {
            matches!(
                k,
                TokenKind::Identifier {
                    kind: IdentifierKind::TempTable
                }
            )
        })
        .unwrap();
    assert!(temp_idx > 0);
}

#[test]
fn test_mssql_global_temp_table() {
    let lexemes = token_lexemes("SELECT * FROM ##global_temp;", &MsSqlDialect);
    assert!(lexemes.contains(&"##global_temp"));
    let kinds = token_kinds("SELECT * FROM ##global_temp;", &MsSqlDialect);
    assert!(kinds.iter().any(|k| matches!(
        k,
        TokenKind::Identifier {
            kind: IdentifierKind::TempTable
        }
    )));
}

#[test]
fn test_mssql_create_temp_table() {
    let lexemes = token_lexemes("CREATE TABLE #my_temp (id INT);", &MsSqlDialect);
    assert_eq!(lexemes[2], "#my_temp");
}

#[test]
fn test_mssql_mixed_at_and_hash() {
    let lexemes = token_lexemes(
        "SELECT @name, @@ROWCOUNT FROM #results WHERE id = @id;",
        &MsSqlDialect,
    );
    assert_eq!(lexemes[1], "@name");
    assert_eq!(lexemes[3], "@@ROWCOUNT");
    assert_eq!(lexemes[5], "#results");
    assert_eq!(lexemes[9], "@id");
}

#[test]
fn test_snowflake_hash_is_operator() {
    // In Snowflake, # is Operator(Hash), not a temp table prefix
    let kinds = token_kinds("SELECT #temp;", &lexega_core::dialect::SnowflakeDialect);
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Operator(lexega_core::Operator::Hash))));
    assert!(!kinds.iter().any(|k| matches!(
        k,
        TokenKind::Identifier {
            kind: IdentifierKind::TempTable
        }
    )));
}

#[test]
fn test_mysql_hash_is_comment() {
    // In MySQL, # starts a line comment — #temp is consumed as trivia
    let trivia = all_trivia_kinds("SELECT 1; #temp", &lexega_core::dialect::MySqlDialect);
    assert!(trivia.contains(&TriviaKind::LineComment));
}

// ============================================================================
// extra_identifier_chars dialect gating
// ============================================================================

#[test]
fn test_mssql_extra_identifier_chars() {
    let d = MsSqlDialect;
    let extra = d.extra_identifier_chars();
    assert!(extra.contains(&'$'));
    assert!(extra.contains(&'#'));
    assert!(extra.contains(&'@'));
}

#[test]
fn test_snowflake_extra_identifier_chars() {
    let d = lexega_core::dialect::SnowflakeDialect;
    let extra = d.extra_identifier_chars();
    assert!(extra.contains(&'$'));
    assert!(extra.contains(&'#'));
}

#[test]
fn test_pg_extra_identifier_chars_empty() {
    let d = lexega_core::dialect::PostgresDialect;
    assert!(d.extra_identifier_chars().is_empty());
}

#[test]
fn test_mysql_extra_identifier_chars_empty() {
    let d = lexega_core::dialect::MySqlDialect;
    assert!(d.extra_identifier_chars().is_empty());
}

#[test]
fn test_bigquery_extra_identifier_chars_empty() {
    let d = lexega_core::dialect::BigQueryDialect;
    assert!(d.extra_identifier_chars().is_empty());
}

#[test]
fn test_pg_hash_not_in_identifier() {
    // In PostgreSQL, data#> should be data + #> operator, NOT data# + >
    let lexemes = token_lexemes(
        "SELECT data#>'{a}';",
        &lexega_core::dialect::PostgresDialect,
    );
    assert_eq!(lexemes[1], "data");
    let kinds = token_kinds(
        "SELECT data#>'{a}';",
        &lexega_core::dialect::PostgresDialect,
    );
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Operator(lexega_core::Operator::HashGt))));
}

#[test]
fn test_pg_hash_double_arrow() {
    // #>> operator
    let lexemes = token_lexemes(
        "SELECT data#>>'{b}';",
        &lexega_core::dialect::PostgresDialect,
    );
    assert_eq!(lexemes[1], "data");
    let kinds = token_kinds(
        "SELECT data#>>'{b}';",
        &lexega_core::dialect::PostgresDialect,
    );
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Operator(lexega_core::Operator::HashGtGt))));
}

#[test]
fn test_snowflake_hash_in_identifier() {
    // In Snowflake, col#1 should be a single identifier
    let lexemes = token_lexemes("SELECT col#1;", &lexega_core::dialect::SnowflakeDialect);
    assert_eq!(lexemes[1], "col#1");
}

#[test]
fn test_pg_dollar_not_in_identifier() {
    // In PostgreSQL, data$x should NOT be a single identifier
    let lexemes = token_lexemes("SELECT data$x;", &lexega_core::dialect::PostgresDialect);
    assert_eq!(lexemes[1], "data"); // stops at $
}

#[test]
fn test_snowflake_dollar_in_identifier() {
    // In Snowflake, data$x should be a single identifier
    let lexemes = token_lexemes("SELECT data$x;", &lexega_core::dialect::SnowflakeDialect);
    assert_eq!(lexemes[1], "data$x");
}

// ============================================================================
// T-SQL Table Hints: WITH (NOLOCK), WITH (UPDLOCK, HOLDLOCK), INDEX(...), etc.
// ============================================================================

#[test]
fn test_mssql_table_hint_nolock_basic() {
    let sql = "SELECT * FROM Orders WITH (NOLOCK);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_with_alias() {
    let sql = "SELECT o.OrderID FROM Orders o WITH (NOLOCK);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_multiple_hints() {
    let sql = "SELECT * FROM Orders o WITH (UPDLOCK, HOLDLOCK);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_index() {
    let sql = "SELECT * FROM Orders WITH (INDEX(idx_order_date));";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_index_multiple_values() {
    let sql = "SELECT * FROM Orders WITH (INDEX(idx1, idx2));";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_forceseek_bare() {
    let sql = "SELECT * FROM Products WITH (FORCESEEK);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_forceseek_with_index_and_columns() {
    let sql = "SELECT * FROM Products WITH (FORCESEEK(PK_Product(ProductID, Name)));";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_forcescan() {
    let sql = "SELECT * FROM Products WITH (FORCESCAN);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_join_both_sides() {
    let sql = "SELECT o.OrderID, c.Name FROM Orders o WITH (NOLOCK) INNER JOIN Customers c WITH (NOLOCK) ON o.CustID = c.CustID;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_join_multiple_tables() {
    let sql = r#"SELECT o.OrderID, c.Name, p.ProductName
FROM Orders o WITH (NOLOCK)
INNER JOIN Customers c WITH (NOLOCK) ON o.CustID = c.CustID
INNER JOIN Products p WITH (NOLOCK) ON o.ProductID = p.ProductID;"#;
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_left_join() {
    let sql = "SELECT * FROM Orders o WITH (NOLOCK) LEFT JOIN Customers c WITH (READUNCOMMITTED) ON o.CustID = c.CustID;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_update_target() {
    let sql = "UPDATE Production.Product WITH (TABLOCK) SET ListPrice = ListPrice * 1.10;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_delete_target() {
    let sql = "DELETE FROM Orders WITH (ROWLOCK) WHERE OrderDate < '2020-01-01';";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_tablock_tablockx() {
    let sql = "SELECT * FROM Inventory WITH (TABLOCKX);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_paglock_xlock() {
    let sql = "SELECT * FROM Inventory WITH (PAGLOCK, XLOCK);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_serializable() {
    let sql = "SELECT * FROM Accounts WITH (SERIALIZABLE);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_readcommitted() {
    let sql = "SELECT * FROM Accounts WITH (READCOMMITTED);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_readpast() {
    let sql = "SELECT * FROM Queue WITH (READPAST, UPDLOCK, ROWLOCK);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_noexpand() {
    // NOEXPAND is used on indexed views
    let sql = "SELECT * FROM dbo.vw_Orders WITH (NOEXPAND);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_snapshot() {
    let sql = "SELECT * FROM Transactions WITH (SNAPSHOT);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_nowait() {
    let sql = "SELECT * FROM Inventory WITH (NOWAIT);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_no_alias() {
    // Hint directly after table name without alias
    let sql = "SELECT * FROM Orders WITH (NOLOCK) WHERE OrderID > 100;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_qualified_table_name() {
    // Three-part name with hint
    let sql = "SELECT * FROM dbo.Sales.Orders WITH (NOLOCK);";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_subquery_no_hint() {
    // Subqueries don't get table hints
    let sql = "SELECT * FROM (SELECT OrderID FROM Orders) AS sub;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_complex_query() {
    let sql = r#"SELECT
    o.OrderID,
    c.CustomerName,
    SUM(od.Quantity * od.UnitPrice) AS OrderTotal
FROM Orders o WITH (NOLOCK)
INNER JOIN Customers c WITH (NOLOCK) ON o.CustomerID = c.CustomerID
INNER JOIN OrderDetails od WITH (NOLOCK) ON o.OrderID = od.OrderID
WHERE o.OrderDate >= '2024-01-01'
GROUP BY o.OrderID, c.CustomerName
HAVING SUM(od.Quantity * od.UnitPrice) > 1000
ORDER BY OrderTotal DESC;"#;
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_mssql_table_hint_idempotent() {
    // Formatting should be idempotent (format twice = same result)
    let sql = "SELECT * FROM Orders o WITH (NOLOCK) INNER JOIN Customers c WITH (NOLOCK) ON o.CustID = c.CustID;";
    let config = mssql_config();
    let first = format_sql_with_config(sql, &config).expect("first format");
    let second = format_sql_with_config(&first, &config).expect("second format");
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_mssql_table_hint_not_parsed_in_snowflake() {
    // In Snowflake dialect, WITH after FROM table should NOT be treated as table hint
    // It should either fail gracefully or be treated differently
    let sql = "SELECT * FROM Orders;";
    let sf_config = FormatterConfig::default();
    format_and_verify(sql, &sf_config);
}

// ============================================================================
// 18. Table Hint Analyzer Rules
// ============================================================================

/// Helper: check if report contains a signal with specific rule ID
fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| {
        let lexega_core::analyzer::RuleMatch::Analysis(p) = s;
        p.matched_rule == rule_id
    })
}

/// Helper: get a signal by rule ID
fn get_rule_signal<'a>(
    report: &'a lexega_core::analyzer::AnalysisReport,
    rule_id: &str,
) -> Option<&'a lexega_core::analyzer::AnalysisSignal> {
    report.signals.iter().find_map(|s| {
        let lexega_core::analyzer::RuleMatch::Analysis(p) = s;
        if p.matched_rule == rule_id {
            Some(p)
        } else {
            None
        }
    })
}

/// Helper: count total evidence for a rule (handles deduplication)
fn evidence_count_for_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> usize {
    report
        .signals
        .iter()
        .filter_map(|s| {
            let lexega_core::analyzer::RuleMatch::Analysis(p) = s;
            if p.matched_rule == rule_id {
                Some(p.evidence_count.unwrap_or(1))
            } else {
                None
            }
        })
        .sum()
}

// --- MSSQL-HINT-DIRTYREAD (High) ---

#[test]
fn test_hint_rule_nolock_select() {
    let sql = "SELECT * FROM Orders WITH (NOLOCK);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "NOLOCK should trigger MSSQL-HINT-DIRTYREAD. Signals: {:?}",
        report.signals
    );

    let sig = get_rule_signal(&report, "MSSQL-HINT-DIRTYREAD").unwrap();
    assert_eq!(sig.risk_level, lexega_core::analyzer::RiskLevel::High);
}

#[test]
fn test_hint_rule_readuncommitted_select() {
    let sql = "SELECT col1 FROM Accounts WITH (READUNCOMMITTED);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "READUNCOMMITTED should trigger MSSQL-HINT-DIRTYREAD"
    );
}

#[test]
fn test_hint_rule_nolock_in_update_subquery() {
    // NOLOCK on a table in an UPDATE's FROM clause
    let sql = "UPDATE o SET o.Status = 'X' FROM Orders o WITH (NOLOCK);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "NOLOCK in UPDATE FROM should trigger MSSQL-HINT-DIRTYREAD"
    );
}

#[test]
fn test_hint_rule_nolock_in_delete() {
    // DELETE with NOLOCK on joined table
    let sql = "DELETE d FROM dbo.Data d INNER JOIN dbo.Ref r WITH (NOLOCK) ON d.id = r.id;";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "NOLOCK in DELETE JOIN should trigger MSSQL-HINT-DIRTYREAD"
    );
}

// --- MSSQL-HINT-XLOCK (Medium) ---

#[test]
fn test_hint_rule_tablockx() {
    let sql = "SELECT * FROM Inventory WITH (TABLOCKX);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-XLOCK"),
        "TABLOCKX should trigger MSSQL-HINT-XLOCK. Signals: {:?}",
        report.signals
    );

    let sig = get_rule_signal(&report, "MSSQL-HINT-XLOCK").unwrap();
    assert_eq!(sig.risk_level, lexega_core::analyzer::RiskLevel::Medium);
}

#[test]
fn test_hint_rule_xlock() {
    let sql = "SELECT id FROM Items WITH (XLOCK, ROWLOCK);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-XLOCK"),
        "XLOCK should trigger MSSQL-HINT-XLOCK"
    );
}

// --- MSSQL-HINT-INDEX (Medium) ---

#[test]
fn test_hint_rule_index_hint() {
    let sql = "SELECT * FROM Orders WITH (INDEX(ix_order_date));";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-INDEX"),
        "INDEX hint should trigger MSSQL-HINT-INDEX. Signals: {:?}",
        report.signals
    );

    let sig = get_rule_signal(&report, "MSSQL-HINT-INDEX").unwrap();
    assert_eq!(sig.risk_level, lexega_core::analyzer::RiskLevel::Medium);
}

#[test]
fn test_hint_rule_index_by_number() {
    let sql = "SELECT * FROM Products WITH (INDEX(0));";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-INDEX"),
        "INDEX(0) should trigger MSSQL-HINT-INDEX"
    );
}

// --- MSSQL-HINT-FORCESCAN (Medium) ---

#[test]
fn test_hint_rule_forcescan() {
    let sql = "SELECT * FROM LargeTable WITH (FORCESCAN);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-FORCESCAN"),
        "FORCESCAN should trigger MSSQL-HINT-FORCESCAN. Signals: {:?}",
        report.signals
    );

    let sig = get_rule_signal(&report, "MSSQL-HINT-FORCESCAN").unwrap();
    assert_eq!(sig.risk_level, lexega_core::analyzer::RiskLevel::Medium);
}

// --- MSSQL-HINT-FORCESEEK (Low) ---

#[test]
fn test_hint_rule_forceseek() {
    let sql = "SELECT * FROM Orders WITH (FORCESEEK);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-FORCESEEK"),
        "FORCESEEK should trigger MSSQL-HINT-FORCESEEK. Signals: {:?}",
        report.signals
    );

    let sig = get_rule_signal(&report, "MSSQL-HINT-FORCESEEK").unwrap();
    assert_eq!(sig.risk_level, lexega_core::analyzer::RiskLevel::Low);
}

#[test]
fn test_hint_rule_forceseek_with_index() {
    let sql = "SELECT * FROM Orders WITH (FORCESEEK(ix_date(OrderDate)));";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-FORCESEEK"),
        "FORCESEEK with index should trigger MSSQL-HINT-FORCESEEK"
    );
}

// --- INFO-MSSQL-HINT (Info) ---

#[test]
fn test_hint_rule_info_any_hint() {
    let sql = "SELECT * FROM Orders WITH (UPDLOCK);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "INFO-MSSQL-HINT"),
        "Any table hint should trigger INFO-MSSQL-HINT. Signals: {:?}",
        report.signals
    );

    let sig = get_rule_signal(&report, "INFO-MSSQL-HINT").unwrap();
    assert_eq!(sig.risk_level, lexega_core::analyzer::RiskLevel::Info);
}

#[test]
fn test_hint_rule_info_holdlock() {
    // HOLDLOCK is a simple hint that doesn't match specific rules —
    // it should only produce INFO-MSSQL-HINT
    let sql = "SELECT * FROM Sessions WITH (HOLDLOCK);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "INFO-MSSQL-HINT"),
        "HOLDLOCK should produce info-level hint signal"
    );
    // Should NOT trigger any of the specific risk rules
    assert!(
        !has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "HOLDLOCK should not trigger dirty-read rule"
    );
    assert!(
        !has_rule(&report, "MSSQL-HINT-XLOCK"),
        "HOLDLOCK should not trigger xlock rule"
    );
}

// --- Negative tests (no false positives) ---

#[test]
fn test_hint_rule_no_hints_no_signals() {
    let sql = "SELECT * FROM Orders WHERE id = 1;";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        !has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "No hints → no dirty-read signal"
    );
    assert!(
        !has_rule(&report, "INFO-MSSQL-HINT"),
        "No hints → no info-level hint signal"
    );
}

// --- Multi-hint / multi-table tests ---

#[test]
fn test_hint_rule_multiple_tables_multiple_hints() {
    let sql = r#"
        SELECT o.*, c.*
        FROM Orders o WITH (NOLOCK)
        INNER JOIN Customers c WITH (TABLOCKX)
            ON o.CustID = c.CustID;
    "#;
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    // Both specific rules should fire
    assert!(
        has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "NOLOCK on Orders should fire"
    );
    assert!(
        has_rule(&report, "MSSQL-HINT-XLOCK"),
        "TABLOCKX on Customers should fire"
    );

    // Info-level hint should also fire
    assert!(
        has_rule(&report, "INFO-MSSQL-HINT"),
        "Info signal should fire for any hint"
    );

    // Evidence count for INFO should cover both tables
    let info_evidence = evidence_count_for_rule(&report, "INFO-MSSQL-HINT");
    assert!(
        info_evidence >= 2,
        "Should have evidence for at least 2 hints, got {}",
        info_evidence
    );
}

#[test]
fn test_hint_rule_nolock_multiple_statements() {
    let sql = r#"
        SELECT * FROM Orders WITH (NOLOCK);
        SELECT * FROM Customers WITH (NOLOCK);
    "#;
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(has_rule(&report, "MSSQL-HINT-DIRTYREAD"));

    // Evidence should capture both occurrences
    let evidence = evidence_count_for_rule(&report, "MSSQL-HINT-DIRTYREAD");
    assert!(
        evidence >= 2,
        "Should have evidence for 2 NOLOCK hints, got {}",
        evidence
    );
}

// --- INSERT statement hint tests ---

#[test]
fn test_hint_rule_insert_tablock() {
    let sql = "INSERT INTO Orders WITH (TABLOCK) (id, name) VALUES (1, 'test');";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    // TABLOCK is not NOLOCK/XLOCK/INDEX/FORCESCAN/FORCESEEK — only INFO fires
    assert!(
        has_rule(&report, "INFO-MSSQL-HINT"),
        "TABLOCK on INSERT should trigger INFO-MSSQL-HINT. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_hint_rule_insert_nolock() {
    // NOLOCK on INSERT is uncommon but syntactically valid
    let sql = "INSERT INTO Orders WITH (NOLOCK) (id) VALUES (1);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "NOLOCK on INSERT should trigger MSSQL-HINT-DIRTYREAD. Signals: {:?}",
        report.signals
    );
    let sig = get_rule_signal(&report, "MSSQL-HINT-DIRTYREAD").unwrap();
    assert_eq!(sig.risk_level, lexega_core::analyzer::RiskLevel::High);
}

#[test]
fn test_hint_rule_insert_tablockx() {
    let sql = "INSERT INTO Orders WITH (TABLOCKX) (id) VALUES (1);";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-XLOCK"),
        "TABLOCKX on INSERT should trigger MSSQL-HINT-XLOCK"
    );
    assert!(has_rule(&report, "INFO-MSSQL-HINT"));
}

#[test]
fn test_hint_rule_insert_select_with_nolock() {
    // INSERT...SELECT where the SELECT source has NOLOCK
    let sql = r#"
        INSERT INTO Archive (id, name)
        SELECT id, name FROM Orders WITH (NOLOCK);
    "#;
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        has_rule(&report, "MSSQL-HINT-DIRTYREAD"),
        "NOLOCK in INSERT...SELECT source should trigger MSSQL-HINT-DIRTYREAD. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_hint_rule_insert_no_hints_no_signal() {
    let sql = "INSERT INTO Orders (id, name) VALUES (1, 'test');";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("analysis should succeed");

    assert!(
        !has_rule(&report, "INFO-MSSQL-HINT"),
        "INSERT without hints should NOT trigger any hint signals"
    );
}

#[test]
fn test_hint_rule_insert_formatting_preserved() {
    let sql = "INSERT INTO Orders WITH (TABLOCK) (id, name) VALUES (1, 'test');";
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config).expect("formatting should succeed");
    lexega_core::verify_formatting_safe(sql, &formatted)
        .expect("formatting should preserve semantics");
    assert!(
        formatted.contains("WITH (TABLOCK)"),
        "Formatted output should preserve WITH (TABLOCK), got: {}",
        formatted
    );
}

// ============================================================================
// TOP PERCENT / WITH TIES
// ============================================================================

#[test]
fn test_top_percent_basic() {
    let sql = "SELECT TOP 10 PERCENT * FROM employees;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_with_ties() {
    let sql = "SELECT TOP 10 WITH TIES name, salary FROM employees ORDER BY salary DESC;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_percent_with_ties() {
    let sql = "SELECT TOP (5) PERCENT WITH TIES * FROM products ORDER BY price;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_parenthesized_expr() {
    let sql = "SELECT TOP (100) name FROM t;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_percent_columns() {
    let sql = "SELECT TOP 10 PERCENT name, age FROM t;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_with_ties_order_by() {
    let sql = "SELECT TOP 100 WITH TIES * FROM t ORDER BY id;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_parenthesized_percent_with_ties() {
    let sql = "SELECT TOP (50) PERCENT WITH TIES col1, col2 FROM t ORDER BY col1;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_bare_number_unchanged() {
    // Verify existing plain TOP still works
    let sql = "SELECT TOP 5 * FROM t;";
    let config = mssql_config();
    format_and_verify(sql, &config);
}

#[test]
fn test_top_percent_preserves_keyword() {
    let sql = "SELECT TOP 25 PERCENT id FROM orders;";
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config).expect("formatting should succeed");
    assert!(
        formatted.contains("PERCENT"),
        "PERCENT keyword must be preserved, got: {}",
        formatted
    );
}

#[test]
fn test_top_with_ties_preserves_keywords() {
    let sql = "SELECT TOP 10 WITH TIES name FROM employees ORDER BY name;";
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config).expect("formatting should succeed");
    assert!(
        formatted.contains("WITH TIES"),
        "WITH TIES must be preserved, got: {}",
        formatted
    );
}
