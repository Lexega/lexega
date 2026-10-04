// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Edge case tests for dialect-specific lexer behavior.
///
/// These tests verify fixes for gaps identified by cross-referencing
/// official vendor documentation against the lexer implementation:
///
/// - Backslash escapes in single-quoted strings (Snowflake + MySQL)
/// - PostgreSQL/MSSQL nested block comments
/// - MySQL -- space requirement for line comments
/// - MySQL /*!...*/ version comments
/// - MSSQL @variables and #temp_tables
/// - BigQuery backtick identifiers and # line comments
use lexega_syntax::dialect::{bigquery, mssql, mysql, postgres, snowflake};
use lexega_syntax::lexer::tokenize_with_dialect;
use lexega_syntax::{Dialect, LiteralKind, Operator, TokenKind, TriviaKind};

// ============================================================================
// Helpers
// ============================================================================

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

// ============================================================================
// Backslash escapes in single-quoted strings
// ============================================================================

#[test]
fn test_mysql_backslash_escape_single_quote_in_string() {
    // MySQL: 'it\'s' should be ONE string token, not string + garbage
    let sql = r"SELECT 'it\'s a test'";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    // Should be: SELECT, string literal
    assert_eq!(
        kinds.len(),
        2,
        "MySQL 'it\\'s a test' should be 2 tokens (SELECT + string), got: {:?}",
        kinds
    );
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
}

#[test]
fn test_mysql_backslash_escape_newline_in_string() {
    // MySQL: 'hello\nworld' — the \n is an escape, not literal chars
    let sql = r"SELECT 'hello\nworld'";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MySQL escaped newline string should be 2 tokens, got: {:?}",
        kinds
    );
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
    let lexemes = token_lexemes(sql, &*d);
    assert_eq!(lexemes[1], r"'hello\nworld'");
}

#[test]
fn test_mysql_backslash_escape_backslash_in_string() {
    // MySQL: 'C:\\path' — escaped backslash
    let sql = r"SELECT 'C:\\path'";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MySQL escaped backslash should be 2 tokens, got: {:?}",
        kinds
    );
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
}

#[test]
fn test_mysql_backslash_escape_null_in_string() {
    // MySQL: 'null\0byte' — null escape
    let sql = r"SELECT 'null\0byte'";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MySQL null escape should be 2 tokens, got: {:?}",
        kinds
    );
}

#[test]
fn test_mysql_doubled_quote_still_works() {
    // MySQL: 'it''s' should still work (standard SQL escaping)
    let sql = "SELECT 'it''s a test'";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(kinds.len(), 2);
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
}

#[test]
fn test_snowflake_backslash_escape_single_quote_in_string() {
    // Snowflake: 'it\'s' should be ONE string token
    // Per Snowflake docs, backslash escapes are always active
    let sql = r"SELECT 'it\'s a test'";
    let d = snowflake();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "Snowflake 'it\\'s a test' should be 2 tokens, got: {:?}",
        kinds
    );
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
}

#[test]
fn test_snowflake_backslash_unicode_escape() {
    // Snowflake: '\u0041' is the unicode escape for 'A'
    let sql = r"SELECT '\u0041'";
    let d = snowflake();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(kinds.len(), 2);
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
}

#[test]
fn test_snowflake_backslash_hex_escape() {
    // Snowflake: '\x41' is hex escape for 'A'
    let sql = r"SELECT '\x41'";
    let d = snowflake();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(kinds.len(), 2);
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
}

#[test]
fn test_snowflake_backslash_tab_escape() {
    // Snowflake: 'hello\tworld'
    let sql = r"SELECT 'hello\tworld'";
    let d = snowflake();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(kinds.len(), 2);
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
    let lexemes = token_lexemes(sql, &*d);
    assert_eq!(lexemes[1], r"'hello\tworld'");
}

#[test]
fn test_postgres_no_backslash_escape_in_regular_string() {
    // PostgreSQL: in regular '...' strings, backslash is literal
    // 'it\'s' should produce string 'it\' then s a test' — two strings
    // (because \ is NOT an escape in PG regular strings)
    let sql = r"SELECT 'it\'s a test'";
    let d = postgres();
    let kinds = token_kinds(sql, &*d);
    // PG treats \ as literal, so ' after \ closes the string,
    // then 's' is identifier, etc.
    assert!(
        kinds.len() > 2,
        "PG should NOT treat backslash as escape in regular strings, got: {:?}",
        kinds
    );
}

#[test]
fn test_postgres_e_string_still_has_backslash_escapes() {
    // PostgreSQL: E'it\'s' should work — E-strings have escapes
    let sql = r"SELECT E'it\'s a test'";
    let d = postgres();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "PG E-string should handle backslash escapes, got: {:?}",
        kinds
    );
    assert_eq!(kinds[1], TokenKind::Literal(LiteralKind::String));
}

#[test]
fn test_mysql_backslash_in_where_clause() {
    // Real-world MySQL: WHERE name = 'O\'Brien'
    let sql = r"SELECT * FROM users WHERE name = 'O\'Brien'";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    // Should end with: =, string
    let last_two: Vec<_> = kinds.iter().rev().take(2).collect();
    assert_eq!(
        *last_two[0],
        TokenKind::Literal(LiteralKind::String),
        "Last token should be string literal, got: {:?}",
        kinds
    );
}

#[test]
fn test_snowflake_backslash_in_regex_pattern() {
    // Snowflake: REGEXP '\\d{3}' — escaped backslash in regex string
    let sql = r"SELECT col FROM t WHERE col REGEXP '\\d{3}'";
    let d = snowflake();
    let kinds = token_kinds(sql, &*d);
    let last = kinds.last().unwrap();
    assert_eq!(*last, TokenKind::Literal(LiteralKind::String));
}

// ============================================================================
// PostgreSQL nested block comments
// ============================================================================

#[test]
fn test_pg_nested_block_comment_basic() {
    // PostgreSQL: /* outer /* inner */ still comment */  SELECT 1
    let sql = "/* outer /* inner */ still comment */ SELECT 1";
    let d = postgres();
    let kinds = token_kinds(sql, &*d);
    // With nesting support, the entire comment is consumed.
    // Should be: SELECT, 1
    assert_eq!(
        kinds.len(),
        2,
        "PG nested comment should be fully consumed as trivia, got: {:?}",
        kinds
    );
    let lexemes = token_lexemes(sql, &*d);
    assert_eq!(lexemes[0], "SELECT");
    assert_eq!(lexemes[1], "1");
}

#[test]
fn test_pg_nested_block_comment_double_nested() {
    // PostgreSQL: /* a /* b /* c */ b */ a */ SELECT 1
    let sql = "/* a /* b /* c */ b */ a */ SELECT 1";
    let d = postgres();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "PG double-nested comment should be fully consumed, got: {:?}",
        kinds
    );
    let lexemes = token_lexemes(sql, &*d);
    assert_eq!(lexemes[0], "SELECT");
}

#[test]
fn test_pg_nested_comment_trivia_kind() {
    // Verify it's tagged as BlockComment trivia
    let sql = "/* outer /* inner */ end */ SELECT 1";
    let d = postgres();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        trivia.contains(&TriviaKind::BlockComment),
        "Nested comment should be BlockComment trivia, got: {:?}",
        trivia
    );
}

#[test]
fn test_snowflake_no_nested_block_comment() {
    // Snowflake: does NOT support nested comments
    // /* outer /* inner */ THIS IS NOT A COMMENT */ SELECT 1
    // The first */ closes the comment, then "THIS IS NOT A COMMENT */" is code
    let sql = "/* outer /* inner */ SELECT 1";
    let d = snowflake();
    let kinds = token_kinds(sql, &*d);
    // First */ closes the comment. Then "SELECT 1" is code.
    assert_eq!(
        kinds.len(),
        2,
        "Snowflake should close at first */, got: {:?}",
        kinds
    );
    let lexemes = token_lexemes(sql, &*d);
    assert_eq!(lexemes[0], "SELECT");
}

#[test]
fn test_mysql_no_nested_block_comment() {
    // MySQL: does NOT support nested comments (same as Snowflake)
    let sql = "/* outer /* inner */ SELECT 1";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MySQL should close at first */, got: {:?}",
        kinds
    );
}

#[test]
fn test_pg_nested_comment_with_code_after() {
    // Full statement with nested comment then actual code
    let sql = "/* comment /* nested */ end */ SELECT 1 AS x";
    let d = postgres();
    let kinds = token_kinds(sql, &*d);
    // SELECT, 1, AS, x
    assert_eq!(
        kinds.len(),
        4,
        "Should have 4 tokens after nested comment, got: {:?}",
        kinds
    );
}

// ============================================================================
// MySQL -- space requirement for line comments
// ============================================================================

#[test]
fn test_mysql_double_dash_with_space_is_comment() {
    // MySQL: '-- comment' (with space) IS a comment
    let sql = "SELECT 1 -- this is a comment";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    // Should be: SELECT, 1 (comment consumed as trivia)
    assert_eq!(
        kinds.len(),
        2,
        "MySQL '-- comment' should be trivia, got: {:?}",
        kinds
    );
}

#[test]
fn test_mysql_double_dash_without_space_is_not_comment() {
    // MySQL: 'x--y' (no space) is NOT a comment, it's x - (-y)
    let sql = "SELECT x--y";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    // Should be: SELECT, x, -, -, y (two minus operators)
    assert!(
        kinds.len() >= 4,
        "MySQL '--' without space should be operators, got: {:?}",
        kinds
    );
    // Check that we have Minus operators
    let minus_count = kinds
        .iter()
        .filter(|k| **k == TokenKind::Operator(Operator::Minus))
        .count();
    assert_eq!(
        minus_count, 2,
        "Should have 2 Minus operators, got: {:?}",
        kinds
    );
}

#[test]
fn test_mysql_double_dash_with_tab_is_comment() {
    // MySQL: '--\t' (with tab) IS a comment
    let sql = "SELECT 1 --\tthis is a comment";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MySQL '--<tab>' should be trivia, got: {:?}",
        kinds
    );
}

#[test]
fn test_mysql_double_dash_at_eof_is_comment() {
    // MySQL: '--' at end of input IS a comment (no following char)
    let sql = "SELECT 1 --";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MySQL '--' at EOF should be trivia, got: {:?}",
        kinds
    );
}

#[test]
fn test_mysql_double_dash_number_not_comment() {
    // MySQL: '--1' is NOT a comment (common in expressions like x--1)
    let sql = "SELECT x--1";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    // Should be: SELECT, x, -, -, 1
    assert!(
        kinds.len() >= 4,
        "MySQL '--1' should not be a comment, got: {:?}",
        kinds
    );
}

#[test]
fn test_snowflake_double_dash_no_space_is_comment() {
    // Snowflake: '--comment' IS a comment (no space required)
    let sql = "SELECT 1 --comment";
    let d = snowflake();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "Snowflake '--comment' should be trivia, got: {:?}",
        kinds
    );
}

#[test]
fn test_postgres_double_dash_no_space_is_comment() {
    // PostgreSQL: '--comment' IS a comment (no space required)
    let sql = "SELECT 1 --comment";
    let d = postgres();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "PG '--comment' should be trivia, got: {:?}",
        kinds
    );
}

#[test]
fn test_mysql_expression_with_double_minus() {
    // Real-world MySQL: SELECT a - -b (should not be confused with comment)
    let sql = "SELECT a - -b";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    // SELECT, a, -, -, b
    assert_eq!(
        kinds.len(),
        5,
        "MySQL 'a - -b' should be 5 tokens, got: {:?}",
        kinds
    );
}

#[test]
fn test_mysql_decrement_pattern() {
    // MySQL: SET @x = @x--1 (decrement by 1)
    // This is @x - (-1), not @x followed by comment
    let sql = "SELECT @x--1";
    let d = mysql();
    let kinds = token_kinds(sql, &*d);
    // Should NOT eat '--1' as a comment
    assert!(
        kinds.len() > 2,
        "MySQL '@x--1' should not treat --1 as comment, got: {:?}",
        kinds
    );
}

// ============================================================================
// MySQL /*!...*/ version comments
// ============================================================================

#[test]
fn test_mysql_version_comment_detected() {
    // MySQL: /*!50100 PARTITION BY HASH(id) */ is a version comment
    let sql = "SELECT 1 /*!50100 PARTITION BY HASH(id) */";
    let d = mysql();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        trivia.contains(&TriviaKind::MysqlVersionComment),
        "MySQL /*! should be MysqlVersionComment, got: {:?}",
        trivia
    );
}

#[test]
fn test_mysql_version_comment_without_version_number() {
    // MySQL: /*! SQL */ (no version number) is also executable
    let sql = "SELECT 1 /*! SOME SQL */";
    let d = mysql();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        trivia.contains(&TriviaKind::MysqlVersionComment),
        "MySQL /*! without version should still be MysqlVersionComment, got: {:?}",
        trivia
    );
}

#[test]
fn test_mysql_regular_block_comment_not_version() {
    // MySQL: /* regular comment */ should NOT be MysqlVersionComment
    let sql = "SELECT 1 /* regular comment */";
    let d = mysql();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        !trivia.contains(&TriviaKind::MysqlVersionComment),
        "Regular MySQL comment should NOT be MysqlVersionComment, got: {:?}",
        trivia
    );
    assert!(
        trivia.contains(&TriviaKind::BlockComment),
        "Regular MySQL comment should be BlockComment"
    );
}

#[test]
fn test_mysql_optimizer_hint_comment() {
    // MySQL: /*+ hint */ — optimizer hints (starts with +, not !)
    // These are NOT version comments, just regular block comments
    let sql = "SELECT /*+ NO_INDEX(t1) */ 1";
    let d = mysql();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        !trivia.contains(&TriviaKind::MysqlVersionComment),
        "Optimizer hints should NOT be MysqlVersionComment, got: {:?}",
        trivia
    );
}

#[test]
fn test_snowflake_no_version_comments() {
    // Snowflake: /*!50100 ... */ is just a regular block comment
    let sql = "SELECT 1 /*!50100 test */";
    let d = snowflake();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        !trivia.contains(&TriviaKind::MysqlVersionComment),
        "Snowflake should NOT produce MysqlVersionComment"
    );
    assert!(trivia.contains(&TriviaKind::BlockComment));
}

#[test]
fn test_postgres_no_version_comments() {
    // PostgreSQL: /*!50100 ... */ is just a regular block comment
    let sql = "SELECT 1 /*!50100 test */";
    let d = postgres();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        !trivia.contains(&TriviaKind::MysqlVersionComment),
        "PG should NOT produce MysqlVersionComment"
    );
    assert!(trivia.contains(&TriviaKind::BlockComment));
}

#[test]
fn test_mysql_version_comment_content_preserved() {
    // The version comment span should include the full /*!...*/ text
    let sql = "SELECT /*!50100 PARTITION BY HASH(id) */ 1";
    let d = mysql();
    let result = tokenize_with_dialect(sql, &*d);
    let mut found = false;
    for tok in &result.tokens {
        for t in &tok.leading_trivia {
            if t.kind == TriviaKind::MysqlVersionComment {
                let text = &sql[t.span.start as usize..t.span.end as usize];
                assert!(
                    text.starts_with("/*!"),
                    "Version comment should start with /*!, got: '{}'",
                    text
                );
                assert!(
                    text.ends_with("*/"),
                    "Version comment should end with */, got: '{}'",
                    text
                );
                assert!(
                    text.contains("PARTITION"),
                    "Version comment should contain SQL content, got: '{}'",
                    text
                );
                found = true;
            }
        }
        for t in &tok.trailing_trivia {
            if t.kind == TriviaKind::MysqlVersionComment {
                let text = &sql[t.span.start as usize..t.span.end as usize];
                assert!(
                    text.starts_with("/*!"),
                    "Version comment should start with /*!, got: '{}'",
                    text
                );
                assert!(
                    text.ends_with("*/"),
                    "Version comment should end with */, got: '{}'",
                    text
                );
                assert!(
                    text.contains("PARTITION"),
                    "Version comment should contain SQL content, got: '{}'",
                    text
                );
                found = true;
            }
        }
    }
    assert!(found, "Should have found a MysqlVersionComment trivia");
}

// ============================================================================
// Dialect trait method tests
// ============================================================================

#[test]
fn test_trait_backslash_escapes_in_single_quoted_strings() {
    assert!(
        snowflake().backslash_escapes_in_single_quoted_strings(),
        "Snowflake should have backslash escapes in single-quoted strings"
    );
    assert!(
        !postgres().backslash_escapes_in_single_quoted_strings(),
        "PostgreSQL should NOT have backslash escapes in regular single-quoted strings"
    );
    assert!(
        mysql().backslash_escapes_in_single_quoted_strings(),
        "MySQL should have backslash escapes in single-quoted strings"
    );
}

#[test]
fn test_trait_requires_space_after_double_dash() {
    assert!(!snowflake().requires_space_after_double_dash());
    assert!(!postgres().requires_space_after_double_dash());
    assert!(mysql().requires_space_after_double_dash());
}

#[test]
fn test_trait_supports_nested_block_comments() {
    assert!(!snowflake().supports_nested_block_comments());
    assert!(postgres().supports_nested_block_comments());
    assert!(!mysql().supports_nested_block_comments());
}

#[test]
fn test_trait_supports_version_comments() {
    assert!(!snowflake().supports_version_comments());
    assert!(!postgres().supports_version_comments());
    assert!(mysql().supports_version_comments());
}

// ============================================================================
// Cross-dialect comparison tests
// ============================================================================

#[test]
fn test_cross_dialect_backslash_string_diverges() {
    // The same SQL produces different tokenization across dialects
    let sql = r"SELECT 'a\'b'";

    let sf_kinds = token_kinds(sql, &*snowflake());
    let my_kinds = token_kinds(sql, &*mysql());
    let pg_kinds = token_kinds(sql, &*postgres());

    // Snowflake and MySQL: 2 tokens (SELECT + string with escaped quote)
    assert_eq!(
        sf_kinds.len(),
        2,
        "Snowflake should handle backslash escape: {:?}",
        sf_kinds
    );
    assert_eq!(
        my_kinds.len(),
        2,
        "MySQL should handle backslash escape: {:?}",
        my_kinds
    );

    // PostgreSQL: more than 2 tokens (backslash is literal, quote closes string)
    assert!(
        pg_kinds.len() > 2,
        "PG should NOT handle backslash escape in regular string: {:?}",
        pg_kinds
    );
}

#[test]
fn test_cross_dialect_double_dash_diverges() {
    // Same SQL, different comment behavior
    let sql = "SELECT x--y";

    let sf_kinds = token_kinds(sql, &*snowflake());
    let my_kinds = token_kinds(sql, &*mysql());
    let pg_kinds = token_kinds(sql, &*postgres());

    // Snowflake: 2 tokens (SELECT, x) — '--y' is a comment
    assert_eq!(
        sf_kinds.len(),
        2,
        "Snowflake should treat --y as comment: {:?}",
        sf_kinds
    );
    // PostgreSQL: 2 tokens (SELECT, x) — '--y' is a comment
    assert_eq!(
        pg_kinds.len(),
        2,
        "PG should treat --y as comment: {:?}",
        pg_kinds
    );
    // MySQL: 5 tokens (SELECT, x, -, -, y) — '--y' is NOT a comment
    assert!(
        my_kinds.len() >= 4,
        "MySQL should NOT treat --y as comment: {:?}",
        my_kinds
    );
}

#[test]
fn test_cross_dialect_nested_comment_diverges() {
    // Same SQL, nested comment behavior differs
    let sql = "/* a /* b */ c */ SELECT 1";

    let pg_kinds = token_kinds(sql, &*postgres());
    let sf_kinds = token_kinds(sql, &*snowflake());

    // PostgreSQL: nested comment fully consumed, then SELECT, 1
    assert_eq!(
        pg_kinds.len(),
        2,
        "PG nested comment should be 2 tokens: {:?}",
        pg_kinds
    );

    // Snowflake: first */ closes comment, then 'c', '*/', SELECT, 1
    assert!(
        sf_kinds.len() > 2,
        "Snowflake should close at first */: {:?}",
        sf_kinds
    );
}

#[test]
fn test_cross_dialect_version_comment_diverges() {
    // Version comment is special in MySQL, regular in others
    let sql = "SELECT 1 /*!50100 EXTRA */";

    let my_trivia = all_trivia_kinds(sql, &*mysql());
    let sf_trivia = all_trivia_kinds(sql, &*snowflake());
    let pg_trivia = all_trivia_kinds(sql, &*postgres());

    assert!(my_trivia.contains(&TriviaKind::MysqlVersionComment));
    assert!(!sf_trivia.contains(&TriviaKind::MysqlVersionComment));
    assert!(!pg_trivia.contains(&TriviaKind::MysqlVersionComment));
}

// ============================================================================
// MSSQL nested block comments
// ============================================================================

#[test]
fn test_mssql_nested_block_comment_basic() {
    // T-SQL supports nested block comments like PostgreSQL
    let sql = "/* outer /* inner */ still comment */ SELECT 1";
    let d = mssql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MSSQL nested comment should be fully consumed as trivia, got: {:?}",
        kinds
    );
    let lexemes = token_lexemes(sql, &*d);
    assert_eq!(lexemes[0], "SELECT");
    assert_eq!(lexemes[1], "1");
}

#[test]
fn test_mssql_nested_block_comment_double_nested() {
    let sql = "/* a /* b /* c */ b */ a */ SELECT 1";
    let d = mssql();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "MSSQL double-nested comment should be fully consumed, got: {:?}",
        kinds
    );
}

#[test]
fn test_mssql_nested_comment_trivia_kind() {
    let sql = "/* outer /* inner */ end */ SELECT 1";
    let d = mssql();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        trivia.contains(&TriviaKind::BlockComment),
        "MSSQL nested comment should be BlockComment trivia, got: {:?}",
        trivia
    );
}

#[test]
fn test_cross_dialect_nested_comment_mssql_vs_mysql() {
    // MSSQL supports nesting, MySQL does not
    let sql = "/* a /* b */ c */ SELECT 1";
    let ms_kinds = token_kinds(sql, &*mssql());
    let my_kinds = token_kinds(sql, &*mysql());

    // MSSQL: full nesting → 2 tokens (SELECT, 1)
    assert_eq!(ms_kinds.len(), 2, "MSSQL: {:?}", ms_kinds);
    // MySQL: closes at first */ → more tokens
    assert!(
        my_kinds.len() > 2,
        "MySQL should close at first */: {:?}",
        my_kinds
    );
}

// ============================================================================
// MSSQL @variables and #temp_tables format round-trip
// ============================================================================

#[test]
fn test_mssql_at_variable_format_roundtrip() {
    let sql = "SELECT @count AS cnt FROM t WHERE @count > 0";
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = mssql();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .expect("MSSQL @var format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("MSSQL @var formatting should be safe");
}

#[test]
fn test_mssql_system_variable_format_roundtrip() {
    let sql = "SELECT @@ROWCOUNT, @@ERROR";
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = mssql();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .expect("MSSQL @@var format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("MSSQL @@var formatting should be safe");
}

#[test]
fn test_mssql_temp_table_format_roundtrip() {
    let sql = "SELECT * FROM #temp_table WHERE id > 10";
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = mssql();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .expect("MSSQL #temp format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("MSSQL #temp formatting should be safe");
}

#[test]
fn test_mssql_global_temp_table_format_roundtrip() {
    let sql = "SELECT * FROM ##global_temp WHERE status = 'active'";
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = mssql();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .expect("MSSQL ##temp format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("MSSQL ##temp formatting should be safe");
}

#[test]
fn test_mssql_mixed_at_hash_format_roundtrip() {
    // Mix @vars and #temp in one statement
    let sql = "SELECT @page_size AS ps FROM #results WHERE @@ROWCOUNT > @min_rows";
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = mssql();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .expect("MSSQL mixed @/# format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("MSSQL mixed @/# formatting should be safe");
}

// ============================================================================
// BigQuery backtick identifiers and # line comments
// ============================================================================

#[test]
fn test_bigquery_backtick_format_roundtrip() {
    let sql = "SELECT `column_name` FROM `project.dataset.table`";
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = bigquery();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .expect("BQ backtick format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("BQ backtick formatting should be safe");
}

#[test]
fn test_bigquery_hash_line_comment() {
    // BigQuery: # starts a line comment
    let sql = "SELECT 1 # this is a comment";
    let d = bigquery();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "BQ # should be comment trivia, got: {:?}",
        kinds
    );
}

#[test]
fn test_bigquery_hash_comment_format_roundtrip() {
    let sql = "SELECT 1 # comment here\n, 2";
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = bigquery();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .expect("BQ hash comment format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("BQ hash comment formatting should be safe");
}

#[test]
fn test_mssql_no_nested_version_comment() {
    // MSSQL does NOT have MySQL-style version comments
    let sql = "SELECT 1 /*!50100 test */";
    let d = mssql();
    let trivia = all_trivia_kinds(sql, &*d);
    assert!(
        !trivia.contains(&TriviaKind::MysqlVersionComment),
        "MSSQL should NOT produce MysqlVersionComment"
    );
    assert!(trivia.contains(&TriviaKind::BlockComment));
}

#[test]
fn test_bq_no_nested_block_comment() {
    // BigQuery does NOT support nested block comments
    let sql = "/* outer /* inner */ SELECT 1";
    let d = bigquery();
    let kinds = token_kinds(sql, &*d);
    assert_eq!(
        kinds.len(),
        2,
        "BQ should close at first */, got: {:?}",
        kinds
    );
}

// ============================================================================
// Trait method tests for MSSQL and BigQuery
// ============================================================================

#[test]
fn test_mssql_trait_nested_comments() {
    assert!(
        mssql().supports_nested_block_comments(),
        "MSSQL should support nested block comments"
    );
}

#[test]
fn test_bq_trait_nested_comments() {
    assert!(
        !bigquery().supports_nested_block_comments(),
        "BigQuery should NOT support nested block comments"
    );
}

#[test]
fn test_mssql_trait_no_version_comments() {
    assert!(
        !mssql().supports_version_comments(),
        "MSSQL should NOT support MySQL version comments"
    );
}

#[test]
fn test_bq_trait_no_version_comments() {
    assert!(
        !bigquery().supports_version_comments(),
        "BigQuery should NOT support MySQL version comments"
    );
}
