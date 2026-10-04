// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Integration tests for the dialect system.
///
/// These tests exercise the full pipeline (lex → parse → format → verify)
/// with non-Snowflake dialects, ensuring the dialect wiring works end-to-end.
///
/// Test categories:
///   1. Format round-trip per dialect (format + verify_formatting_safe)
///   2. MySQL dialect trait properties (parity with PG/SF trait test files)
///   3. Lexer edge cases (unterminated strings, empty tags, EOF)
///   4. Multi-statement dialect scripts
///   5. Cross-dialect: same SQL, different formatting behavior
///   6. Risk analysis with dialect (analyze_risk_with_policy_config)
use lexega_core::dialect::{
    bigquery, mssql, mysql, postgres, MySqlDialect, PostgresDialect, SnowflakeDialect,
};
use lexega_core::lexer::tokenize_with_dialect;
use lexega_core::{format_sql_with_config, Dialect, FormatterConfig, TokenKind};

// ============================================================================
// Helpers
// ============================================================================

fn pg_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = postgres();
    config
}

fn mysql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mysql();
    config
}

fn sf_config() -> FormatterConfig {
    FormatterConfig::default() // Snowflake is the default
}

/// Format and verify round-trip safety for a given dialect config.
fn format_and_verify(sql: &str, config: &FormatterConfig) {
    let formatted = format_sql_with_config(sql, config)
        .unwrap_or_else(|e| panic!("Format failed for {}: {}", config.dialect.name(), e));

    lexega_core::verify_formatting_safe_with_dialect(&sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "{} formatting verification failed: {}",
                config.dialect.name(),
                e
            )
        });
}

// ============================================================================
// 1. FORMAT ROUND-TRIP: PostgreSQL
// ============================================================================

#[test]
fn test_pg_format_simple_select() {
    let sql = "SELECT id, name FROM users WHERE active = true";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_pg_format_with_estring() {
    let sql = r"SELECT E'hello\nworld' AS greeting FROM t";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_pg_format_with_dollar_quote() {
    let sql = "SELECT $$body text$$ AS body FROM t";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_pg_format_with_named_dollar_tag() {
    let sql = "SELECT $fn$SELECT 1;$fn$ AS func_body FROM t";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_pg_format_with_type_cast() {
    // PostgreSQL :: cast operator
    let sql = "SELECT '2024-01-01'::DATE AS d FROM t";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_pg_format_returning_clause() {
    let sql = "INSERT INTO users (name) VALUES ('alice') RETURNING id, name";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_pg_format_distinct_on() {
    let sql =
        "SELECT DISTINCT ON (user_id) user_id, name FROM users ORDER BY user_id, created_at DESC";
    format_and_verify(sql, &pg_config());
}

// ============================================================================
// 2. FORMAT ROUND-TRIP: MySQL
// ============================================================================

#[test]
fn test_mysql_format_simple_select() {
    let sql = "SELECT id, name FROM users WHERE active = 1";
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_mysql_format_backtick_identifiers() {
    let sql = "SELECT `id`, `name` FROM `users` WHERE `status` = 'active'";
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_mysql_format_double_quote_string() {
    let sql = r#"SELECT id FROM users WHERE name = "alice""#;
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_mysql_format_backtick_with_spaces() {
    let sql = "SELECT `user id`, `full name` FROM `my table`";
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_mysql_format_hash_comment() {
    let sql = "SELECT 1 # this is a comment\n, 2";
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_mysql_format_limit_offset() {
    let sql = "SELECT id FROM users ORDER BY id LIMIT 10 OFFSET 20";
    format_and_verify(sql, &mysql_config());
}

// ============================================================================
// 3. FORMAT ROUND-TRIP: Cross-Dialect (same SQL, all dialects)
// ============================================================================

#[test]
fn test_ansi_sql_formats_in_all_dialects() {
    // Pure ANSI SQL should survive formatting in every dialect
    let sql = "SELECT a, b, c FROM t1 INNER JOIN t2 ON t1.id = t2.id WHERE a > 10 ORDER BY b";

    format_and_verify(sql, &sf_config());
    format_and_verify(sql, &pg_config());
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_cte_formats_in_all_dialects() {
    let sql = "WITH cte AS (SELECT id, name FROM users WHERE active = 1) SELECT * FROM cte";

    format_and_verify(sql, &sf_config());
    format_and_verify(sql, &pg_config());
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_subquery_formats_in_all_dialects() {
    let sql =
        "SELECT * FROM (SELECT id, count(*) AS cnt FROM orders GROUP BY id) sub WHERE cnt > 5";

    format_and_verify(sql, &sf_config());
    format_and_verify(sql, &pg_config());
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_aggregate_formats_in_all_dialects() {
    let sql = "SELECT department, COUNT(*), SUM(salary), AVG(age) FROM employees GROUP BY department HAVING COUNT(*) > 10";

    format_and_verify(sql, &sf_config());
    format_and_verify(sql, &pg_config());
    format_and_verify(sql, &mysql_config());
}

// ============================================================================
// 4. MULTI-STATEMENT: Dialect-specific scripts
// ============================================================================

#[test]
fn test_pg_multi_statement_script() {
    let sql = "\
SELECT id FROM users;\n\
INSERT INTO log (msg) VALUES ('test');\n\
SELECT count(*) FROM orders WHERE total > 100;\
";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_mysql_multi_statement_script() {
    let sql = "\
SELECT `id` FROM `users`;\n\
INSERT INTO `log` (`msg`) VALUES ('test');\n\
SELECT count(*) FROM `orders` WHERE `total` > 100;\
";
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_pg_estring_multi_statement() {
    let sql = "\
SELECT E'line1\\nline2' AS msg;\n\
SELECT E'tab\\there' AS tabbed;\
";
    format_and_verify(sql, &pg_config());
}

// ============================================================================
// 5. MYSQL TRAIT PROPERTIES (parity with test_postgres_dialect.rs)
// ============================================================================

#[test]
fn test_mysql_dialect_name() {
    let d = mysql();
    assert_eq!(d.name(), "mysql");
}

#[test]
fn test_mysql_reserved_keywords() {
    let d = MySqlDialect;

    // Core SQL (shared)
    assert!(d.is_reserved_keyword("SELECT"));
    assert!(d.is_reserved_keyword("FROM"));
    assert!(d.is_reserved_keyword("WHERE"));
    assert!(d.is_reserved_keyword("JOIN"));

    // Non-keywords
    assert!(!d.is_reserved_keyword("foo"));
    assert!(!d.is_reserved_keyword("my_table"));
}

#[test]
fn test_mysql_keyword_case_insensitivity() {
    let d = MySqlDialect;
    assert!(d.is_reserved_keyword("SELECT"));
    assert!(d.is_reserved_keyword("select"));
    assert!(d.is_reserved_keyword("Select"));
    assert!(d.is_keyword("LIMIT"));
    assert!(d.is_keyword("limit"));
}

#[test]
fn test_mysql_identifier_rules() {
    let d = MySqlDialect;
    assert_eq!(d.identifier_quote_char(), '`');
    assert_eq!(d.max_identifier_length(), Some(64));
    assert!(!d.unquoted_identifiers_case_sensitive());
}

#[test]
fn test_mysql_string_rules() {
    let d = MySqlDialect;
    assert_eq!(d.string_quote_char(), '\'');
    assert!(d.supports_double_quoted_strings()); // MySQL uses " for strings
    assert!(d.supports_string_escapes());
}

#[test]
fn test_mysql_operator_support() {
    let d = MySqlDialect;

    // || is logical OR in MySQL, not concat
    assert!(!d.pipe_pipe_is_concat());

    // JSON operators (->)
    assert!(d.supports_json_operators());

    // No :: type cast
    assert!(!d.supports_type_cast_operator());
}

#[test]
fn test_mysql_statement_support() {
    let d = MySqlDialect;

    assert!(d.supports_cte());
    assert!(d.supports_lateral());
    assert!(d.supports_window_functions());

    // MySQL-specific absences
    assert!(!d.supports_merge());
    assert!(!d.supports_qualify());
    assert!(!d.supports_time_travel());
    assert!(!d.supports_pivot());
    assert!(!d.supports_unpivot());
    assert!(!d.supports_flatten());
    assert!(!d.supports_sample());
}

#[test]
fn test_mysql_comment_rules() {
    let d = MySqlDialect;
    assert!(d.hash_is_line_comment());
    assert!(!d.supports_nested_block_comments());
}

#[test]
fn test_mysql_vs_snowflake_differences() {
    let m = MySqlDialect;
    let s = SnowflakeDialect;

    // Identifier quoting differs
    assert_eq!(m.identifier_quote_char(), '`');
    assert_eq!(s.identifier_quote_char(), '"');

    // Double-quote semantics differ
    assert!(m.supports_double_quoted_strings());
    assert!(!s.supports_double_quoted_strings());

    // Hash semantics differ
    assert!(m.hash_is_line_comment());
    assert!(!s.hash_is_line_comment());

    // || semantics differ
    assert!(!m.pipe_pipe_is_concat());
    assert!(s.pipe_pipe_is_concat());

    // Type cast operator
    assert!(!m.supports_type_cast_operator());
    assert!(s.supports_type_cast_operator());

    // Merge
    assert!(!m.supports_merge());
    assert!(s.supports_merge());
}

#[test]
fn test_mysql_vs_postgres_differences() {
    let m = MySqlDialect;
    let p = PostgresDialect;

    // Identifier quoting
    assert_eq!(m.identifier_quote_char(), '`');
    assert_eq!(p.identifier_quote_char(), '"');

    // Double-quote semantics
    assert!(m.supports_double_quoted_strings());
    assert!(!p.supports_double_quoted_strings());

    // Hash comments
    assert!(m.hash_is_line_comment());
    assert!(!p.hash_is_line_comment());

    // || is concat in PG, OR in MySQL
    assert!(!m.pipe_pipe_is_concat());
    assert!(p.pipe_pipe_is_concat());

    // E-strings and dollar-quotes
    assert!(!m.supports_escape_string_literals());
    assert!(p.supports_escape_string_literals());
    assert!(!m.supports_dollar_quoted_strings());
    assert!(p.supports_dollar_quoted_strings());

    // Max identifier length
    assert_eq!(m.max_identifier_length(), Some(64));
    assert_eq!(p.max_identifier_length(), Some(63));

    // Merge
    assert!(!m.supports_merge());
    assert!(p.supports_merge()); // PG 15+
}

// ============================================================================
// 6. LEXER EDGE CASES
// ============================================================================

#[test]
fn test_pg_empty_dollar_quote() {
    // $$$$ — empty body between dollar tags
    let sql = "SELECT $$$$ AS empty_body";
    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let kinds: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect();

    // Should have at least SELECT, the dollar-quoted string, AS, empty_body
    assert!(
        kinds.len() >= 3,
        "Should tokenize empty dollar-quote, got {:?}",
        kinds
    );
    // No Unknown tokens
    assert!(
        !kinds.iter().any(|k| matches!(k, TokenKind::Unknown)),
        "Empty dollar-quote should not produce Unknown tokens"
    );
}

#[test]
fn test_pg_dollar_quote_with_single_quotes_inside() {
    // Dollar-quoting is specifically designed to avoid quote escaping
    let sql = "SELECT $$it's got 'quotes' and ''doubles''$$ AS val";
    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let sig: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    // The dollar-quoted string should be a single token
    assert!(sig
        .iter()
        .any(|t| matches!(t.kind, TokenKind::Literal(lexega_core::LiteralKind::String))));
}

#[test]
fn test_pg_estring_empty() {
    let sql = "SELECT E'' AS empty_escape";
    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let kinds: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect();
    // E'' should be one string token
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, TokenKind::Literal(lexega_core::LiteralKind::String))),
        "Empty E-string should be a string literal, got {:?}",
        kinds
    );
}

#[test]
fn test_pg_estring_with_backslash_at_end() {
    let sql = r"SELECT E'trailing backslash\\' AS val";
    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let kinds: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect();
    // Should parse without panic or error
    assert!(
        kinds.len() >= 3,
        "Should tokenize E-string with trailing backslash"
    );
}

#[test]
fn test_mysql_backtick_empty() {
    // `` — empty backtick identifier
    let sql = "SELECT `` AS empty_id";
    let result = tokenize_with_dialect(sql, &MySqlDialect);
    let sig: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    // Should not panic — just produces tokens
    assert!(sig.len() >= 3, "Should handle empty backtick identifier");
}

#[test]
fn test_mysql_backtick_with_special_chars() {
    let sql = "SELECT `col-with-dashes`, `col.with.dots`, `col with spaces` FROM `t`";
    let result = tokenize_with_dialect(sql, &MySqlDialect);
    let kinds: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect();
    // All backtick-quoted names should be quoted identifiers
    let quoted_count = kinds
        .iter()
        .filter(|k| {
            matches!(
                k,
                TokenKind::Identifier {
                    kind: lexega_core::IdentifierKind::Quoted
                }
            )
        })
        .count();
    assert!(
        quoted_count >= 4,
        "Should have 4 quoted identifiers (3 cols + table), got {}",
        quoted_count
    );
}

#[test]
fn test_mysql_consecutive_hash_comments() {
    let sql = "# comment 1\n# comment 2\nSELECT 1";
    let result = tokenize_with_dialect(sql, &MySqlDialect);
    let sig: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    // Only significant tokens should be SELECT and 1
    assert_eq!(
        sig.len(),
        2,
        "Two consecutive hash comments should both be trivia, got {:?}",
        sig.iter().map(|t| t.lexeme(sql)).collect::<Vec<_>>()
    );
}

#[test]
fn test_pg_dollar_tag_with_numbers() {
    // Dollar tags can contain digits (after first char). Dollar-quoted regions
    // now lex as opener + inner + closer in the single canonical stream (so
    // PG/Redshift procedure bodies become first-class analyzable statements,
    // converging on Snowflake's token shape). At the LEXER level a bare
    // `$tag1$...$tag1$` is therefore three significant tokens: the two
    // delimiters (Identifier, lexeme `$tag1$`) bracketing the inner content;
    // the matching close tag is still located correctly.
    let sql = "$tag1$content$tag1$";
    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let sig: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    assert_eq!(
        sig.len(),
        3,
        "opener + inner + closer, got {:?}",
        sig.iter().map(|t| t.lexeme(sql)).collect::<Vec<_>>()
    );
    assert_eq!(sig[0].lexeme(sql), "$tag1$", "opening delimiter");
    assert_eq!(sig[1].lexeme(sql), "content", "inner content");
    assert_eq!(
        sig[2].lexeme(sql),
        "$tag1$",
        "closing delimiter matches opener"
    );

    // Value/opacity is unchanged at the parser level: at expression position the
    // run reassembles to a single string literal that round-trips verbatim.
    let mut cfg = FormatterConfig::default();
    cfg.dialect = postgres();
    let out = format_sql_with_config("SELECT $tag1$content$tag1$ AS c;", &cfg)
        .expect("dollar-quoted literal should format");
    assert!(
        out.contains("$tag1$content$tag1$"),
        "literal preserved verbatim, got: {out}"
    );
}

#[test]
fn test_pg_dollar_tag_case_sensitive() {
    // Dollar tags are case-sensitive: a region opened with `$Fn$` closes only on
    // an exact `$Fn$`. With the canonical 3-token shape the matched region is
    // opener + inner + closer.
    let sql = "$Fn$body$Fn$";
    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let sig: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    assert_eq!(
        sig.len(),
        3,
        "matched $Fn$ tag closes: opener + inner + closer, got {:?}",
        sig.iter().map(|t| t.lexeme(sql)).collect::<Vec<_>>()
    );
    assert_eq!(sig[0].lexeme(sql), "$Fn$", "opening delimiter");
    assert_eq!(
        sig[2].lexeme(sql),
        "$Fn$",
        "closer matches opener case-sensitively"
    );

    // Negative: a case-mismatched close tag does NOT close the region. With no
    // exact `$Fn$` to find, the opaque close-scan finds no close and the whole
    // run stays a single token (tag matching is byte-exact). An unterminated
    // dollar-quote is lexically invalid, so it surfaces as `Unknown` — the
    // parser rejects it (→ OpaqueContent) instead of accepting a literal that
    // silently swallows the rest of the input.
    let mismatched = "$Fn$body$fn$";
    let r2 = tokenize_with_dialect(mismatched, &PostgresDialect);
    let sig2: Vec<_> = r2
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    assert_eq!(
        sig2.len(),
        1,
        "case-mismatched close tag does not close; whole run is one token, got {:?}",
        sig2.iter()
            .map(|t| t.lexeme(mismatched))
            .collect::<Vec<_>>()
    );
    assert!(matches!(sig2[0].kind, TokenKind::Unknown));
}

// ============================================================================
// 7. DIALECT FACTORY FUNCTIONS
// ============================================================================

#[test]
fn test_factory_functions_return_correct_dialects() {
    use lexega_core::dialect::{mysql, postgres, snowflake};

    assert_eq!(snowflake().name(), "snowflake");
    assert_eq!(postgres().name(), "postgresql");
    assert_eq!(mysql().name(), "mysql");
}

#[test]
fn test_dialect_ref_is_arc_clonable() {
    let d = postgres();
    let d2 = d.clone(); // Arc clone
    assert_eq!(d.name(), d2.name());
}

#[test]
fn test_formatter_config_accepts_dialect_ref() {
    // Verify the wiring: FormatterConfig.dialect = DialectRef
    let mut config = FormatterConfig::default();
    assert_eq!(config.dialect.name(), "snowflake"); // default

    config.dialect = postgres();
    assert_eq!(config.dialect.name(), "postgresql");

    config.dialect = mysql();
    assert_eq!(config.dialect.name(), "mysql");
}

// ============================================================================
// 8. REALISTIC QUERIES PER DIALECT
// ============================================================================

#[test]
fn test_pg_realistic_analytics_query() {
    let sql = "\
SELECT
    u.id,
    u.name,
    count(o.id) AS order_count,
    sum(o.total) AS total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.created_at >= '2024-01-01'::DATE
GROUP BY u.id, u.name
HAVING sum(o.total) > 100
ORDER BY total_spent DESC";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_pg_window_function_query() {
    let sql = "\
SELECT
    department,
    employee,
    salary,
    rank() OVER (PARTITION BY department ORDER BY salary DESC) AS dept_rank,
    lag(salary) OVER (PARTITION BY department ORDER BY salary) AS prev_salary
FROM employees";
    format_and_verify(sql, &pg_config());
}

#[test]
fn test_mysql_realistic_join_query() {
    let sql = "\
SELECT
    `u`.`id`,
    `u`.`name`,
    `o`.`total`,
    `p`.`name` AS `product_name`
FROM `users` `u`
INNER JOIN `orders` `o` ON `u`.`id` = `o`.`user_id`
INNER JOIN `order_items` `oi` ON `o`.`id` = `oi`.`order_id`
INNER JOIN `products` `p` ON `oi`.`product_id` = `p`.`id`
WHERE `o`.`status` = 'completed'
ORDER BY `o`.`total` DESC
LIMIT 50";
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_mysql_realistic_insert() {
    let sql = "\
INSERT INTO `audit_log` (`user_id`, `action`, `created_at`)
VALUES (1, 'login', NOW()), (2, 'logout', NOW())";
    format_and_verify(sql, &mysql_config());
}

#[test]
fn test_pg_cte_with_dollar_quote() {
    let sql = "\
WITH raw AS (
    SELECT id, $$raw body$$ AS body FROM source
)
SELECT * FROM raw WHERE body IS NOT NULL";
    format_and_verify(sql, &pg_config());
}

// ============================================================================
// 9. RISK ANALYSIS WITH DIALECT
// ============================================================================

fn pg_analysis_config() -> lexega_core::analyzer::AnalysisConfig {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(postgres());
    config
}

fn mysql_analysis_config() -> lexega_core::analyzer::AnalysisConfig {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mysql());
    config
}

fn mssql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mssql();
    config
}

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = bigquery();
    config
}

fn mssql_analysis_config() -> lexega_core::analyzer::AnalysisConfig {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mssql());
    config
}

fn bq_analysis_config() -> lexega_core::analyzer::AnalysisConfig {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    config
}

#[test]
fn test_pg_risk_analysis_basic_select() {
    let sql = "SELECT id, name FROM users WHERE active = true";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &pg_analysis_config())
        .expect("PG risk analysis should succeed");
    // Should parse and analyze without error
    assert!(
        report.summary.statements_parsed >= 1,
        "Should parse at least 1 statement with PG dialect"
    );
}

#[test]
fn test_pg_risk_analysis_with_estring() {
    // E-strings are PG-only — without dialect, E would be parsed as an identifier
    let sql = r"SELECT E'hello\nworld' AS greeting FROM users";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &pg_analysis_config())
        .expect("PG risk analysis with E-string should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_pg_risk_analysis_with_dollar_quote() {
    let sql = "SELECT $$body text$$ AS body FROM documents";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &pg_analysis_config())
        .expect("PG risk analysis with dollar-quote should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_mysql_risk_analysis_basic_select() {
    let sql = "SELECT id, name FROM users WHERE active = 1";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
        .expect("MySQL risk analysis should succeed");
    assert!(
        report.summary.statements_parsed >= 1,
        "Should parse at least 1 statement with MySQL dialect"
    );
}

#[test]
fn test_mysql_risk_analysis_with_backticks() {
    let sql = "SELECT `id`, `name` FROM `users` WHERE `status` = 'active'";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
        .expect("MySQL risk analysis with backticks should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_mysql_risk_analysis_with_double_quote_string() {
    // In MySQL, "active" is a string literal — must be parsed as such
    let sql = r#"SELECT id FROM users WHERE status = "active""#;
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
        .expect("MySQL risk analysis with double-quote string should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_pg_risk_multi_statement() {
    let sql = "\
SELECT id FROM users;\n\
INSERT INTO log (msg) VALUES ('test');\n\
DELETE FROM sessions WHERE expired = true;\
";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &pg_analysis_config())
        .expect("PG multi-statement risk analysis should succeed");
    assert!(
        report.summary.statements_parsed >= 3,
        "Should parse all 3 statements, got {}",
        report.summary.statements_parsed
    );
}

#[test]
fn test_mysql_risk_multi_statement() {
    let sql = "\
SELECT `id` FROM `users`;\n\
INSERT INTO `log` (`msg`) VALUES ('test');\n\
DELETE FROM `sessions` WHERE `expired` = 1;\
";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
        .expect("MySQL multi-statement risk analysis should succeed");
    assert!(
        report.summary.statements_parsed >= 3,
        "Should parse all 3 statements, got {}",
        report.summary.statements_parsed
    );
}

#[test]
fn test_risk_default_config_uses_snowflake() {
    // Default AnalysisConfig should have dialect: None → Snowflake parsing
    let config = lexega_core::analyzer::AnalysisConfig::default();
    assert!(
        config.dialect.is_none(),
        "Default config should have no dialect override"
    );

    // Snowflake-style SQL should work fine with default config
    let sql = "SELECT * FROM t QUALIFY row_number() OVER (ORDER BY x) = 1";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("Default (Snowflake) risk analysis should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_risk_cross_dialect_ansi_sql() {
    // Pure ANSI SQL should produce reports in all dialects
    let sql = "SELECT a, b FROM t1 INNER JOIN t2 ON t1.id = t2.id WHERE a > 10";

    let sf_report = lexega_core::api::analyze_risk_with_policy_config(
        sql,
        &lexega_core::analyzer::AnalysisConfig::default(),
    )
    .expect("SF analysis should succeed");

    let pg_report = lexega_core::api::analyze_risk_with_policy_config(sql, &pg_analysis_config())
        .expect("PG analysis should succeed");

    let my_report =
        lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
            .expect("MySQL analysis should succeed");

    let ms_report =
        lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
            .expect("MSSQL analysis should succeed");

    let bq_report = lexega_core::api::analyze_risk_with_policy_config(sql, &bq_analysis_config())
        .expect("BigQuery analysis should succeed");

    // All should parse 1 statement
    assert_eq!(sf_report.summary.statements_parsed, 1);
    assert_eq!(pg_report.summary.statements_parsed, 1);
    assert_eq!(my_report.summary.statements_parsed, 1);
    assert_eq!(ms_report.summary.statements_parsed, 1);
    assert_eq!(bq_report.summary.statements_parsed, 1);
}

// ============================================================================
// 10. MSSQL RISK ANALYSIS
// ============================================================================

#[test]
fn test_mssql_risk_analysis_basic_select() {
    let sql = "SELECT id, name FROM users WHERE active = 1";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("MSSQL risk analysis should succeed");
    assert!(
        report.summary.statements_parsed >= 1,
        "Should parse at least 1 statement"
    );
}

#[test]
fn test_mssql_risk_analysis_delete_no_where() {
    let sql = "DELETE FROM orders";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("MSSQL risk analysis should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_mssql_risk_analysis_cross_join() {
    let sql = "SELECT a.*, b.* FROM users a CROSS JOIN orders b";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mssql_analysis_config())
        .expect("MSSQL risk analysis should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

// ============================================================================
// 11. BIGQUERY RISK ANALYSIS
// ============================================================================

#[test]
fn test_bq_risk_analysis_basic_select() {
    let sql = "SELECT id, name FROM users WHERE active = true";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &bq_analysis_config())
        .expect("BigQuery risk analysis should succeed");
    assert!(
        report.summary.statements_parsed >= 1,
        "Should parse at least 1 statement"
    );
}

#[test]
fn test_bq_risk_analysis_delete_no_where() {
    let sql = "DELETE FROM orders";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &bq_analysis_config())
        .expect("BigQuery risk analysis should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

#[test]
fn test_bq_risk_analysis_cross_join() {
    let sql = "SELECT a.*, b.* FROM table_a a CROSS JOIN table_b b";
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &bq_analysis_config())
        .expect("BigQuery risk analysis should succeed");
    assert!(report.summary.statements_parsed >= 1);
}

// ============================================================================
// 12. MSSQL FORMAT ROUND-TRIP
// ============================================================================

#[test]
fn test_mssql_format_simple_select() {
    let sql = "SELECT id, name FROM users WHERE active = 1";
    format_and_verify(sql, &mssql_config());
}

#[test]
fn test_mssql_format_bracket_identifiers() {
    let sql = "SELECT [Column Name], [Other Col] FROM [My Table]";
    format_and_verify(sql, &mssql_config());
}

#[test]
fn test_mssql_format_at_variable() {
    let sql = "SELECT @count AS cnt FROM t WHERE @count > 0";
    format_and_verify(sql, &mssql_config());
}

// ============================================================================
// 13. BIGQUERY FORMAT ROUND-TRIP
// ============================================================================

#[test]
fn test_bq_format_simple_select() {
    let sql = "SELECT id, name FROM users WHERE active = true";
    format_and_verify(sql, &bq_config());
}

#[test]
fn test_bq_format_backtick_identifiers() {
    let sql = "SELECT `column_name` FROM `project.dataset.table`";
    format_and_verify(sql, &bq_config());
}
