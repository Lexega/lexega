// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for BigQuery `@param` named query parameters (P4).
///
/// Covers:
///   1. Lexer tokenization — `@name` produces single `AtVariable` token
///   2. Format round-trip — `@param` preserved through parse → format → verify
///   3. Multiple parameters — several `@param` in one query
///   4. Path expressions — `@param.field`
///   5. Reserved keyword as parameter name — `@from`, `@select`
///   6. Positional parameter `?` — already works, regression guard
///   7. Bare `@` without identifier — produces `Unknown` token
///   8. `@@system_var` — accepted as `AtVariable` (harmless, permissive)
///   9. Multi-statement — multiple statements with `@param`
///  10. Risk analysis — statements with `@param` are parsed (not opaque)
///  11. Snowflake dialect — `@` stays `Unknown` (no cross-dialect leak)
use lexega_core::dialect::{bigquery, snowflake, BigQueryDialect};
use lexega_core::lexer::tokenize_with_dialect;
use lexega_core::lexer::Operator;
use lexega_core::{
    format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig, IdentifierKind,
    TokenKind,
};

// ============================================================================
// Helpers
// ============================================================================

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = bigquery();
    config
}

fn bq_token_kinds(sql: &str) -> Vec<TokenKind> {
    let dialect = BigQueryDialect;
    let result = tokenize_with_dialect(sql, &dialect);
    result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect()
}

fn bq_token_lexemes<'a>(sql: &'a str) -> Vec<&'a str> {
    let dialect = BigQueryDialect;
    let result = tokenize_with_dialect(sql, &dialect);
    result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.lexeme(sql))
        .collect()
}

fn format_and_verify_bq(sql: &str) -> String {
    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &formatted, &*config.dialect)
        .expect("formatting should preserve semantics");
    formatted
}

// ============================================================================
// 1. Lexer: Basic @param tokenization
// ============================================================================

#[test]
fn test_bq_at_param_single_token() {
    let kinds = bq_token_kinds("@myparam");
    assert_eq!(
        kinds,
        vec![TokenKind::Identifier {
            kind: IdentifierKind::AtVariable
        }],
        "@myparam should be a single AtVariable token"
    );
}

#[test]
fn test_bq_at_param_lexeme_includes_at() {
    let lexemes = bq_token_lexemes("@myparam");
    assert_eq!(lexemes, vec!["@myparam"]);
}

#[test]
fn test_bq_at_param_in_where() {
    let kinds = bq_token_kinds("SELECT * FROM t WHERE col = @val");
    // Find the @val token
    let at_var_count = kinds
        .iter()
        .filter(|k| {
            matches!(
                k,
                TokenKind::Identifier {
                    kind: IdentifierKind::AtVariable
                }
            )
        })
        .count();
    assert_eq!(at_var_count, 1, "Should have exactly one AtVariable token");
}

#[test]
fn test_bq_at_param_underscore_name() {
    let lexemes = bq_token_lexemes("@first_name");
    assert_eq!(lexemes, vec!["@first_name"]);
}

// ============================================================================
// 2. Lexer: Multiple parameters
// ============================================================================

#[test]
fn test_bq_multiple_at_params() {
    let kinds = bq_token_kinds("@a = @b AND @c");
    let at_var_count = kinds
        .iter()
        .filter(|k| {
            matches!(
                k,
                TokenKind::Identifier {
                    kind: IdentifierKind::AtVariable
                }
            )
        })
        .count();
    assert_eq!(at_var_count, 3, "Should have 3 AtVariable tokens");
}

// ============================================================================
// 3. Lexer: Reserved keyword as parameter name
// ============================================================================

#[test]
fn test_bq_at_param_reserved_keyword_from() {
    let lexemes = bq_token_lexemes("@from");
    assert_eq!(lexemes, vec!["@from"], "@from should be a single token");
    let kinds = bq_token_kinds("@from");
    assert_eq!(
        kinds,
        vec![TokenKind::Identifier {
            kind: IdentifierKind::AtVariable
        }]
    );
}

#[test]
fn test_bq_at_param_reserved_keyword_select() {
    let lexemes = bq_token_lexemes("@select");
    assert_eq!(lexemes, vec!["@select"]);
}

// ============================================================================
// 4. Lexer: Path expression @param.field
// ============================================================================

#[test]
fn test_bq_at_param_path_expression() {
    let lexemes = bq_token_lexemes("@struct_param.field_name");
    assert_eq!(
        lexemes,
        vec!["@struct_param", ".", "field_name"],
        "@param.field should be 3 tokens: AtVariable, Dot, Identifier"
    );
}

// ============================================================================
// 5. Lexer: @@system_variable (permissive acceptance)
// ============================================================================

#[test]
fn test_bq_double_at_accepted() {
    // BigQuery doesn't use @@ but permissive parser should accept it
    let lexemes = bq_token_lexemes("@@system_var");
    assert_eq!(lexemes, vec!["@@system_var"]);
    let kinds = bq_token_kinds("@@system_var");
    assert_eq!(
        kinds,
        vec![TokenKind::Identifier {
            kind: IdentifierKind::AtVariable
        }]
    );
}

// ============================================================================
// 6. Lexer: Bare @ produces Operator::At
// ============================================================================

#[test]
fn test_bq_bare_at_is_operator() {
    // A bare `@` not followed by an identifier body is the `@` operator — used
    // by MySQL `'user'@'host'` grantees and other surfaces that pair `@` with
    // non-identifier tokens.
    let kinds = bq_token_kinds("@ ");
    assert!(
        kinds.contains(&TokenKind::Operator(Operator::At)),
        "Bare @ should produce Operator::At token, got: {:?}",
        kinds
    );
}

// ============================================================================
// 7. Format round-trip: @param preserved
// ============================================================================

#[test]
fn test_bq_format_at_param_basic() {
    let sql = "SELECT * FROM Roster WHERE LastName = @myparam;";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("@myparam"),
        "Formatted output should contain @myparam, got: {}",
        formatted
    );
}

#[test]
fn test_bq_format_at_param_multiple() {
    let sql = "SELECT * FROM t WHERE a = @first AND b = @second AND c = @third;";
    let formatted = format_and_verify_bq(sql);
    assert!(formatted.contains("@first"), "Should preserve @first");
    assert!(formatted.contains("@second"), "Should preserve @second");
    assert!(formatted.contains("@third"), "Should preserve @third");
}

#[test]
fn test_bq_format_at_param_in_insert() {
    let sql = "INSERT INTO my_table (col1, col2) VALUES (@val1, @val2);";
    format_and_verify_bq(sql);
}

#[test]
fn test_bq_format_at_param_in_join() {
    let sql = "SELECT a.id, b.name FROM table_a AS a JOIN table_b AS b ON a.id = @target_id;";
    format_and_verify_bq(sql);
}

#[test]
fn test_bq_format_at_param_in_between() {
    let sql = "SELECT * FROM t WHERE col BETWEEN @lo AND @hi;";
    format_and_verify_bq(sql);
}

#[test]
fn test_bq_format_at_param_in_in_list() {
    let sql = "SELECT * FROM t WHERE col IN (@v1, @v2, @v3);";
    format_and_verify_bq(sql);
}

#[test]
fn test_bq_format_at_param_in_case() {
    let sql = "SELECT CASE WHEN col = @threshold THEN 'match' ELSE 'no match' END FROM t;";
    format_and_verify_bq(sql);
}

#[test]
fn test_bq_format_at_param_in_function() {
    let sql = "SELECT TIMESTAMP_ADD(@ts_param, INTERVAL 1 DAY);";
    format_and_verify_bq(sql);
}

#[test]
fn test_bq_format_at_param_path_expression() {
    let sql = "SELECT @struct_param.field_name AS val;";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("@struct_param"),
        "Should preserve @struct_param"
    );
}

// ============================================================================
// 8. Multi-statement with @param
// ============================================================================

#[test]
fn test_bq_format_at_param_multi_statement() {
    let sql = r#"
SELECT * FROM users WHERE id = @user_id;
INSERT INTO audit_log (user_id, action) VALUES (@user_id, @action);
UPDATE settings SET value = @new_val WHERE key = @setting_key;
"#;
    let formatted = format_and_verify_bq(sql);
    // All 4 distinct @params should be preserved
    assert!(formatted.contains("@user_id"), "Should preserve @user_id");
    assert!(formatted.contains("@action"), "Should preserve @action");
    assert!(formatted.contains("@new_val"), "Should preserve @new_val");
    assert!(
        formatted.contains("@setting_key"),
        "Should preserve @setting_key"
    );
}

// ============================================================================
// 9. Risk analysis: @param queries parsed correctly
// ============================================================================

#[test]
fn test_bq_at_param_risk_analysis() {
    let sql = "SELECT * FROM users WHERE id = @user_id AND status = @status;";
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("BQ risk analysis should succeed with @param");
    assert!(
        report.summary.statements_parsed > 0,
        "Statement should be parsed (not opaque), got {} parsed",
        report.summary.statements_parsed
    );
}

#[test]
fn test_bq_at_param_risk_multi_statement() {
    let sql = r#"
SELECT * FROM orders WHERE customer_id = @cust_id;
DELETE FROM expired_sessions WHERE session_id = @sess_id;
"#;
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(bigquery());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("BQ risk analysis should succeed");
    assert!(
        report.summary.statements_parsed >= 2,
        "Both statements should be parsed, got {}",
        report.summary.statements_parsed
    );
}

// ============================================================================
// 10. Positional parameter ? — regression guard
// ============================================================================

#[test]
fn test_bq_positional_param_still_works() {
    let sql = "SELECT * FROM t WHERE a = ? AND b = ?;";
    let formatted = format_and_verify_bq(sql);
    let question_count = formatted.matches('?').count();
    assert_eq!(question_count, 2, "Both ? placeholders should be preserved");
}

// ============================================================================
// 11. Cross-dialect: Snowflake should NOT tokenize @param
// ============================================================================

#[test]
fn test_snowflake_at_still_unknown() {
    // Snowflake doesn't support @param — @ should remain Unknown
    let sf = snowflake();
    let result = tokenize_with_dialect("@myparam", &*sf);
    let kinds: Vec<TokenKind> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect();
    assert!(
        kinds.contains(&TokenKind::Unknown),
        "Snowflake should produce Unknown for @, got: {:?}",
        kinds
    );
    // Should be 2 tokens: Unknown(@) + Identifier(myparam)
    assert_eq!(kinds.len(), 2, "Should be 2 separate tokens in Snowflake");
}
