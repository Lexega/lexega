// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! GOLDEN TEST: Jinja/dbt CST/trivia preservation with EXACT token verification
//!
//! NOTE: This file tests exact token preservation and trivia handling.
//! For basic parse/format/roundtrip testing, see test_fixtures_jinja.rs
//!
//! This test uses `hostile_jinja.sql` - a stress test file with hundreds of comments
//! across Jinja templates, mixing SQL comments (-- and /* */) with Jinja comments ({# #}).
//!
//! The test verifies that formatting preserves ALL tokens including Jinja blocks,
//! and that Jinja comments are not conflated with SQL comments.

use lexega_syntax::{format_sql_with_config, tokenize, FormatterConfig};

/// Extract significant (non-trivia) tokens from SQL for comparison
fn extract_significant_tokens(sql: &str) -> Vec<String> {
    let lex_result = tokenize(sql);
    lex_result
        .tokens
        .into_iter()
        .filter(|t| {
            !matches!(
                t.kind,
                lexega_syntax::lexer::TokenKind::LineComment
                    | lexega_syntax::lexer::TokenKind::BlockComment
                    | lexega_syntax::lexer::TokenKind::JinjaComment
            )
        })
        .map(|t| t.lexeme(sql).to_string())
        .collect()
}

/// Check if token sequences match, allowing for acceptable normalizations
fn tokens_match_with_normalizations(orig: &[String], fmt: &[String]) -> bool {
    if orig.len() != fmt.len() {
        return false;
    }

    orig.iter()
        .zip(fmt.iter())
        .all(|(o, f)| o.eq_ignore_ascii_case(f))
}

/// Count Jinja constructs in SQL
fn count_jinja_constructs(sql: &str) -> (usize, usize, usize, usize) {
    let expressions = sql.matches("{{").count();
    let statements = sql.matches("{%").count();
    let jinja_comments = sql.matches("{#").count();
    // Also count closing tags to ensure balance
    let expr_close = sql.matches("}}").count();
    let stmt_close = sql.matches("%}").count();
    let comment_close = sql.matches("#}").count();

    // Return tuple: (expressions, statements, jinja_comments, balanced)
    let balanced =
        if expressions == expr_close && statements == stmt_close && jinja_comments == comment_close
        {
            1
        } else {
            0
        };

    (expressions, statements, jinja_comments, balanced)
}

#[test]
fn test_hostile_jinja_lexes_completely() {
    // Load the hostile Jinja test file
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");
    let lex_result = tokenize(sql);

    // Should produce tokens without panicking
    assert!(
        !lex_result.tokens.is_empty(),
        "Hostile Jinja file should produce tokens"
    );

    // Check that all Jinja token types are recognized
    let token_kinds: Vec<_> = lex_result
        .tokens
        .iter()
        .map(|t| format!("{:?}", t.kind))
        .collect();
    let token_str = token_kinds.join(" ");

    // Should contain Jinja expression tokens
    assert!(
        token_str.contains("JinjaExprOpen") || token_str.contains("JinjaExprClose"),
        "Should recognize Jinja expressions {{{{ }}}}"
    );

    // Should contain Jinja statement tokens
    assert!(
        token_str.contains("JinjaStmtOpen") || token_str.contains("JinjaStmtClose"),
        "Should recognize Jinja statements {{%% %%}}"
    );

    // Should contain Jinja comments in trivia (they are trivia, like SQL comments)
    let has_jinja_comments = lex_result.tokens.iter().any(|t| {
        t.leading_trivia
            .iter()
            .any(|trivia| matches!(trivia.kind, lexega_syntax::lexer::TriviaKind::JinjaComment))
            || t.trailing_trivia
                .iter()
                .any(|trivia| matches!(trivia.kind, lexega_syntax::lexer::TriviaKind::JinjaComment))
    });
    assert!(
        has_jinja_comments,
        "Should recognize Jinja comments {{{{# #}}}} in trivia"
    );

    // Should contain SQL comments in trivia
    let has_sql_comments = lex_result.tokens.iter().any(|t| {
        t.leading_trivia.iter().any(|trivia| {
            matches!(
                trivia.kind,
                lexega_syntax::lexer::TriviaKind::LineComment
                    | lexega_syntax::lexer::TriviaKind::BlockComment
            )
        }) || t.trailing_trivia.iter().any(|trivia| {
            matches!(
                trivia.kind,
                lexega_syntax::lexer::TriviaKind::LineComment
                    | lexega_syntax::lexer::TriviaKind::BlockComment
            )
        })
    });
    assert!(
        has_sql_comments,
        "Should also recognize SQL comments in trivia"
    );
}

#[test]
fn test_hostile_jinja_no_data_loss() {
    // Load the hostile Jinja test file
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");

    // Extract original tokens
    let orig_tokens = extract_significant_tokens(sql);

    // Format the SQL
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Jinja formatting should succeed");

    // Extract formatted tokens
    let fmt_tokens = extract_significant_tokens(&formatted);

    // Verify token counts match
    assert_eq!(
        orig_tokens.len(),
        fmt_tokens.len(),
        "Token count mismatch! Original: {}, Formatted: {}\n\
         First 20 original: {:?}\n\
         First 20 formatted: {:?}",
        orig_tokens.len(),
        fmt_tokens.len(),
        &orig_tokens[..20.min(orig_tokens.len())],
        &fmt_tokens[..20.min(fmt_tokens.len())]
    );

    // Verify tokens match (case-insensitive for keywords)
    assert!(
        tokens_match_with_normalizations(&orig_tokens, &fmt_tokens),
        "Token content mismatch detected - potential data loss or corruption"
    );
}

#[test]
fn test_hostile_jinja_comments_preserved() {
    // Load the hostile Jinja test file
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");

    // Count SQL block comments in original
    let orig_block_comments = sql.matches("*/").count();

    // Count SQL line comments in original
    let orig_line_comments = sql.lines().filter(|l| l.trim().starts_with("--")).count();

    // Count Jinja comments in original
    let orig_jinja_comments = sql.matches("#}").count();

    // Format
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Jinja formatting should succeed");

    // Count comments in formatted
    let fmt_block_comments = formatted.matches("*/").count();
    let fmt_line_comments = formatted
        .lines()
        .filter(|l| l.trim().starts_with("--"))
        .count();
    let fmt_jinja_comments = formatted.matches("#}").count();

    // All SQL block comments must be preserved
    assert_eq!(
        orig_block_comments, fmt_block_comments,
        "SQL block comment count mismatch! Original: {}, Formatted: {}",
        orig_block_comments, fmt_block_comments
    );

    // All SQL line comments must be preserved
    assert_eq!(
        orig_line_comments, fmt_line_comments,
        "SQL line comment count mismatch! Original: {}, Formatted: {}",
        orig_line_comments, fmt_line_comments
    );

    // All Jinja comments must be preserved
    assert_eq!(
        orig_jinja_comments, fmt_jinja_comments,
        "Jinja comment count mismatch! Original: {}, Formatted: {}",
        orig_jinja_comments, fmt_jinja_comments
    );
}

#[test]
fn test_hostile_jinja_constructs_preserved() {
    // Load the hostile Jinja test file
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");

    // Count Jinja constructs in original
    let (orig_expr, orig_stmt, orig_jcomment, orig_balanced) = count_jinja_constructs(sql);

    // Original should be balanced
    assert_eq!(
        orig_balanced, 1,
        "Original file should have balanced Jinja tags"
    );

    // Format
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Jinja formatting should succeed");

    // Count Jinja constructs in formatted
    let (fmt_expr, fmt_stmt, fmt_jcomment, fmt_balanced) = count_jinja_constructs(&formatted);

    // All Jinja expressions must be preserved
    assert_eq!(
        orig_expr, fmt_expr,
        "Jinja expression count mismatch! Original: {}, Formatted: {}",
        orig_expr, fmt_expr
    );

    // All Jinja statements must be preserved
    assert_eq!(
        orig_stmt, fmt_stmt,
        "Jinja statement count mismatch! Original: {}, Formatted: {}",
        orig_stmt, fmt_stmt
    );

    // All Jinja comments must be preserved
    assert_eq!(
        orig_jcomment, fmt_jcomment,
        "Jinja comment count mismatch! Original: {}, Formatted: {}",
        orig_jcomment, fmt_jcomment
    );

    // Formatted should still be balanced
    assert_eq!(
        fmt_balanced, 1,
        "Formatted file should have balanced Jinja tags"
    );
}

#[test]
fn test_hostile_jinja_idempotent() {
    // Load the hostile Jinja test file
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");

    let config = FormatterConfig::default();

    // Format once
    let formatted1 =
        format_sql_with_config(sql, &config).expect("First Jinja format should succeed");

    // Format again
    let formatted2 =
        format_sql_with_config(&formatted1, &config).expect("Second Jinja format should succeed");

    // Should be identical (idempotent)
    assert_eq!(
        formatted1, formatted2,
        "Jinja formatting is not idempotent - second pass produced different output"
    );
}

#[test]
fn test_hostile_jinja_ultra_style() {
    // Test with ultra style (maximum formatting changes)
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");

    // Use ultra_readable() preset
    let config = FormatterConfig::ultra_readable();

    // Format should succeed
    let formatted =
        format_sql_with_config(sql, &config).expect("Ultra Jinja formatting should succeed");

    // Verify no data loss with ultra style
    let orig_tokens = extract_significant_tokens(sql);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens.len(),
        fmt_tokens.len(),
        "Ultra style Jinja token count mismatch! Original: {}, Formatted: {}",
        orig_tokens.len(),
        fmt_tokens.len()
    );

    // Verify Jinja constructs preserved
    let (orig_expr, orig_stmt, orig_jcomment, _) = count_jinja_constructs(sql);
    let (fmt_expr, fmt_stmt, fmt_jcomment, _) = count_jinja_constructs(&formatted);

    assert_eq!(orig_expr, fmt_expr, "Ultra: Jinja expressions lost");
    assert_eq!(orig_stmt, fmt_stmt, "Ultra: Jinja statements lost");
    assert_eq!(orig_jcomment, fmt_jcomment, "Ultra: Jinja comments lost");
}

#[test]
fn test_hostile_jinja_specific_constructs() {
    // Load the hostile Jinja test file
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");

    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Jinja formatting should succeed");

    // Check specific critical Jinja patterns are preserved exactly

    // dbt ref() macro
    assert!(
        formatted.contains("{{ ref(") || formatted.contains("{{ref("),
        "dbt ref() macro should be preserved"
    );

    // dbt source() macro
    assert!(
        formatted.contains("{{ source(") || formatted.contains("{{source("),
        "dbt source() macro should be preserved"
    );

    // dbt config block
    assert!(
        formatted.contains("{{ config(") || formatted.contains("{{config("),
        "dbt config() should be preserved"
    );

    // is_incremental check
    assert!(
        formatted.contains("is_incremental()"),
        "is_incremental() should be preserved"
    );

    // var() function
    assert!(
        formatted.contains("var("),
        "var() function should be preserved"
    );

    // Control flow keywords
    assert!(
        formatted.contains("{% if ") || formatted.contains("{%if "),
        "{{%% if %%}} blocks should be preserved"
    );
    assert!(
        formatted.contains("{% for ") || formatted.contains("{%for "),
        "{{%% for %%}} loops should be preserved"
    );
    assert!(
        formatted.contains("{% endif %}") || formatted.contains("{%endif%}"),
        "{{%% endif %%}} should be preserved"
    );
    assert!(
        formatted.contains("{% endfor %}") || formatted.contains("{%endfor%}"),
        "{{%% endfor %%}} should be preserved"
    );

    // Loop variables
    assert!(
        formatted.contains("loop.last")
            || formatted.contains("loop.first")
            || formatted.contains("loop.index"),
        "loop variables should be preserved"
    );
}

#[test]
fn test_hostile_jinja_comment_types_not_conflated() {
    // Verify that SQL comments and Jinja comments are distinct in output
    let sql = include_str!("fixtures/stress/hostile_jinja.sql");

    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Jinja formatting should succeed");

    // Jinja comments should remain as {# ... #}
    // They should NOT be converted to SQL comments
    let jinja_comment_pattern_preserved = formatted.contains("{#") && formatted.contains("#}");

    assert!(
        jinja_comment_pattern_preserved,
        "Jinja comments {{# #}} should not be converted to SQL comments"
    );

    // SQL line comments should remain as --
    let sql_line_comments = formatted.lines().filter(|l| l.contains("--")).count();
    assert!(
        sql_line_comments > 0,
        "SQL line comments (--) should be preserved"
    );

    // SQL block comments should remain as /* */
    let sql_block_comments = formatted.matches("/*").count();
    assert!(
        sql_block_comments > 0,
        "SQL block comments (/* */) should be preserved"
    );
}
