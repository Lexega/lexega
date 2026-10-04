// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Golden test for comprehensive CST/trivia preservation
//!
//! This test uses `hostile_all_stmts.sql` - a stress test file with 700+ comments
//! covering the entire SQL statement surface (DDL, DML, Scripting, etc.).
//!
//! The test verifies that formatting preserves ALL tokens with zero data loss.
//! This is the primary regression guard for the CST trivia system.

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

#[test]
fn test_hostile_all_stmts_no_data_loss() {
    // Load the hostile test file with 700+ comments
    let sql = include_str!("fixtures/stress/hostile_all_stmts.sql");

    // Extract original tokens
    let orig_tokens = extract_significant_tokens(sql);

    // Format the SQL
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Formatting should succeed");

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
fn test_hostile_all_stmts_comments_preserved() {
    // Load the hostile test file
    let sql = include_str!("fixtures/stress/hostile_all_stmts.sql");

    // Count block comments in original
    let orig_block_comments = sql.matches("*/").count();

    // Count line comments in original (approximate - lines starting with --)
    let orig_line_comments = sql.lines().filter(|l| l.trim().starts_with("--")).count();

    // Format
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Formatting should succeed");

    // Count comments in formatted
    let fmt_block_comments = formatted.matches("*/").count();
    let fmt_line_comments = formatted
        .lines()
        .filter(|l| l.trim().starts_with("--"))
        .count();

    // All block comments must be preserved
    assert_eq!(
        orig_block_comments, fmt_block_comments,
        "Block comment count mismatch! Original: {}, Formatted: {}",
        orig_block_comments, fmt_block_comments
    );

    // All line comments must be preserved
    assert_eq!(
        orig_line_comments, fmt_line_comments,
        "Line comment count mismatch! Original: {}, Formatted: {}",
        orig_line_comments, fmt_line_comments
    );
}

#[test]
fn test_hostile_all_stmts_idempotent() {
    // Load the hostile test file
    let sql = include_str!("fixtures/stress/hostile_all_stmts.sql");

    let config = FormatterConfig::default();

    // Format once
    let formatted1 = format_sql_with_config(sql, &config).expect("First format should succeed");

    // Format again
    let formatted2 =
        format_sql_with_config(&formatted1, &config).expect("Second format should succeed");

    // Should be identical (idempotent)
    assert_eq!(
        formatted1, formatted2,
        "Formatting is not idempotent - second pass produced different output"
    );
}

#[test]
fn test_hostile_all_stmts_ultra_style() {
    // Test with ultra style (maximum formatting changes)
    let sql = include_str!("fixtures/stress/hostile_all_stmts.sql");

    // Use ultra_readable() preset
    let config = FormatterConfig::ultra_readable();

    // Format should succeed
    let formatted = format_sql_with_config(sql, &config).expect("Ultra formatting should succeed");

    // Verify no data loss with ultra style
    let orig_tokens = extract_significant_tokens(sql);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens.len(),
        fmt_tokens.len(),
        "Ultra style token count mismatch! Original: {}, Formatted: {}",
        orig_tokens.len(),
        fmt_tokens.len()
    );

    assert!(
        tokens_match_with_normalizations(&orig_tokens, &fmt_tokens),
        "Ultra style token content mismatch - potential data loss"
    );
}
