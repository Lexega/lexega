// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Comprehensive hostile trivia tests for various SQL constructs.
/// These tests place comments in aggressive positions to find trivia preservation bugs.
use lexega_syntax::{format_sql_with_config, tokenize, FormatterConfig};

// Helper to count comments in formatted output
fn count_comments(sql: &str) -> (usize, usize) {
    let block_comments = sql.matches("/*").count();
    let line_comments = sql
        .lines()
        .filter(|line| line.trim_start().starts_with("--"))
        .count();
    (block_comments, line_comments)
}

// Helper to extract non-trivia tokens
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

// ============================================================================
// Test: MERGE with hostile comments
// ============================================================================

const HOSTILE_MERGE: &str = include_str!("./fixtures/test_hostile_merge.sql");

#[test]
fn test_hostile_merge_formats() {
    let result = format_sql_with_config(HOSTILE_MERGE, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "MERGE with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_merge_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_MERGE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_MERGE);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in MERGE"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in MERGE"
    );
}

#[test]
fn test_hostile_merge_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_MERGE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_MERGE);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in MERGE (no data loss)"
    );
}

#[test]
fn test_hostile_merge_idempotent() {
    let formatted_once = format_sql_with_config(HOSTILE_MERGE, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    // Normalize line endings for comparison
    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "MERGE formatting should be idempotent"
    );
}

// ============================================================================
// Test: MATCH_RECOGNIZE with hostile comments
// ============================================================================

const HOSTILE_MATCH_RECOGNIZE: &str = include_str!("./fixtures/test_hostile_match_recognize.sql");

#[test]
fn test_hostile_match_recognize_formats() {
    let result = format_sql_with_config(HOSTILE_MATCH_RECOGNIZE, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "MATCH_RECOGNIZE with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_match_recognize_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_MATCH_RECOGNIZE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_MATCH_RECOGNIZE);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in MATCH_RECOGNIZE"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in MATCH_RECOGNIZE"
    );
}

#[test]
fn test_hostile_match_recognize_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_MATCH_RECOGNIZE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_MATCH_RECOGNIZE);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in MATCH_RECOGNIZE (no data loss)"
    );
}

#[test]
fn test_hostile_match_recognize_idempotent() {
    let formatted_once =
        format_sql_with_config(HOSTILE_MATCH_RECOGNIZE, &FormatterConfig::default())
            .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "MATCH_RECOGNIZE formatting should be idempotent"
    );
}

// ============================================================================
// Test: PIVOT with hostile comments
// ============================================================================

const HOSTILE_PIVOT: &str = include_str!("./fixtures/test_hostile_pivot.sql");

#[test]
fn test_hostile_pivot_formats() {
    let result = format_sql_with_config(HOSTILE_PIVOT, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "PIVOT with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_pivot_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_PIVOT, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_PIVOT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in PIVOT"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in PIVOT"
    );
}

#[test]
fn test_hostile_pivot_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_PIVOT, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_PIVOT);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in PIVOT (no data loss)"
    );
}

#[test]
fn test_hostile_pivot_idempotent() {
    let formatted_once = format_sql_with_config(HOSTILE_PIVOT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "PIVOT formatting should be idempotent"
    );
}

// ============================================================================
// Test: Window functions with hostile comments
// ============================================================================

const HOSTILE_WINDOW: &str = include_str!("./fixtures/test_hostile_window.sql");

#[test]
fn test_hostile_window_formats() {
    let result = format_sql_with_config(HOSTILE_WINDOW, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "Window functions with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_window_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_WINDOW, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_WINDOW);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in window functions"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in window functions"
    );
}

#[test]
fn test_hostile_window_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_WINDOW, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_WINDOW);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in window functions (no data loss)"
    );
}

#[test]
fn test_hostile_window_idempotent() {
    let formatted_once = format_sql_with_config(HOSTILE_WINDOW, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "Window function formatting should be idempotent"
    );
}

// ============================================================================
// Test: CTEs with hostile comments
// ============================================================================

const HOSTILE_CTE: &str = include_str!("./fixtures/test_hostile_cte.sql");

#[test]
fn test_hostile_cte_formats() {
    let result = format_sql_with_config(HOSTILE_CTE, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "CTEs with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_cte_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_CTE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_CTE);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in CTEs"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in CTEs"
    );
}

#[test]
fn test_hostile_cte_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_CTE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_CTE);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in CTEs (no data loss)"
    );
}

#[test]
fn test_hostile_cte_idempotent() {
    let formatted_once = format_sql_with_config(HOSTILE_CTE, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "CTE formatting should be idempotent"
    );
}

// ============================================================================
// Test: CASE expressions with hostile comments
// ============================================================================

const HOSTILE_CASE: &str = include_str!("./fixtures/test_hostile_case.sql");

#[test]
fn test_hostile_case_formats() {
    let result = format_sql_with_config(HOSTILE_CASE, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "CASE expressions with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_case_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_CASE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_CASE);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in CASE expressions"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in CASE expressions"
    );
}

#[test]
fn test_hostile_case_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_CASE, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_CASE);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in CASE expressions (no data loss)"
    );
}

#[test]
fn test_hostile_case_idempotent() {
    let formatted_once = format_sql_with_config(HOSTILE_CASE, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "CASE expression formatting should be idempotent"
    );
}

// ============================================================================
// Test: Correlated subqueries with hostile comments
// ============================================================================

const HOSTILE_SUBQUERY: &str = include_str!("./fixtures/test_hostile_subquery.sql");

#[test]
fn test_hostile_subquery_formats() {
    let result = format_sql_with_config(HOSTILE_SUBQUERY, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "Correlated subqueries with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_subquery_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_SUBQUERY, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_SUBQUERY);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in correlated subqueries"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in correlated subqueries"
    );
}

#[test]
fn test_hostile_subquery_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_SUBQUERY, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_SUBQUERY);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in correlated subqueries (no data loss)"
    );
}

#[test]
fn test_hostile_subquery_idempotent() {
    let formatted_once = format_sql_with_config(HOSTILE_SUBQUERY, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "Correlated subquery formatting should be idempotent"
    );
}

// ============================================================================
// Test: DDL with hostile comments
// ============================================================================

const HOSTILE_DDL: &str = include_str!("./fixtures/test_hostile_ddl.sql");

#[test]
fn test_hostile_ddl_formats() {
    let result = format_sql_with_config(HOSTILE_DDL, &FormatterConfig::default());
    assert!(
        result.is_ok(),
        "DDL with hostile comments should format successfully"
    );
}

#[test]
fn test_hostile_ddl_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_DDL, &FormatterConfig::default())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_DDL);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "All block comments should be preserved in DDL"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "All line comments should be preserved in DDL"
    );
}

#[test]
fn test_hostile_ddl_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_DDL, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_DDL);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens, fmt_tokens,
        "All tokens should be preserved in DDL (no data loss)"
    );
}

#[test]
fn test_hostile_ddl_idempotent() {
    let formatted_once = format_sql_with_config(HOSTILE_DDL, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    let once_normalized = formatted_once.replace("\r\n", "\n");
    let twice_normalized = formatted_twice.replace("\r\n", "\n");

    assert_eq!(
        once_normalized.trim(),
        twice_normalized.trim(),
        "DDL formatting should be idempotent"
    );
}
