// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for comment/trivia preservation under different FormatterConfig settings.
/// Config-specific code paths may have different trivia handling; these tests ensure
/// that no configuration causes comment loss or duplication.
use lexega_syntax::{format_sql_with_config, tokenize, FormatterConfig};

// Helper to count comments
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

// Use test_scattered_comments as a representative comment-heavy file
const SCATTERED_COMMENTS_INPUT: &str = include_str!("fixtures/test_scattered_comments.sql");

// ============================================================================
// Config: ultra_readable()
// ============================================================================

#[test]
fn test_scattered_comments_ultra_readable_preserves_comments() {
    let formatted =
        format_sql_with_config(SCATTERED_COMMENTS_INPUT, &FormatterConfig::ultra_readable())
            .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(SCATTERED_COMMENTS_INPUT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "ultra_readable: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "ultra_readable: All line comments should be preserved"
    );
}

#[test]
fn test_scattered_comments_ultra_readable_idempotent() {
    let config = FormatterConfig::ultra_readable();
    let formatted_once = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("first format should succeed");
    let formatted_twice =
        format_sql_with_config(&formatted_once, &config).expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "ultra_readable formatting should be idempotent"
    );
}

// ============================================================================
// Config: readable()
// ============================================================================

#[test]
fn test_scattered_comments_readable_preserves_comments() {
    let formatted = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &FormatterConfig::readable())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(SCATTERED_COMMENTS_INPUT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "readable: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "readable: All line comments should be preserved"
    );
}

#[test]
fn test_scattered_comments_readable_idempotent() {
    let config = FormatterConfig::readable();
    let formatted_once = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("first format should succeed");
    let formatted_twice =
        format_sql_with_config(&formatted_once, &config).expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "readable formatting should be idempotent"
    );
}

// ============================================================================
// Config: compact()
// ============================================================================

#[test]
fn test_scattered_comments_compact_preserves_comments() {
    let formatted = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &FormatterConfig::compact())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(SCATTERED_COMMENTS_INPUT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "compact: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "compact: All line comments should be preserved"
    );
}

#[test]
fn test_scattered_comments_compact_idempotent() {
    let config = FormatterConfig::compact();
    let formatted_once = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("first format should succeed");
    let formatted_twice =
        format_sql_with_config(&formatted_once, &config).expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "compact formatting should be idempotent"
    );
}

// ============================================================================
// Config: Custom with clauses_on_newlines
// ============================================================================

#[test]
fn test_scattered_comments_clauses_on_newlines_preserves_comments() {
    let mut config = FormatterConfig::default();
    config.clauses_on_newlines = true;

    let formatted = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(SCATTERED_COMMENTS_INPUT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "clauses_on_newlines: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "clauses_on_newlines: All line comments should be preserved"
    );
}

#[test]
fn test_scattered_comments_clauses_on_newlines_idempotent() {
    let mut config = FormatterConfig::default();
    config.clauses_on_newlines = true;

    let formatted_once = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("first format should succeed");
    let formatted_twice =
        format_sql_with_config(&formatted_once, &config).expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "clauses_on_newlines formatting should be idempotent"
    );
}

// ============================================================================
// Config: Custom with select_items_on_newlines
// ============================================================================

#[test]
fn test_scattered_comments_select_items_on_newlines_preserves_comments() {
    let mut config = FormatterConfig::default();
    config.select_items_on_newlines = true;

    let formatted = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(SCATTERED_COMMENTS_INPUT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "select_items_on_newlines: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "select_items_on_newlines: All line comments should be preserved"
    );
}

#[test]
fn test_scattered_comments_select_items_on_newlines_idempotent() {
    let mut config = FormatterConfig::default();
    config.select_items_on_newlines = true;

    let formatted_once = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("first format should succeed");
    let formatted_twice =
        format_sql_with_config(&formatted_once, &config).expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "select_items_on_newlines formatting should be idempotent"
    );
}

// ============================================================================
// Config: Custom with indent_style variations
// ============================================================================

#[test]
fn test_scattered_comments_tab_indent_preserves_comments() {
    let mut config = FormatterConfig::default();
    config.indent_style = lexega_syntax::formatter::config::IndentStyle::Tabs;

    let formatted = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(SCATTERED_COMMENTS_INPUT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "tab indent: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "tab indent: All line comments should be preserved"
    );
}

#[test]
fn test_scattered_comments_space_indent_preserves_comments() {
    let mut config = FormatterConfig::default();
    config.indent_style = lexega_syntax::formatter::config::IndentStyle::Spaces(2);

    let formatted = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(SCATTERED_COMMENTS_INPUT);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "space(2) indent: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "space(2) indent: All line comments should be preserved"
    );
}

// ============================================================================
// Config: Hostile golden test with ultra_readable
// ============================================================================

const HOSTILE_ALL_STMTS: &str = include_str!("fixtures/stress/hostile_all_stmts.sql");

#[test]
fn test_hostile_all_stmts_ultra_readable_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_ALL_STMTS, &FormatterConfig::ultra_readable())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_ALL_STMTS);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "hostile ultra_readable: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "hostile ultra_readable: All line comments should be preserved"
    );
}

#[test]
fn test_hostile_all_stmts_ultra_readable_idempotent() {
    let config = FormatterConfig::ultra_readable();
    let formatted_once =
        format_sql_with_config(HOSTILE_ALL_STMTS, &config).expect("first format should succeed");
    let formatted_twice =
        format_sql_with_config(&formatted_once, &config).expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "hostile ultra_readable should be idempotent"
    );
}

#[test]
fn test_hostile_all_stmts_readable_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_ALL_STMTS, &FormatterConfig::readable())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_ALL_STMTS);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "hostile readable: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "hostile readable: All line comments should be preserved"
    );
}

#[test]
fn test_hostile_all_stmts_compact_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_ALL_STMTS, &FormatterConfig::compact())
        .expect("formatting should succeed");

    let (input_blocks, input_lines) = count_comments(HOSTILE_ALL_STMTS);
    let (fmt_blocks, fmt_lines) = count_comments(&formatted);

    assert_eq!(
        input_blocks, fmt_blocks,
        "hostile compact: All block comments should be preserved"
    );
    assert_eq!(
        input_lines, fmt_lines,
        "hostile compact: All line comments should be preserved"
    );
}

// ============================================================================
// Config: Test all configs preserve tokens (not just comments)
// ============================================================================

#[test]
fn test_all_configs_preserve_tokens() {
    let configs = vec![
        ("default", FormatterConfig::default()),
        ("ultra_readable", FormatterConfig::ultra_readable()),
        ("readable", FormatterConfig::readable()),
        ("compact", FormatterConfig::compact()),
    ];

    let orig_tokens = extract_significant_tokens(SCATTERED_COMMENTS_INPUT);

    for (name, config) in configs {
        let formatted = format_sql_with_config(SCATTERED_COMMENTS_INPUT, &config)
            .expect(&format!("{} should format", name));
        let fmt_tokens = extract_significant_tokens(&formatted);

        assert_eq!(
            orig_tokens.len(),
            fmt_tokens.len(),
            "{}: Token count should be preserved",
            name
        );
    }
}
