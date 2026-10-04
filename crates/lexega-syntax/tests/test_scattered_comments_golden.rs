// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// GOLDEN TEST: Verifies EXACT formatted output for test_scattered_comments.sql.
///
/// NOTE: This file tests exact golden output matching and idempotence.
/// For basic parse/format/roundtrip testing, see test_fixtures_comments_trivia.rs
///
/// This verifies exact placement and formatting of comments scattered throughout various SQL constructs.
use lexega_syntax::{format_sql_with_config, FormatterConfig};

const INPUT: &str = include_str!("fixtures/test_scattered_comments.sql");
const EXPECTED: &str = include_str!("fixtures/test_scattered_comments_formatted.sql");

#[test]
fn test_scattered_comments_golden_default() {
    let formatted = format_sql_with_config(INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(
        formatted.trim(),
        EXPECTED.trim(),
        "Formatted output should match golden file test_scattered_comments_formatted.sql"
    );
}

#[test]
fn test_scattered_comments_idempotent() {
    // Format once
    let formatted_once = format_sql_with_config(INPUT, &FormatterConfig::default())
        .expect("first format should succeed");

    // Format again
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Formatting should be idempotent"
    );
}

#[test]
fn test_scattered_comments_preserves_all_comments() {
    let formatted = format_sql_with_config(INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Count block comments
    let input_block_comments = INPUT.matches("/*").count();
    let formatted_block_comments = formatted.matches("/*").count();
    assert_eq!(
        input_block_comments, formatted_block_comments,
        "All block comments should be preserved"
    );

    // Count line comments
    let input_line_comments = INPUT
        .lines()
        .filter(|line| line.trim_start().starts_with("--"))
        .count();
    let formatted_line_comments = formatted
        .lines()
        .filter(|line| line.trim_start().starts_with("--"))
        .count();
    assert_eq!(
        input_line_comments, formatted_line_comments,
        "All line comments should be preserved"
    );
}
