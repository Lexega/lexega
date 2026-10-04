// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dedicated tests for comment preservation and trivia tracking
//! Covers scattered comments, hostile comment scenarios, trivia-intensive SQL

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::fs;

// ============================================================================
// Scattered Comments
// ============================================================================

#[test]
fn test_scattered_comments() {
    let sql = fs::read_to_string("tests/fixtures/test_scattered_comments.sql")
        .expect("failed to read test_scattered_comments.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scattered_comments.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_scattered_comments.sql formatting should be safe");

    // Verify comments are preserved
    let input_block_comments = sql.matches("/*").count();
    let formatted_block_comments = formatted.matches("/*").count();
    assert_eq!(
        input_block_comments, formatted_block_comments,
        "All block comments should be preserved in test_scattered_comments.sql"
    );
}

// ============================================================================
// Trivia Central (Main trivia test fixture)
// ============================================================================

#[test]
fn test_trivia_central() {
    let sql = fs::read_to_string("tests/fixtures/test_trivia_central.sql")
        .expect("failed to read test_trivia_central.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_trivia_central.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_trivia_central.sql formatting should be safe");

    // Verify comments are preserved
    let input_line_comments = sql
        .lines()
        .filter(|l| l.trim_start().starts_with("--"))
        .count();
    let formatted_line_comments = formatted
        .lines()
        .filter(|l| l.trim_start().starts_with("--"))
        .count();
    assert_eq!(
        input_line_comments, formatted_line_comments,
        "All line comments should be preserved in test_trivia_central.sql"
    );
}

#[test]
fn test_star_trivia() {
    let sql = fs::read_to_string("tests/fixtures/test_star_trivia.sql")
        .expect("failed to read test_star_trivia.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_star_trivia.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_star_trivia.sql formatting should be safe");
}

// ============================================================================
// Hostile Comment Tests (Comment Carnage Series)
// ============================================================================

#[test]
fn test_comment_carnage() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_carnage.sql")
        .expect("failed to read test_comment_carnage.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_carnage.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_carnage.sql formatting should be safe");
}

#[test]
fn test_comment_case_madness() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_case_madness.sql")
        .expect("failed to read test_comment_case_madness.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_case_madness.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_case_madness.sql formatting should be safe");
}

#[test]
fn test_comment_create_table_nightmare() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_create_table_nightmare.sql")
        .expect("failed to read test_comment_create_table_nightmare.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_create_table_nightmare.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_create_table_nightmare.sql formatting should be safe");
}

#[test]
fn test_comment_cte_chaos() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_cte_chaos.sql")
        .expect("failed to read test_comment_cte_chaos.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_cte_chaos.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_cte_chaos.sql formatting should be safe");
}

#[test]
fn test_comment_merge_apocalypse() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_merge_apocalypse.sql")
        .expect("failed to read test_comment_merge_apocalypse.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_merge_apocalypse.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_merge_apocalypse.sql formatting should be safe");
}

#[test]
fn test_comment_nesting_hell() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_nesting_hell.sql")
        .expect("failed to read test_comment_nesting_hell.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_nesting_hell.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_nesting_hell.sql formatting should be safe");
}

#[test]
fn test_comment_window_hell() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_window_hell.sql")
        .expect("failed to read test_comment_window_hell.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_window_hell.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_window_hell.sql formatting should be safe");
}

// ============================================================================
// Hostile Comments (General)
// ============================================================================

#[test]
fn test_hostile_comments() {
    let sql = fs::read_to_string("tests/fixtures/test_hostile_comments.sql")
        .expect("failed to read test_hostile_comments.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_hostile_comments.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_hostile_comments.sql formatting should be safe");
}

// ============================================================================
// Comments Between Clauses
// ============================================================================

#[test]
fn test_comments_between() {
    let sql = fs::read_to_string("tests/fixtures/test_comments_between.sql")
        .expect("failed to read test_comments_between.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comments_between.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comments_between.sql formatting should be safe");
}

// ============================================================================
// USE Statement with Comments
// ============================================================================

#[test]
fn test_use_comments_baseline() {
    let sql = fs::read_to_string("tests/fixtures/test_use_comments_baseline.sql")
        .expect("failed to read test_use_comments_baseline.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_use_comments_baseline.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_use_comments_baseline.sql formatting should be safe");
}

#[test]
fn test_use_comments_v3() {
    let sql = fs::read_to_string("tests/fixtures/test_use_comments_v3.sql")
        .expect("failed to read test_use_comments_v3.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_use_comments_v3.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_use_comments_v3.sql formatting should be safe");
}

#[test]
fn test_use_comments_v3_current() {
    let sql = fs::read_to_string("tests/fixtures/test_use_comments_v3_current.sql")
        .expect("failed to read test_use_comments_v3_current.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_use_comments_v3_current.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_use_comments_v3_current.sql formatting should be safe");
}

#[test]
fn test_use_comments_v3_debug() {
    let sql = fs::read_to_string("tests/fixtures/test_use_comments_v3_debug.sql")
        .expect("failed to read test_use_comments_v3_debug.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_use_comments_v3_debug.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_use_comments_v3_debug.sql formatting should be safe");
}

#[test]
fn test_use_comments_v3_final() {
    let sql = fs::read_to_string("tests/fixtures/test_use_comments_v3_final.sql")
        .expect("failed to read test_use_comments_v3_final.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_use_comments_v3_final.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_use_comments_v3_final.sql formatting should be safe");
}

// ============================================================================
// COLLATE with Comments
// ============================================================================

#[test]
fn test_collate_not_null() {
    let sql = fs::read_to_string("tests/fixtures/test_collate_not_null.sql")
        .expect("failed to read test_collate_not_null.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_collate_not_null.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_collate_not_null.sql formatting should be safe");
}

#[test]
fn test_collate_not_null_comments() {
    let sql = fs::read_to_string("tests/fixtures/test_collate_not_null_comments.sql")
        .expect("failed to read test_collate_not_null_comments.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_collate_not_null_comments.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_collate_not_null_comments.sql formatting should be safe");
}
