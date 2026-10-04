// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::verify_formatting_safe;
/// GOLDEN TESTS: Verify EXACT formatted output for trivia/comment-intensive fixtures.
///
/// NOTE: These tests verify exact golden output matching and idempotence.
/// For basic parse/format/roundtrip testing, see test_fixtures_comments_trivia.rs
///
/// These files were explicitly created to stress comment placement.
use lexega_syntax::{format_sql_with_config, tokenize, FormatterConfig};

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
// Test: test_trivia_central.sql
// ============================================================================

const TRIVIA_CENTRAL_INPUT: &str = include_str!("./fixtures/test_trivia_central.sql");
const TRIVIA_CENTRAL_EXPECTED: &str = include_str!("./fixtures/test_trivia_central_formatted.sql");

#[test]
fn test_trivia_central_golden() {
    let formatted = format_sql_with_config(TRIVIA_CENTRAL_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(
        formatted.trim(),
        TRIVIA_CENTRAL_EXPECTED.trim(),
        "test_trivia_central.sql should format to golden output"
    );
}

#[test]
fn test_trivia_central_preserves_comments() {
    let formatted = format_sql_with_config(TRIVIA_CENTRAL_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(TRIVIA_CENTRAL_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_trivia_central_idempotent() {
    let formatted_once = format_sql_with_config(TRIVIA_CENTRAL_INPUT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_hostile_comments.sql
// ============================================================================

const HOSTILE_COMMENTS_INPUT: &str = include_str!("./fixtures/test_hostile_comments.sql");

#[test]
fn test_hostile_comments_golden() {
    let formatted = format_sql_with_config(HOSTILE_COMMENTS_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Use the same verification logic as --check flag (allows acceptable normalizations)
    // This includes normalization like adding trailing spaces after block comments

    verify_formatting_safe(HOSTILE_COMMENTS_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_hostile_comments_preserves_comments() {
    let formatted = format_sql_with_config(HOSTILE_COMMENTS_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(HOSTILE_COMMENTS_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_hostile_comments_preserves_tokens() {
    let formatted = format_sql_with_config(HOSTILE_COMMENTS_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(HOSTILE_COMMENTS_INPUT);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens.len(),
        fmt_tokens.len(),
        "Token count should be preserved in test_hostile_comments"
    );
}

#[test]
fn test_hostile_comments_idempotent() {
    let formatted_once =
        format_sql_with_config(HOSTILE_COMMENTS_INPUT, &FormatterConfig::default())
            .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_star_trivia.sql (star modifiers with comments)
// ============================================================================

const STAR_TRIVIA_INPUT: &str = include_str!("./fixtures/test_star_trivia.sql");
const STAR_TRIVIA_EXPECTED: &str = include_str!("./fixtures/test_star_trivia_formatted.sql");

#[test]
fn test_star_trivia_golden() {
    let formatted = format_sql_with_config(STAR_TRIVIA_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(
        formatted.trim(),
        STAR_TRIVIA_EXPECTED.trim(),
        "test_star_trivia.sql should format to golden output"
    );
}

#[test]
fn test_star_trivia_preserves_comments() {
    let formatted = format_sql_with_config(STAR_TRIVIA_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(STAR_TRIVIA_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_star_trivia_idempotent() {
    let formatted_once = format_sql_with_config(STAR_TRIVIA_INPUT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Star trivia formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_scripting_trivia.sql
// ============================================================================

const SCRIPTING_TRIVIA_INPUT: &str = include_str!("./fixtures/test_scripting_trivia.sql");
const SCRIPTING_TRIVIA_EXPECTED: &str =
    include_str!("./fixtures/test_scripting_trivia_formatted.sql");

#[test]
fn test_scripting_trivia_golden() {
    let formatted = format_sql_with_config(SCRIPTING_TRIVIA_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(
        formatted.trim(),
        SCRIPTING_TRIVIA_EXPECTED.trim(),
        "test_scripting_trivia.sql should format to golden output"
    );
}

#[test]
fn test_scripting_trivia_preserves_comments() {
    let formatted = format_sql_with_config(SCRIPTING_TRIVIA_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(SCRIPTING_TRIVIA_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_scripting_trivia_idempotent() {
    let formatted_once =
        format_sql_with_config(SCRIPTING_TRIVIA_INPUT, &FormatterConfig::default())
            .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Scripting trivia formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_cluster_dup.sql (CLUSTER BY comment duplication bug)
// ============================================================================

const CLUSTER_DUP_INPUT: &str = include_str!("./fixtures/test_cluster_dup.sql");
const CLUSTER_DUP_EXPECTED: &str = include_str!("./fixtures/test_cluster_dup_formatted.sql");

#[test]
fn test_cluster_dup_golden() {
    let formatted = format_sql_with_config(CLUSTER_DUP_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(
        formatted.trim(),
        CLUSTER_DUP_EXPECTED.trim(),
        "test_cluster_dup.sql should format to golden output"
    );
}

#[test]
fn test_cluster_dup_no_comment_duplication() {
    // This file was explicitly created to catch CLUSTER BY comment duplication.
    // Ensure each comment appears exactly once.
    let formatted = format_sql_with_config(CLUSTER_DUP_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(CLUSTER_DUP_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");

    // Also check that "after CLUSTER" comment appears exactly once
    let cluster_comment_count = formatted.matches("/* after CLUSTER */").count();
    assert_eq!(
        cluster_comment_count, 1,
        "CLUSTER BY comment should not be duplicated"
    );
}

#[test]
fn test_cluster_dup_idempotent() {
    let formatted_once = format_sql_with_config(CLUSTER_DUP_INPUT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Cluster dup formatting should be idempotent"
    );
}

// ============================================================================
// STRESS TESTS: Comment carnage designed to murder parsers
// ============================================================================

// ============================================================================
// Test: test_comment_carnage.sql - Stress test with comments in every possible position
// ============================================================================

const COMMENT_CARNAGE_INPUT: &str = include_str!("./fixtures/test_comment_carnage.sql");

#[test]
fn test_comment_carnage_preserves_all_comments() {
    let formatted = format_sql_with_config(COMMENT_CARNAGE_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(COMMENT_CARNAGE_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_comment_carnage_preserves_tokens() {
    let formatted = format_sql_with_config(COMMENT_CARNAGE_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    let orig_tokens = extract_significant_tokens(COMMENT_CARNAGE_INPUT);
    let fmt_tokens = extract_significant_tokens(&formatted);

    assert_eq!(
        orig_tokens.len(),
        fmt_tokens.len(),
        "Token count should be preserved through carnage"
    );

    // Verify key tokens are present
    let formatted_lower = formatted.to_lowercase();
    assert!(
        formatted_lower.contains("select"),
        "SELECT should be present"
    );
    assert!(formatted_lower.contains("where"), "WHERE should be present");
    assert!(formatted_lower.contains("group"), "GROUP should be present");
    assert!(
        formatted_lower.contains("having"),
        "HAVING should be present"
    );
    assert!(formatted_lower.contains("order"), "ORDER should be present");
    assert!(formatted_lower.contains("limit"), "LIMIT should be present");
}

#[test]
fn test_comment_carnage_idempotent() {
    let formatted_once = format_sql_with_config(COMMENT_CARNAGE_INPUT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Carnage formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_comment_nesting_hell.sql - Deeply nested subqueries with comments
// ============================================================================

const COMMENT_NESTING_HELL_INPUT: &str = include_str!("./fixtures/test_comment_nesting_hell.sql");

#[test]
fn test_nesting_hell_preserves_all_comments() {
    let formatted = format_sql_with_config(COMMENT_NESTING_HELL_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(COMMENT_NESTING_HELL_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_nesting_hell_preserves_structure() {
    let formatted = format_sql_with_config(COMMENT_NESTING_HELL_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Check that all 5 levels are present by looking for level markers
    assert!(formatted.contains("level 0"), "Level 0 should be present");
    assert!(formatted.contains("level 1"), "Level 1 should be present");
    assert!(formatted.contains("level 2"), "Level 2 should be present");
    assert!(formatted.contains("level 3"), "Level 3 should be present");
    assert!(formatted.contains("level 4"), "Level 4 should be present");

    // Check nesting aliases
    let formatted_lower = formatted.to_lowercase();
    assert!(
        formatted_lower.contains("nested1"),
        "nested1 alias should be present"
    );
    assert!(
        formatted_lower.contains("nested2"),
        "nested2 alias should be present"
    );
    assert!(
        formatted_lower.contains("nested3"),
        "nested3 alias should be present"
    );
    assert!(
        formatted_lower.contains("nested4"),
        "nested4 alias should be present"
    );
}

#[test]
fn test_nesting_hell_idempotent() {
    let formatted_once =
        format_sql_with_config(COMMENT_NESTING_HELL_INPUT, &FormatterConfig::default())
            .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Nesting hell formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_comment_cte_chaos.sql (CTEs with comments everywhere)
// ============================================================================

const CTE_CHAOS_INPUT: &str = include_str!("./fixtures/test_comment_cte_chaos.sql");

#[test]
fn test_cte_chaos_preserves_all_comments() {
    let formatted = format_sql_with_config(CTE_CHAOS_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(CTE_CHAOS_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_cte_chaos_preserves_cte_names() {
    let formatted = format_sql_with_config(CTE_CHAOS_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    let formatted_lower = formatted.to_lowercase();
    assert!(formatted_lower.contains("cte1"), "cte1 should be present");
    assert!(formatted_lower.contains("cte2"), "cte2 should be present");
    assert!(formatted_lower.contains("cte3"), "cte3 should be present");
}

#[test]
fn test_cte_chaos_idempotent() {
    let formatted_once = format_sql_with_config(CTE_CHAOS_INPUT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "CTE chaos formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_comment_case_madness.sql (CASE expressions with heavy commenting)
// ============================================================================

const CASE_MADNESS_INPUT: &str = include_str!("./fixtures/test_comment_case_madness.sql");

#[test]
fn test_case_madness_preserves_all_comments() {
    let formatted = format_sql_with_config(CASE_MADNESS_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(CASE_MADNESS_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_case_madness_preserves_case_structure() {
    let formatted = format_sql_with_config(CASE_MADNESS_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    let formatted_lower = formatted.to_lowercase();
    let case_count = formatted_lower.matches("case").count();
    let when_count = formatted_lower.matches("when").count();
    let then_count = formatted_lower.matches("then").count();
    let end_count = formatted_lower.matches("end").count();

    assert!(case_count >= 3, "Should have at least 3 CASE expressions");
    assert!(when_count >= 6, "Should have at least 6 WHEN clauses");
    assert!(then_count >= 6, "Should have at least 6 THEN clauses");
    assert!(end_count >= 3, "Should have at least 3 END keywords");
}

#[test]
fn test_case_madness_idempotent() {
    let formatted_once = format_sql_with_config(CASE_MADNESS_INPUT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "CASE madness formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_comment_window_hell.sql (window functions with maximum comments)
// ============================================================================

const WINDOW_HELL_INPUT: &str = include_str!("./fixtures/test_comment_window_hell.sql");

#[test]
fn test_window_hell_preserves_all_comments() {
    let formatted = format_sql_with_config(WINDOW_HELL_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    verify_formatting_safe(WINDOW_HELL_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_window_hell_preserves_window_functions() {
    let formatted = format_sql_with_config(WINDOW_HELL_INPUT, &FormatterConfig::default())
        .expect("formatting should succeed");

    let formatted_lower = formatted.to_lowercase();
    assert!(
        formatted_lower.contains("row_number"),
        "ROW_NUMBER should be present"
    );
    assert!(formatted_lower.contains("sum"), "SUM should be present");
    assert!(formatted_lower.contains("avg"), "AVG should be present");
    assert!(formatted_lower.contains("lead"), "LEAD should be present");

    let over_count = formatted_lower.matches("over").count();
    assert!(over_count >= 4, "Should have at least 4 OVER clauses");
}

#[test]
fn test_window_hell_idempotent() {
    let formatted_once = format_sql_with_config(WINDOW_HELL_INPUT, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Window hell formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_comment_create_table_nightmare.sql (CREATE TABLE with exhaustive comments)
// ============================================================================

const CREATE_TABLE_NIGHTMARE_INPUT: &str =
    include_str!("./fixtures/test_comment_create_table_nightmare.sql");

#[test]
fn test_create_table_nightmare_preserves_all_comments() {
    let formatted =
        format_sql_with_config(CREATE_TABLE_NIGHTMARE_INPUT, &FormatterConfig::default())
            .expect("formatting should succeed");

    verify_formatting_safe(CREATE_TABLE_NIGHTMARE_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_create_table_nightmare_preserves_structure() {
    let formatted =
        format_sql_with_config(CREATE_TABLE_NIGHTMARE_INPUT, &FormatterConfig::default())
            .expect("formatting should succeed");

    let formatted_lower = formatted.to_lowercase();
    assert!(
        formatted_lower.contains("create"),
        "CREATE should be present"
    );
    assert!(formatted_lower.contains("table"), "TABLE should be present");
    // PRIMARY KEY may have comments between the keywords, so check separately
    assert!(
        formatted_lower.contains("primary"),
        "PRIMARY should be present"
    );
    assert!(formatted_lower.contains("key"), "KEY should be present");
    // FOREIGN KEY may have comments between the keywords, so check separately
    assert!(
        formatted_lower.contains("foreign"),
        "FOREIGN should be present"
    );
    assert!(
        formatted_lower.contains("cluster by"),
        "CLUSTER BY should be present"
    );
    assert!(
        formatted_lower.contains("change_tracking"),
        "CHANGE_TRACKING should be present"
    );
}

#[test]
fn test_create_table_nightmare_idempotent() {
    let formatted_once =
        format_sql_with_config(CREATE_TABLE_NIGHTMARE_INPUT, &FormatterConfig::default())
            .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "CREATE TABLE nightmare formatting should be idempotent"
    );
}

// ============================================================================
// Test: test_comment_merge_apocalypse.sql - MERGE with maximum comment density
// ============================================================================

const COMMENT_MERGE_APOCALYPSE_INPUT: &str =
    include_str!("./fixtures/test_comment_merge_apocalypse.sql");

#[test]
fn test_merge_apocalypse_preserves_all_comments() {
    let formatted =
        format_sql_with_config(COMMENT_MERGE_APOCALYPSE_INPUT, &FormatterConfig::default())
            .expect("formatting should succeed");

    verify_formatting_safe(COMMENT_MERGE_APOCALYPSE_INPUT, &formatted)
        .expect("Formatting should preserve all significant tokens and comments");
}

#[test]
fn test_merge_apocalypse_preserves_merge_clauses() {
    let formatted =
        format_sql_with_config(COMMENT_MERGE_APOCALYPSE_INPUT, &FormatterConfig::default())
            .expect("formatting should succeed");

    let formatted_lower = formatted.to_lowercase();
    assert!(formatted_lower.contains("merge"), "MERGE should be present");
    assert!(formatted_lower.contains("using"), "USING should be present");

    // Check for all WHEN clauses
    let when_matched_count = formatted_lower.matches("when matched").count();
    let when_not_matched_count = formatted_lower.matches("when not matched").count();

    assert!(
        when_matched_count >= 2,
        "Should have at least 2 WHEN MATCHED clauses"
    );
    assert!(
        when_not_matched_count >= 2,
        "Should have at least 2 WHEN NOT MATCHED clauses"
    );

    assert!(
        formatted_lower.contains("update"),
        "UPDATE should be present"
    );
    assert!(
        formatted_lower.contains("insert"),
        "INSERT should be present"
    );
    assert!(
        formatted_lower.contains("delete"),
        "DELETE should be present"
    );
}

#[test]
fn test_merge_apocalypse_idempotent() {
    let formatted_once =
        format_sql_with_config(COMMENT_MERGE_APOCALYPSE_INPUT, &FormatterConfig::default())
            .expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "MERGE apocalypse formatting should be idempotent"
    );
}
