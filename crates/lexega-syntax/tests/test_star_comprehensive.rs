// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Comprehensive tests for star modifiers (EXCLUDE/REPLACE/RENAME) with comments.
/// Verifies both parsing AND formatting with trivia preservation.
use lexega_syntax::{format_sql_with_config, parse_stmt_from_str, FormatterConfig};

// Test star patterns from test_star_trivia.sql
const STAR_TRIVIA_SQL: &str = include_str!("./fixtures/test_star_trivia.sql");

#[test]
fn test_star_patterns_parse() {
    let patterns = vec![
        "SELECT col1, * FROM table1;",
        "SELECT a, * EXCLUDE (id, password) FROM users;",
        "SELECT b, * REPLACE (UPPER(name) AS name) FROM data;",
        "SELECT c, * RENAME (old_col AS new_col) FROM data;",
        "SELECT d, * EXCLUDE (id) REPLACE (1 AS status) RENAME (old AS new) FROM data;",
        "SELECT x, t.* EXCLUDE (secret) FROM table1 t;",
        "SELECT y, emp.* REPLACE (UPPER(name) AS name) FROM employees emp;",
        "SELECT z, dept.* RENAME (dname AS department_name) FROM departments dept;",
        "SELECT a, *, b, t.* EXCLUDE (id), c FROM t;",
        "SELECT x, *, y FROM data;",
    ];

    for (i, sql) in patterns.iter().enumerate() {
        let stmt = parse_stmt_from_str(sql);
        assert!(stmt.is_some(), "Pattern {} should parse: {}", i + 1, sql);
    }
}

#[test]
fn test_star_patterns_format() {
    let patterns = vec![
        "SELECT col1, * FROM table1;",
        "SELECT a, * EXCLUDE (id, password) FROM users;",
        "SELECT b, * REPLACE (UPPER(name) AS name) FROM data;",
        "SELECT c, * RENAME (old_col AS new_col) FROM data;",
        "SELECT d, * EXCLUDE (id) REPLACE (1 AS status) RENAME (old AS new) FROM data;",
        "SELECT x, t.* EXCLUDE (secret) FROM table1 t;",
        "SELECT y, emp.* REPLACE (UPPER(name) AS name) FROM employees emp;",
        "SELECT z, dept.* RENAME (dname AS department_name) FROM departments dept;",
        "SELECT a, *, b, t.* EXCLUDE (id), c FROM t;",
        "SELECT x, *, y FROM data;",
    ];

    for (i, sql) in patterns.iter().enumerate() {
        let formatted = format_sql_with_config(sql, &FormatterConfig::default());
        assert!(
            formatted.is_ok(),
            "Pattern {} should format: {}",
            i + 1,
            sql
        );

        // Verify idempotence
        let formatted_once = formatted.unwrap();
        let formatted_twice = format_sql_with_config(&formatted_once, &FormatterConfig::default())
            .expect("second format should succeed");
        assert_eq!(
            formatted_once.trim(),
            formatted_twice.trim(),
            "Pattern {} formatting should be idempotent",
            i + 1
        );
    }
}

#[test]
fn test_star_with_comments_parse() {
    // Parse the comprehensive star+comment test file
    let stmt = parse_stmt_from_str(STAR_TRIVIA_SQL);
    assert!(
        stmt.is_some(),
        "test_star_trivia.sql should parse successfully"
    );
}

#[test]
fn test_star_with_comments_format() {
    // Format the star+comment test file and verify it succeeds
    let formatted = format_sql_with_config(STAR_TRIVIA_SQL, &FormatterConfig::default());
    assert!(
        formatted.is_ok(),
        "test_star_trivia.sql should format successfully"
    );
}

#[test]
fn test_star_comments_preserved() {
    let formatted = format_sql_with_config(STAR_TRIVIA_SQL, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Count block comments
    let input_blocks = STAR_TRIVIA_SQL.matches("/*").count();
    let formatted_blocks = formatted.matches("/*").count();
    assert_eq!(
        input_blocks, formatted_blocks,
        "All block comments around stars should be preserved"
    );

    // Count line comments
    let input_lines = STAR_TRIVIA_SQL
        .lines()
        .filter(|l| l.trim_start().starts_with("--"))
        .count();
    let formatted_lines = formatted
        .lines()
        .filter(|l| l.trim_start().starts_with("--"))
        .count();
    assert_eq!(
        input_lines, formatted_lines,
        "All line comments around stars should be preserved"
    );
}

#[test]
fn test_star_specific_comment_placement() {
    // Test that specific comments around star modifiers are preserved in correct positions
    let sql = "SELECT /* before star */ * /* after star */ EXCLUDE /* after exclude */ (id) /* after list */ FROM t;";
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("formatting should succeed");

    // All 4 comments should be present
    assert_eq!(
        formatted.matches("/*").count(),
        4,
        "All 4 comments should be preserved"
    );
    assert!(
        formatted.contains("/* before star */"),
        "Comment before star should be preserved"
    );
    assert!(
        formatted.contains("/* after star */"),
        "Comment after star should be preserved"
    );
    assert!(
        formatted.contains("/* after exclude */"),
        "Comment after EXCLUDE should be preserved"
    );
    assert!(
        formatted.contains("/* after list */"),
        "Comment after column list should be preserved"
    );
}
