// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for edge case formatting scenarios
//!
//! These tests ensure the formatter handles unusual inputs gracefully:
//! - Empty input
//! - Comment-only input
//! - Semicolon-only input
//! - Whitespace-only input

use lexega_syntax::{format_sql, verify_formatting_safe};

#[test]
fn test_empty_input() {
    let sql = "";
    let result = format_sql(sql);
    assert!(result.is_ok(), "Empty input should format successfully");
    assert_eq!(result.unwrap(), "");
}

#[test]
fn test_whitespace_only() {
    let sql = "   \n\n   \t  ";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Whitespace-only input should format successfully"
    );
    // Whitespace is preserved as-is
    let formatted = result.unwrap();
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_single_line_comment_only() {
    let sql = "-- just a comment";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Comment-only input should format successfully"
    );
    let formatted = result.unwrap();
    assert!(
        formatted.contains("-- just a comment"),
        "Comment should be preserved"
    );
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_block_comment_only() {
    let sql = "/* block comment */";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Block comment-only input should format successfully"
    );
    let formatted = result.unwrap();
    assert!(
        formatted.contains("/* block comment */"),
        "Block comment should be preserved"
    );
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_multiple_comments_only() {
    let sql = r#"-- Header comment
/* block comment */

-- Another comment"#;
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Multiple comments should format successfully"
    );
    let formatted = result.unwrap();
    assert!(
        formatted.contains("-- Header comment"),
        "First comment should be preserved"
    );
    assert!(
        formatted.contains("/* block comment */"),
        "Block comment should be preserved"
    );
    assert!(
        formatted.contains("-- Another comment"),
        "Last comment should be preserved"
    );
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_semicolon_only() {
    let sql = ";";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Semicolon-only input should format successfully"
    );
    let formatted = result.unwrap();
    assert!(formatted.contains(";"), "Semicolon should be preserved");
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_multiple_semicolons() {
    let sql = ";;;\n;";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Multiple semicolons should format successfully"
    );
    let formatted = result.unwrap();
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_comment_then_statement() {
    let sql = r#"-- Header comment
SELECT 1;"#;
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Comment before statement should format successfully"
    );
    let formatted = result.unwrap();
    assert!(
        formatted.contains("-- Header comment"),
        "Header comment should be preserved"
    );
    assert!(formatted.contains("SELECT"), "Statement should be present");
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_statement_then_comment() {
    let sql = r#"SELECT 1;
-- Trailing comment"#;
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Statement with trailing comment should format successfully"
    );
    let formatted = result.unwrap();
    assert!(
        formatted.contains("-- Trailing comment"),
        "Trailing comment should be preserved"
    );
    assert!(formatted.contains("SELECT"), "Statement should be present");
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}

#[test]
fn test_newline_only() {
    let sql = "\n";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Newline-only input should format successfully"
    );
}

#[test]
fn test_comment_with_trailing_newlines() {
    let sql = "-- comment\n\n\n";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Comment with trailing newlines should format successfully"
    );
    let formatted = result.unwrap();
    assert!(
        formatted.contains("-- comment"),
        "Comment should be preserved"
    );
    verify_formatting_safe(sql, &formatted).expect("Should be safe");
}
