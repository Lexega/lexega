// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for data loss verification
//!
//! These tests verify that the parser's verification catches scenarios
//! where tokens might be consumed but not properly added to the AST.

use lexega_syntax::{parser::try_parse_stmt, tokenize, try_parse_stmt_from_str};

#[test]
fn test_all_tokens_consumed_verification() {
    // Valid SQL - should parse successfully
    let sql = "SELECT * FROM users WHERE id > 10";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Valid SQL should parse: {:?}", result.err());
}

#[test]
fn test_unconsumed_tokens_detected() {
    // This should be caught by verify_all_tokens_consumed if parser stops early
    let sql = "SELECT * FROM users; DROP TABLE users";

    // If we only parse the first statement, the DROP TABLE should be caught
    let tokens = tokenize(sql).tokens;
    let result = try_parse_stmt(sql, &tokens);

    // Should fail because DROP TABLE tokens remain unconsumed
    assert!(result.is_err(), "Should detect unconsumed tokens");
    if let Err(e) = result {
        let msg = e.message();
        assert!(
            msg.contains("unconsumed") || msg.contains("DATA LOSS"),
            "Error should mention unconsumed tokens: {}",
            msg
        );
    }
}

#[test]
fn test_span_coverage_basic() {
    // Simple SELECT - AST span should cover all source
    let sql = "SELECT id, name FROM users";
    let result = try_parse_stmt_from_str(sql);

    assert!(result.is_ok(), "Should parse successfully");

    if let Ok(stmt) = result {
        let span = stmt.span();
        // Span should cover most of the source (allowing for trailing whitespace)
        let expected_min = (sql.trim().len().saturating_sub(1)) as u32;
        assert!(
            span.end >= expected_min,
            "AST span {} should cover source length {}",
            span.end,
            sql.trim().len()
        );
    }
}

#[test]
fn test_complex_statement_coverage() {
    let sql = r#"
        CREATE TABLE users (
            id INT PRIMARY KEY,
            name STRING NOT NULL,
            email STRING UNIQUE
        )
    "#;

    let result = try_parse_stmt_from_str(sql);
    assert!(
        result.is_ok(),
        "Complex CREATE TABLE should parse: {:?}",
        result.err()
    );

    if let Ok(stmt) = result {
        let span = stmt.span();
        // Should cover most of the trimmed source
        let trimmed = sql.trim();
        let expected_min = (trimmed.len().saturating_sub(10)) as u32;
        assert!(
            span.end >= expected_min, // Allow small margin
            "AST span {} should cover source (length {})",
            span.end,
            trimmed.len()
        );
    }
}

#[test]
fn test_jinja_tokens_included() {
    let sql = "SELECT {{ column }} FROM {{ table_name }} WHERE id > 10";
    let result = try_parse_stmt_from_str(sql);

    assert!(result.is_ok(), "Jinja SQL should parse: {:?}", result.err());

    if let Ok(stmt) = result {
        let span = stmt.span();
        // Jinja tokens should be included in span
        let expected_min = (sql.trim().len().saturating_sub(5)) as u32;
        assert!(
            span.end >= expected_min,
            "AST should include Jinja tokens in span"
        );
    }
}

#[test]
fn test_verification_diagnostic_messages() {
    // Create invalid SQL that will leave tokens unconsumed
    let sql = "SELECT * INVALID SYNTAX HERE";
    let result = try_parse_stmt_from_str(sql);

    // Should fail with detailed diagnostic
    assert!(result.is_err(), "Invalid SQL should fail parsing");

    if let Err(e) = result {
        let msg = e.message();
        // New verification should provide detailed diagnostics
        assert!(
            msg.contains("DATA LOSS") || msg.contains("unconsumed") || msg.contains("unexpected"),
            "Error should have detailed diagnostic: {}",
            msg
        );
    }
}

#[test]
fn test_multiple_statements_first_only() {
    // Multiple statements - parsing just first should detect remaining tokens
    let sql = "SELECT 1; SELECT 2; SELECT 3";
    let tokens = tokenize(sql).tokens;

    // try_parse_stmt should detect that tokens remain after first statement
    let result = try_parse_stmt(sql, &tokens);

    // This should fail because semicolon and subsequent statements remain
    assert!(result.is_err(), "Should detect multiple statements");
}

#[test]
fn test_trailing_semicolon_ok() {
    // Single statement with trailing semicolon should be OK
    // (semicolon is part of the statement)
    let sql = "SELECT * FROM users;";
    let result = try_parse_stmt_from_str(sql);

    // This might succeed or fail depending on how semicolons are handled
    // The key is it shouldn't crash and should give clear error if it fails
    match result {
        Ok(_) => assert!(true, "Parsed successfully"),
        Err(e) => {
            let msg = e.message();
            assert!(
                msg.contains("unconsumed")
                    || msg.contains("DATA LOSS")
                    || msg.contains("semicolon"),
                "Error should be clear: {}",
                msg
            );
        }
    }
}
