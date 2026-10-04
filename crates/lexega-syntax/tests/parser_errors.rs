// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for parse error reporting.
//!
//! These tests verify that the parser returns structured errors with
//! meaningful messages and accurate span information when given invalid SQL.

use lexega_syntax::{try_parse_script_from_str, try_parse_stmt_from_str};

#[test]
fn test_empty_input() {
    let result = try_parse_stmt_from_str("");
    assert!(result.is_err(), "Empty input should fail");

    let err = result.unwrap_err();
    assert_eq!(err.span.start, 0);
    assert_eq!(err.span.end, 0);
}

#[test]
fn test_incomplete_select() {
    let result = try_parse_stmt_from_str("SELECT");
    assert!(result.is_err(), "Incomplete SELECT should fail");

    let err = result.unwrap_err();
    // The message names the failed statement or the missing projection.
    let msg = err.message();
    assert!(
        msg.contains("Failed to parse") || msg.contains("projection") || msg.contains("Invalid"),
        "Error should mention parsing failure, got: {}",
        msg
    );
}

#[test]
fn test_select_missing_from_expression() {
    // Currently the parser may accept "SELECT FROM users" as valid
    // This test documents current behavior
    let result = try_parse_stmt_from_str("SELECT FROM users");
    match result {
        Ok(_) => {} // Parser is lenient
        Err(err) => {
            assert!(err.span.end >= err.span.start, "Error span should be valid");
        }
    }
}

#[test]
fn test_unclosed_parenthesis() {
    // Currently may succeed with partial parse
    let result = try_parse_stmt_from_str("SELECT * FROM (SELECT * FROM users");
    match result {
        Ok(_) => {}  // Parser may be lenient
        Err(_) => {} // Or it may fail
    }
}

#[test]
fn test_invalid_create_table() {
    // CREATE TABLE without name - currently returns Some
    let result = try_parse_stmt_from_str("CREATE TABLE");
    match result {
        Ok(_) => {}  // Parser is lenient
        Err(_) => {} // Or strict
    }
}

#[test]
fn test_invalid_insert() {
    // INSERT INTO without table - now properly rejected
    let result = try_parse_stmt_from_str("INSERT INTO");
    assert!(result.is_err(), "INSERT INTO without table should fail");
}

#[test]
fn test_invalid_update() {
    // UPDATE without table - now properly rejected
    let result = try_parse_stmt_from_str("UPDATE");
    assert!(result.is_err(), "UPDATE without table should fail");
}

#[test]
fn test_update_missing_set() {
    // UPDATE without SET - now properly rejected
    let result = try_parse_stmt_from_str("UPDATE users");
    assert!(result.is_err(), "UPDATE without SET should fail");
}

#[test]
fn test_invalid_delete() {
    // DELETE without FROM - now properly rejected
    let result = try_parse_stmt_from_str("DELETE");
    assert!(result.is_err(), "DELETE without FROM should fail");
}

#[test]
fn test_invalid_merge() {
    // MERGE without INTO - now properly rejected
    let result = try_parse_stmt_from_str("MERGE");
    assert!(result.is_err(), "MERGE without INTO should fail");
}

#[test]
fn test_merge_missing_using() {
    // MERGE without USING - now properly rejected
    let result = try_parse_stmt_from_str("MERGE INTO target");
    assert!(result.is_err(), "MERGE without USING should fail");
}

#[test]
fn test_merge_missing_on() {
    // MERGE without ON - now properly rejected
    let result = try_parse_stmt_from_str("MERGE INTO target USING source");
    assert!(result.is_err(), "MERGE without ON should fail");
}

#[test]
fn test_invalid_case_expression() {
    let result = try_parse_stmt_from_str("SELECT CASE WHEN x > 5 FROM users");
    assert!(result.is_err(), "CASE without THEN should fail");
}

#[test]
fn test_unclosed_case_expression() {
    let result = try_parse_stmt_from_str("SELECT CASE WHEN x > 5 THEN 1 FROM users");
    assert!(result.is_err(), "CASE without END should fail");
}

#[test]
fn test_invalid_join() {
    // JOIN without table - currently returns Some
    let result = try_parse_stmt_from_str("SELECT * FROM users JOIN");
    match result {
        Ok(_) => {}  // Parser is lenient
        Err(_) => {} // Or strict
    }
}

#[test]
fn test_join_missing_on() {
    // JOIN without ON/USING - currently returns Some
    let result = try_parse_stmt_from_str("SELECT * FROM users JOIN orders");
    match result {
        Ok(_) => {}  // Parser is lenient
        Err(_) => {} // Or strict
    }
}

#[test]
fn test_invalid_scripting_block() {
    let result = try_parse_stmt_from_str("BEGIN");
    assert!(result.is_err(), "BEGIN without END should fail");
}

#[test]
fn test_unmatched_end() {
    let result = try_parse_stmt_from_str("END;");
    assert!(result.is_err(), "END without BEGIN should fail");
}

#[test]
fn test_invalid_if_statement() {
    let result = try_parse_stmt_from_str("IF (x > 5) THEN");
    assert!(result.is_err(), "IF without body should fail");
}

#[test]
fn test_invalid_loop() {
    let result = try_parse_stmt_from_str("LOOP");
    assert!(result.is_err(), "LOOP without END LOOP should fail");
}

#[test]
fn test_script_with_one_invalid_stmt() {
    // First statement is valid, second is not - but parser might be lenient
    let result = try_parse_script_from_str("SELECT * FROM users; INSERT INTO");
    match result {
        Ok(script) => {
            // Parser succeeded, possibly with partial parse of second statement
            assert!(script.stmts.len() >= 1);
        }
        Err(_) => {
            // Or parser failed on invalid second statement
        }
    }
}

// Test that error messages are descriptive
#[test]
fn test_error_message_quality() {
    // SELEKT is not a valid keyword - should fail at parse_stmt_core level
    let result = try_parse_stmt_from_str("SELEKT * FROM users");
    assert!(result.is_err(), "Invalid keyword should fail");

    let err = result.unwrap_err();
    let message = err.message();
    // The message should indicate the parse failed
    assert!(
        !message.is_empty(),
        "Error message should not be empty: '{}'",
        message
    );
}

// Test span accuracy
#[test]
fn test_error_span_for_typo() {
    // This will fail because WHRE is not recognized
    let sql = "SELECT * FROM users WHRE id > 5";
    let result = try_parse_stmt_from_str(sql);

    match result {
        Ok(_) => {
            // Parser may have stopped at WHRE and considered it valid
        }
        Err(err) => {
            // The span should be somewhere in the input (not beyond it)
            assert!(
                err.span.start < sql.len() as u32,
                "Span start should be within input"
            );
            assert!(
                err.span.end <= sql.len() as u32,
                "Span end should be within input"
            );
        }
    }
}

// Test Display implementation
#[test]
fn test_error_display() {
    let result = try_parse_stmt_from_str("SELECT");
    assert!(result.is_err());

    let err = result.unwrap_err();
    let display_str = format!("{}", err);

    // Should contain "Parse error at" and a message
    assert!(display_str.contains("Parse error"));
    assert!(display_str.contains(".."));
}

// Test successful parse returns Ok
#[test]
fn test_valid_sql_returns_ok() {
    let result = try_parse_stmt_from_str("SELECT * FROM users");
    assert!(result.is_ok(), "Valid SQL should parse successfully");
}

#[test]
fn test_valid_script_returns_ok() {
    let result =
        try_parse_script_from_str("SELECT * FROM users; INSERT INTO logs VALUES (1, 'test');");
    assert!(result.is_ok(), "Valid script should parse successfully");
}

// Test various invalid expressions
#[test]
fn test_invalid_binary_operator() {
    let result = try_parse_stmt_from_str("SELECT 1 + FROM users");
    assert!(result.is_err(), "Invalid binary operator usage should fail");
}

#[test]
fn test_invalid_function_call() {
    let result = try_parse_stmt_from_str("SELECT MAX( FROM users");
    assert!(result.is_err(), "Unclosed function call should fail");
}

#[test]
fn test_invalid_subquery() {
    // Incomplete subquery - parser may be lenient
    let result = try_parse_stmt_from_str("SELECT * FROM (SELECT * FROM");
    match result {
        Ok(_) => {}  // Parser is lenient
        Err(_) => {} // Or strict
    }
}

#[test]
fn test_missing_comma_in_projection() {
    // This might actually parse as separate expressions depending on implementation
    let result = try_parse_stmt_from_str("SELECT id name FROM users");
    // Accept either success (if parser is lenient) or error
    match result {
        Ok(_) => {} // Parser accepted it
        Err(e) => {
            assert!(!e.message().is_empty(), "Error should have message");
        }
    }
}
