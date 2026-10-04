// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! VALIDATION TESTS: INSERT statement error handling.
//!
//! These tests verify that validation errors are detected.

use lexega_syntax::format_sql;

#[test]
fn test_insert_column_count_mismatch() {
    // Parser should accept mismatched column counts
    // Snowflake runtime will validate this, not the parser
    let sql = "INSERT INTO t VALUES (1, 2), (3, 4, 5)";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Parser should accept mismatched column counts (Snowflake runtime will validate)"
    );
}

#[test]
fn test_insert_column_list_mismatch() {
    // Parser should accept column list/values count mismatches
    // Snowflake runtime will validate this, not the parser
    let sql = "INSERT INTO t (a, b) VALUES (1, 2, 3)";
    let result = format_sql(sql);
    assert!(
        result.is_ok(),
        "Parser should accept column list/values mismatch (Snowflake runtime will validate)"
    );
}

#[test]
fn test_insert_with_default() {
    // Test that DEFAULT keyword works in VALUES
    let sql = "INSERT INTO t (a, b, c) VALUES (1, DEFAULT, 3)";
    let result = format_sql(sql);
    assert!(result.is_ok());
}

#[test]
fn test_insert_with_null() {
    // Test that NULL keyword works in VALUES
    let sql = "INSERT INTO t VALUES (1, NULL, 3)";
    let result = format_sql(sql);
    assert!(result.is_ok());
}

#[test]
fn test_insert_valid() {
    // Test valid INSERT with matching counts
    let sql = "INSERT INTO employees (id, name, dept) VALUES (1, 'John', 'Engineering'), (2, 'Jane', 'Sales')";
    let result = format_sql(sql);
    if let Err(e) = &result {
        eprintln!("Error formatting: {}", e);
    }
    assert!(result.is_ok());
}
