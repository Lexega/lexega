// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dedicated tests for procedures and Snowflake Scripting
//! Covers stored procedures, JavaScript procedures, scripting constructs, transactions

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

// ============================================================================
// Basic Procedures
// ============================================================================

#[test]
fn test_minimal_proc() {
    let sql = fs::read_to_string("tests/fixtures/test_minimal_proc.sql")
        .expect("failed to read test_minimal_proc.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_minimal_proc.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_minimal_proc.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_minimal_proc.sql formatting should be safe");
}

#[test]
fn test_minimal_proc_flow() {
    let sql = fs::read_to_string("tests/fixtures/test_minimal_proc_flow.sql")
        .expect("failed to read test_minimal_proc_flow.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_minimal_proc_flow.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_minimal_proc_flow.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_minimal_proc_flow.sql formatting should be safe");
}

#[test]
fn test_proc_minimal() {
    let sql = fs::read_to_string("tests/fixtures/test_proc_minimal.sql")
        .expect("failed to read test_proc_minimal.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_proc_minimal.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_proc_minimal.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_proc_minimal.sql formatting should be safe");
}

// ============================================================================
// JavaScript Procedures
// ============================================================================

#[test]
fn test_js_proc() {
    let sql = fs::read_to_string("tests/fixtures/test_js_proc.sql")
        .expect("failed to read test_js_proc.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_js_proc.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_js_proc.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_js_proc.sql formatting should be safe");
}

// ============================================================================
// Complex Procedures
// ============================================================================

#[test]
fn test_proc_debug() {
    let sql = fs::read_to_string("tests/fixtures/test_proc_debug.sql")
        .expect("failed to read test_proc_debug.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_proc_debug.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_proc_debug.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_proc_debug.sql formatting should be safe");
}

#[test]
fn test_proc_extract() {
    let sql = fs::read_to_string("tests/fixtures/test_proc_extract.sql")
        .expect("failed to read test_proc_extract.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_proc_extract.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_proc_extract.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_proc_extract.sql formatting should be safe");
}

#[test]
fn test_proc_gnarly() {
    let sql = fs::read_to_string("tests/fixtures/test_proc_gnarly.sql")
        .expect("failed to read test_proc_gnarly.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_proc_gnarly.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_proc_gnarly.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_proc_gnarly.sql formatting should be safe");
}

// ============================================================================
// Snowflake Scripting
// ============================================================================

#[test]
fn test_scripting() {
    let sql = fs::read_to_string("tests/fixtures/test_scripting.sql")
        .expect("failed to read test_scripting.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_scripting.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scripting.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_scripting.sql formatting should be safe");
}

#[test]
fn test_scripting_comments() {
    let sql = fs::read_to_string("tests/fixtures/test_scripting_comments.sql")
        .expect("failed to read test_scripting_comments.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_scripting_comments.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scripting_comments.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_scripting_comments.sql formatting should be safe");
}

#[test]
fn test_scripting_comments_declare() {
    let sql = fs::read_to_string("tests/fixtures/test_scripting_comments_declare.sql")
        .expect("failed to read test_scripting_comments_declare.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_scripting_comments_declare.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scripting_comments_declare.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_scripting_comments_declare.sql formatting should be safe");
}

#[test]
fn test_scripting_loops() {
    let sql = fs::read_to_string("tests/fixtures/test_scripting_loops.sql")
        .expect("failed to read test_scripting_loops.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_scripting_loops.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scripting_loops.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_scripting_loops.sql formatting should be safe");
}

#[test]
fn test_scripting_pipe_subquery() {
    let sql = fs::read_to_string("tests/fixtures/test_scripting_pipe_subquery.sql")
        .expect("failed to read test_scripting_pipe_subquery.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_scripting_pipe_subquery.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scripting_pipe_subquery.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_scripting_pipe_subquery.sql formatting should be safe");
}

#[test]
fn test_scripting_trivia() {
    let sql = fs::read_to_string("tests/fixtures/test_scripting_trivia.sql")
        .expect("failed to read test_scripting_trivia.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_scripting_trivia.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scripting_trivia.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_scripting_trivia.sql formatting should be safe");
}

#[test]
fn test_scripting_var() {
    let sql = fs::read_to_string("tests/fixtures/test_scripting_var.sql")
        .expect("failed to read test_scripting_var.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_scripting_var.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_scripting_var.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_scripting_var.sql formatting should be safe");
}

// ============================================================================
// Transactions
// ============================================================================

#[test]
fn test_transactions() {
    let sql = fs::read_to_string("tests/fixtures/test_transactions.sql")
        .expect("failed to read test_transactions.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_transactions.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_transactions.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_transactions.sql formatting should be safe");
}

#[test]
fn test_txn_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_txn_simple.sql")
        .expect("failed to read test_txn_simple.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_txn_simple.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_txn_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_txn_simple.sql formatting should be safe");
}
