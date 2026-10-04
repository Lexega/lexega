// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dedicated tests for MATCH_RECOGNIZE pattern matching
//! Covers simple to complex MATCH_RECOGNIZE statements with various measures and patterns

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

// ============================================================================
// Simple MATCH_RECOGNIZE Tests
// ============================================================================

#[test]
fn test_match_recognize_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_match_recognize_simple.sql")
        .expect("failed to read test_match_recognize_simple.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_match_recognize_simple.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_match_recognize_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_match_recognize_simple.sql formatting should be safe");
}

#[test]
fn test_match_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_match_simple.sql")
        .expect("failed to read test_match_simple.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_match_simple.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_match_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_match_simple.sql formatting should be safe");
}

#[test]
fn test_mr_oneline() {
    let sql = fs::read_to_string("tests/fixtures/test_mr_oneline.sql")
        .expect("failed to read test_mr_oneline.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_mr_oneline.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_mr_oneline.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_mr_oneline.sql formatting should be safe");
}

#[test]
fn test_mr_no_measures() {
    let sql = fs::read_to_string("tests/fixtures/test_mr_no_measures.sql")
        .expect("failed to read test_mr_no_measures.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_mr_no_measures.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_mr_no_measures.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_mr_no_measures.sql formatting should be safe");
}

// ============================================================================
// Complex & Deep MATCH_RECOGNIZE Tests
// ============================================================================

#[test]
fn test_match_recognize_deep() {
    let sql = fs::read_to_string("tests/fixtures/test_match_recognize_deep.sql")
        .expect("failed to read test_match_recognize_deep.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_match_recognize_deep.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_match_recognize_deep.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_match_recognize_deep.sql formatting should be safe");
}

#[test]
fn test_match_recognize_nested() {
    let sql = fs::read_to_string("tests/fixtures/test_match_recognize_nested.sql")
        .expect("failed to read test_match_recognize_nested.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_match_recognize_nested.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_match_recognize_nested.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_match_recognize_nested.sql formatting should be safe");
}

#[test]
fn test_match_recognize_15() {
    let sql = fs::read_to_string("tests/fixtures/test_match_recognize_15.sql")
        .expect("failed to read test_match_recognize_15.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_match_recognize_15.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_match_recognize_15.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_match_recognize_15.sql formatting should be safe");
}

#[test]
fn test_match_recognize_20() {
    let sql = fs::read_to_string("tests/fixtures/test_match_recognize_20.sql")
        .expect("failed to read test_match_recognize_20.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_match_recognize_20.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_match_recognize_20.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_match_recognize_20.sql formatting should be safe");
}

// ============================================================================
// MATCH_RECOGNIZE Features
// ============================================================================

#[test]
fn test_mr_measures() {
    let sql = fs::read_to_string("tests/fixtures/test_mr_measures.sql")
        .expect("failed to read test_mr_measures.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_mr_measures.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_mr_measures.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_mr_measures.sql formatting should be safe");
}

#[test]
fn test_mr_exact() {
    let sql = fs::read_to_string("tests/fixtures/test_mr_exact.sql")
        .expect("failed to read test_mr_exact.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_mr_exact.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_mr_exact.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_mr_exact.sql formatting should be safe");
}

#[test]
fn test_mr_comment() {
    let sql = fs::read_to_string("tests/fixtures/test_mr_comment.sql")
        .expect("failed to read test_mr_comment.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_mr_comment.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_mr_comment.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_mr_comment.sql formatting should be safe");
}

#[test]
fn test_mr_from_gnarly() {
    let sql = fs::read_to_string("tests/fixtures/test_mr_from_gnarly.sql")
        .expect("failed to read test_mr_from_gnarly.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_mr_from_gnarly.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_mr_from_gnarly.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_mr_from_gnarly.sql formatting should be safe");
}

// ============================================================================
// Hostile MATCH_RECOGNIZE Tests
// ============================================================================

#[test]
fn test_hostile_match_recognize() {
    let sql = fs::read_to_string("tests/fixtures/test_hostile_match_recognize.sql")
        .expect("failed to read test_hostile_match_recognize.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_hostile_match_recognize.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_hostile_match_recognize.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_hostile_match_recognize.sql formatting should be safe");
}

// ============================================================================
// Procedure with MATCH_RECOGNIZE Tests
// ============================================================================

#[test]
fn test_proc_match() {
    let sql = fs::read_to_string("tests/fixtures/test_proc_match.sql")
        .expect("failed to read test_proc_match.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_proc_match.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_proc_match.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_proc_match.sql formatting should be safe");
}

#[test]
fn test_proc_match_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_proc_match_simple.sql")
        .expect("failed to read test_proc_match_simple.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_proc_match_simple.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_proc_match_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_proc_match_simple.sql formatting should be safe");
}
