// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dedicated tests for DML operations: UPDATE, INSERT, DELETE, MERGE
//! Covers all fixture files related to data manipulation statements.

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

// ============================================================================
// UPDATE Operations
// ============================================================================

#[test]
fn test_update_basic() {
    let sql = fs::read_to_string("tests/fixtures/test_update.sql")
        .expect("failed to read test_update.sql");

    // Parse
    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_update.sql should parse successfully: {:?}",
        parsed.err()
    );

    // Format
    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_update.sql should format successfully");

    // Verify safe
    verify_formatting_safe(&sql, &formatted).expect("test_update.sql formatting should be safe");
}

#[test]
fn test_update_complex() {
    let sql = fs::read_to_string("tests/fixtures/test_update_complex.sql")
        .expect("failed to read test_update_complex.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_update_complex.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_update_complex.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_update_complex.sql formatting should be safe");
}

#[test]
fn test_update_from() {
    let sql = fs::read_to_string("tests/fixtures/test_update_from.sql")
        .expect("failed to read test_update_from.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_update_from.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_update_from.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_update_from.sql formatting should be safe");
}

#[test]
fn test_update_join() {
    let sql = fs::read_to_string("tests/fixtures/test_update_join.sql")
        .expect("failed to read test_update_join.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_update_join.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_update_join.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_update_join.sql formatting should be safe");
}

#[test]
fn test_update_multi() {
    let sql = fs::read_to_string("tests/fixtures/test_update_multi.sql")
        .expect("failed to read test_update_multi.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_update_multi.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_update_multi.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_update_multi.sql formatting should be safe");
}

#[test]
fn test_update_varied() {
    let sql = fs::read_to_string("tests/fixtures/test_update_varied.sql")
        .expect("failed to read test_update_varied.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_update_varied.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_update_varied.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_update_varied.sql formatting should be safe");
}

// ============================================================================
// INSERT Operations
// ============================================================================

#[test]
fn test_insert_basic() {
    let sql = fs::read_to_string("tests/fixtures/test_insert.sql")
        .expect("failed to read test_insert.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_insert.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_insert.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_insert.sql formatting should be safe");
}

#[test]
fn test_insert_multi() {
    let sql = fs::read_to_string("tests/fixtures/test_insert_multi.sql")
        .expect("failed to read test_insert_multi.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_insert_multi.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_insert_multi.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_insert_multi.sql formatting should be safe");
}

#[test]
fn test_insert_nested() {
    let sql = fs::read_to_string("tests/fixtures/test_insert_nested.sql")
        .expect("failed to read test_insert_nested.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_insert_nested.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_insert_nested.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_insert_nested.sql formatting should be safe");
}

// ============================================================================
// DELETE Operations
// ============================================================================

#[test]
fn test_delete_basic() {
    let sql = fs::read_to_string("tests/fixtures/test_delete.sql")
        .expect("failed to read test_delete.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_delete.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_delete.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_delete.sql formatting should be safe");
}

// ============================================================================
// MERGE Operations
// ============================================================================

#[test]
fn test_merge_basic() {
    let sql =
        fs::read_to_string("tests/fixtures/test_merge.sql").expect("failed to read test_merge.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_merge.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_merge.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_merge.sql formatting should be safe");
}

#[test]
fn test_merge_insert() {
    let sql = fs::read_to_string("tests/fixtures/test_merge_insert.sql")
        .expect("failed to read test_merge_insert.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_merge_insert.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_merge_insert.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_merge_insert.sql formatting should be safe");
}

#[test]
fn test_merge_multi() {
    let sql = fs::read_to_string("tests/fixtures/test_merge_multi.sql")
        .expect("failed to read test_merge_multi.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_merge_multi.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_merge_multi.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_merge_multi.sql formatting should be safe");
}

#[test]
fn test_merge_nested() {
    let sql = fs::read_to_string("tests/fixtures/test_merge_nested.sql")
        .expect("failed to read test_merge_nested.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_merge_nested.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_merge_nested.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_merge_nested.sql formatting should be safe");
}

#[test]
fn test_merge_hostile() {
    let sql = fs::read_to_string("tests/fixtures/test_hostile_merge.sql")
        .expect("failed to read test_hostile_merge.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_hostile_merge.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_hostile_merge.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_hostile_merge.sql formatting should be safe");
}
