// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dedicated tests for DDL operations
//! Covers CREATE TABLE, CREATE VIEW, CREATE FUNCTION, CREATE STAGE, compliance policies

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

// ============================================================================
// CREATE TABLE
// ============================================================================

#[test]
fn test_create_table() {
    let sql = fs::read_to_string("tests/fixtures/test_create_table.sql")
        .expect("failed to read test_create_table.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_create_table.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_create_table.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_create_table.sql formatting should be safe");
}

#[test]
fn test_create_table_simple_dup() {
    let sql = fs::read_to_string("tests/fixtures/test_create_table_simple_dup.sql")
        .expect("failed to read test_create_table_simple_dup.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_create_table_simple_dup.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_create_table_simple_dup.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_create_table_simple_dup.sql formatting should be safe");
}

#[test]
fn test_ctas_verify() {
    let sql = fs::read_to_string("tests/fixtures/test_ctas_verify.sql")
        .expect("failed to read test_ctas_verify.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_ctas_verify.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_ctas_verify.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_ctas_verify.sql formatting should be safe");
}

// ============================================================================
// CREATE VIEW
// ============================================================================

#[test]
fn test_create_view() {
    let sql = fs::read_to_string("tests/fixtures/test_create_view.sql")
        .expect("failed to read test_create_view.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_create_view.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_create_view.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_create_view.sql formatting should be safe");
}

#[test]
fn test_debug_view() {
    let sql = fs::read_to_string("tests/fixtures/test_debug_view.sql")
        .expect("failed to read test_debug_view.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_debug_view.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_debug_view.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_debug_view.sql formatting should be safe");
}

#[test]
fn test_view_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_view_simple.sql")
        .expect("failed to read test_view_simple.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_view_simple.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_view_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_view_simple.sql formatting should be safe");
}

// ============================================================================
// CREATE FUNCTION
// ============================================================================

#[test]
fn test_create_function_format() {
    let sql = fs::read_to_string("tests/fixtures/test_create_function_format.sql")
        .expect("failed to read test_create_function_format.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_create_function_format.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_create_function_format.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_create_function_format.sql formatting should be safe");
}

// ============================================================================
// CREATE STAGE
// ============================================================================

#[test]
fn test_create_stage() {
    let sql = fs::read_to_string("tests/fixtures/test_create_stage.sql")
        .expect("failed to read test_create_stage.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_create_stage.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_create_stage.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_create_stage.sql formatting should be safe");
}

// ============================================================================
// Compliance & Policies
// ============================================================================

#[test]
fn test_compliance() {
    let sql = fs::read_to_string("tests/fixtures/test_compliance.sql")
        .expect("failed to read test_compliance.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_compliance.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_compliance.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_compliance.sql formatting should be safe");
}

#[test]
fn test_compliance_policies() {
    let sql = fs::read_to_string("tests/fixtures/test_compliance_policies.sql")
        .expect("failed to read test_compliance_policies.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_compliance_policies.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_compliance_policies.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_compliance_policies.sql formatting should be safe");
}

#[test]
fn test_all_compliance_rules() {
    let sql = fs::read_to_string("tests/fixtures/test_all_compliance_rules.sql")
        .expect("failed to read test_all_compliance_rules.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_all_compliance_rules.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_all_compliance_rules.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_all_compliance_rules.sql formatting should be safe");
}

#[test]
fn test_view_compliance() {
    let sql = fs::read_to_string("tests/fixtures/test_view_compliance.sql")
        .expect("failed to read test_view_compliance.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_view_compliance.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_view_compliance.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_view_compliance.sql formatting should be safe");
}

#[test]
fn test_view_compliance_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_view_compliance_simple.sql")
        .expect("failed to read test_view_compliance_simple.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_view_compliance_simple.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_view_compliance_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_view_compliance_simple.sql formatting should be safe");
}

#[test]
fn test_view_row_policy() {
    let sql = fs::read_to_string("tests/fixtures/test_view_row_policy.sql")
        .expect("failed to read test_view_row_policy.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_view_row_policy.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_view_row_policy.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_view_row_policy.sql formatting should be safe");
}

#[test]
fn test_view_row_policy_correct() {
    let sql = fs::read_to_string("tests/fixtures/test_view_row_policy_correct.sql")
        .expect("failed to read test_view_row_policy_correct.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_view_row_policy_correct.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_view_row_policy_correct.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_view_row_policy_correct.sql formatting should be safe");
}

// ============================================================================
// USE Statement
// ============================================================================

#[test]
fn test_use() {
    let sql =
        fs::read_to_string("tests/fixtures/test_use.sql").expect("failed to read test_use.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_use.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_use.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_use.sql formatting should be safe");
}

#[test]
fn test_use_simple_baseline() {
    let sql = fs::read_to_string("tests/fixtures/test_use_simple_baseline.sql")
        .expect("failed to read test_use_simple_baseline.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_use_simple_baseline.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_use_simple_baseline.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_use_simple_baseline.sql formatting should be safe");
}
