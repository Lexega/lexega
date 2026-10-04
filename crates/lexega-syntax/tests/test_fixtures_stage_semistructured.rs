// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dedicated tests for Snowflake-specific features: stages, FLATTEN, semi-structured data
//! Covers stage operations, LATERAL FLATTEN, VARIANT access, arrow operators

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

// ============================================================================
// Stage Operations - Basic
// ============================================================================

#[test]
fn test_stage_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_simple.sql")
        .expect("failed to read test_stage_simple.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_simple.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_simple.sql formatting should be safe");
}

#[test]
fn test_stage_with_path() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_with_path.sql")
        .expect("failed to read test_stage_with_path.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_with_path.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_with_path.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_with_path.sql formatting should be safe");
}

#[test]
fn test_stage_with_options() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_with_options.sql")
        .expect("failed to read test_stage_with_options.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_with_options.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_with_options.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_with_options.sql formatting should be safe");
}

// ============================================================================
// Stage Operations - Features
// ============================================================================

#[test]
fn test_stage_features() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_features.sql")
        .expect("failed to read test_stage_features.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_features.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_features.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_features.sql formatting should be safe");
}

#[test]
fn test_stage_comprehensive() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_comprehensive.sql")
        .expect("failed to read test_stage_comprehensive.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_comprehensive.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_comprehensive.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_comprehensive.sql formatting should be safe");
}

#[test]
fn test_stage_fileformat() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_fileformat.sql")
        .expect("failed to read test_stage_fileformat.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_fileformat.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_fileformat.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_fileformat.sql formatting should be safe");
}

#[test]
fn test_stage_storage() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_storage.sql")
        .expect("failed to read test_stage_storage.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_storage.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_storage.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_storage.sql formatting should be safe");
}

// ============================================================================
// Stage with LATERAL
// ============================================================================

#[test]
fn test_stage_alias_lateral() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_alias_lateral.sql")
        .expect("failed to read test_stage_alias_lateral.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_alias_lateral.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_alias_lateral.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_alias_lateral.sql formatting should be safe");
}

#[test]
fn test_stage_lateral_keyword() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_lateral_keyword.sql")
        .expect("failed to read test_stage_lateral_keyword.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_lateral_keyword.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_lateral_keyword.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_lateral_keyword.sql formatting should be safe");
}

#[test]
fn test_stage_no_options_with_flatten() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_no_options_with_flatten.sql")
        .expect("failed to read test_stage_no_options_with_flatten.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_no_options_with_flatten.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_no_options_with_flatten.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_no_options_with_flatten.sql formatting should be safe");
}

#[test]
fn test_stage_then_table() {
    let sql = fs::read_to_string("tests/fixtures/test_stage_then_table.sql")
        .expect("failed to read test_stage_then_table.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_stage_then_table.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_stage_then_table.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_stage_then_table.sql formatting should be safe");
}

// ============================================================================
// Stage with Dollar Sign Notation
// ============================================================================

#[test]
fn test_src_dollar_1() {
    let sql = fs::read_to_string("tests/fixtures/test_src_dollar_1.sql")
        .expect("failed to read test_src_dollar_1.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_src_dollar_1.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_src_dollar_1.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_src_dollar_1.sql formatting should be safe");
}

#[test]
fn test_minimal_src_dollar() {
    let sql = fs::read_to_string("tests/fixtures/test_minimal_src_dollar.sql")
        .expect("failed to read test_minimal_src_dollar.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_minimal_src_dollar.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_minimal_src_dollar.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_minimal_src_dollar.sql formatting should be safe");
}

#[test]
fn test_source_func() {
    let sql = fs::read_to_string("tests/fixtures/test_source_func.sql")
        .expect("failed to read test_source_func.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_source_func.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_source_func.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_source_func.sql formatting should be safe");
}

// ============================================================================
// FLATTEN Operations
// ============================================================================

#[test]
fn test_flatten_then_lateral_select() {
    let sql = fs::read_to_string("tests/fixtures/test_flatten_then_lateral_select.sql")
        .expect("failed to read test_flatten_then_lateral_select.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_flatten_then_lateral_select.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_flatten_then_lateral_select.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_flatten_then_lateral_select.sql formatting should be safe");
}

#[test]
fn test_just_flatten() {
    let sql = fs::read_to_string("tests/fixtures/test_just_flatten.sql")
        .expect("failed to read test_just_flatten.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_just_flatten.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_just_flatten.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_just_flatten.sql formatting should be safe");
}

#[test]
fn test_simplest_flatten() {
    let sql = fs::read_to_string("tests/fixtures/test_simplest_flatten.sql")
        .expect("failed to read test_simplest_flatten.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_simplest_flatten.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_simplest_flatten.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_simplest_flatten.sql formatting should be safe");
}

#[test]
fn test_table_flatten() {
    let sql = fs::read_to_string("tests/fixtures/test_table_flatten.sql")
        .expect("failed to read test_table_flatten.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_table_flatten.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_table_flatten.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_table_flatten.sql formatting should be safe");
}

#[test]
fn test_table_then_flatten() {
    let sql = fs::read_to_string("tests/fixtures/test_table_then_flatten.sql")
        .expect("failed to read test_table_then_flatten.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_table_then_flatten.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_table_then_flatten.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_table_then_flatten.sql formatting should be safe");
}

#[test]
fn test_case_in_flatten() {
    let sql = fs::read_to_string("tests/fixtures/test_case_in_flatten.sql")
        .expect("failed to read test_case_in_flatten.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_case_in_flatten.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_case_in_flatten.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_case_in_flatten.sql formatting should be safe");
}

// ============================================================================
// Semi-structured Data: VARIANT, Arrow Operators, DICT
// ============================================================================

#[test]
fn test_variant_colon() {
    let sql = fs::read_to_string("tests/fixtures/test_variant_colon.sql")
        .expect("failed to read test_variant_colon.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_variant_colon.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_variant_colon.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_variant_colon.sql formatting should be safe");
}

#[test]
fn test_variant_in_proc() {
    let sql = fs::read_to_string("tests/fixtures/test_variant_in_proc.sql")
        .expect("failed to read test_variant_in_proc.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_variant_in_proc.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_variant_in_proc.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_variant_in_proc.sql formatting should be safe");
}

#[test]
fn test_arrow_operator() {
    let sql = fs::read_to_string("tests/fixtures/test_arrow_operator.sql")
        .expect("failed to read test_arrow_operator.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_arrow_operator.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_arrow_operator.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_arrow_operator.sql formatting should be safe");
}

#[test]
fn test_dict() {
    let sql =
        fs::read_to_string("tests/fixtures/test_dict.sql").expect("failed to read test_dict.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_dict.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_dict.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_dict.sql formatting should be safe");
}

// ============================================================================
// Positional References ($1, $2, etc.)
// ============================================================================

#[test]
fn test_just_positional() {
    let sql = fs::read_to_string("tests/fixtures/test_just_positional.sql")
        .expect("failed to read test_just_positional.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_just_positional.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_just_positional.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_just_positional.sql formatting should be safe");
}

#[test]
fn test_simplest_positional() {
    let sql = fs::read_to_string("tests/fixtures/test_simplest_positional.sql")
        .expect("failed to read test_simplest_positional.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_simplest_positional.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_simplest_positional.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_simplest_positional.sql formatting should be safe");
}

#[test]
fn test_positional_ref() {
    let sql = fs::read_to_string("tests/fixtures/test_positional_ref.sql")
        .expect("failed to read test_positional_ref.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_positional_ref.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_positional_ref.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_positional_ref.sql formatting should be safe");
}
