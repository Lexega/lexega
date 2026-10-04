// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dedicated tests for Jinja templating constructs
//! Covers dbt-style templating, conditionals, loops, ref/source functions, and complex nesting

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::fs;

// ============================================================================
// Basic Jinja Tests
// ============================================================================

#[test]
fn test_jinja_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_simple2.sql")
        .expect("failed to read test_jinja_simple2.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_simple2.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_simple2.sql formatting should be safe");
}

#[test]
fn test_simple_jinja_test() {
    let sql = fs::read_to_string("tests/fixtures/simple_jinja_test.sql")
        .expect("failed to read simple_jinja_test.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("simple_jinja_test.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("simple_jinja_test.sql formatting should be safe");
}

#[test]
fn test_very_simple_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test-very-simple-jinja.sql")
        .expect("failed to read test-very-simple-jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test-very-simple-jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test-very-simple-jinja.sql formatting should be safe");
}

#[test]
fn test_jinja_simple_conditional() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_simple_conditional.sql")
        .expect("failed to read test_jinja_simple_conditional.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_simple_conditional.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_simple_conditional.sql formatting should be safe");
}

// ============================================================================
// Conditionals: if/elif/else
// ============================================================================

#[test]
fn test_jinja_if_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_if_simple.sql")
        .expect("failed to read test_jinja_if_simple.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_if_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_if_simple.sql formatting should be safe");
}

#[test]
fn test_if_simple() {
    let sql = fs::read_to_string("tests/fixtures/test-if-simple.sql")
        .expect("failed to read test-if-simple.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test-if-simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test-if-simple.sql formatting should be safe");
}

#[test]
fn test_if_else() {
    let sql = fs::read_to_string("tests/fixtures/test-if-else.sql")
        .expect("failed to read test-if-else.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test-if-else.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test-if-else.sql formatting should be safe");
}

#[test]
fn test_jinja_elif() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_elif.sql")
        .expect("failed to read test_jinja_elif.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_elif.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_elif.sql formatting should be safe");
}

#[test]
fn test_jinja_elif_simple() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_elif_simple.sql")
        .expect("failed to read test_jinja_elif_simple.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_elif_simple.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_elif_simple.sql formatting should be safe");
}

#[test]
fn test_elif() {
    let sql =
        fs::read_to_string("tests/fixtures/test-elif.sql").expect("failed to read test-elif.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test-elif.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test-elif.sql formatting should be safe");
}

#[test]
fn test_if_parens() {
    let sql = fs::read_to_string("tests/fixtures/test_if_parens.sql")
        .expect("failed to read test_if_parens.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_if_parens.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_if_parens.sql formatting should be safe");
}

#[test]
fn test_jinja_if_table() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_if_table.sql")
        .expect("failed to read test_jinja_if_table.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_if_table.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_if_table.sql formatting should be safe");
}

// ============================================================================
// Loops
// ============================================================================

#[test]
fn test_jinja_loop() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_loop.sql")
        .expect("failed to read test_jinja_loop.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_loop.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_loop.sql formatting should be safe");
}

// ============================================================================
// dbt Functions: ref, source
// ============================================================================

#[test]
fn test_jinja_ref() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_ref.sql")
        .expect("failed to read test_jinja_ref.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_ref.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_jinja_ref.sql formatting should be safe");
}

#[test]
fn test_jinja_source() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_source.sql")
        .expect("failed to read test_jinja_source.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_source.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_source.sql formatting should be safe");
}

#[test]
fn test_jinja_qualified() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_qualified.sql")
        .expect("failed to read test_jinja_qualified.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_qualified.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_qualified.sql formatting should be safe");
}

#[test]
fn test_simple_dbt() {
    let sql = fs::read_to_string("tests/fixtures/test-simple-dbt.sql")
        .expect("failed to read test-simple-dbt.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test-simple-dbt.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test-simple-dbt.sql formatting should be safe");
}

#[test]
fn test_stg_orders() {
    let sql =
        fs::read_to_string("tests/fixtures/stg_orders.sql").expect("failed to read stg_orders.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("stg_orders.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("stg_orders.sql formatting should be safe");
}

#[test]
fn test_dbt_model() {
    let sql = fs::read_to_string("tests/fixtures/test_dbt_model.sql")
        .expect("failed to read test_dbt_model.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_dbt_model.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_dbt_model.sql formatting should be safe");
}

#[test]
fn test_dbt_tests_in() {
    let sql = fs::read_to_string("tests/fixtures/dbt_tests_in.sql")
        .expect("failed to read dbt_tests_in.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("dbt_tests_in.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("dbt_tests_in.sql formatting should be safe");
}

// ============================================================================
// Complex & Comprehensive Jinja
// ============================================================================

#[test]
fn test_golden_jinja_comprehensive() {
    let sql = fs::read_to_string("tests/fixtures/golden_jinja_comprehensive.sql")
        .expect("failed to read golden_jinja_comprehensive.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("golden_jinja_comprehensive.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("golden_jinja_comprehensive.sql formatting should be safe");
}

#[test]
fn test_jinja_showcase() {
    let sql = fs::read_to_string("tests/fixtures/jinja_showcase.sql")
        .expect("failed to read jinja_showcase.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("jinja_showcase.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("jinja_showcase.sql formatting should be safe");
}

#[test]
fn test_jinja_nested_structures() {
    let sql = fs::read_to_string("tests/fixtures/jinja_nested_structures.sql")
        .expect("failed to read jinja_nested_structures.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("jinja_nested_structures.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("jinja_nested_structures.sql formatting should be safe");
}

#[test]
fn test_jinja_expr() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_expr.sql")
        .expect("failed to read test_jinja_expr.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_expr.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_expr.sql formatting should be safe");
}

// ============================================================================
// Jinja Integration with SQL Constructs
// ============================================================================

#[test]
fn test_comment_after_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_comment_after_jinja.sql")
        .expect("failed to read test_comment_after_jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_comment_after_jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_comment_after_jinja.sql formatting should be safe");
}

#[test]
fn test_group_by_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_group_by_jinja.sql")
        .expect("failed to read test_group_by_jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_group_by_jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_group_by_jinja.sql formatting should be safe");
}

#[test]
fn test_order_by_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_order_by_jinja.sql")
        .expect("failed to read test_order_by_jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_order_by_jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_order_by_jinja.sql formatting should be safe");
}

#[test]
fn test_union_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_union_jinja.sql")
        .expect("failed to read test_union_jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_union_jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_union_jinja.sql formatting should be safe");
}

#[test]
fn test_where_jinja_conditional() {
    let sql = fs::read_to_string("tests/fixtures/test_where_jinja_conditional.sql")
        .expect("failed to read test_where_jinja_conditional.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_where_jinja_conditional.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_where_jinja_conditional.sql formatting should be safe");
}

#[test]
fn test_trailing_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_trailing_jinja.sql")
        .expect("failed to read test_trailing_jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_trailing_jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_trailing_jinja.sql formatting should be safe");
}

// ============================================================================
// Edge Cases & Special Tests
// ============================================================================

#[test]
fn test_no_format_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_no_format_jinja.sql")
        .expect("failed to read test_no_format_jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_no_format_jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_no_format_jinja.sql formatting should be safe");
}

#[test]
fn test_unclosed_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_unclosed_jinja.sql")
        .expect("failed to read test_unclosed_jinja.sql");

    // This may intentionally fail parsing - test that it handles gracefully
    let _ = format_sql_with_config(&sql, &FormatterConfig::default());
}

#[test]
fn test_jinja_indent() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_indent.sql")
        .expect("failed to read test_jinja_indent.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_indent.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_indent.sql formatting should be safe");
}

#[test]
fn test_jinja_normalize() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_normalize.sql")
        .expect("failed to read test_jinja_normalize.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_normalize.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_normalize.sql formatting should be safe");
}

// ============================================================================
// CLI & Debug Tests
// ============================================================================

#[test]
fn test_cli_jinja() {
    let sql = fs::read_to_string("tests/fixtures/test_cli_jinja.sql")
        .expect("failed to read test_cli_jinja.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_cli_jinja.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_cli_jinja.sql formatting should be safe");
}

#[test]
fn test_cli_jinja2() {
    let sql = fs::read_to_string("tests/fixtures/test_cli_jinja2.sql")
        .expect("failed to read test_cli_jinja2.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_cli_jinja2.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_cli_jinja2.sql formatting should be safe");
}

#[test]
fn test_jinja_cli() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_cli.sql")
        .expect("failed to read test_jinja_cli.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_cli.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_jinja_cli.sql formatting should be safe");
}

#[test]
fn test_debug_jinja_in() {
    let sql = fs::read_to_string("tests/fixtures/debug_jinja_in.sql")
        .expect("failed to read debug_jinja_in.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("debug_jinja_in.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("debug_jinja_in.sql formatting should be safe");
}

// ============================================================================
// Miscellaneous Jinja Tests
// ============================================================================

#[test]
fn test_jinja_lex() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_lex.sql")
        .expect("failed to read test_jinja_lex.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_lex.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_jinja_lex.sql formatting should be safe");
}

#[test]
fn test_jinja_parse() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_parse.sql")
        .expect("failed to read test_jinja_parse.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_parse.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_parse.sql formatting should be safe");
}

#[test]
fn test_jinja_fresh() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_fresh.sql")
        .expect("failed to read test_jinja_fresh.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_fresh.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_jinja_fresh.sql formatting should be safe");
}

#[test]
fn test_jinja_cst() {
    let sql = fs::read_to_string("tests/fixtures/test_jinja_cst.sql")
        .expect("failed to read test_jinja_cst.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_jinja_cst.sql should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("test_jinja_cst.sql formatting should be safe");
}

#[test]
fn test_endif_position() {
    let sql = fs::read_to_string("tests/fixtures/test_endif_position.sql")
        .expect("failed to read test_endif_position.sql");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_endif_position.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_endif_position.sql formatting should be safe");
}
