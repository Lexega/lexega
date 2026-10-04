// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for BigQuery typed STRUCT/ARRAY constructors
// P5: ARRAY<type>[...] and STRUCT<type>(...) with type parameters

use lexega_syntax::dialect::bigquery;
use lexega_syntax::{format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig};

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = bigquery();
    config
}

fn format_and_verify_bq(sql: &str) -> String {
    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("BigQuery format failed:\n{}\nSQL:\n{}", e, sql));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref()).unwrap_or_else(
        |e| {
            panic!(
                "BigQuery round-trip verification failed:\n{}\nFormatted:\n{}\nSQL:\n{}",
                e, formatted, sql
            )
        },
    );
    formatted
}

// =============================================================================
// Basic typed ARRAY constructors
// =============================================================================

#[test]
fn test_array_float64_literal() {
    let sql = "SELECT ARRAY<FLOAT64>[1.1, 2.2, 3.3];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<FLOAT64>"),
        "Should preserve type annotation: {}",
        formatted
    );
}

#[test]
fn test_array_int64_literal() {
    let sql = "SELECT ARRAY<INT64>[1, 2, 3];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<INT64>"),
        "Should preserve type annotation: {}",
        formatted
    );
}

#[test]
fn test_array_string_literal() {
    let sql = "SELECT ARRAY<STRING>[`a`, `b`, `c`];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<STRING>"),
        "Should preserve type annotation: {}",
        formatted
    );
}

#[test]
fn test_array_bool_literal() {
    let sql = "SELECT ARRAY<BOOL>[TRUE, FALSE, TRUE];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<BOOL>"),
        "Should preserve type annotation: {}",
        formatted
    );
}

// =============================================================================
// Empty typed ARRAY
// =============================================================================

#[test]
fn test_array_empty_int64() {
    let sql = "SELECT ARRAY<INT64>[];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<INT64>[]"),
        "Should preserve empty typed array: {}",
        formatted
    );
}

#[test]
fn test_array_empty_string() {
    let sql = "SELECT ARRAY<STRING>[];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<STRING>[]"),
        "Should preserve empty typed array: {}",
        formatted
    );
}

// =============================================================================
// Nested type parameters
// =============================================================================

#[test]
fn test_array_struct_nested() {
    let sql = "SELECT ARRAY<STRUCT<x INT64, y STRING>>[(1, `a`), (2, `b`)];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<STRUCT<x INT64, y STRING>>"),
        "Should preserve nested type params: {}",
        formatted
    );
}

#[test]
fn test_array_array_nested() {
    let sql = "SELECT ARRAY<ARRAY<INT64>>[[1, 2], [3, 4]];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<ARRAY<INT64>>"),
        "Should preserve nested ARRAY type: {}",
        formatted
    );
}

#[test]
fn test_array_struct_deeply_nested() {
    let sql = "SELECT ARRAY<STRUCT<a INT64, b STRUCT<c STRING>>>[STRUCT(1, STRUCT(`x`))];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<STRUCT<a INT64, b STRUCT<c STRING>>>"),
        "Should preserve deeply nested type: {}",
        formatted
    );
}

// =============================================================================
// STRUCT<type>(...) constructors (already working, regression guard)
// =============================================================================

#[test]
fn test_struct_typed_constructor() {
    let sql = "SELECT STRUCT<INT64>(5);";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("STRUCT<INT64>"),
        "Should preserve STRUCT type: {}",
        formatted
    );
}

#[test]
fn test_struct_multi_field_typed() {
    let sql = "SELECT STRUCT<x INT64, y STRING>(1, `hello`);";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("STRUCT<x INT64, y STRING>"),
        "Should preserve STRUCT multi-field type: {}",
        formatted
    );
}

#[test]
fn test_struct_untyped_constructor() {
    let sql = "SELECT STRUCT(1 AS a, 2 AS b);";
    format_and_verify_bq(sql);
}

// =============================================================================
// Bare array/ARRAY (no type params) — regression guards
// =============================================================================

#[test]
fn test_bare_array_literal() {
    let sql = "SELECT [1, 2, 3];";
    format_and_verify_bq(sql);
}

#[test]
fn test_array_keyword_no_type() {
    let sql = "SELECT ARRAY[1, 2, 3];";
    format_and_verify_bq(sql);
}

#[test]
fn test_empty_bare_array() {
    let sql = "SELECT [];";
    format_and_verify_bq(sql);
}

// =============================================================================
// Typed ARRAY in various SQL positions
// =============================================================================

#[test]
fn test_array_typed_in_select_list() {
    let sql = "SELECT 1 AS id, ARRAY<INT64>[10, 20] AS nums, `name`;";
    format_and_verify_bq(sql);
}

#[test]
fn test_array_typed_in_where_clause() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST(ARRAY<INT64>[1, 2, 3]);";
    format_and_verify_bq(sql);
}

#[test]
fn test_array_typed_in_insert() {
    let sql = "INSERT INTO t (arr_col) VALUES (ARRAY<STRING>[`a`, `b`]);";
    format_and_verify_bq(sql);
}

#[test]
fn test_array_typed_in_cte() {
    let sql = r#"WITH data AS (
    SELECT ARRAY<INT64>[1, 2, 3] AS nums
)
SELECT * FROM data;"#;
    format_and_verify_bq(sql);
}

// =============================================================================
// Multiple typed arrays in same statement
// =============================================================================

#[test]
fn test_multiple_typed_arrays() {
    let sql = "SELECT ARRAY<INT64>[1, 2], ARRAY<STRING>[`a`, `b`], ARRAY<FLOAT64>[1.0];";
    let formatted = format_and_verify_bq(sql);
    assert!(
        formatted.contains("ARRAY<INT64>"),
        "Missing INT64 type: {}",
        formatted
    );
    assert!(
        formatted.contains("ARRAY<STRING>"),
        "Missing STRING type: {}",
        formatted
    );
    assert!(
        formatted.contains("ARRAY<FLOAT64>"),
        "Missing FLOAT64 type: {}",
        formatted
    );
}

// =============================================================================
// Expressions inside typed arrays
// =============================================================================

#[test]
fn test_array_with_expressions() {
    let sql = "SELECT ARRAY<INT64>[1 + 2, 3 * 4, ABS(-5)];";
    format_and_verify_bq(sql);
}

#[test]
fn test_array_with_subquery_element() {
    let sql = "SELECT ARRAY<INT64>[(SELECT MAX(id) FROM t)];";
    format_and_verify_bq(sql);
}

#[test]
fn test_array_with_case_element() {
    let sql = "SELECT ARRAY<STRING>[CASE WHEN x > 0 THEN `pos` ELSE `neg` END];";
    format_and_verify_bq(sql);
}

// =============================================================================
// CAST with ARRAY<type> (already working, regression guard)
// =============================================================================

#[test]
fn test_cast_as_array_type() {
    let sql = "SELECT CAST(x AS ARRAY<INT64>);";
    format_and_verify_bq(sql);
}

#[test]
fn test_cast_as_struct_type() {
    let sql = "SELECT CAST(x AS STRUCT<a INT64, b STRING>);";
    format_and_verify_bq(sql);
}

// =============================================================================
// Snowflake dialect regression (no typed ARRAY constructors in Snowflake)
// =============================================================================

#[test]
fn test_snowflake_bare_array_still_works() {
    let sql = "SELECT [1, 2, 3];";
    let config = FormatterConfig::default(); // Snowflake
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    lexega_syntax::verify_formatting_safe(sql, &formatted).expect("should preserve");
}

#[test]
fn test_snowflake_array_construct_still_works() {
    let sql = "SELECT ARRAY_CONSTRUCT(1, 2, 3);";
    let config = FormatterConfig::default(); // Snowflake
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    lexega_syntax::verify_formatting_safe(sql, &formatted).expect("should preserve");
}

// =============================================================================
// Idempotency: format(format(sql)) == format(sql)
// =============================================================================

#[test]
fn test_idempotent_typed_array() {
    let sql = "SELECT ARRAY<FLOAT64>[1.1, 2.2, 3.3];";
    let config = bq_config();
    let first = format_sql_with_config(sql, &config).expect("first format");
    let second = format_sql_with_config(&first, &config).expect("second format");
    assert_eq!(first, second, "Typed ARRAY formatting should be idempotent");
}

#[test]
fn test_idempotent_typed_struct() {
    let sql = "SELECT STRUCT<x INT64, y STRING>(1, `hello`);";
    let config = bq_config();
    let first = format_sql_with_config(sql, &config).expect("first format");
    let second = format_sql_with_config(&first, &config).expect("second format");
    assert_eq!(
        first, second,
        "Typed STRUCT formatting should be idempotent"
    );
}

#[test]
fn test_idempotent_nested_array_struct() {
    let sql = "SELECT ARRAY<STRUCT<x INT64>>[(1), (2)];";
    let config = bq_config();
    let first = format_sql_with_config(sql, &config).expect("first format");
    let second = format_sql_with_config(&first, &config).expect("second format");
    assert_eq!(
        first, second,
        "Nested ARRAY<STRUCT> formatting should be idempotent"
    );
}
