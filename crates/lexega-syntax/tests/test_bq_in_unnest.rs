// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for BigQuery IN UNNEST(...) syntax
// BigQuery allows: search_value [NOT] IN UNNEST(array_expression)
// UNNEST is tokenized as Identifier { kind: Unquoted }, not a keyword.

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
// Basic IN UNNEST
// =============================================================================

#[test]
fn test_in_unnest_array_literal() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST([1, 2, 3]);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve IN UNNEST: {}",
        fmt
    );
}

#[test]
fn test_not_in_unnest_array_literal() {
    let sql = "SELECT * FROM t WHERE x NOT IN UNNEST([1, 2, 3]);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("NOT IN UNNEST("),
        "Should preserve NOT IN UNNEST: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_string_array() {
    let sql = "SELECT * FROM t WHERE name IN UNNEST(['alice', 'bob', 'charlie']);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve IN UNNEST: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_empty_array() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST([]);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve IN UNNEST: {}",
        fmt
    );
}

// =============================================================================
// IN UNNEST with @parameters
// =============================================================================

#[test]
fn test_in_unnest_at_param() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST(@array_param);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST(@array_param)"),
        "Should preserve @param: {}",
        fmt
    );
}

#[test]
fn test_not_in_unnest_at_param() {
    let sql = "SELECT * FROM t WHERE x NOT IN UNNEST(@excluded_ids);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("NOT IN UNNEST(@excluded_ids)"),
        "Should preserve NOT IN UNNEST(@param): {}",
        fmt
    );
}

// =============================================================================
// IN UNNEST with column references
// =============================================================================

#[test]
fn test_in_unnest_column_ref() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST(t.array_col);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST(t.array_col)"),
        "Should preserve column ref: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_qualified_column() {
    let sql = "SELECT * FROM dataset.table AS t WHERE t.id IN UNNEST(t.id_list);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve IN UNNEST: {}",
        fmt
    );
}

// =============================================================================
// IN UNNEST with function calls inside
// =============================================================================

#[test]
fn test_in_unnest_function_arg() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST(ARRAY_CONCAT([1,2], [3,4]));";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve IN UNNEST with function: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_generate_array() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST(GENERATE_ARRAY(1, 100));";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST(GENERATE_ARRAY"),
        "Should preserve nested function: {}",
        fmt
    );
}

// =============================================================================
// IN UNNEST in different clause positions
// =============================================================================

#[test]
fn test_in_unnest_in_having() {
    let sql = "SELECT department, COUNT(*) AS cnt FROM t GROUP BY department HAVING department IN UNNEST(['sales', 'eng']);";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("IN UNNEST("), "Should work in HAVING: {}", fmt);
}

#[test]
fn test_in_unnest_in_case() {
    let sql = "SELECT CASE WHEN x IN UNNEST([1,2,3]) THEN 'yes' ELSE 'no' END FROM t;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should work in CASE WHEN: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_in_join_condition() {
    let sql = "SELECT * FROM a JOIN b ON a.id = b.id AND a.tag IN UNNEST(b.tags);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should work in JOIN ON: {}",
        fmt
    );
}

// =============================================================================
// Multiple IN UNNEST in same query
// =============================================================================

#[test]
fn test_multiple_in_unnest() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST([1,2]) AND y NOT IN UNNEST([3,4]);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST([1,2])"),
        "Should preserve first IN UNNEST: {}",
        fmt
    );
    assert!(
        fmt.contains("NOT IN UNNEST([3,4])"),
        "Should preserve second NOT IN UNNEST: {}",
        fmt
    );
}

// =============================================================================
// IN UNNEST with typed arrays
// =============================================================================

#[test]
fn test_in_unnest_typed_array() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST(ARRAY<INT64>[1, 2, 3]);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve typed array in UNNEST: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_typed_string_array() {
    let sql = "SELECT * FROM t WHERE name IN UNNEST(ARRAY<STRING>['a', 'b']);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve typed string array: {}",
        fmt
    );
}

// =============================================================================
// IN UNNEST with subquery inside (rare but valid)
// =============================================================================

#[test]
fn test_in_unnest_with_subquery_arg() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST((SELECT arr FROM config LIMIT 1));";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should preserve subquery inside UNNEST: {}",
        fmt
    );
}

// =============================================================================
// Normal IN (parenthesized list) still works
// =============================================================================

#[test]
fn test_normal_in_list_still_works() {
    let sql = "SELECT * FROM t WHERE x IN (1, 2, 3);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN ("),
        "Normal IN list should still work: {}",
        fmt
    );
}

#[test]
fn test_normal_not_in_list_still_works() {
    let sql = "SELECT * FROM t WHERE x NOT IN (1, 2, 3);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("NOT IN ("),
        "Normal NOT IN list should still work: {}",
        fmt
    );
}

#[test]
fn test_normal_in_subquery_still_works() {
    let sql = "SELECT * FROM t WHERE x IN (SELECT id FROM other);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN ("),
        "Normal IN subquery should still work: {}",
        fmt
    );
}

// =============================================================================
// Round-trip stability (format twice should be identical)
// =============================================================================

#[test]
fn test_in_unnest_idempotent() {
    let sql = "SELECT * FROM t WHERE x IN UNNEST([1, 2, 3]);";
    let config = bq_config();
    let first = format_sql_with_config(sql, &config).unwrap();
    let second = format_sql_with_config(&first, &config).unwrap();
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_not_in_unnest_idempotent() {
    let sql = "SELECT * FROM t WHERE x NOT IN UNNEST(@arr);";
    let config = bq_config();
    let first = format_sql_with_config(sql, &config).unwrap();
    let second = format_sql_with_config(&first, &config).unwrap();
    assert_eq!(first, second, "Formatting should be idempotent");
}

// =============================================================================
// Case insensitivity of UNNEST
// =============================================================================

#[test]
fn test_in_unnest_lowercase() {
    let sql = "SELECT * FROM t WHERE x IN unnest([1, 2]);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("unnest("),
        "Should preserve lowercase unnest: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_mixed_case() {
    let sql = "SELECT * FROM t WHERE x IN Unnest([1, 2]);";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("Unnest("),
        "Should preserve mixed case Unnest: {}",
        fmt
    );
}

// =============================================================================
// Complex real-world patterns
// =============================================================================

#[test]
fn test_in_unnest_with_and_or() {
    let sql = "SELECT * FROM t WHERE (x IN UNNEST([1,2]) OR y IN UNNEST([3,4])) AND z = 5;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IN UNNEST("),
        "Should handle compound WHERE: {}",
        fmt
    );
}

#[test]
fn test_in_unnest_cte() {
    let sql = r#"
WITH params AS (
  SELECT [1, 2, 3] AS ids
)
SELECT * FROM t, params WHERE t.id IN UNNEST(params.ids);
"#;
    let fmt = format_and_verify_bq(sql.trim());
    assert!(
        fmt.contains("IN UNNEST(params.ids)"),
        "Should work with CTE: {}",
        fmt
    );
}
