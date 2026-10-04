// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for JOIN keyword normalization toggle.
//!
//! The `normalize_join_keywords` config option controls whether JOINs are normalized to their
//! explicit OUTER form (LEFT OUTER JOIN, RIGHT OUTER JOIN) or preserved in their compact form
//! (LEFT JOIN, RIGHT JOIN).
//!
//! Default is false (compact form).

use lexega_syntax::{format_sql_with_config, FormatterConfig};

#[test]
fn test_left_join_default_no_normalization() {
    let sql = "SELECT * FROM orders o LEFT JOIN customers c ON c.id = o.customer_id";

    let config = FormatterConfig::default();
    let result = format_sql_with_config(sql, &config).unwrap();

    // Default config: normalize_join_keywords is false, so LEFT JOIN stays as LEFT JOIN
    assert!(result.contains("LEFT JOIN"));
    assert!(!result.contains("LEFT OUTER JOIN"));
}

#[test]
fn test_left_join_with_normalization() {
    let sql = "SELECT * FROM orders o LEFT JOIN customers c ON c.id = o.customer_id";

    let mut config = FormatterConfig::default();
    config.normalize_join_keywords = true;
    let result = format_sql_with_config(sql, &config).unwrap();

    // With normalization: LEFT JOIN becomes LEFT OUTER JOIN
    assert!(result.contains("LEFT OUTER JOIN"));
    assert!(!result.contains("LEFT JOIN"));
}

#[test]
fn test_right_join_default_no_normalization() {
    let sql = "SELECT * FROM orders o RIGHT JOIN customers c ON c.id = o.customer_id";

    let config = FormatterConfig::default();
    let result = format_sql_with_config(sql, &config).unwrap();

    // Default config: RIGHT JOIN stays as RIGHT JOIN
    assert!(result.contains("RIGHT JOIN"));
    assert!(!result.contains("RIGHT OUTER JOIN"));
}

#[test]
fn test_right_join_with_normalization() {
    let sql = "SELECT * FROM orders o RIGHT JOIN customers c ON c.id = o.customer_id";

    let mut config = FormatterConfig::default();
    config.normalize_join_keywords = true;
    let result = format_sql_with_config(sql, &config).unwrap();

    // With normalization: RIGHT JOIN becomes RIGHT OUTER JOIN
    assert!(result.contains("RIGHT OUTER JOIN"));
    assert!(!result.contains("RIGHT JOIN"));
}

#[test]
fn test_full_outer_join_always_explicit() {
    let sql = "SELECT * FROM orders o FULL OUTER JOIN customers c ON c.id = o.customer_id";

    // Test both with and without normalization - FULL OUTER JOIN always stays explicit
    let config_default = FormatterConfig::default();
    let result_default = format_sql_with_config(sql, &config_default).unwrap();
    assert!(result_default.contains("FULL OUTER JOIN"));

    let mut config_normalized = FormatterConfig::default();
    config_normalized.normalize_join_keywords = true;
    let result_normalized = format_sql_with_config(sql, &config_normalized).unwrap();
    assert!(result_normalized.contains("FULL OUTER JOIN"));
}

#[test]
fn test_inner_join_unchanged() {
    let sql = "SELECT * FROM orders o INNER JOIN customers c ON c.id = o.customer_id";

    // INNER JOIN should be unchanged regardless of normalization setting
    let config_default = FormatterConfig::default();
    let result_default = format_sql_with_config(sql, &config_default).unwrap();
    assert!(result_default.contains("INNER JOIN"));

    let mut config_normalized = FormatterConfig::default();
    config_normalized.normalize_join_keywords = true;
    let result_normalized = format_sql_with_config(sql, &config_normalized).unwrap();
    assert!(result_normalized.contains("INNER JOIN"));
}

#[test]
fn test_cross_join_unchanged() {
    let sql = "SELECT * FROM orders o CROSS JOIN customers c";

    // CROSS JOIN should be unchanged regardless of normalization setting
    let config_default = FormatterConfig::default();
    let result_default = format_sql_with_config(sql, &config_default).unwrap();
    assert!(result_default.contains("CROSS JOIN"));

    let mut config_normalized = FormatterConfig::default();
    config_normalized.normalize_join_keywords = true;
    let result_normalized = format_sql_with_config(sql, &config_normalized).unwrap();
    assert!(result_normalized.contains("CROSS JOIN"));
}

#[test]
fn test_natural_left_join_default_no_normalization() {
    let sql = "SELECT * FROM orders o NATURAL LEFT JOIN customers c";

    let config = FormatterConfig::default();
    let result = format_sql_with_config(sql, &config).unwrap();

    // Default config: NATURAL LEFT JOIN stays as NATURAL LEFT JOIN
    assert!(result.contains("NATURAL LEFT JOIN"));
    assert!(!result.contains("NATURAL LEFT OUTER JOIN"));
}

#[test]
fn test_natural_left_join_with_normalization() {
    let sql = "SELECT * FROM orders o NATURAL LEFT JOIN customers c";

    let mut config = FormatterConfig::default();
    config.normalize_join_keywords = true;
    let result = format_sql_with_config(sql, &config).unwrap();

    // With normalization: NATURAL LEFT JOIN becomes NATURAL LEFT OUTER JOIN
    assert!(result.contains("NATURAL LEFT OUTER JOIN"));
    assert!(!result.contains("NATURAL LEFT JOIN"));
}

#[test]
fn test_natural_right_join_default_no_normalization() {
    let sql = "SELECT * FROM orders o NATURAL RIGHT JOIN customers c";

    let config = FormatterConfig::default();
    let result = format_sql_with_config(sql, &config).unwrap();

    // Default config: NATURAL RIGHT JOIN stays as NATURAL RIGHT JOIN
    assert!(result.contains("NATURAL RIGHT JOIN"));
    assert!(!result.contains("NATURAL RIGHT OUTER JOIN"));
}

#[test]
fn test_natural_right_join_with_normalization() {
    let sql = "SELECT * FROM orders o NATURAL RIGHT JOIN customers c";

    let mut config = FormatterConfig::default();
    config.normalize_join_keywords = true;
    let result = format_sql_with_config(sql, &config).unwrap();

    // With normalization: NATURAL RIGHT JOIN becomes NATURAL RIGHT OUTER JOIN
    assert!(result.contains("NATURAL RIGHT OUTER JOIN"));
    assert!(!result.contains("NATURAL RIGHT JOIN"));
}

#[test]
fn test_multiple_joins_mixed() {
    let sql = r#"
        SELECT *
        FROM orders o
        LEFT JOIN customers c ON c.id = o.customer_id
        RIGHT JOIN regions r ON r.id = c.region_id
        INNER JOIN products p ON p.id = o.product_id
    "#;

    // Test default (no normalization)
    let config_default = FormatterConfig::default();
    let result_default = format_sql_with_config(sql, &config_default).unwrap();
    assert!(result_default.contains("LEFT JOIN"));
    assert!(result_default.contains("RIGHT JOIN"));
    assert!(result_default.contains("INNER JOIN"));
    assert!(!result_default.contains("OUTER"));

    // Test with normalization
    let mut config_normalized = FormatterConfig::default();
    config_normalized.normalize_join_keywords = true;
    let result_normalized = format_sql_with_config(sql, &config_normalized).unwrap();
    assert!(result_normalized.contains("LEFT OUTER JOIN"));
    assert!(result_normalized.contains("RIGHT OUTER JOIN"));
    assert!(result_normalized.contains("INNER JOIN"));
}

#[test]
fn test_directed_left_join_no_normalization() {
    let sql = "SELECT * FROM orders o DIRECTED LEFT JOIN customers c ON c.id = o.customer_id";

    let config = FormatterConfig::default();
    let result = format_sql_with_config(sql, &config).unwrap();

    // DIRECTED should be preserved, LEFT JOIN should not be normalized
    assert!(result.contains("DIRECTED"));
    assert!(result.contains("LEFT JOIN"));
    assert!(!result.contains("LEFT OUTER JOIN"));
}

#[test]
fn test_directed_left_join_with_normalization() {
    let sql = "SELECT * FROM orders o DIRECTED LEFT JOIN customers c ON c.id = o.customer_id";

    let mut config = FormatterConfig::default();
    config.normalize_join_keywords = true;
    let result = format_sql_with_config(sql, &config).unwrap();

    // DIRECTED should be preserved, LEFT JOIN should be normalized
    assert!(result.contains("DIRECTED"));
    assert!(result.contains("LEFT OUTER JOIN"));
    assert!(!result.contains("DIRECTED LEFT JOIN")); // Should be "DIRECTED LEFT OUTER JOIN"
}

#[test]
fn test_lateral_left_join_no_normalization() {
    let sql = "SELECT * FROM orders o LATERAL LEFT JOIN customers c ON c.id = o.customer_id";

    let config = FormatterConfig::default();
    let result = format_sql_with_config(sql, &config).unwrap();

    // LATERAL should be preserved, LEFT JOIN should not be normalized
    assert!(result.contains("LATERAL"));
    assert!(result.contains("LEFT JOIN"));
    assert!(!result.contains("LEFT OUTER JOIN"));
}

#[test]
fn test_lateral_left_join_with_normalization() {
    let sql = "SELECT * FROM orders o LATERAL LEFT JOIN customers c ON c.id = o.customer_id";

    let mut config = FormatterConfig::default();
    config.normalize_join_keywords = true;
    let result = format_sql_with_config(sql, &config).unwrap();

    // LATERAL should be preserved, LEFT JOIN should be normalized
    assert!(result.contains("LATERAL"));
    assert!(result.contains("LEFT OUTER JOIN"));
    assert!(!result.contains("LATERAL LEFT JOIN")); // Should be "LATERAL LEFT OUTER JOIN"
}
