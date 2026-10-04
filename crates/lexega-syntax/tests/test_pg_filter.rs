// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL FILTER (WHERE ...) clause on aggregates.
//!
//! Each construct is tested for:
//!   1. Format round-trip with semantic safety verification
//!   2. Multiple syntax variants (basic, DISTINCT, window, complex WHERE)
//!
//! Token gotchas verified via --debug-tokens:
//!   FILTER → Identifier { kind: Unquoted } ⚠️ NOT Keyword
//!   (      → Punctuation(LParen) ✅
//!   WHERE  → Keyword(Where) ✅
//!   )      → Punctuation(RParen) ✅

use lexega_syntax::{
    format_sql_with_config, verify_formatting_safe, FormatterConfig, PostgresDialect,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn pg_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = std::sync::Arc::new(PostgresDialect);
    config
}

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &pg_config())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

// ═══════════════════════════════════════════════════════════════════════════
// Basic aggregate FILTER
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_count_star() {
    let sql = "SELECT count(*) FILTER (WHERE status = 'active') FROM orders";
    let out = format_and_verify(sql);
    assert!(out.to_uppercase().contains("FILTER"));
    assert!(out.to_uppercase().contains("WHERE"));
}

#[test]
fn test_filter_sum() {
    let sql = "SELECT sum(amount) FILTER (WHERE region = 'US') FROM sales";
    format_and_verify(sql);
}

#[test]
fn test_filter_avg() {
    let sql = "SELECT avg(price) FILTER (WHERE qty > 0) FROM items";
    format_and_verify(sql);
}

#[test]
fn test_filter_min_max() {
    let sql = "SELECT min(val) FILTER (WHERE val > 0), max(val) FILTER (WHERE val < 100) FROM t";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// FILTER with DISTINCT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_count_distinct() {
    let sql = "SELECT count(DISTINCT category) FILTER (WHERE price > 100) FROM products";
    format_and_verify(sql);
}

#[test]
fn test_filter_sum_distinct() {
    let sql = "SELECT sum(DISTINCT val) FILTER (WHERE val > 0) FROM t";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// FILTER on window functions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_window_partition() {
    let sql = "SELECT id, sum(amount) FILTER (WHERE status = 'paid') OVER (PARTITION BY customer_id) FROM invoices";
    let out = format_and_verify(sql);
    assert!(out.to_uppercase().contains("FILTER"));
    assert!(out.to_uppercase().contains("OVER"));
}

#[test]
fn test_filter_window_order_by() {
    let sql = "SELECT id, count(*) FILTER (WHERE active) OVER (ORDER BY created_at) FROM users";
    format_and_verify(sql);
}

#[test]
fn test_filter_window_rows_frame() {
    let sql = "SELECT id, count(*) FILTER (WHERE active) OVER (ORDER BY created_at ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM users";
    format_and_verify(sql);
}

#[test]
fn test_filter_window_partition_and_order() {
    let sql = "SELECT id, avg(score) FILTER (WHERE passed) OVER (PARTITION BY class ORDER BY student_id) FROM results";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multiple FILTER clauses in single query
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_filters_in_select() {
    let sql = r#"SELECT
    count(*) FILTER (WHERE i < 5) AS cnt_lt5,
    count(*) FILTER (WHERE i >= 5) AS cnt_gte5,
    count(*) AS total
FROM generate_series(1, 10) AS s(i)"#;
    format_and_verify(sql);
}

#[test]
fn test_multiple_different_aggregates_filtered() {
    let sql = r#"SELECT
    avg(salary) FILTER (WHERE department = 'eng') AS avg_eng,
    avg(salary) FILTER (WHERE department = 'sales') AS avg_sales,
    max(salary) FILTER (WHERE level > 5) AS max_senior
FROM employees"#;
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Complex WHERE conditions inside FILTER
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_and_condition() {
    let sql = "SELECT count(*) FILTER (WHERE status = 'active' AND created_at > '2024-01-01') FROM accounts";
    format_and_verify(sql);
}

#[test]
fn test_filter_or_condition() {
    let sql = "SELECT count(*) FILTER (WHERE status = 'a' OR status = 'b') FROM t";
    format_and_verify(sql);
}

#[test]
fn test_filter_is_not_null() {
    let sql = "SELECT count(*) FILTER (WHERE email IS NOT NULL) FROM users";
    format_and_verify(sql);
}

#[test]
fn test_filter_in_list() {
    let sql = "SELECT sum(amount) FILTER (WHERE category IN ('A', 'B', 'C')) FROM transactions";
    format_and_verify(sql);
}

#[test]
fn test_filter_between() {
    let sql = "SELECT avg(score) FILTER (WHERE age BETWEEN 18 AND 25) FROM students";
    format_and_verify(sql);
}

#[test]
fn test_filter_boolean_column() {
    let sql = "SELECT count(*) FILTER (WHERE is_verified) FROM accounts";
    format_and_verify(sql);
}

#[test]
fn test_filter_nested_function() {
    let sql = "SELECT sum(amount) FILTER (WHERE lower(status) = 'active') FROM orders";
    format_and_verify(sql);
}

#[test]
fn test_filter_subquery_in_where() {
    let sql = "SELECT count(*) FILTER (WHERE id IN (SELECT user_id FROM premium_users)) FROM users";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Mixed case
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_lowercase() {
    let sql = "select count(*) filter (where x > 0) from t";
    format_and_verify(sql);
}

#[test]
fn test_filter_mixed_case() {
    let sql = "SELECT Count(*) Filter (Where status = 'ok') FROM orders";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// FILTER with WITHIN GROUP (ordered-set aggregates)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_with_within_group() {
    // percentile_cont is an ordered-set aggregate that uses WITHIN GROUP
    // FILTER can appear after WITHIN GROUP
    let sql = "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY salary) FILTER (WHERE department = 'eng') FROM employees";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Roundtrip idempotence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_roundtrip_basic() {
    let sql = "SELECT count(*) FILTER (WHERE x > 0) FROM t";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_filter_roundtrip_window() {
    let sql = "SELECT sum(x) FILTER (WHERE y > 0) OVER (PARTITION BY z) FROM t";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_filter_roundtrip_complex() {
    let sql = r#"SELECT
    count(*) FILTER (WHERE a = 1) AS c1,
    sum(b) FILTER (WHERE c > 0) OVER (ORDER BY d) AS s1
FROM tbl"#;
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_filter_alias_no_as() {
    // "FILTER" as a column alias (not the clause) should still work
    let sql = "SELECT 1 AS filter FROM t";
    format_and_verify(sql);
}

#[test]
fn test_filter_table_name() {
    // "filter" used as a table name
    let sql = "SELECT * FROM filter WHERE id = 1";
    format_and_verify(sql);
}

#[test]
fn test_filter_no_args_count_star() {
    // count(*) with FILTER — hits Path 2 (COUNT(*) path)
    let sql = "SELECT count(*) FILTER (WHERE x = 1) FROM t";
    format_and_verify(sql);
}

#[test]
fn test_filter_single_arg() {
    // Single arg function — hits Path 3 (regular args)
    let sql = "SELECT sum(val) FILTER (WHERE val > 0) FROM t";
    format_and_verify(sql);
}
