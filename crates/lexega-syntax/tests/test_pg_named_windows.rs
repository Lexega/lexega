// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL WINDOW clause (named window definitions).
//!
//! Covers:
//!   - WINDOW w AS (...) in SELECT
//!   - Bare OVER w references
//!   - OVER (w ORDER BY ...) refinement
//!   - Multiple window definitions
//!   - Dialect gating (Snowflake must NOT parse WINDOW as a clause)
//!   - Format round-trip with semantic safety verification

use std::sync::Arc;

use lexega_syntax::{
    format_sql_with_config, verify_formatting_safe, verify_formatting_safe_with_dialect,
    FormatterConfig, PostgresDialect,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn pg_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = Arc::new(PostgresDialect);
    config
}

/// Parse + format + verify round-trip under PostgreSQL dialect.
fn pg_format_and_verify(sql: &str) -> String {
    let config = pg_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe_with_dialect(sql, &formatted, &PostgresDialect).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

/// Parse + format under Snowflake (default) dialect.
fn sf_format_and_verify(sql: &str) -> String {
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

// ═════════════════════════════════════════════════════════════════════════════
// WINDOW CLAUSE - Basic Definitions
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_window_clause_single_definition() {
    let sql = "SELECT sum(salary) OVER w FROM employees WINDOW w AS (ORDER BY salary);";
    let formatted = pg_format_and_verify(sql);
    assert!(
        formatted.contains("WINDOW"),
        "Should preserve WINDOW clause"
    );
    assert!(
        formatted.contains("OVER w"),
        "Should preserve bare OVER w reference"
    );
}

#[test]
fn test_window_clause_partition_and_order() {
    let sql = "SELECT row_number() OVER w FROM t WINDOW w AS (PARTITION BY dept ORDER BY id);";
    let formatted = pg_format_and_verify(sql);
    assert!(
        formatted.contains("WINDOW"),
        "Should preserve WINDOW clause"
    );
    assert!(
        formatted.contains("PARTITION BY"),
        "Should preserve PARTITION BY"
    );
    assert!(formatted.contains("ORDER BY"), "Should preserve ORDER BY");
}

#[test]
fn test_window_clause_multiple_definitions() {
    let sql = concat!(
        "SELECT sum(x) OVER w1, avg(x) OVER w2 ",
        "FROM t ",
        "WINDOW w1 AS (PARTITION BY a ORDER BY b), ",
        "w2 AS (ORDER BY c);"
    );
    let formatted = pg_format_and_verify(sql);
    assert!(formatted.contains("w1"), "Should preserve window name w1");
    assert!(formatted.contains("w2"), "Should preserve window name w2");
}

#[test]
fn test_window_clause_empty_spec() {
    // WINDOW w AS () — empty window spec (no partition, no order, no frame)
    let sql = "SELECT count(*) OVER w FROM t WINDOW w AS ();";
    let formatted = pg_format_and_verify(sql);
    assert!(
        formatted.contains("WINDOW"),
        "Should preserve WINDOW clause"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// BARE OVER w REFERENCES
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_bare_over_window_name() {
    let sql = "SELECT rank() OVER w FROM t WINDOW w AS (ORDER BY id);";
    let formatted = pg_format_and_verify(sql);
    assert!(formatted.contains("OVER w"), "Should preserve bare OVER w");
}

#[test]
fn test_bare_over_multiple_references() {
    let sql = concat!(
        "SELECT sum(a) OVER w, avg(b) OVER w, max(c) OVER w ",
        "FROM t WINDOW w AS (PARTITION BY grp);"
    );
    let formatted = pg_format_and_verify(sql);
    // All three references should survive
    let count = formatted.matches("OVER w").count();
    assert!(
        count >= 3,
        "Should have at least 3 OVER w references, got {}",
        count
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// OVER (w ...) REFINEMENT
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_over_refinement_with_order_by() {
    // OVER (w ORDER BY ...) - refines named window w with ORDER BY
    let sql = concat!(
        "SELECT sum(salary) OVER (w ORDER BY hire_date) ",
        "FROM employees ",
        "WINDOW w AS (PARTITION BY department);"
    );
    let formatted = pg_format_and_verify(sql);
    assert!(
        formatted.contains("PARTITION BY"),
        "Should preserve PARTITION BY in definition"
    );
    assert!(
        formatted.contains("ORDER BY"),
        "Should preserve ORDER BY in refinement"
    );
}

#[test]
fn test_over_refinement_with_frame() {
    let sql = concat!(
        "SELECT sum(x) OVER (w ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) ",
        "FROM t ",
        "WINDOW w AS (PARTITION BY grp ORDER BY id);"
    );
    let formatted = pg_format_and_verify(sql);
    assert!(
        formatted.contains("ROWS BETWEEN"),
        "Should preserve frame clause in refinement"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// WINDOW CLAUSE WITH EXISTING WINDOW NAME REFERENCE
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_window_def_referencing_another_window() {
    // w2 AS (w1 ORDER BY ...) — w2 inherits from w1
    let sql = concat!(
        "SELECT sum(x) OVER w2 ",
        "FROM t ",
        "WINDOW w1 AS (PARTITION BY a), ",
        "w2 AS (w1 ORDER BY b);"
    );
    let formatted = pg_format_and_verify(sql);
    assert!(formatted.contains("w1"), "Should preserve w1 reference");
    assert!(formatted.contains("w2"), "Should preserve w2 reference");
}

// ═════════════════════════════════════════════════════════════════════════════
// DIALECT GATING — SNOWFLAKE
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_snowflake_window_is_identifier() {
    // In Snowflake, "window" is a valid identifier, not a clause keyword
    // SELECT window FROM t should parse fine, NOT as a WINDOW clause
    let sql = "SELECT window FROM t;";
    let formatted = sf_format_and_verify(sql);
    assert!(
        formatted.to_lowercase().contains("window"),
        "Should preserve 'window' as identifier"
    );
}

#[test]
fn test_snowflake_window_as_alias() {
    // window as column alias in Snowflake
    let sql = "SELECT id AS window FROM t;";
    let formatted = sf_format_and_verify(sql);
    assert!(
        formatted.to_lowercase().contains("as window"),
        "Should preserve 'window' as alias"
    );
}

#[test]
fn test_snowflake_over_always_parenthesized() {
    // In Snowflake, OVER is always followed by (...) — bare OVER w should not be parsed
    // This tests that Snowflake mode still handles normal OVER (PARTITION BY ...) fine
    let sql = "SELECT row_number() OVER (PARTITION BY dept ORDER BY id) FROM employees;";
    let formatted = sf_format_and_verify(sql);
    assert!(formatted.contains("OVER"), "Should preserve OVER clause");
    assert!(
        formatted.contains("PARTITION BY"),
        "Should preserve PARTITION BY"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// WINDOW CLAUSE POSITION IN SELECT
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_window_before_order_by() {
    let sql = concat!(
        "SELECT sum(salary) OVER w ",
        "FROM employees ",
        "WHERE active = true ",
        "GROUP BY department ",
        "WINDOW w AS (PARTITION BY department) ",
        "ORDER BY department;"
    );
    let formatted = pg_format_and_verify(sql);
    // Verify WINDOW appears before ORDER BY in formatted output
    let window_pos = formatted.find("WINDOW").expect("Should have WINDOW");
    let order_pos = formatted
        .find("ORDER BY department")
        .expect("Should have ORDER BY");
    assert!(
        window_pos < order_pos,
        "WINDOW should appear before ORDER BY"
    );
}

#[test]
fn test_window_with_having() {
    let sql = concat!(
        "SELECT department, sum(salary) OVER w ",
        "FROM employees ",
        "GROUP BY department ",
        "HAVING count(*) > 5 ",
        "WINDOW w AS (ORDER BY department);"
    );
    pg_format_and_verify(sql);
}

#[test]
fn test_window_with_limit() {
    let sql = concat!(
        "SELECT sum(salary) OVER w ",
        "FROM employees ",
        "WINDOW w AS (ORDER BY salary) ",
        "ORDER BY salary ",
        "LIMIT 10;"
    );
    pg_format_and_verify(sql);
}

// ═════════════════════════════════════════════════════════════════════════════
// COMPLEX PATTERNS
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_window_functions_same_window() {
    let sql = concat!(
        "SELECT ",
        "row_number() OVER w, ",
        "rank() OVER w, ",
        "dense_rank() OVER w, ",
        "lag(salary) OVER w, ",
        "lead(salary) OVER w ",
        "FROM employees ",
        "WINDOW w AS (PARTITION BY department ORDER BY salary DESC);"
    );
    let formatted = pg_format_and_verify(sql);
    let over_w_count = formatted.matches("OVER w").count();
    assert!(
        over_w_count >= 5,
        "Should have 5 OVER w references, got {}",
        over_w_count
    );
}

#[test]
fn test_mixed_bare_and_parenthesized_over() {
    // Some functions use bare OVER w, some use OVER (w ORDER BY ...)
    let sql = concat!(
        "SELECT ",
        "sum(salary) OVER w, ",
        "row_number() OVER (w ORDER BY hire_date) ",
        "FROM employees ",
        "WINDOW w AS (PARTITION BY department);"
    );
    pg_format_and_verify(sql);
}

#[test]
fn test_window_clause_with_cte() {
    let sql = concat!(
        "WITH active AS (SELECT * FROM employees WHERE active) ",
        "SELECT sum(salary) OVER w ",
        "FROM active ",
        "WINDOW w AS (PARTITION BY department ORDER BY salary);"
    );
    pg_format_and_verify(sql);
}

// ═════════════════════════════════════════════════════════════════════════════
// IDEMPOTENCY
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_window_clause_idempotent() {
    let sql = "SELECT sum(salary) OVER w FROM employees WINDOW w AS (ORDER BY salary);";
    let first = pg_format_and_verify(sql);
    let second = pg_format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_window_clause_multiple_defs_idempotent() {
    let sql = concat!(
        "SELECT sum(x) OVER w1, avg(x) OVER w2 ",
        "FROM t ",
        "WINDOW w1 AS (PARTITION BY a), w2 AS (ORDER BY b);"
    );
    let first = pg_format_and_verify(sql);
    let second = pg_format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}
