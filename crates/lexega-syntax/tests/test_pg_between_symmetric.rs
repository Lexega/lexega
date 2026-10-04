// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for BETWEEN SYMMETRIC expression parsing and formatting.
//!
//! BETWEEN SYMMETRIC is a PostgreSQL extension to the standard BETWEEN operator.
//! Unlike regular BETWEEN (which requires lower <= upper), SYMMETRIC automatically
//! reorders the bounds so `x BETWEEN SYMMETRIC 10 AND 5` is equivalent to
//! `x BETWEEN 5 AND 10`.
//!
//! Syntax: expr [NOT] BETWEEN SYMMETRIC lower AND upper

use lexega_syntax::{format_sql, verify_formatting_safe};

fn fmt(sql: &str) -> String {
    format_sql(sql).unwrap_or_else(|e| panic!("Failed to format: {e}\nSQL: {sql}"))
}

fn roundtrip(sql: &str) {
    let formatted = fmt(sql);
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!("Verification failed: {e}\nOriginal:  {sql}\nFormatted: {formatted}")
    });
}

// ============================================================================
// Basic BETWEEN SYMMETRIC
// ============================================================================

#[test]
fn test_basic_between_symmetric() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC 10 AND 5;");
}

#[test]
fn test_between_symmetric_normal_order() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC 1 AND 10;");
}

#[test]
fn test_between_symmetric_column_refs() {
    roundtrip("SELECT * FROM t WHERE val BETWEEN SYMMETRIC lo AND hi;");
}

#[test]
fn test_between_symmetric_strings() {
    roundtrip("SELECT * FROM t WHERE name BETWEEN SYMMETRIC 'Z' AND 'A';");
}

#[test]
fn test_between_symmetric_dates() {
    roundtrip(
        "SELECT * FROM events WHERE created_at BETWEEN SYMMETRIC '2024-12-31' AND '2024-01-01';",
    );
}

// ============================================================================
// NOT BETWEEN SYMMETRIC
// ============================================================================

#[test]
fn test_not_between_symmetric() {
    roundtrip("SELECT * FROM t WHERE x NOT BETWEEN SYMMETRIC 10 AND 5;");
}

#[test]
fn test_not_between_symmetric_columns() {
    roundtrip("SELECT * FROM t WHERE score NOT BETWEEN SYMMETRIC min_score AND max_score;");
}

// ============================================================================
// BETWEEN SYMMETRIC with expressions
// ============================================================================

#[test]
fn test_between_symmetric_with_arithmetic() {
    roundtrip("SELECT * FROM t WHERE col BETWEEN SYMMETRIC a + b AND c * d;");
}

#[test]
fn test_between_symmetric_with_function_calls() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC ABS(y) AND CEIL(z);");
}

#[test]
fn test_between_symmetric_with_negation() {
    roundtrip("SELECT * FROM t WHERE val BETWEEN SYMMETRIC -10 AND -1;");
}

#[test]
fn test_between_symmetric_complex_expr_lhs() {
    roundtrip("SELECT * FROM t WHERE a + b BETWEEN SYMMETRIC 1 AND 10;");
}

#[test]
fn test_between_symmetric_with_cast() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC 1::numeric AND 10::numeric;");
}

// ============================================================================
// Mixed with regular BETWEEN
// ============================================================================

#[test]
fn test_regular_between_still_works() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN 1 AND 10;");
}

#[test]
fn test_not_between_still_works() {
    roundtrip("SELECT * FROM t WHERE x NOT BETWEEN 1 AND 10;");
}

#[test]
fn test_mixed_between_and_symmetric() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN 1 AND 10 AND y BETWEEN SYMMETRIC 20 AND 5;");
}

// ============================================================================
// BETWEEN SYMMETRIC in different clauses
// ============================================================================

#[test]
fn test_between_symmetric_in_case() {
    roundtrip("SELECT CASE WHEN x BETWEEN SYMMETRIC 10 AND 1 THEN 'yes' ELSE 'no' END FROM t;");
}

#[test]
fn test_between_symmetric_in_having() {
    roundtrip(
        "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) BETWEEN SYMMETRIC 10 AND 1;",
    );
}

#[test]
fn test_between_symmetric_in_join() {
    roundtrip("SELECT * FROM t1 JOIN t2 ON t1.x BETWEEN SYMMETRIC t2.lo AND t2.hi;");
}

#[test]
fn test_between_symmetric_in_subquery() {
    roundtrip("SELECT * FROM t WHERE x IN (SELECT y FROM u WHERE y BETWEEN SYMMETRIC 10 AND 1);");
}

// ============================================================================
// BETWEEN SYMMETRIC with AND disambiguation
// ============================================================================

#[test]
fn test_between_symmetric_followed_by_and() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC 1 AND 10 AND y > 0;");
}

#[test]
fn test_not_between_symmetric_followed_by_and() {
    roundtrip("SELECT * FROM t WHERE x NOT BETWEEN SYMMETRIC 10 AND 5 AND z = 1;");
}

#[test]
fn test_between_symmetric_followed_by_or() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC 10 AND 5 OR y = 0;");
}

#[test]
fn test_between_symmetric_in_complex_predicate() {
    roundtrip("SELECT * FROM t WHERE a = 1 AND b BETWEEN SYMMETRIC 10 AND 5 AND c > 0;");
}

// ============================================================================
// Case preservation
// ============================================================================

#[test]
fn test_between_symmetric_lowercase() {
    roundtrip("SELECT * FROM t WHERE x between symmetric 10 and 5;");
}

#[test]
fn test_between_symmetric_mixed_case() {
    roundtrip("SELECT * FROM t WHERE x Between Symmetric 10 And 5;");
}

#[test]
fn test_not_between_symmetric_lowercase() {
    roundtrip("SELECT * FROM t WHERE x not between symmetric 10 and 5;");
}

// ============================================================================
// Multi-statement
// ============================================================================

#[test]
fn test_between_symmetric_multi_statement() {
    roundtrip(
        "SELECT * FROM t WHERE x BETWEEN SYMMETRIC 10 AND 5;\n\
         SELECT * FROM u WHERE y NOT BETWEEN SYMMETRIC 20 AND 1;",
    );
}

// ============================================================================
// CTE with BETWEEN SYMMETRIC
// ============================================================================

#[test]
fn test_between_symmetric_in_cte() {
    roundtrip(
        "WITH filtered AS (SELECT * FROM t WHERE x BETWEEN SYMMETRIC 10 AND 1) \
         SELECT * FROM filtered;",
    );
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_between_symmetric_parenthesized_bounds() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC (1 + 2) AND (3 + 4);");
}

#[test]
fn test_between_symmetric_nested_subquery_bound() {
    roundtrip("SELECT * FROM t WHERE x BETWEEN SYMMETRIC (SELECT MIN(y) FROM u) AND (SELECT MAX(y) FROM u);");
}

#[test]
fn test_between_symmetric_with_null_check() {
    roundtrip("SELECT * FROM t WHERE x IS NOT NULL AND x BETWEEN SYMMETRIC 10 AND 1;");
}

// ============================================================================
// Formatted output verification
// ============================================================================

#[test]
fn test_between_symmetric_output_preserves_keyword() {
    let formatted = fmt("SELECT * FROM t WHERE x BETWEEN SYMMETRIC 10 AND 5;");
    assert!(
        formatted.contains("BETWEEN SYMMETRIC"),
        "SYMMETRIC keyword should be preserved in output. Got: {}",
        formatted
    );
}

#[test]
fn test_not_between_symmetric_output_preserves_keywords() {
    let formatted = fmt("SELECT * FROM t WHERE x NOT BETWEEN SYMMETRIC 10 AND 5;");
    assert!(
        formatted.contains("NOT BETWEEN SYMMETRIC"),
        "NOT BETWEEN SYMMETRIC should be preserved in output. Got: {}",
        formatted
    );
}
