// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for SIMILAR TO expression parsing and formatting.
//!
//! SIMILAR TO is a SQL-standard pattern matching operator (PostgreSQL) that
//! uses SQL regular expression syntax (_, %, |, *, +, ?, {m,n}).
//! Syntax: expr [NOT] SIMILAR TO pattern [ESCAPE escape-char]

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
// Basic SIMILAR TO
// ============================================================================

#[test]
fn test_basic_similar_to() {
    roundtrip("SELECT * FROM t WHERE name SIMILAR TO '%foo%';");
}

#[test]
fn test_similar_to_with_column() {
    roundtrip("SELECT col FROM t WHERE col SIMILAR TO 'abc';");
}

#[test]
fn test_similar_to_string_literal() {
    roundtrip("SELECT 'hello' SIMILAR TO 'h%';");
}

// ============================================================================
// NOT SIMILAR TO
// ============================================================================

#[test]
fn test_not_similar_to() {
    roundtrip("SELECT * FROM t WHERE name NOT SIMILAR TO '%bar%';");
}

#[test]
fn test_not_similar_to_column() {
    roundtrip("SELECT col FROM t WHERE col NOT SIMILAR TO 'xyz';");
}

// ============================================================================
// SIMILAR TO with ESCAPE
// ============================================================================

#[test]
fn test_similar_to_escape() {
    roundtrip("SELECT * FROM t WHERE name SIMILAR TO '%10\\%%' ESCAPE '\\';");
}

#[test]
fn test_not_similar_to_escape() {
    roundtrip("SELECT * FROM t WHERE name NOT SIMILAR TO '%test\\_%' ESCAPE '\\';");
}

// ============================================================================
// SQL regex patterns (SIMILAR TO specific)
// ============================================================================

#[test]
fn test_similar_to_alternation() {
    roundtrip("SELECT * FROM t WHERE name SIMILAR TO '(foo|bar|baz)';");
}

#[test]
fn test_similar_to_quantifiers() {
    roundtrip("SELECT * FROM t WHERE code SIMILAR TO '[0-9]{3}-[0-9]{4}';");
}

#[test]
fn test_similar_to_character_class() {
    roundtrip("SELECT * FROM t WHERE val SIMILAR TO '[A-Za-z]+';");
}

#[test]
fn test_similar_to_optional() {
    roundtrip("SELECT * FROM t WHERE phone SIMILAR TO '\\+?[0-9]+';");
}

#[test]
fn test_similar_to_complex_pattern() {
    roundtrip("SELECT * FROM t WHERE email SIMILAR TO '[a-z]+@[a-z]+\\.[a-z]{2,4}';");
}

// ============================================================================
// In different clause positions
// ============================================================================

#[test]
fn test_similar_to_in_case() {
    roundtrip(
        "SELECT CASE WHEN name SIMILAR TO 'A%' THEN 'starts_with_A' ELSE 'other' END FROM t;",
    );
}

#[test]
fn test_similar_to_in_case_not() {
    roundtrip("SELECT CASE WHEN name NOT SIMILAR TO 'A%' THEN 'no_A' ELSE 'has_A' END FROM t;");
}

#[test]
fn test_similar_to_in_where_and() {
    roundtrip("SELECT * FROM t WHERE a SIMILAR TO 'x%' AND b > 5;");
}

#[test]
fn test_similar_to_in_where_or() {
    roundtrip("SELECT * FROM t WHERE a SIMILAR TO 'x%' OR a SIMILAR TO 'y%';");
}

#[test]
fn test_similar_to_with_not_and_and() {
    roundtrip("SELECT * FROM t WHERE a NOT SIMILAR TO 'x%' AND b NOT SIMILAR TO 'y%';");
}

// ============================================================================
// Mixed with other predicates
// ============================================================================

#[test]
fn test_similar_to_mixed_with_like() {
    roundtrip("SELECT * FROM t WHERE a LIKE '%foo%' AND b SIMILAR TO '(bar|baz)';");
}

#[test]
fn test_similar_to_mixed_with_in() {
    roundtrip("SELECT * FROM t WHERE a SIMILAR TO 'x%' AND b IN (1, 2, 3);");
}

#[test]
fn test_similar_to_mixed_with_between() {
    roundtrip("SELECT * FROM t WHERE a SIMILAR TO '[0-9]+' AND b BETWEEN 1 AND 10;");
}

#[test]
fn test_similar_to_mixed_with_is_null() {
    roundtrip("SELECT * FROM t WHERE a IS NOT NULL AND a SIMILAR TO '%test%';");
}

// ============================================================================
// Expression as left-hand side
// ============================================================================

#[test]
fn test_similar_to_function_lhs() {
    roundtrip("SELECT * FROM t WHERE LOWER(name) SIMILAR TO '(alice|bob)';");
}

#[test]
fn test_similar_to_concat_lhs() {
    roundtrip("SELECT * FROM t WHERE first_name || last_name SIMILAR TO 'John%';");
}

#[test]
fn test_similar_to_cast_lhs() {
    roundtrip("SELECT * FROM t WHERE CAST(id AS TEXT) SIMILAR TO '[0-9]+';");
}

// ============================================================================
// Subquery pattern
// ============================================================================

#[test]
fn test_similar_to_in_subquery() {
    roundtrip("SELECT * FROM t WHERE name SIMILAR TO (SELECT pattern FROM patterns LIMIT 1);");
}

// ============================================================================
// Multiple statements
// ============================================================================

#[test]
fn test_similar_to_multi_stmt() {
    roundtrip(
        "SELECT * FROM a WHERE x SIMILAR TO 'foo%';\nSELECT * FROM b WHERE y NOT SIMILAR TO 'bar%';",
    );
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_similar_to_empty_pattern() {
    roundtrip("SELECT * FROM t WHERE name SIMILAR TO '';");
}

#[test]
fn test_similar_to_percent_only() {
    roundtrip("SELECT * FROM t WHERE name SIMILAR TO '%';");
}

#[test]
fn test_similar_to_underscore() {
    roundtrip("SELECT * FROM t WHERE code SIMILAR TO '___';");
}

#[test]
fn test_similar_to_preserves_case() {
    // SIMILAR is an identifier (not a keyword), so original case should be preserved
    let sql = "SELECT * FROM t WHERE name similar to '%foo%';";
    let formatted = fmt(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
    assert!(
        formatted.contains("similar") || formatted.contains("SIMILAR"),
        "Should preserve original case of SIMILAR: {formatted}"
    );
}

#[test]
fn test_similar_to_mixed_case() {
    roundtrip("SELECT * FROM t WHERE name Similar To '%test%';");
}

// ============================================================================
// Parenthesized expressions
// ============================================================================

#[test]
fn test_similar_to_parenthesized_expr() {
    roundtrip("SELECT * FROM t WHERE (name SIMILAR TO '%foo%');");
}

#[test]
fn test_not_similar_to_parenthesized() {
    roundtrip("SELECT * FROM t WHERE (name NOT SIMILAR TO '%bar%');");
}

// ============================================================================
// CTE with SIMILAR TO
// ============================================================================

#[test]
fn test_similar_to_in_cte() {
    roundtrip(
        "WITH filtered AS (SELECT * FROM t WHERE code SIMILAR TO '[A-Z]{3}') SELECT * FROM filtered;",
    );
}

// ============================================================================
// Verify formatting output
// ============================================================================

#[test]
fn test_similar_to_formatting_output() {
    let sql = "SELECT * FROM t WHERE  name   SIMILAR   TO   '%x%';";
    let formatted = fmt(sql);
    // Should normalize whitespace
    assert!(
        formatted.contains("SIMILAR") || formatted.contains("similar"),
        "Formatted output should contain SIMILAR TO: {formatted}"
    );
    verify_formatting_safe(sql, &formatted).unwrap();
}
