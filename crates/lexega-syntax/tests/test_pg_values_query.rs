// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for standalone VALUES query (PostgreSQL-style)
///
/// Covers:
/// - Standalone VALUES (...), (...), ...
/// - VALUES with ORDER BY, LIMIT, OFFSET
/// - VALUES in UNION/INTERSECT/EXCEPT
/// - VALUES in IN subquery
/// - VALUES in FROM subquery (already supported, regression guard)
use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn roundtrip(sql: &str) {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Verification failed:\n{}\nFormatted:\n{}\nError: {}",
            sql, formatted, e
        )
    });
}

// =========================================================================
// Basic standalone VALUES
// =========================================================================

#[test]
fn test_values_basic_multi_row() {
    roundtrip("VALUES (1, 'one'), (2, 'two'), (3, 'three');");
}

#[test]
fn test_values_single_row() {
    roundtrip("VALUES (42);");
}

#[test]
fn test_values_single_column_multi_row() {
    roundtrip("VALUES (1), (2), (3);");
}

#[test]
fn test_values_null_and_expressions() {
    roundtrip("VALUES (1, NULL, 2 + 3), (4, 'hello', 6 * 7);");
}

#[test]
fn test_values_string_literals() {
    roundtrip("VALUES ('alice', 'admin'), ('bob', 'user');");
}

#[test]
fn test_values_boolean_literals() {
    roundtrip("VALUES (TRUE, 1), (FALSE, 0);");
}

// =========================================================================
// VALUES with ORDER BY
// =========================================================================

#[test]
fn test_values_order_by_ordinal() {
    roundtrip("VALUES (1, 'alice'), (2, 'bob') ORDER BY 1;");
}

#[test]
fn test_values_order_by_desc() {
    roundtrip("VALUES (1, 'z'), (2, 'a') ORDER BY 2 DESC;");
}

#[test]
fn test_values_order_by_multiple() {
    roundtrip("VALUES (1, 'a'), (2, 'b'), (1, 'c') ORDER BY 1, 2;");
}

// =========================================================================
// VALUES with LIMIT
// =========================================================================

#[test]
fn test_values_limit() {
    roundtrip("VALUES (1, 'a'), (2, 'b'), (3, 'c') LIMIT 2;");
}

// =========================================================================
// VALUES with OFFSET
// =========================================================================

#[test]
fn test_values_offset() {
    roundtrip("VALUES (1, 'a'), (2, 'b'), (3, 'c') OFFSET 1;");
}

// =========================================================================
// VALUES with ORDER BY + LIMIT + OFFSET
// =========================================================================

#[test]
fn test_values_order_limit_offset() {
    roundtrip("VALUES (3, 'c'), (1, 'a'), (2, 'b') ORDER BY 1 LIMIT 2 OFFSET 1;");
}

#[test]
fn test_values_limit_offset_no_order() {
    roundtrip("VALUES (1), (2), (3), (4), (5) LIMIT 3 OFFSET 1;");
}

// =========================================================================
// VALUES with FETCH FIRST (SQL standard LIMIT alternative)
// =========================================================================

#[test]
fn test_values_fetch_first() {
    roundtrip("VALUES (1), (2), (3) FETCH FIRST 2 ROWS ONLY;");
}

// =========================================================================
// VALUES in UNION / INTERSECT / EXCEPT
// =========================================================================

#[test]
fn test_values_union_all_with_select() {
    roundtrip("SELECT 1, 'a' UNION ALL VALUES (2, 'b'), (3, 'c');");
}

#[test]
fn test_values_union_values() {
    roundtrip("VALUES (1, 'a') UNION ALL VALUES (2, 'b');");
}

#[test]
fn test_values_except() {
    roundtrip("VALUES (1), (2), (3) EXCEPT VALUES (2);");
}

#[test]
fn test_values_intersect() {
    roundtrip("VALUES (1), (2), (3) INTERSECT VALUES (2), (3), (4);");
}

#[test]
fn test_select_union_values_union_select() {
    roundtrip("SELECT 1 UNION ALL VALUES (2) UNION ALL SELECT 3;");
}

// =========================================================================
// VALUES in IN subquery
// =========================================================================

#[test]
fn test_values_in_subquery() {
    roundtrip(
        "SELECT * FROM machines WHERE ip_address IN (VALUES ('192.168.0.1'), ('192.168.0.10'));",
    );
}

#[test]
fn test_values_not_in_subquery() {
    roundtrip("SELECT * FROM machines WHERE ip_address NOT IN (VALUES ('192.168.0.1'));");
}

// =========================================================================
// VALUES in FROM clause (regression guards — already supported)
// =========================================================================

#[test]
fn test_values_in_from_clause() {
    roundtrip("SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS t(id, name);");
}

#[test]
fn test_values_in_from_with_join() {
    roundtrip(
        "SELECT e.name, v.bonus FROM employees e JOIN (VALUES (1, 100), (2, 200)) AS v(dept_id, bonus) ON e.dept_id = v.dept_id;",
    );
}

// =========================================================================
// Multi-statement with VALUES
// =========================================================================

#[test]
fn test_values_multi_statement() {
    roundtrip("VALUES (1, 'a');\nVALUES (2, 'b');\nVALUES (3, 'c');");
}
