// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for PostgreSQL INSERT extras:
//   - INSERT DEFAULT VALUES
//   - FROM ONLY (inheritance exclusion)
//   - OVERRIDING { SYSTEM | USER } VALUE

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

// ============================================================================
// INSERT DEFAULT VALUES
// ============================================================================

#[test]
fn test_insert_default_values_basic() {
    roundtrip("INSERT INTO t1 DEFAULT VALUES;");
}

#[test]
fn test_insert_default_values_qualified_table() {
    roundtrip("INSERT INTO myschema.my_table DEFAULT VALUES;");
}

#[test]
fn test_insert_default_values_returning() {
    roundtrip("INSERT INTO t1 DEFAULT VALUES RETURNING id;");
}

#[test]
fn test_insert_default_values_returning_star() {
    roundtrip("INSERT INTO t1 DEFAULT VALUES RETURNING *;");
}

#[test]
fn test_insert_default_values_returning_multiple() {
    roundtrip("INSERT INTO t1 DEFAULT VALUES RETURNING id, name, created_at;");
}

#[test]
fn test_insert_default_values_with_cte() {
    roundtrip("WITH dummy AS (SELECT 1) INSERT INTO t1 DEFAULT VALUES;");
}

#[test]
fn test_insert_default_values_multi_statement() {
    roundtrip("INSERT INTO t1 DEFAULT VALUES;\n\nINSERT INTO t2 DEFAULT VALUES;");
}

// ============================================================================
// FROM ONLY (PostgreSQL inheritance exclusion)
// ============================================================================

#[test]
fn test_select_from_only_basic() {
    roundtrip("SELECT * FROM ONLY parent_table;");
}

#[test]
fn test_select_from_only_with_alias() {
    roundtrip("SELECT * FROM ONLY parent_table AS p;");
}

#[test]
fn test_select_from_only_qualified() {
    roundtrip("SELECT * FROM ONLY myschema.parent_table;");
}

#[test]
fn test_select_from_only_with_where() {
    roundtrip("SELECT id, name FROM ONLY parent_table WHERE id > 10;");
}

#[test]
fn test_select_from_only_with_join() {
    roundtrip(
        "SELECT p.id, c.val FROM ONLY parent_table p JOIN child_table c ON p.id = c.parent_id;",
    );
}

#[test]
fn test_update_only() {
    roundtrip("UPDATE ONLY parent_table SET status = 'active' WHERE id = 1;");
}

#[test]
fn test_delete_from_only() {
    roundtrip("DELETE FROM ONLY parent_table WHERE id = 1;");
}

#[test]
fn test_select_from_only_multi_statement() {
    roundtrip("SELECT * FROM ONLY t1;\n\nSELECT * FROM ONLY t2;");
}

// ============================================================================
// OVERRIDING { SYSTEM | USER } VALUE
// ============================================================================

#[test]
fn test_insert_overriding_system_value() {
    roundtrip("INSERT INTO t1 (id, name) OVERRIDING SYSTEM VALUE VALUES (1, 'test');");
}

#[test]
fn test_insert_overriding_user_value() {
    roundtrip("INSERT INTO t1 (id, name) OVERRIDING USER VALUE VALUES (1, 'test');");
}

#[test]
fn test_insert_overriding_system_value_returning() {
    roundtrip("INSERT INTO t1 (id) OVERRIDING SYSTEM VALUE VALUES (1) RETURNING id;");
}

#[test]
fn test_insert_overriding_system_value_multi_row() {
    roundtrip("INSERT INTO t1 (id, name) OVERRIDING SYSTEM VALUE VALUES (1, 'a'), (2, 'b');");
}

#[test]
fn test_insert_overriding_user_value_select() {
    roundtrip("INSERT INTO t1 (id, name) OVERRIDING USER VALUE SELECT id, name FROM t2;");
}

#[test]
fn test_insert_overriding_value_default_values() {
    roundtrip("INSERT INTO t1 OVERRIDING SYSTEM VALUE DEFAULT VALUES;");
}

#[test]
fn test_insert_overriding_value_multi_statement() {
    roundtrip(
        "INSERT INTO t1 (id) OVERRIDING SYSTEM VALUE VALUES (1);\n\n\
         INSERT INTO t2 (id) OVERRIDING USER VALUE VALUES (2);",
    );
}

// ============================================================================
// Combined / edge cases
// ============================================================================

#[test]
fn test_combined_only_and_default_values() {
    // FROM ONLY in a SELECT + DEFAULT VALUES INSERT in a multi-statement script
    roundtrip(
        "SELECT * FROM ONLY parent_table;\n\n\
         INSERT INTO t1 DEFAULT VALUES;",
    );
}

#[test]
fn test_insert_default_values_on_conflict() {
    roundtrip("INSERT INTO t1 DEFAULT VALUES ON CONFLICT DO NOTHING;");
}

#[test]
fn test_insert_overriding_with_on_conflict() {
    roundtrip(
        "INSERT INTO t1 (id) OVERRIDING SYSTEM VALUE VALUES (1) ON CONFLICT (id) DO NOTHING;",
    );
}
