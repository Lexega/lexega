// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for PostgreSQL expression-based ON CONFLICT targets:
//   - Function call expressions: ON CONFLICT (LOWER(email))
//   - Arithmetic expressions: ON CONFLICT ((a + b))
//   - Mixed columns and expressions: ON CONFLICT (tenant_id, LOWER(email))
//   - COLLATE modifier: ON CONFLICT (email COLLATE "C")
//   - WHERE predicate on target (partial index): ON CONFLICT (email) WHERE active = true
//   - Combinations of above with DO NOTHING and DO UPDATE SET

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
// SIMPLE COLUMN TARGETS (baseline — already worked)
// ============================================================================

#[test]
fn test_on_conflict_simple_column() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (id) DO NOTHING;");
}

#[test]
fn test_on_conflict_multi_column() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (tenant_id, email) DO NOTHING;");
}

#[test]
fn test_on_conflict_on_constraint() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT ON CONSTRAINT users_pkey DO NOTHING;");
}

#[test]
fn test_on_conflict_do_update_set() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;");
}

// ============================================================================
// EXPRESSION TARGETS — function calls
// ============================================================================

#[test]
fn test_on_conflict_expr_lower() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (LOWER(email)) DO NOTHING;");
}

#[test]
fn test_on_conflict_expr_upper() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (UPPER(email)) DO NOTHING;");
}

#[test]
fn test_on_conflict_expr_coalesce() {
    roundtrip("INSERT INTO data (id, a, b) VALUES (1, 2, 3) ON CONFLICT (COALESCE(a, b)) DO UPDATE SET a = EXCLUDED.a;");
}

#[test]
fn test_on_conflict_expr_trim() {
    roundtrip(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (TRIM(email)) DO NOTHING;",
    );
}

#[test]
fn test_on_conflict_expr_nested_function() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (LOWER(TRIM(email))) DO NOTHING;");
}

// ============================================================================
// EXPRESSION TARGETS — arithmetic / parenthesized
// ============================================================================

#[test]
fn test_on_conflict_expr_arithmetic() {
    roundtrip("INSERT INTO data (id, a, b) VALUES (1, 2, 3) ON CONFLICT ((a + b)) DO NOTHING;");
}

#[test]
fn test_on_conflict_expr_arithmetic_multiply() {
    roundtrip("INSERT INTO data (id, x, y) VALUES (1, 2, 3) ON CONFLICT ((x * y)) DO NOTHING;");
}

#[test]
fn test_on_conflict_expr_modulo() {
    roundtrip("INSERT INTO data (id, x) VALUES (1, 10) ON CONFLICT ((x % 100)) DO NOTHING;");
}

// ============================================================================
// MIXED COLUMNS AND EXPRESSIONS
// ============================================================================

#[test]
fn test_on_conflict_mixed_column_and_function() {
    roundtrip("INSERT INTO users (id, email, name) VALUES (1, 'a@b.com', 'Alice') ON CONFLICT (tenant_id, LOWER(email)) DO NOTHING;");
}

#[test]
fn test_on_conflict_mixed_three_items() {
    roundtrip("INSERT INTO data (id, a, b, c) VALUES (1, 2, 3, 4) ON CONFLICT (id, LOWER(a), (b + c)) DO NOTHING;");
}

#[test]
fn test_on_conflict_mixed_with_do_update() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (tenant_id, LOWER(email)) DO UPDATE SET email = EXCLUDED.email;");
}

// ============================================================================
// COLLATE modifier
// ============================================================================

#[test]
fn test_on_conflict_collate_bare() {
    roundtrip(
        r#"INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (email COLLATE "C") DO NOTHING;"#,
    );
}

#[test]
fn test_on_conflict_collate_with_expression() {
    roundtrip(
        r#"INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (LOWER(email) COLLATE "C") DO NOTHING;"#,
    );
}

// ============================================================================
// WHERE predicate on conflict target (partial index inference)
// ============================================================================

#[test]
fn test_on_conflict_where_predicate_simple() {
    roundtrip("INSERT INTO users (id, email, active) VALUES (1, 'a@b.com', true) ON CONFLICT (email) WHERE active = true DO NOTHING;");
}

#[test]
fn test_on_conflict_where_predicate_boolean_column() {
    roundtrip("INSERT INTO users (id, email, active) VALUES (1, 'a@b.com', true) ON CONFLICT (email) WHERE active DO NOTHING;");
}

#[test]
fn test_on_conflict_where_predicate_is_not_null() {
    roundtrip("INSERT INTO users (id, email, deleted_at) VALUES (1, 'a@b.com', NULL) ON CONFLICT (email) WHERE deleted_at IS NULL DO NOTHING;");
}

#[test]
fn test_on_conflict_where_predicate_with_do_update() {
    roundtrip("INSERT INTO users (id, email, active) VALUES (1, 'a@b.com', true) ON CONFLICT (email) WHERE active = true DO UPDATE SET email = EXCLUDED.email;");
}

#[test]
fn test_on_conflict_expr_with_where() {
    roundtrip("INSERT INTO users (id, email, active) VALUES (1, 'a@b.com', true) ON CONFLICT (LOWER(email)) WHERE active DO UPDATE SET email = EXCLUDED.email;");
}

// ============================================================================
// DO UPDATE with WHERE on the action (not the target) — already worked
// ============================================================================

#[test]
fn test_on_conflict_do_update_where_action() {
    roundtrip("INSERT INTO users (id, email, name) VALUES (1, 'a@b.com', 'Alice') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, email = EXCLUDED.email WHERE users.updated_at < EXCLUDED.updated_at;");
}

#[test]
fn test_on_conflict_do_update_where_both_target_and_action() {
    roundtrip("INSERT INTO users (id, email, active) VALUES (1, 'a@b.com', true) ON CONFLICT (email) WHERE active = true DO UPDATE SET email = EXCLUDED.email WHERE users.updated_at < EXCLUDED.updated_at;");
}

// ============================================================================
// NO TARGET (bare ON CONFLICT DO NOTHING)
// ============================================================================

#[test]
fn test_on_conflict_no_target() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT DO NOTHING;");
}

// ============================================================================
// COMBINED with other PG INSERT features
// ============================================================================

#[test]
fn test_on_conflict_expr_with_returning() {
    roundtrip("INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (LOWER(email)) DO NOTHING RETURNING id;");
}

#[test]
fn test_on_conflict_expr_with_default_values() {
    roundtrip("INSERT INTO users DEFAULT VALUES ON CONFLICT (id) DO NOTHING;");
}

#[test]
fn test_on_conflict_expr_with_select_source() {
    roundtrip("INSERT INTO users (id, email) SELECT id, email FROM staging ON CONFLICT (LOWER(email)) DO UPDATE SET email = EXCLUDED.email;");
}
