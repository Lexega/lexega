// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL FOR UPDATE/SHARE/NO KEY UPDATE/KEY SHARE locking clauses.
//!
//! PostgreSQL syntax:
//!   FOR { UPDATE | NO KEY UPDATE | SHARE | KEY SHARE }
//!       [ OF table_name [, ...] ] [ NOWAIT | SKIP LOCKED ]
//! Multiple locking clauses are allowed.

use std::sync::Arc;

use lexega_syntax::{
    format_sql_with_config, verify_formatting_safe, verify_formatting_safe_with_dialect,
    FormatterConfig, PostgresDialect,
};

fn pg_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = Arc::new(PostgresDialect);
    config
}

fn roundtrip(sql: &str) {
    let config = pg_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Parse failed for:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe_with_dialect(sql, &formatted, &PostgresDialect).unwrap_or_else(|e| {
        panic!(
            "Verification failed for:\n{}\nFormatted:\n{}\nError: {}",
            sql, formatted, e
        )
    });
}

fn roundtrip_not_opaque(sql: &str) {
    let config = pg_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Parse failed for:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe_with_dialect(sql, &formatted, &PostgresDialect).unwrap_or_else(|e| {
        panic!(
            "Verification failed for:\n{}\nFormatted:\n{}\nError: {}",
            sql, formatted, e
        )
    });
    // Ensure it didn't fall back to OpaqueContent
    assert!(
        !formatted.contains("OpaqueContent"),
        "Should not produce OpaqueContent for:\n{}\nFormatted:\n{}",
        sql,
        formatted
    );
}

// ============================================================================
// Basic lock strengths
// ============================================================================

#[test]
fn test_for_update_basic() {
    roundtrip_not_opaque("SELECT * FROM t FOR UPDATE");
}

#[test]
fn test_for_share_basic() {
    roundtrip_not_opaque("SELECT * FROM t FOR SHARE");
}

#[test]
fn test_for_no_key_update() {
    roundtrip_not_opaque("SELECT * FROM t FOR NO KEY UPDATE");
}

#[test]
fn test_for_key_share() {
    roundtrip_not_opaque("SELECT * FROM t FOR KEY SHARE");
}

// ============================================================================
// OF clause
// ============================================================================

#[test]
fn test_for_update_of_single_table() {
    roundtrip_not_opaque("SELECT * FROM t1 JOIN t2 ON t1.id = t2.id FOR UPDATE OF t1");
}

#[test]
fn test_for_update_of_multiple_tables() {
    roundtrip_not_opaque("SELECT * FROM t1, t2, t3 FOR UPDATE OF t1, t2");
}

#[test]
fn test_for_share_of_table() {
    roundtrip_not_opaque("SELECT * FROM t1 JOIN t2 ON t1.id = t2.id FOR SHARE OF t2");
}

// ============================================================================
// Wait policies
// ============================================================================

#[test]
fn test_for_update_nowait() {
    roundtrip_not_opaque("SELECT * FROM t FOR UPDATE NOWAIT");
}

#[test]
fn test_for_share_nowait() {
    roundtrip_not_opaque("SELECT * FROM t FOR SHARE NOWAIT");
}

#[test]
fn test_for_update_skip_locked() {
    roundtrip_not_opaque("SELECT * FROM t FOR UPDATE SKIP LOCKED");
}

#[test]
fn test_for_share_skip_locked() {
    roundtrip_not_opaque("SELECT * FROM t FOR SHARE SKIP LOCKED");
}

#[test]
fn test_for_no_key_update_skip_locked() {
    roundtrip_not_opaque("SELECT * FROM t FOR NO KEY UPDATE SKIP LOCKED");
}

#[test]
fn test_for_key_share_nowait() {
    roundtrip_not_opaque("SELECT * FROM t FOR KEY SHARE NOWAIT");
}

// ============================================================================
// OF + wait policy combined
// ============================================================================

#[test]
fn test_for_update_of_table_nowait() {
    roundtrip_not_opaque("SELECT * FROM t1, t2 FOR UPDATE OF t1 NOWAIT");
}

#[test]
fn test_for_update_of_table_skip_locked() {
    roundtrip_not_opaque("SELECT * FROM t1, t2 FOR UPDATE OF t1 SKIP LOCKED");
}

#[test]
fn test_for_share_of_table_skip_locked() {
    roundtrip_not_opaque("SELECT * FROM t1, t2 FOR SHARE OF t2 SKIP LOCKED");
}

// ============================================================================
// Multiple locking clauses
// ============================================================================

#[test]
fn test_multiple_for_clauses() {
    roundtrip_not_opaque("SELECT * FROM t1, t2 FOR UPDATE OF t1 FOR SHARE OF t2");
}

#[test]
fn test_multiple_for_clauses_with_policies() {
    roundtrip_not_opaque(
        "SELECT * FROM t1, t2 FOR UPDATE OF t1 NOWAIT FOR SHARE OF t2 SKIP LOCKED",
    );
}

#[test]
fn test_three_locking_clauses() {
    roundtrip_not_opaque(
        "SELECT * FROM t1, t2, t3 FOR UPDATE OF t1 FOR NO KEY UPDATE OF t2 FOR KEY SHARE OF t3",
    );
}

// ============================================================================
// With other SELECT clauses
// ============================================================================

#[test]
fn test_for_update_with_where() {
    roundtrip_not_opaque("SELECT * FROM t WHERE id = 1 FOR UPDATE");
}

#[test]
fn test_for_update_with_order_by_limit() {
    roundtrip_not_opaque("SELECT * FROM t ORDER BY id LIMIT 10 FOR UPDATE");
}

#[test]
fn test_for_update_with_join() {
    roundtrip_not_opaque(
        "SELECT t1.a, t2.b FROM t1 INNER JOIN t2 ON t1.id = t2.id FOR UPDATE OF t1",
    );
}

#[test]
fn test_for_update_in_subquery() {
    roundtrip_not_opaque("SELECT * FROM (SELECT * FROM t FOR UPDATE) sub");
}

#[test]
fn test_for_update_with_cte() {
    roundtrip_not_opaque("WITH cte AS (SELECT * FROM t) SELECT * FROM cte FOR UPDATE");
}

// ============================================================================
// Snowflake compatibility (FOR UPDATE with WAIT)
// ============================================================================

#[test]
fn test_for_update_wait_snowflake() {
    // Snowflake syntax: FOR UPDATE WAIT <n>
    let sql = "SELECT * FROM t FOR UPDATE WAIT 5";
    let config = FormatterConfig::default();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Parse failed: {:?}", e));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}

#[test]
fn test_for_update_nowait_snowflake() {
    let sql = "SELECT * FROM t FOR UPDATE NOWAIT";
    let config = FormatterConfig::default();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Parse failed: {:?}", e));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_for_update_qualified_table_name() {
    roundtrip_not_opaque("SELECT * FROM myschema.t FOR UPDATE OF myschema.t");
}

#[test]
fn test_for_update_no_from() {
    // FOR UPDATE without FROM is unusual but syntactically accepted by some parsers
    // Our parser only emits FOR if FOR keyword is present after LIMIT/OFFSET
    roundtrip("SELECT 1 FOR UPDATE");
}
