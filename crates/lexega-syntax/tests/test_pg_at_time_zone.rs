// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL AT TIME ZONE / AT LOCAL expressions.
//!
//! Each construct is tested for:
//!   1. Format round-trip with semantic safety verification
//!   2. Multiple syntax variants (string, INTERVAL, column, chained, AT LOCAL)
//!
//! Token gotchas verified via --debug-tokens:
//!   AT   → Identifier { kind: Unquoted } ⚠️ NOT Keyword
//!   TIME → Identifier { kind: Unquoted } ⚠️ NOT Keyword
//!   ZONE → Identifier { kind: Unquoted } ⚠️ NOT Keyword
//!   LOCAL → Keyword(Local) ✅ Is a Keyword

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
// Basic AT TIME ZONE with string literal
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_basic_string() {
    format_and_verify("SELECT col AT TIME ZONE 'UTC' FROM t;");
}

#[test]
fn test_at_time_zone_named_timezone() {
    format_and_verify("SELECT created_at AT TIME ZONE 'America/New_York' FROM events;");
}

#[test]
fn test_at_time_zone_europe() {
    format_and_verify("SELECT ts AT TIME ZONE 'Europe/London' FROM logs;");
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE with TIMESTAMP literal
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_timestamp_literal() {
    format_and_verify("SELECT TIMESTAMP '2024-01-15 10:30:00' AT TIME ZONE 'America/Denver';");
}

#[test]
fn test_at_time_zone_timestamptz() {
    format_and_verify(
        "SELECT TIMESTAMP WITH TIME ZONE '2024-01-15 10:30:00+00' AT TIME ZONE 'US/Pacific';",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// AT LOCAL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_local_basic() {
    format_and_verify("SELECT ts AT LOCAL FROM events;");
}

#[test]
fn test_at_local_in_select_list() {
    format_and_verify("SELECT created_at AT LOCAL, updated_at AT LOCAL FROM logs;");
}

#[test]
fn test_at_local_timestamp_literal() {
    format_and_verify("SELECT TIMESTAMP '2024-06-01 12:00:00+00' AT LOCAL;");
}

// ═══════════════════════════════════════════════════════════════════════════
// Chained AT TIME ZONE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_chained() {
    format_and_verify("SELECT ts AT TIME ZONE 'UTC' AT TIME ZONE 'US/Eastern' FROM events;");
}

#[test]
fn test_at_time_zone_triple_chain() {
    format_and_verify(
        "SELECT ts AT TIME ZONE 'UTC' AT TIME ZONE 'CET' AT TIME ZONE 'US/Pacific' FROM t;",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE with INTERVAL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_interval() {
    format_and_verify("SELECT ts AT TIME ZONE INTERVAL '5' HOUR FROM events;");
}

#[test]
fn test_at_time_zone_negative_interval() {
    format_and_verify("SELECT ts AT TIME ZONE INTERVAL '-8' HOUR FROM t;");
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE with column reference as zone
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_column_ref() {
    format_and_verify("SELECT ts AT TIME ZONE user_tz FROM events;");
}

#[test]
fn test_at_time_zone_qualified_column_ref() {
    format_and_verify(
        "SELECT e.ts AT TIME ZONE u.timezone FROM events e JOIN users u ON e.user_id = u.id;",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE in different clauses
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_in_where() {
    format_and_verify("SELECT * FROM events WHERE created_at AT TIME ZONE 'UTC' > '2024-01-01';");
}

#[test]
fn test_at_time_zone_in_order_by() {
    format_and_verify("SELECT * FROM events ORDER BY created_at AT TIME ZONE 'UTC';");
}

#[test]
fn test_at_time_zone_in_group_by() {
    format_and_verify(
        "SELECT DATE(created_at AT TIME ZONE 'UTC'), COUNT(*) FROM events GROUP BY DATE(created_at AT TIME ZONE 'UTC');",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE with functions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_now() {
    format_and_verify("SELECT NOW() AT TIME ZONE 'UTC';");
}

#[test]
fn test_at_time_zone_current_timestamp() {
    format_and_verify("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'America/Chicago';");
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE with CAST
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_with_cast() {
    format_and_verify("SELECT CAST(col AS TIMESTAMP) AT TIME ZONE 'UTC' FROM t;");
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE in complex expressions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_in_comparison() {
    format_and_verify(
        "SELECT * FROM events WHERE created_at AT TIME ZONE 'UTC' BETWEEN '2024-01-01' AND '2024-12-31';",
    );
}

#[test]
fn test_at_time_zone_aliased() {
    format_and_verify("SELECT ts AT TIME ZONE 'UTC' AS utc_time FROM events;");
}

#[test]
fn test_at_time_zone_in_case() {
    format_and_verify(
        "SELECT CASE WHEN region = 'US' THEN ts AT TIME ZONE 'US/Eastern' ELSE ts AT TIME ZONE 'UTC' END FROM events;",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases: AT as regular identifier (should NOT trigger AT TIME ZONE)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_as_alias() {
    // "at" used as column alias - should NOT be treated as AT TIME ZONE
    format_and_verify("SELECT col at FROM t;");
}

#[test]
fn test_at_as_table_alias() {
    // "at" used as table alias
    format_and_verify("SELECT at.col FROM my_table at;");
}

// ═══════════════════════════════════════════════════════════════════════════
// Idempotence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_idempotent() {
    let sql = "SELECT ts AT TIME ZONE 'UTC' FROM events;";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "AT TIME ZONE formatting is not idempotent");
}

#[test]
fn test_at_local_idempotent() {
    let sql = "SELECT ts AT LOCAL FROM events;";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "AT LOCAL formatting is not idempotent");
}

#[test]
fn test_chained_at_time_zone_idempotent() {
    let sql = "SELECT ts AT TIME ZONE 'UTC' AT TIME ZONE 'US/Eastern' FROM events;";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(
        first, second,
        "Chained AT TIME ZONE formatting is not idempotent"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// AT TIME ZONE with parenthesized expressions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_at_time_zone_parenthesized_expr() {
    format_and_verify("SELECT (ts + INTERVAL '1 hour') AT TIME ZONE 'UTC' FROM events;");
}

#[test]
fn test_at_time_zone_in_subquery() {
    format_and_verify(
        "SELECT * FROM (SELECT ts AT TIME ZONE 'UTC' AS utc_ts FROM events) sub WHERE utc_ts > NOW();",
    );
}
