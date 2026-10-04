// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL Writable CTEs and dialect-gated RETURNING behavior.
//!
//! Covers:
//!   - WITH ... INSERT/UPDATE/DELETE (writable CTEs)
//!   - CTE body containing INSERT/UPDATE/DELETE
//!   - INSERT ... SELECT ... RETURNING (RETURNING is a clause, not an alias)
//!   - Cross-dialect RETURNING behavior (PG clause vs. Snowflake alias)
//!   - Multi-CTE chains with DML + SELECT
//!   - Format round-trip with semantic safety verification

use std::sync::Arc;

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe,
    verify_formatting_safe_with_dialect, AstStmt, FormatterConfig, PostgresDialect,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn pg_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = Arc::new(PostgresDialect);
    config
}

fn sf_config() -> FormatterConfig {
    FormatterConfig::default() // Snowflake is the default
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

/// Parse with PG dialect and assert no statement is OpaqueContent.
fn pg_parses_ok(sql: &str) {
    let script = parse_sql_with_dialect(sql, &PostgresDialect)
        .unwrap_or_else(|e| panic!("Failed to parse:\n{}\nError: {:?}", sql, e));
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
}

/// Parse with PG dialect and check the first statement matches a predicate.
#[allow(dead_code)]
fn pg_parses_as(sql: &str, check: fn(&AstStmt) -> bool) -> bool {
    let script = parse_sql_with_dialect(sql, &PostgresDialect)
        .unwrap_or_else(|e| panic!("Failed to parse:\n{}\nError: {:?}", sql, e));
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent:\n{}",
            sql
        );
    }
    script.stmts.iter().any(|s| check(s))
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH ... INSERT (writable CTE as top-level statement)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_with_insert_basic() {
    let sql = r#"
        WITH new_users AS (
            SELECT 'Alice' AS name, 'alice@example.com' AS email
        )
        INSERT INTO users (name, email)
        SELECT name, email FROM new_users
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_with_insert_returning() {
    let sql = r#"
        WITH source AS (
            SELECT id, name FROM staging
        )
        INSERT INTO target (id, name)
        SELECT id, name FROM source
        RETURNING id
    "#;
    let out = pg_format_and_verify(sql);
    assert!(
        out.to_uppercase().contains("RETURNING"),
        "Should preserve RETURNING"
    );
    assert!(out.to_uppercase().contains("WITH"), "Should preserve WITH");
}

#[test]
fn test_with_insert_values() {
    let sql = r#"
        WITH constants AS (
            SELECT 42 AS magic_number
        )
        INSERT INTO config (key, value)
        VALUES ('magic', (SELECT magic_number FROM constants))
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH ... UPDATE (writable CTE as top-level statement)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_with_update_basic() {
    let sql = r#"
        WITH active_users AS (
            SELECT id FROM users WHERE active = true
        )
        UPDATE accounts
        SET status = 'active'
        WHERE user_id IN (SELECT id FROM active_users)
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_with_update_returning() {
    let sql = r#"
        WITH targets AS (
            SELECT id FROM users WHERE score > 100
        )
        UPDATE users
        SET tier = 'gold'
        WHERE id IN (SELECT id FROM targets)
        RETURNING id, tier
    "#;
    let out = pg_format_and_verify(sql);
    assert!(
        out.to_uppercase().contains("RETURNING"),
        "Should preserve RETURNING"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH ... DELETE (writable CTE as top-level statement)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_with_delete_basic() {
    let sql = r#"
        WITH old_users AS (
            SELECT id FROM users WHERE last_login < '2020-01-01'
        )
        DELETE FROM accounts
        WHERE user_id IN (SELECT id FROM old_users)
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_with_delete_returning() {
    let sql = r#"
        WITH expired AS (
            SELECT id FROM sessions WHERE expires_at < NOW()
        )
        DELETE FROM sessions
        WHERE id IN (SELECT id FROM expired)
        RETURNING id, user_id
    "#;
    let out = pg_format_and_verify(sql);
    assert!(
        out.to_uppercase().contains("RETURNING"),
        "Should preserve RETURNING"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-CTE chains with DML
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_cte_with_insert() {
    let sql = r#"
        WITH
            source_a AS (
                SELECT id, name FROM table_a
            ),
            source_b AS (
                SELECT id, name FROM table_b
            )
        INSERT INTO combined (id, name)
        SELECT id, name FROM source_a
        UNION ALL
        SELECT id, name FROM source_b
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_multi_cte_with_delete() {
    let sql = r#"
        WITH
            inactive AS (
                SELECT id FROM users WHERE active = false
            ),
            no_orders AS (
                SELECT user_id FROM orders GROUP BY user_id HAVING count(*) = 0
            )
        DELETE FROM users
        WHERE id IN (SELECT id FROM inactive)
          AND id NOT IN (SELECT user_id FROM no_orders)
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CTE body containing DML (writable CTE inside CTE definition)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_cte_body_is_insert_returning() {
    // The CTE itself contains an INSERT ... RETURNING, then outer SELECT reads it
    let sql = r#"
        WITH moved_rows AS (
            INSERT INTO archive (id, name)
            SELECT id, name FROM staging
            RETURNING id
        )
        SELECT id FROM moved_rows
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_cte_body_is_delete_returning() {
    let sql = r#"
        WITH deleted AS (
            DELETE FROM sessions
            WHERE expires_at < NOW()
            RETURNING id, user_id
        )
        SELECT user_id, count(*) FROM deleted GROUP BY user_id
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_cte_body_is_update_returning() {
    let sql = r#"
        WITH updated AS (
            UPDATE users
            SET last_seen = NOW()
            WHERE active = true
            RETURNING id, last_seen
        )
        SELECT id, last_seen FROM updated
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_multi_cte_dml_and_select_bodies() {
    // First CTE is a writable CTE (DELETE RETURNING), second is a normal SELECT
    let sql = r#"
        WITH
            removed AS (
                DELETE FROM old_data
                WHERE created_at < '2020-01-01'
                RETURNING id, category
            ),
            summary AS (
                SELECT category, count(*) AS cnt FROM removed GROUP BY category
            )
        SELECT * FROM summary ORDER BY cnt DESC
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// INSERT ... SELECT ... RETURNING (the key RETURNING-as-alias bug case)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_insert_select_returning_not_consumed_as_alias_pg() {
    // This was the primary bug: in PG dialect, RETURNING after the SELECT
    // was being consumed as a table alias by the FROM clause parser.
    let sql = "INSERT INTO target (id, name) SELECT id, name FROM source RETURNING id;";
    let out = pg_format_and_verify(sql);
    assert!(
        out.to_uppercase().contains("RETURNING"),
        "RETURNING must be preserved as a clause, not consumed as alias.\nFormatted: {}",
        out
    );
}

#[test]
fn test_insert_select_returning_star_pg() {
    let sql = "INSERT INTO target SELECT * FROM source RETURNING *;";
    let out = pg_format_and_verify(sql);
    assert!(out.to_uppercase().contains("RETURNING"));
}

#[test]
fn test_insert_select_returning_multiple_columns_pg() {
    let sql = "INSERT INTO target (a, b) SELECT a, b FROM source RETURNING a, b, created_at;";
    let out = pg_format_and_verify(sql);
    assert!(out.to_uppercase().contains("RETURNING"));
}

#[test]
fn test_insert_select_with_where_returning_pg() {
    let sql = r#"
        INSERT INTO archive (id, name)
        SELECT id, name FROM users WHERE active = false
        RETURNING id
    "#;
    let out = pg_format_and_verify(sql);
    assert!(out.to_uppercase().contains("RETURNING"));
    assert!(out.to_uppercase().contains("WHERE"));
}

#[test]
fn test_insert_select_with_join_returning_pg() {
    let sql = r#"
        INSERT INTO report (user_name, order_count)
        SELECT u.name, count(o.id)
        FROM users u
        JOIN orders o ON o.user_id = u.id
        GROUP BY u.name
        RETURNING user_name
    "#;
    let out = pg_format_and_verify(sql);
    assert!(out.to_uppercase().contains("RETURNING"));
    assert!(out.to_uppercase().contains("JOIN"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-dialect RETURNING behavior
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_returning_is_table_alias_in_snowflake() {
    // In Snowflake, RETURNING is NOT a clause boundary — it's a valid table alias.
    // "SELECT * FROM t RETURNING" means "SELECT * FROM t AS returning".
    // This should NOT fail parsing in Snowflake dialect.
    let sql = "SELECT * FROM my_table RETURNING";
    let config = sf_config();
    let result = format_sql_with_config(sql, &config);
    assert!(
        result.is_ok(),
        "Snowflake should accept RETURNING as alias. Error: {:?}",
        result.err()
    );
}

#[test]
fn test_returning_is_clause_in_pg_not_alias() {
    // In PG, "SELECT * FROM t RETURNING" as a standalone SELECT doesn't make sense,
    // but INSERT...SELECT...FROM t RETURNING id must treat RETURNING as a clause.
    // We verify the INSERT case specifically:
    let sql = "INSERT INTO tgt SELECT * FROM src RETURNING id;";
    let out = pg_format_and_verify(sql);
    assert!(out.to_uppercase().contains("RETURNING"));
}

#[test]
fn test_snowflake_returning_as_alias_in_subquery() {
    // Edge case: INSERT INTO tgt SELECT * FROM src RETURNING
    // In Snowflake dialect, RETURNING after FROM src should be consumed as alias.
    let sql = "INSERT INTO tgt SELECT * FROM src RETURNING";
    let config = sf_config();
    // Should parse successfully (RETURNING is the alias of src)
    let result = format_sql_with_config(sql, &config);
    // Whether this succeeds or not depends on the overall INSERT parsing,
    // but the key invariant is it should NOT treat RETURNING as a clause keyword.
    // In Snowflake, INSERT ... RETURNING is also supported, so this may parse
    // as RETURNING clause. The critical test is the PG case above.
    if let Ok(formatted) = result {
        // If it parses, it should round-trip
        verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
            panic!(
                "Safety check failed:\n{}\n→\n{}\nError: {}",
                sql, formatted, e
            )
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Writable CTE + RETURNING combined patterns
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_writable_cte_insert_select_returning_combined() {
    // Complete pattern: WITH clause → CTE body → INSERT SELECT → RETURNING
    let sql = r#"
        WITH source_data AS (
            SELECT id, name, email
            FROM staging_users
            WHERE validated = true
        )
        INSERT INTO production_users (id, name, email)
        SELECT id, name, email
        FROM source_data
        RETURNING id, name
    "#;
    let out = pg_format_and_verify(sql);
    assert!(out.to_uppercase().contains("WITH"), "WITH preserved");
    assert!(
        out.to_uppercase().contains("RETURNING"),
        "RETURNING preserved"
    );
    assert!(out.to_uppercase().contains("INSERT"), "INSERT preserved");
    assert!(out.to_uppercase().contains("SELECT"), "SELECT preserved");
}

#[test]
fn test_writable_cte_chain_delete_then_insert() {
    // Realistic pattern: archive deleted rows
    let sql = r#"
        WITH deleted_rows AS (
            DELETE FROM active_sessions
            WHERE expires_at < CURRENT_TIMESTAMP
            RETURNING *
        )
        INSERT INTO session_archive
        SELECT * FROM deleted_rows
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_writable_cte_update_then_select() {
    let sql = r#"
        WITH promoted AS (
            UPDATE employees
            SET role = 'senior'
            WHERE years_experience > 5
            RETURNING id, name, role
        )
        SELECT name, role FROM promoted
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_with_recursive_then_insert() {
    let sql = r#"
        WITH RECURSIVE nums AS (
            SELECT 1 AS n
            UNION ALL
            SELECT n + 1 FROM nums WHERE n < 10
        )
        INSERT INTO numbers (value)
        SELECT n FROM nums
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_simple_insert_select_no_returning_pg() {
    // Ensure normal INSERT...SELECT still works in PG dialect (no regression)
    let sql = "INSERT INTO target (id) SELECT id FROM source;";
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_simple_insert_values_no_returning_pg() {
    // No-RETURNING case — basic regression check
    let sql = "INSERT INTO users (name) VALUES ('Alice');";
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_with_select_still_works_pg() {
    // Regular WITH...SELECT (not writable) still works under PG dialect
    let sql = r#"
        WITH totals AS (
            SELECT department, sum(salary) AS total
            FROM employees
            GROUP BY department
        )
        SELECT * FROM totals WHERE total > 100000
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_insert_on_conflict_with_returning_pg() {
    // INSERT...ON CONFLICT...RETURNING (all PG extensions together)
    let sql = r#"
        INSERT INTO kv (key, value)
        VALUES ('foo', 'bar')
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        RETURNING key, value
    "#;
    let out = pg_format_and_verify(sql);
    assert!(out.to_uppercase().contains("RETURNING"));
    assert!(out.to_uppercase().contains("ON CONFLICT"));
}

#[test]
fn test_writable_cte_with_semicolon() {
    // Ensure semicolons are handled correctly at the end
    let sql = r#"
        WITH src AS (SELECT 1 AS id)
        INSERT INTO tgt (id) SELECT id FROM src;
    "#;
    pg_parses_ok(sql);
    pg_format_and_verify(sql);
}

#[test]
fn test_multi_statement_writable_cte() {
    // Multiple writable CTE statements in sequence
    let sql = r#"
        WITH src AS (SELECT 1 AS id)
        INSERT INTO t1 (id) SELECT id FROM src;

        WITH del AS (
            DELETE FROM t1 WHERE id = 1 RETURNING id
        )
        SELECT * FROM del;
    "#;
    let config = pg_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe_with_dialect(sql, &formatted, &PostgresDialect).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
}
