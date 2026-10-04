// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL PREPARE, EXECUTE, and DEALLOCATE statements.
//!
//! Each construct is tested for:
//!   1. Correct AST variant (not OpaqueContent)
//!   2. Format round-trip with semantic safety verification
//!   3. Multiple syntax variants
//!
//! Token gotchas verified via --debug-tokens:
//!   PREPARE → Identifier (NOT a Keyword!)
//!   EXECUTE → Keyword(Execute) (conflicts with Snowflake EXECUTE IMMEDIATE)
//!   DEALLOCATE → Identifier (NOT a Keyword!)
//!   AS → Keyword(As)
//!   ALL → Keyword(All)
//!   Type names (int, text, bool, numeric) → Identifier
//!   $1, $2 → Literal(Position)

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe, AstStmt,
    FormatterConfig, PostgresDialect,
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

fn parses_as(sql: &str, check: fn(&AstStmt) -> bool) -> bool {
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script.stmts.iter().any(|s| check(s))
}

// ═══════════════════════════════════════════════════════════════════════════
// PREPARE — basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_basic_select() {
    let sql = "PREPARE my_query AS SELECT * FROM users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_with_semicolon() {
    let sql = "PREPARE my_query AS SELECT * FROM users;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_select_with_where() {
    let sql = "PREPARE my_query AS SELECT id, name FROM users WHERE active = true";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// PREPARE — with parameter types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_with_single_param_type() {
    let sql = "PREPARE my_query (int) AS SELECT * FROM users WHERE id = $1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_with_multiple_param_types() {
    let sql = "PREPARE my_query (int, text) AS SELECT * FROM users WHERE id = $1 AND name = $2";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_with_many_param_types() {
    let sql = "PREPARE q (int, text, bool, numeric) AS SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3 AND d = $4";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_with_varchar_param_type() {
    let sql = "PREPARE q (varchar) AS SELECT * FROM t WHERE name = $1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// PREPARE — with INSERT body
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_insert() {
    let sql = "PREPARE ins_user (int, text) AS INSERT INTO users (id, name) VALUES ($1, $2)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_insert_single_column() {
    let sql = "PREPARE ins_item (text) AS INSERT INTO items (name) VALUES ($1)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// PREPARE — with UPDATE body
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_update() {
    let sql = "PREPARE upd_user (text, int) AS UPDATE users SET name = $1 WHERE id = $2";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// PREPARE — with DELETE body
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_delete() {
    let sql = "PREPARE del_user (int) AS DELETE FROM users WHERE id = $1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// PREPARE — case variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_lowercase() {
    let sql = "prepare my_query as select * from users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_mixed_case() {
    let sql = "Prepare My_Query (Int, Text) As Select * From Users Where id = $1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTE — basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_no_args() {
    let sql = "EXECUTE my_query";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

#[test]
fn test_execute_with_semicolon() {
    let sql = "EXECUTE my_query;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTE — with arguments
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_single_arg() {
    let sql = "EXECUTE my_query(1)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

#[test]
fn test_execute_multiple_args() {
    let sql = "EXECUTE my_query(1, 'hello')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

#[test]
fn test_execute_with_expression_args() {
    let sql = "EXECUTE my_query(42, 'test_user', true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTE — case variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_lowercase() {
    let sql = "execute my_query";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

#[test]
fn test_execute_lowercase_with_args() {
    let sql = "execute my_query(1, 'hello')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DEALLOCATE — name
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_deallocate_name() {
    let sql = "DEALLOCATE my_query";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

#[test]
fn test_deallocate_name_with_semicolon() {
    let sql = "DEALLOCATE my_query;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DEALLOCATE PREPARE — name
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_deallocate_prepare_name() {
    let sql = "DEALLOCATE PREPARE my_query";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

#[test]
fn test_deallocate_prepare_name_with_semicolon() {
    let sql = "DEALLOCATE PREPARE my_query;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DEALLOCATE ALL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_deallocate_all() {
    let sql = "DEALLOCATE ALL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

#[test]
fn test_deallocate_prepare_all() {
    let sql = "DEALLOCATE PREPARE ALL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DEALLOCATE — case variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_deallocate_lowercase() {
    let sql = "deallocate my_query";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

#[test]
fn test_deallocate_prepare_lowercase() {
    let sql = "deallocate prepare my_query";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

#[test]
fn test_deallocate_all_lowercase() {
    let sql = "deallocate all";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgDeallocate(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement scripts
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_execute_deallocate_sequence() {
    let sql = "\
PREPARE my_query (int) AS SELECT * FROM users WHERE id = $1;
EXECUTE my_query(42);
DEALLOCATE my_query;";
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse");
    assert_eq!(script.stmts.len(), 3, "Should parse 3 statements");
    assert!(matches!(&script.stmts[0], AstStmt::PgPrepare(_)));
    assert!(matches!(&script.stmts[1], AstStmt::PgExecute(_)));
    assert!(matches!(&script.stmts[2], AstStmt::PgDeallocate(_)));
    format_and_verify(sql);
}

#[test]
fn test_prepare_then_deallocate_all() {
    let sql = "\
PREPARE q1 AS SELECT 1;
PREPARE q2 AS SELECT 2;
DEALLOCATE ALL;";
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse");
    assert_eq!(script.stmts.len(), 3, "Should parse 3 statements");
    assert!(matches!(&script.stmts[0], AstStmt::PgPrepare(_)));
    assert!(matches!(&script.stmts[1], AstStmt::PgPrepare(_)));
    assert!(matches!(&script.stmts[2], AstStmt::PgDeallocate(_)));
    format_and_verify(sql);
}

#[test]
fn test_multiple_execute_statements() {
    let sql = "\
EXECUTE q1(1);
EXECUTE q2(2, 'x');
EXECUTE q3;";
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse");
    assert_eq!(script.stmts.len(), 3, "Should parse 3 statements");
    for s in &script.stmts {
        assert!(
            matches!(s, AstStmt::PgExecute(_)),
            "All should be PgExecute"
        );
    }
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// PREPARE — complex bodies
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_select_with_join() {
    let sql = "PREPARE user_orders (int) AS SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.id = $1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_select_with_subquery() {
    let sql = "PREPARE active_users AS SELECT * FROM users WHERE id IN (SELECT user_id FROM sessions WHERE active = true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

#[test]
fn test_prepare_select_with_cte() {
    let sql = "PREPARE report AS WITH totals AS (SELECT dept, SUM(salary) AS total FROM emp GROUP BY dept) SELECT * FROM totals";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgPrepare(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTE — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_with_null_arg() {
    let sql = "EXECUTE my_query(NULL)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

#[test]
fn test_execute_with_string_arg() {
    let sql = "EXECUTE my_query('hello world')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgExecute(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Mixed with other PG statements
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_prepare_after_create_table() {
    let sql = "\
CREATE TABLE test_tbl (id int, name text);
PREPARE ins (int, text) AS INSERT INTO test_tbl (id, name) VALUES ($1, $2);";
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse");
    assert_eq!(script.stmts.len(), 2);
    assert!(matches!(&script.stmts[1], AstStmt::PgPrepare(_)));
    format_and_verify(sql);
}
