// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL utility statements:
//!   CREATE INDEX, COMMENT ON, DO $$...$$, VACUUM, ANALYZE,
//!   CREATE TYPE, ALTER TYPE, CREATE EXTENSION
//!
//! Each construct is tested for:
//!   1. Correct AST variant (not OpaqueContent)
//!   2. Format round-trip with semantic safety verification
//!   3. Multiple syntax variants

use lexega_syntax::{
    format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt, FormatterConfig,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
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
    let script = parse_sql(sql).expect("should parse");
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
// CREATE INDEX
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_index_basic() {
    let sql = "CREATE INDEX idx_users_name ON users (name)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_unique_index() {
    let sql = "CREATE UNIQUE INDEX idx_email ON users (email)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_index_if_not_exists() {
    let sql = "CREATE INDEX IF NOT EXISTS idx_id ON orders (id)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_index_concurrently() {
    let sql = "CREATE INDEX CONCURRENTLY idx_ts ON events (created_at)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_index_using_method() {
    let sql = "CREATE INDEX idx_gin ON docs USING gin (content)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_index_multi_column() {
    let sql = "CREATE INDEX idx_multi ON users (last_name, first_name)";
    format_and_verify(sql);
}

#[test]
fn test_create_index_with_include() {
    let sql = "CREATE INDEX idx_inc ON users (id) INCLUDE (name, email)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_index_with_where() {
    let sql = "CREATE INDEX idx_active ON users (id) WHERE active = true";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_unique_index_concurrently_if_not_exists() {
    let sql = "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_uniq ON items (sku)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_index_schema_qualified() {
    let sql = "CREATE INDEX idx_sq ON myschema.users (id)";
    format_and_verify(sql);
}

#[test]
fn test_create_index_expression() {
    let sql = "CREATE INDEX idx_lower ON users (lower(email))";
    format_and_verify(sql);
}

#[test]
fn test_create_index_full_featured() {
    let sql = "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_full ON public.orders USING btree (customer_id, created_at DESC) INCLUDE (total) WHERE status = 'active'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// COMMENT ON
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_comment_on_table() {
    let sql = "COMMENT ON TABLE users IS 'Main user table'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CommentOn(_))));
    format_and_verify(sql);
}

#[test]
fn test_comment_on_column() {
    let sql = "COMMENT ON COLUMN users.email IS 'Primary email address'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CommentOn(_))));
    format_and_verify(sql);
}

#[test]
fn test_comment_on_index() {
    let sql = "COMMENT ON INDEX idx_users_name IS 'Name lookup index'";
    format_and_verify(sql);
}

#[test]
fn test_comment_on_function() {
    let sql = "COMMENT ON FUNCTION my_func(integer) IS 'Helper function'";
    format_and_verify(sql);
}

#[test]
fn test_comment_on_schema() {
    let sql = "COMMENT ON SCHEMA public IS 'Default schema'";
    format_and_verify(sql);
}

#[test]
fn test_comment_on_null() {
    let sql = "COMMENT ON TABLE users IS NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CommentOn(_))));
    format_and_verify(sql);
}

#[test]
fn test_comment_on_schema_qualified() {
    let sql = "COMMENT ON TABLE public.users IS 'User table in public'";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DO $$ ... $$ (anonymous blocks)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_do_block_basic() {
    let sql = "DO $$ BEGIN RAISE NOTICE 'hello'; END $$";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DoBlock(_))));
    format_and_verify(sql);
}

#[test]
fn test_do_block_with_language() {
    let sql = "DO LANGUAGE plpgsql $$ BEGIN NULL; END $$";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DoBlock(_))));
    format_and_verify(sql);
}

#[test]
fn test_do_block_language_after_body() {
    let sql = "DO $$ BEGIN NULL; END $$ LANGUAGE plpgsql";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DoBlock(_))));
    format_and_verify(sql);
}

#[test]
fn test_do_block_tagged_dollar_quote() {
    let sql = "DO $body$ BEGIN RAISE NOTICE 'test'; END $body$";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DoBlock(_))));
    format_and_verify(sql);
}

#[test]
fn test_do_block_multiline() {
    let sql = "DO $$\nDECLARE\n  v_count integer;\nBEGIN\n  SELECT count(*) INTO v_count FROM users;\n  RAISE NOTICE 'Count: %', v_count;\nEND\n$$";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DoBlock(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// VACUUM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_vacuum_basic() {
    let sql = "VACUUM";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Vacuum(_))));
    format_and_verify(sql);
}

#[test]
fn test_vacuum_table() {
    let sql = "VACUUM users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Vacuum(_))));
    format_and_verify(sql);
}

#[test]
fn test_vacuum_full() {
    let sql = "VACUUM FULL users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Vacuum(_))));
    format_and_verify(sql);
}

#[test]
fn test_vacuum_verbose() {
    let sql = "VACUUM VERBOSE users";
    format_and_verify(sql);
}

#[test]
fn test_vacuum_analyze() {
    let sql = "VACUUM ANALYZE users";
    format_and_verify(sql);
}

#[test]
fn test_vacuum_full_verbose_analyze() {
    let sql = "VACUUM FULL VERBOSE ANALYZE users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Vacuum(_))));
    format_and_verify(sql);
}

#[test]
fn test_vacuum_with_columns() {
    let sql = "VACUUM ANALYZE users (name, email)";
    format_and_verify(sql);
}

#[test]
fn test_vacuum_freeze() {
    let sql = "VACUUM FREEZE users";
    format_and_verify(sql);
}

#[test]
fn test_vacuum_parenthesized_options() {
    let sql = "VACUUM (VERBOSE, ANALYZE) users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Vacuum(_))));
    format_and_verify(sql);
}

#[test]
fn test_vacuum_schema_qualified() {
    let sql = "VACUUM public.users";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ANALYZE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_analyze_basic() {
    let sql = "ANALYZE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AnalyzeStmt(_))));
    format_and_verify(sql);
}

#[test]
fn test_analyze_table() {
    let sql = "ANALYZE users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AnalyzeStmt(_))));
    format_and_verify(sql);
}

#[test]
fn test_analyze_verbose() {
    let sql = "ANALYZE VERBOSE users";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AnalyzeStmt(_))));
    format_and_verify(sql);
}

#[test]
fn test_analyze_with_columns() {
    let sql = "ANALYZE users (name, email)";
    format_and_verify(sql);
}

#[test]
fn test_analyze_schema_qualified() {
    let sql = "ANALYZE public.orders";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TYPE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_type_enum() {
    let sql = "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateType(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_type_composite() {
    let sql = "CREATE TYPE address AS (street text, city text, zip varchar(10))";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateType(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_type_range() {
    let sql = "CREATE TYPE float_range AS RANGE (SUBTYPE = float8)";
    format_and_verify(sql);
}

#[test]
fn test_create_type_shell() {
    // Shell type — CREATE TYPE with no definition
    let sql = "CREATE TYPE box";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateType(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_type_schema_qualified() {
    let sql = "CREATE TYPE myschema.status AS ENUM ('active', 'inactive')";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER TYPE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_type_add_value() {
    let sql = "ALTER TYPE mood ADD VALUE 'anxious'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterType(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_type_add_value_before() {
    let sql = "ALTER TYPE mood ADD VALUE 'worried' BEFORE 'sad'";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_add_value_after() {
    let sql = "ALTER TYPE mood ADD VALUE 'content' AFTER 'ok'";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_add_value_if_not_exists() {
    let sql = "ALTER TYPE mood ADD VALUE IF NOT EXISTS 'happy'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterType(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_type_rename() {
    let sql = "ALTER TYPE mood RENAME TO feeling";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_rename_value() {
    let sql = "ALTER TYPE mood RENAME VALUE 'sad' TO 'melancholy'";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_set_schema() {
    let sql = "ALTER TYPE mood SET SCHEMA myschema";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_add_attribute() {
    let sql = "ALTER TYPE address ADD ATTRIBUTE country text";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE EXTENSION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_extension_basic() {
    let sql = "CREATE EXTENSION hstore";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateExtension(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_extension_if_not_exists() {
    let sql = "CREATE EXTENSION IF NOT EXISTS pgcrypto";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateExtension(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_extension_with_schema() {
    let sql = "CREATE EXTENSION hstore WITH SCHEMA public";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateExtension(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_extension_with_version() {
    let sql = "CREATE EXTENSION hstore VERSION '1.4'";
    format_and_verify(sql);
}

#[test]
fn test_create_extension_cascade() {
    let sql = "CREATE EXTENSION hstore CASCADE";
    format_and_verify(sql);
}

#[test]
fn test_create_extension_full() {
    let sql = "CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA public VERSION '3.1' CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateExtension(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_pg_utility_statements() {
    let sql = "\
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy');
CREATE INDEX idx_users_mood ON users (mood);
COMMENT ON TABLE users IS 'User accounts';
VACUUM ANALYZE users;
";
    format_and_verify(sql);
}

#[test]
fn test_pg_utility_mixed_with_dml() {
    let sql = "\
CREATE INDEX idx_id ON users (id);
SELECT * FROM users WHERE id = 1;
COMMENT ON TABLE users IS 'table';
";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Idempotency tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_index_idempotent() {
    let sql = "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_full ON public.orders USING btree (customer_id, created_at DESC) INCLUDE (total) WHERE status = 'active'";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_comment_on_idempotent() {
    let sql = "COMMENT ON TABLE public.users IS 'Main user table'";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_create_extension_idempotent() {
    let sql = "CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA public VERSION '3.1' CASCADE";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_vacuum_idempotent() {
    let sql = "VACUUM FULL VERBOSE ANALYZE users (name, email)";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_create_type_idempotent() {
    let sql = "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}

#[test]
fn test_do_block_idempotent() {
    let sql = "DO $$ BEGIN RAISE NOTICE 'hello'; END $$";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "Formatting should be idempotent");
}
