// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL CREATE SEQUENCE, ALTER SEQUENCE, DROP SEQUENCE
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
// CREATE SEQUENCE — basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_sequence_basic() {
    let sql = "CREATE SEQUENCE my_seq";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_with_options() {
    let sql = "CREATE SEQUENCE my_seq INCREMENT BY 1 START WITH 100 MINVALUE 1 MAXVALUE 99999 CACHE 10 NO CYCLE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_schema_qualified() {
    let sql = "CREATE SEQUENCE public.my_seq START WITH 1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_if_not_exists() {
    let sql = "CREATE SEQUENCE IF NOT EXISTS my_seq INCREMENT 5";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_temp_sequence() {
    let sql = "CREATE TEMPORARY SEQUENCE temp_seq";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_temp_short_sequence() {
    let sql = "CREATE TEMP SEQUENCE temp_seq START 1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_unlogged_sequence() {
    let sql = "CREATE UNLOGGED SEQUENCE unlogged_seq CACHE 20";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_as_type() {
    let sql = "CREATE SEQUENCE typed_seq AS bigint";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_as_smallint() {
    let sql = "CREATE SEQUENCE small_seq AS smallint MINVALUE 1 MAXVALUE 32767";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_cycle() {
    let sql = "CREATE SEQUENCE cycling_seq INCREMENT 1 MINVALUE 1 MAXVALUE 100 CYCLE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_no_minvalue_no_maxvalue() {
    let sql = "CREATE SEQUENCE nobound_seq NO MINVALUE NO MAXVALUE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_owned_by() {
    let sql = "CREATE SEQUENCE my_seq OWNED BY my_table.id";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_owned_by_none() {
    let sql = "CREATE SEQUENCE my_seq OWNED BY NONE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_negative_start() {
    let sql = "CREATE SEQUENCE neg_seq START WITH -100 INCREMENT BY -1 MINVALUE -1000 MAXVALUE -1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_sequence_all_options() {
    let sql = "CREATE TEMPORARY SEQUENCE IF NOT EXISTS public.full_seq AS bigint INCREMENT BY 2 MINVALUE 0 MAXVALUE 10000 START WITH 0 CACHE 50 CYCLE OWNED BY orders.id";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateSequence(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER SEQUENCE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_sequence_basic() {
    let sql = "ALTER SEQUENCE my_seq RESTART";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_restart_with() {
    let sql = "ALTER SEQUENCE my_seq RESTART WITH 100";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_increment() {
    let sql = "ALTER SEQUENCE my_seq INCREMENT BY 5";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_if_exists() {
    let sql = "ALTER SEQUENCE IF EXISTS my_seq RESTART WITH 1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_schema_qualified() {
    let sql = "ALTER SEQUENCE public.my_seq SET SCHEMA private";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_owner() {
    let sql = "ALTER SEQUENCE my_seq OWNER TO new_owner";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_rename() {
    let sql = "ALTER SEQUENCE my_seq RENAME TO new_seq";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_multiple_options() {
    let sql = "ALTER SEQUENCE my_seq INCREMENT BY 10 MINVALUE 1 MAXVALUE 99999 CACHE 20 NO CYCLE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_owned_by() {
    let sql = "ALTER SEQUENCE my_seq OWNED BY users.id";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_set_logged() {
    let sql = "ALTER SEQUENCE my_seq SET LOGGED";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_sequence_set_unlogged() {
    let sql = "ALTER SEQUENCE my_seq SET UNLOGGED";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterSequence(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP SEQUENCE (generic DROP handler — verify it works)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_sequence_basic() {
    let sql = "DROP SEQUENCE my_seq";
    format_and_verify(sql);
}

#[test]
fn test_drop_sequence_if_exists() {
    let sql = "DROP SEQUENCE IF EXISTS my_seq";
    format_and_verify(sql);
}

#[test]
fn test_drop_sequence_cascade() {
    let sql = "DROP SEQUENCE my_seq CASCADE";
    format_and_verify(sql);
}

#[test]
fn test_drop_sequence_restrict() {
    let sql = "DROP SEQUENCE my_seq RESTRICT";
    format_and_verify(sql);
}

#[test]
fn test_drop_sequence_multiple() {
    let sql = "DROP SEQUENCE seq1, seq2, seq3";
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_sequence_multi_statement() {
    let sql = r#"
CREATE SEQUENCE order_seq INCREMENT BY 1 START WITH 1000;
ALTER SEQUENCE order_seq RESTART WITH 5000;
DROP SEQUENCE IF EXISTS old_seq CASCADE;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("CREATE SEQUENCE"));
    assert!(formatted.contains("ALTER SEQUENCE"));
    assert!(formatted.contains("DROP SEQUENCE"));
}

#[test]
fn test_create_and_alter_sequence_round_trip() {
    let sql = r#"
CREATE TEMPORARY SEQUENCE IF NOT EXISTS app.counter_seq AS integer INCREMENT BY 1 MINVALUE 1 NO MAXVALUE START WITH 1 CACHE 10 NO CYCLE;
ALTER SEQUENCE IF EXISTS app.counter_seq RESTART WITH 500 INCREMENT BY 2 MAXVALUE 100000;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("TEMPORARY"));
    assert!(formatted.contains("IF NOT EXISTS"));
    assert!(formatted.contains("IF EXISTS"));
}
