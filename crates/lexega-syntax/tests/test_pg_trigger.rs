// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL CREATE TRIGGER, ALTER TRIGGER, DROP TRIGGER
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
// CREATE TRIGGER — BEFORE / AFTER / INSTEAD OF
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_before_insert() {
    let sql = "CREATE TRIGGER check_insert BEFORE INSERT ON accounts FOR EACH ROW EXECUTE FUNCTION check_account_update()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_after_update() {
    let sql = "CREATE TRIGGER audit_update AFTER UPDATE ON employees FOR EACH ROW EXECUTE PROCEDURE audit_func()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_after_delete() {
    let sql = "CREATE TRIGGER log_delete AFTER DELETE ON orders FOR EACH ROW EXECUTE FUNCTION log_deletion()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_instead_of() {
    let sql = "CREATE TRIGGER view_insert INSTEAD OF INSERT ON my_view FOR EACH ROW EXECUTE FUNCTION insert_into_base()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TRIGGER — multiple events with OR
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_insert_or_update() {
    let sql = "CREATE TRIGGER multi_event BEFORE INSERT OR UPDATE ON items FOR EACH ROW EXECUTE FUNCTION validate_item()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_three_events() {
    let sql = "CREATE TRIGGER all_dml AFTER INSERT OR UPDATE OR DELETE ON products FOR EACH ROW EXECUTE FUNCTION sync_products()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_truncate() {
    let sql = "CREATE TRIGGER on_truncate BEFORE TRUNCATE ON big_table FOR EACH STATEMENT EXECUTE FUNCTION notify_truncate()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TRIGGER — UPDATE OF columns
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_update_of_single_column() {
    let sql = "CREATE TRIGGER salary_check BEFORE UPDATE OF salary ON employees FOR EACH ROW EXECUTE FUNCTION check_salary()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_update_of_multiple_columns() {
    let sql = "CREATE TRIGGER multi_col BEFORE UPDATE OF price, quantity ON inventory FOR EACH ROW EXECUTE FUNCTION validate_update()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TRIGGER — FOR EACH ROW vs FOR EACH STATEMENT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_for_each_statement() {
    let sql = "CREATE TRIGGER stmt_trigger AFTER INSERT ON logs FOR EACH STATEMENT EXECUTE FUNCTION count_inserts()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_for_row_shorthand() {
    // FOR ROW without EACH is valid PG syntax
    let sql = "CREATE TRIGGER short_trigger BEFORE INSERT ON t FOR ROW EXECUTE FUNCTION f()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_for_statement_shorthand() {
    // FOR STATEMENT without EACH is valid PG syntax
    let sql = "CREATE TRIGGER short_stmt AFTER INSERT ON t FOR STATEMENT EXECUTE FUNCTION f()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TRIGGER — WHEN condition
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_with_when() {
    let sql = "CREATE TRIGGER check_balance BEFORE UPDATE ON accounts FOR EACH ROW WHEN (OLD.balance IS DISTINCT FROM NEW.balance) EXECUTE FUNCTION check_balance()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_with_when_simple() {
    let sql = "CREATE TRIGGER guard BEFORE INSERT ON t FOR EACH ROW WHEN (NEW.active = true) EXECUTE FUNCTION guard_func()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TRIGGER — REFERENCING (transition tables)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_referencing_new_table() {
    let sql = "CREATE TRIGGER with_ref AFTER INSERT ON orders REFERENCING NEW TABLE AS new_orders FOR EACH STATEMENT EXECUTE FUNCTION process_new_orders()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_trigger_referencing_old_and_new() {
    let sql = "CREATE TRIGGER with_both AFTER UPDATE ON data REFERENCING OLD TABLE AS old_data NEW TABLE AS new_data FOR EACH STATEMENT EXECUTE FUNCTION diff_data()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE OR REPLACE TRIGGER
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_or_replace_trigger() {
    let sql = "CREATE OR REPLACE TRIGGER my_trigger BEFORE INSERT ON my_table FOR EACH ROW EXECUTE FUNCTION my_func()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE CONSTRAINT TRIGGER
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_constraint_trigger_basic() {
    let sql = "CREATE CONSTRAINT TRIGGER fk_check AFTER INSERT ON child_table FOR EACH ROW EXECUTE FUNCTION check_fk()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_constraint_trigger_deferrable() {
    let sql = "CREATE CONSTRAINT TRIGGER deferred_check AFTER INSERT ON child_table DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_fk()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_constraint_trigger_initially_immediate() {
    let sql = "CREATE CONSTRAINT TRIGGER imm_check AFTER UPDATE ON child_table DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION validate()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_constraint_trigger_not_deferrable() {
    let sql = "CREATE CONSTRAINT TRIGGER strict_check AFTER DELETE ON parent_table NOT DEFERRABLE FOR EACH ROW EXECUTE FUNCTION strict_validate()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_constraint_trigger_from_table() {
    let sql = "CREATE CONSTRAINT TRIGGER ref_check AFTER INSERT ON child_table FROM parent_table DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_ref()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TRIGGER — function with arguments
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_func_with_args() {
    let sql = "CREATE TRIGGER with_args BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION my_func('arg1', 'arg2')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE TRIGGER — schema-qualified names
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_schema_qualified_table() {
    let sql = "CREATE TRIGGER qualified_trig BEFORE INSERT ON myschema.mytable FOR EACH ROW EXECUTE FUNCTION myschema.myfunc()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER TRIGGER — RENAME TO
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_trigger_rename() {
    let sql = "ALTER TRIGGER old_name ON my_table RENAME TO new_name";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_trigger_rename_schema_qualified() {
    let sql = "ALTER TRIGGER trig_name ON public.my_table RENAME TO better_name";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER TRIGGER — DEPENDS ON EXTENSION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_trigger_depends_on_extension() {
    let sql = "ALTER TRIGGER my_trig ON my_table DEPENDS ON EXTENSION pg_trgm";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_trigger_no_depends_on_extension() {
    let sql = "ALTER TRIGGER my_trig ON my_table NO DEPENDS ON EXTENSION pg_trgm";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP TRIGGER — basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_trigger_basic() {
    let sql = "DROP TRIGGER my_trigger ON my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_trigger_if_exists() {
    let sql = "DROP TRIGGER IF EXISTS my_trigger ON my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_trigger_cascade() {
    let sql = "DROP TRIGGER my_trigger ON my_table CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_trigger_restrict() {
    let sql = "DROP TRIGGER my_trigger ON my_table RESTRICT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_trigger_if_exists_cascade() {
    let sql = "DROP TRIGGER IF EXISTS old_trigger ON public.my_table CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgTrigger(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement scripts
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_trigger_statements() {
    let sql = "\
CREATE TRIGGER audit_insert BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION audit_func();
CREATE TRIGGER audit_update AFTER UPDATE ON users FOR EACH ROW EXECUTE FUNCTION audit_func();
DROP TRIGGER IF EXISTS old_trigger ON users CASCADE;
";
    let script = parse_sql(sql).expect("should parse");
    let trigger_count = script
        .stmts
        .iter()
        .filter(|s| matches!(s, AstStmt::CreatePgTrigger(_) | AstStmt::DropPgTrigger(_)))
        .count();
    assert_eq!(trigger_count, 3, "Should parse all 3 trigger statements");
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Complex / combined syntax
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_trigger_all_clauses_combined() {
    // Constraint trigger with FROM, DEFERRABLE, FOR EACH ROW, WHEN, and EXECUTE
    let sql = "CREATE CONSTRAINT TRIGGER full_check AFTER INSERT ON child FROM parent DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'active') EXECUTE FUNCTION full_check_func()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_or_replace_constraint_trigger() {
    let sql = "CREATE OR REPLACE CONSTRAINT TRIGGER fancy AFTER UPDATE ON t DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION fancy_func()";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgTrigger(_))));
    format_and_verify(sql);
}
