// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL CREATE POLICY, ALTER POLICY, DROP POLICY (Row-Level Security)
//!
//! Each construct is tested for:
//!   1. Correct AST variant (not OpaqueContent)
//!   2. Format round-trip with semantic safety verification
//!   3. Multiple syntax variants
//!
//! Expression parsing (USING, WITH CHECK) is verified by confirming the AST
//! contains the correct variants rather than OpaqueContent fallbacks.

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
// CREATE POLICY — minimal / basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_minimal() {
    let sql = "CREATE POLICY p1 ON my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_schema_qualified_table() {
    let sql = "CREATE POLICY p1 ON myschema.my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — AS PERMISSIVE / RESTRICTIVE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_as_permissive() {
    let sql = "CREATE POLICY p1 ON t1 AS PERMISSIVE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_as_restrictive() {
    let sql = "CREATE POLICY p1 ON t1 AS RESTRICTIVE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — FOR command
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_for_all() {
    let sql = "CREATE POLICY p1 ON t1 FOR ALL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_for_select() {
    let sql = "CREATE POLICY p1 ON t1 FOR SELECT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_for_insert() {
    let sql = "CREATE POLICY p1 ON t1 FOR INSERT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_for_update() {
    let sql = "CREATE POLICY p1 ON t1 FOR UPDATE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_for_delete() {
    let sql = "CREATE POLICY p1 ON t1 FOR DELETE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — TO roles
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_to_public() {
    let sql = "CREATE POLICY p1 ON t1 TO PUBLIC";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_to_role() {
    let sql = "CREATE POLICY p1 ON t1 TO admin_role";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_to_current_user() {
    let sql = "CREATE POLICY p1 ON t1 TO CURRENT_USER";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_to_current_role() {
    let sql = "CREATE POLICY p1 ON t1 TO CURRENT_ROLE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_to_session_user() {
    let sql = "CREATE POLICY p1 ON t1 TO SESSION_USER";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_to_multiple_roles() {
    let sql = "CREATE POLICY p1 ON t1 TO admin, manager, PUBLIC";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — USING expression
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_using_simple() {
    let sql = "CREATE POLICY p1 ON t1 USING (user_id = current_user)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_using_true() {
    let sql = "CREATE POLICY p1 ON t1 USING (true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_using_complex() {
    let sql = "CREATE POLICY p1 ON t1 USING (department IN ('sales', 'engineering'))";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — WITH CHECK expression
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_with_check_simple() {
    let sql = "CREATE POLICY p1 ON t1 WITH CHECK (user_id = current_user)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_with_check_true() {
    let sql = "CREATE POLICY p1 ON t1 WITH CHECK (true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — USING + WITH CHECK
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_using_and_with_check() {
    let sql = "CREATE POLICY p1 ON t1 USING (visible = true) WITH CHECK (editable = true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — full syntax (all clauses)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_full_all_clauses() {
    let sql = "CREATE POLICY account_managers ON accounts AS PERMISSIVE FOR SELECT TO managers, admin USING (manager_id = current_user)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_full_insert_with_check() {
    let sql = "CREATE POLICY insert_policy ON orders FOR INSERT TO sales_team WITH CHECK (region = current_setting('app.region'))";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_full_update_both_exprs() {
    let sql = "CREATE POLICY update_own ON documents AS RESTRICTIVE FOR UPDATE TO authenticated_users USING (owner = current_user) WITH CHECK (owner = current_user)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_for_all_to_public_using() {
    let sql = "CREATE POLICY public_read ON articles FOR ALL TO PUBLIC USING (published = true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE POLICY — subquery in expressions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_using_exists_subquery() {
    let sql = "CREATE POLICY p1 ON t1 USING (EXISTS (SELECT 1 FROM allowed_users WHERE allowed_users.id = t1.user_id))";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER POLICY — RENAME TO
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_policy_rename() {
    let sql = "ALTER POLICY p1 ON t1 RENAME TO p2";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_policy_rename_schema_qualified() {
    let sql = "ALTER POLICY old_pol ON myschema.accounts RENAME TO new_pol";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER POLICY — TO roles
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_policy_to_single_role() {
    let sql = "ALTER POLICY p1 ON t1 TO new_role";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_policy_to_multiple_roles() {
    let sql = "ALTER POLICY p1 ON t1 TO role_a, role_b, PUBLIC";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER POLICY — USING expression
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_policy_using() {
    let sql = "ALTER POLICY p1 ON t1 USING (active = true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER POLICY — WITH CHECK expression
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_policy_with_check() {
    let sql = "ALTER POLICY p1 ON t1 WITH CHECK (status <> 'archived')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER POLICY — combined clauses
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_policy_to_and_using() {
    let sql = "ALTER POLICY p1 ON t1 TO admin USING (role = 'admin')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_policy_using_and_with_check() {
    let sql = "ALTER POLICY p1 ON t1 USING (active = true) WITH CHECK (active = true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_policy_all_modify_clauses() {
    let sql = "ALTER POLICY p1 ON t1 TO admin, manager USING (dept_id = current_setting('app.dept')::int) WITH CHECK (dept_id = current_setting('app.dept')::int)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP POLICY — basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_policy_basic() {
    let sql = "DROP POLICY p1 ON t1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_policy_schema_qualified() {
    let sql = "DROP POLICY p1 ON myschema.accounts";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP POLICY — IF EXISTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_policy_if_exists() {
    let sql = "DROP POLICY IF EXISTS p1 ON t1";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP POLICY — CASCADE / RESTRICT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_policy_cascade() {
    let sql = "DROP POLICY p1 ON t1 CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_policy_restrict() {
    let sql = "DROP POLICY p1 ON t1 RESTRICT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_policy_if_exists_cascade() {
    let sql = "DROP POLICY IF EXISTS p1 ON t1 CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgPolicy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement / semicolon handling
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_with_semicolon() {
    let sql = "CREATE POLICY p1 ON t1 USING (true);";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_multi_policy_statements() {
    let sql = "\
CREATE POLICY read_own ON documents FOR SELECT TO PUBLIC USING (owner = current_user);
ALTER POLICY read_own ON documents TO admin, PUBLIC;
DROP POLICY IF EXISTS old_policy ON documents CASCADE;";
    let script = parse_sql(sql).expect("should parse");
    assert_eq!(script.stmts.len(), 3, "should parse 3 statements");
    assert!(matches!(&script.stmts[0], AstStmt::CreatePgPolicy(_)));
    assert!(matches!(&script.stmts[1], AstStmt::AlterPgPolicy(_)));
    assert!(matches!(&script.stmts[2], AstStmt::DropPgPolicy(_)));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Idempotency — format(format(x)) == format(x)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_idempotent() {
    let sql = "CREATE POLICY p1 ON t1 AS PERMISSIVE FOR SELECT TO admin USING (id > 0) WITH CHECK (id > 0)";
    let once = format_and_verify(sql);
    let twice = format_and_verify(&once);
    assert_eq!(once, twice, "formatting should be idempotent");
}

#[test]
fn test_alter_policy_idempotent() {
    let sql = "ALTER POLICY p1 ON t1 TO admin USING (active = true) WITH CHECK (active = true)";
    let once = format_and_verify(sql);
    let twice = format_and_verify(&once);
    assert_eq!(once, twice, "formatting should be idempotent");
}

#[test]
fn test_drop_policy_idempotent() {
    let sql = "DROP POLICY IF EXISTS p1 ON t1 CASCADE";
    let once = format_and_verify(sql);
    let twice = format_and_verify(&once);
    assert_eq!(once, twice, "formatting should be idempotent");
}

// ═══════════════════════════════════════════════════════════════════════════
// Keyword casing preserved
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_policy_lowercase() {
    let sql = "create policy p1 on t1 as permissive for select to public using (true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_policy_mixed_case() {
    let sql = "Create Policy p1 On t1 As Permissive For Select To Public Using (true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreatePgPolicy(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_policy_lowercase() {
    let sql = "drop policy if exists p1 on t1 cascade";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropPgPolicy(_))));
    format_and_verify(sql);
}
