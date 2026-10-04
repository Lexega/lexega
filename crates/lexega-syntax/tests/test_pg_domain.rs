// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL CREATE DOMAIN, ALTER DOMAIN, DROP DOMAIN
//!
//! Each construct is tested for:
//!   1. Correct AST variant (not OpaqueContent)
//!   2. Format round-trip with semantic safety verification
//!   3. Multiple syntax variants
//!
//! Expression parsing (DEFAULT, CHECK) is verified by confirming the AST
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
// CREATE DOMAIN — basic types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_domain_simple_text() {
    let sql = "CREATE DOMAIN us_postal_code AS TEXT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_integer() {
    let sql = "CREATE DOMAIN positive_int AS INTEGER";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_varchar_precision() {
    let sql = "CREATE DOMAIN email_address AS VARCHAR(255)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_numeric_precision_scale() {
    let sql = "CREATE DOMAIN currency AS NUMERIC(10, 2)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_without_as() {
    // AS is optional in PostgreSQL
    let sql = "CREATE DOMAIN score INTEGER";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_schema_qualified() {
    let sql = "CREATE DOMAIN myschema.us_postal_code AS TEXT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE DOMAIN — COLLATE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_domain_collate() {
    let sql = r#"CREATE DOMAIN name_type AS TEXT COLLATE "en_US""#;
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE DOMAIN — DEFAULT expression (properly parsed)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_domain_default_literal() {
    let sql = "CREATE DOMAIN status AS TEXT DEFAULT 'active'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_default_numeric() {
    let sql = "CREATE DOMAIN rating AS INTEGER DEFAULT 0";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_default_null() {
    let sql = "CREATE DOMAIN optional_name AS TEXT DEFAULT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE DOMAIN — NOT NULL / NULL constraints
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_domain_not_null() {
    let sql = "CREATE DOMAIN required_text AS TEXT NOT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_null() {
    let sql = "CREATE DOMAIN nullable_text AS TEXT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE DOMAIN — CHECK constraint (expression properly parsed)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_domain_check_simple() {
    let sql = "CREATE DOMAIN positive_int AS INTEGER CHECK (VALUE > 0)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_check_regex() {
    let sql = "CREATE DOMAIN us_postal_code AS TEXT CHECK (VALUE ~ '^\\d{5}$')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_check_between() {
    let sql = "CREATE DOMAIN percentage AS NUMERIC(5, 2) CHECK (VALUE >= 0 AND VALUE <= 100)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_named_check() {
    let sql = "CREATE DOMAIN positive_int AS INTEGER CONSTRAINT must_be_positive CHECK (VALUE > 0)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE DOMAIN — combined clauses
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_domain_all_clauses() {
    let sql =
        "CREATE DOMAIN us_postal_code AS TEXT DEFAULT '00000' NOT NULL CHECK (VALUE ~ '^\\d{5}$')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_default_and_not_null() {
    let sql = "CREATE DOMAIN status AS TEXT DEFAULT 'pending' NOT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_create_domain_multiple_constraints() {
    let sql =
        "CREATE DOMAIN rating AS INTEGER DEFAULT 0 NOT NULL CHECK (VALUE >= 0) CHECK (VALUE <= 5)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — SET DEFAULT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_set_default_literal() {
    let sql = "ALTER DOMAIN us_postal_code SET DEFAULT '00000'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_set_default_number() {
    let sql = "ALTER DOMAIN rating SET DEFAULT 3";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — DROP DEFAULT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_drop_default() {
    let sql = "ALTER DOMAIN us_postal_code DROP DEFAULT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — SET NOT NULL / DROP NOT NULL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_set_not_null() {
    let sql = "ALTER DOMAIN us_postal_code SET NOT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_drop_not_null() {
    let sql = "ALTER DOMAIN us_postal_code DROP NOT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — ADD CONSTRAINT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_add_check() {
    let sql = "ALTER DOMAIN us_postal_code ADD CHECK (VALUE <> '00000')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_add_named_check() {
    let sql = "ALTER DOMAIN us_postal_code ADD CONSTRAINT valid_zip CHECK (VALUE ~ '^\\d{5}$')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_add_not_null() {
    let sql = "ALTER DOMAIN us_postal_code ADD NOT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_add_check_not_valid() {
    let sql =
        "ALTER DOMAIN us_postal_code ADD CONSTRAINT no_zero CHECK (VALUE <> '00000') NOT VALID";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — DROP CONSTRAINT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_drop_constraint() {
    let sql = "ALTER DOMAIN us_postal_code DROP CONSTRAINT valid_zip";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_drop_constraint_if_exists() {
    let sql = "ALTER DOMAIN us_postal_code DROP CONSTRAINT IF EXISTS valid_zip";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_drop_constraint_cascade() {
    let sql = "ALTER DOMAIN us_postal_code DROP CONSTRAINT valid_zip CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_drop_constraint_restrict() {
    let sql = "ALTER DOMAIN us_postal_code DROP CONSTRAINT valid_zip RESTRICT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — RENAME CONSTRAINT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_rename_constraint() {
    let sql = "ALTER DOMAIN us_postal_code RENAME CONSTRAINT valid_zip TO zip_check";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — VALIDATE CONSTRAINT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_validate_constraint() {
    let sql = "ALTER DOMAIN us_postal_code VALIDATE CONSTRAINT valid_zip";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — OWNER TO
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_owner_to_user() {
    let sql = "ALTER DOMAIN us_postal_code OWNER TO admin_user";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_domain_owner_to_current_user() {
    let sql = "ALTER DOMAIN us_postal_code OWNER TO CURRENT_USER";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — RENAME TO
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_rename_to() {
    let sql = "ALTER DOMAIN us_postal_code RENAME TO zip_code";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — SET SCHEMA
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_set_schema() {
    let sql = "ALTER DOMAIN us_postal_code SET SCHEMA public";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER DOMAIN — schema-qualified name
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_domain_schema_qualified() {
    let sql = "ALTER DOMAIN myschema.us_postal_code SET NOT NULL";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP DOMAIN — basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_domain_simple() {
    let sql = "DROP DOMAIN us_postal_code";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_domain_if_exists() {
    let sql = "DROP DOMAIN IF EXISTS us_postal_code";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_domain_cascade() {
    let sql = "DROP DOMAIN us_postal_code CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_domain_restrict() {
    let sql = "DROP DOMAIN us_postal_code RESTRICT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP DOMAIN — multiple names
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_domain_multiple() {
    let sql = "DROP DOMAIN us_postal_code, email_address";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_domain_multiple_cascade() {
    let sql = "DROP DOMAIN us_postal_code, email_address, currency CASCADE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

#[test]
fn test_drop_domain_if_exists_multiple() {
    let sql = "DROP DOMAIN IF EXISTS us_postal_code, email_address";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// DROP DOMAIN — schema-qualified
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_domain_schema_qualified() {
    let sql = "DROP DOMAIN myschema.us_postal_code";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::DropDomain(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_domain_statements() {
    let sql = r#"
CREATE DOMAIN email AS TEXT CHECK (VALUE ~ '@');
ALTER DOMAIN email SET DEFAULT 'user@example.com';
DROP DOMAIN IF EXISTS email CASCADE;
"#;
    let script = parse_sql(sql).expect("should parse multi-statement");
    assert_eq!(
        script.stmts.len(),
        3,
        "Should parse 3 domain statements, got {}",
        script.stmts.len()
    );
    assert!(matches!(script.stmts[0], AstStmt::CreateDomain(_)));
    assert!(matches!(script.stmts[1], AstStmt::AlterDomain(_)));
    assert!(matches!(script.stmts[2], AstStmt::DropDomain(_)));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Array types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_domain_array_type() {
    let sql = "CREATE DOMAIN tag_list AS TEXT[]";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::CreateDomain(_))));
    format_and_verify(sql);
}
