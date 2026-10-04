// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL CREATE [OR ALTER] TRIGGER statement support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
use lexega_syntax::ast::AstStmt;
use lexega_syntax::dialect::mssql;
use lexega_syntax::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

// ============================================================================
// Helpers
// ============================================================================

fn mssql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mssql();
    config
}

fn parse_mssql(sql: &str) -> Vec<AstStmt> {
    let dialect = mssql();
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    script.stmts
}

fn ast_variant_name(stmt: &AstStmt) -> &'static str {
    match stmt {
        AstStmt::CreateMssqlTrigger(_) => "CreateMssqlTrigger",
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

fn format_verify_and_assert_variant(sql: &str, expected_variant: &str) {
    let config = mssql_config();

    let stmts = parse_mssql(sql);
    assert!(!stmts.is_empty(), "Should parse at least one statement");
    let variant_name = ast_variant_name(&stmts[0]);
    assert_eq!(
        variant_name, expected_variant,
        "Expected AST variant {}, got {} — parser likely fell back to OpaqueContent\nSQL: {}",
        expected_variant, variant_name, sql
    );

    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed: {}\nSQL: {}", e, sql));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
}

// ============================================================================
// Basic AFTER trigger
// ============================================================================

#[test]
fn test_create_trigger_basic_after_insert() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_audit ON dbo.Employees AFTER INSERT AS BEGIN INSERT INTO AuditLog (Action) VALUES ('INSERT'); END;",
        "CreateMssqlTrigger",
    );
}

#[test]
fn test_create_trigger_after_update() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_upd ON dbo.Orders AFTER UPDATE AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

#[test]
fn test_create_trigger_after_delete() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_del ON dbo.Products AFTER DELETE AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// Multiple events
// ============================================================================

#[test]
fn test_create_trigger_multiple_events() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_multi ON dbo.Products AFTER INSERT, UPDATE, DELETE AS BEGIN SET NOCOUNT ON; SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

#[test]
fn test_create_trigger_two_events() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_two ON dbo.Items AFTER INSERT, DELETE AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// OR ALTER
// ============================================================================

#[test]
fn test_create_or_alter_trigger() {
    format_verify_and_assert_variant(
        "CREATE OR ALTER TRIGGER trg_update_audit ON Sales.Orders AFTER UPDATE AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// INSTEAD OF trigger
// ============================================================================

#[test]
fn test_create_trigger_instead_of() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_instead ON dbo.MyView INSTEAD OF DELETE AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

#[test]
fn test_create_trigger_instead_of_insert() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_instead_ins ON dbo.MyView INSTEAD OF INSERT AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// FOR trigger (synonym for AFTER)
// ============================================================================

#[test]
fn test_create_trigger_for_insert() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_for ON dbo.Items FOR INSERT AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// NOT FOR REPLICATION
// ============================================================================

#[test]
fn test_create_trigger_not_for_replication() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_nfr ON dbo.Customers AFTER INSERT NOT FOR REPLICATION AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// Qualified trigger name
// ============================================================================

#[test]
fn test_create_trigger_qualified_name() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER dbo.trg_qualified ON dbo.Employees AFTER INSERT AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// DDL trigger (ON DATABASE)
// ============================================================================

#[test]
fn test_create_trigger_on_database() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_ddl ON DATABASE AFTER CREATE_TABLE, ALTER_TABLE AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// Logon trigger (ON ALL SERVER)
// ============================================================================

#[test]
fn test_create_trigger_on_all_server() {
    format_verify_and_assert_variant(
        "CREATE TRIGGER trg_logon ON ALL SERVER AFTER LOGON AS BEGIN SELECT 1; END;",
        "CreateMssqlTrigger",
    );
}

// ============================================================================
// Multi-statement body
// ============================================================================

#[test]
fn test_create_trigger_complex_body() {
    let sql = r#"CREATE TRIGGER trg_complex
ON dbo.Employees
AFTER INSERT, UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO AuditLog (Action) VALUES ('CHANGE');
    SELECT 1;
END;"#;
    format_verify_and_assert_variant(sql, "CreateMssqlTrigger");
}

// ============================================================================
// Multi-statement: multiple triggers in one script
// ============================================================================

#[test]
fn test_multiple_triggers_in_script() {
    let sql = r#"CREATE TRIGGER trg1 ON dbo.T1 AFTER INSERT AS BEGIN SELECT 1; END;
CREATE TRIGGER trg2 ON dbo.T2 AFTER DELETE AS BEGIN SELECT 2; END;"#;

    let config = mssql_config();
    let stmts = parse_mssql(sql);

    assert_eq!(stmts.len(), 2, "Should parse two trigger statements");
    assert_eq!(ast_variant_name(&stmts[0]), "CreateMssqlTrigger");
    assert_eq!(ast_variant_name(&stmts[1]), "CreateMssqlTrigger");

    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}

// ============================================================================
// OR ALTER with complex body
// ============================================================================

#[test]
fn test_create_or_alter_trigger_complex() {
    let sql = r#"CREATE OR ALTER TRIGGER dbo.trg_full
ON dbo.Employees
INSTEAD OF INSERT, UPDATE
NOT FOR REPLICATION
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO AuditLog (Action, Timestamp) VALUES ('CHANGE', GETDATE());
END;"#;
    format_verify_and_assert_variant(sql, "CreateMssqlTrigger");
}
