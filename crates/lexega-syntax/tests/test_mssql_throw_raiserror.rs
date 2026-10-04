// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL THROW and RAISERROR statement support.
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
        AstStmt::MssqlThrow(_) => "MssqlThrow",
        AstStmt::MssqlRaiserror(_) => "MssqlRaiserror",
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
// THROW — basic forms
// ============================================================================

#[test]
fn test_throw_with_arguments() {
    format_verify_and_assert_variant("THROW 50000, 'Record not found.', 1;", "MssqlThrow");
}

#[test]
fn test_throw_with_variables() {
    format_verify_and_assert_variant(
        "THROW @ErrorNumber, @ErrorMessage, @ErrorState;",
        "MssqlThrow",
    );
}

#[test]
fn test_throw_no_semicolon() {
    format_verify_and_assert_variant("THROW 50000, 'Error msg', 1", "MssqlThrow");
}

// ============================================================================
// THROW — re-throw inside CATCH
// ============================================================================

#[test]
fn test_throw_rethrow_in_catch() {
    let sql = r#"BEGIN TRY
  SELECT 1;
END TRY
BEGIN CATCH
  THROW;
END CATCH;"#;
    let config = mssql_config();
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

#[test]
fn test_throw_rethrow_standalone() {
    // THROW with no args outside a CATCH — syntactically valid, runtime error
    format_verify_and_assert_variant("THROW;", "MssqlThrow");
}

// ============================================================================
// RAISERROR — basic forms
// ============================================================================

#[test]
fn test_raiserror_basic() {
    format_verify_and_assert_variant("RAISERROR('Error occurred', 16, 1);", "MssqlRaiserror");
}

#[test]
fn test_raiserror_printf_style() {
    format_verify_and_assert_variant(
        "RAISERROR('Error %s in %d', 16, 1, 'test', 42);",
        "MssqlRaiserror",
    );
}

#[test]
fn test_raiserror_msg_id() {
    format_verify_and_assert_variant("RAISERROR(50001, 16, 1);", "MssqlRaiserror");
}

#[test]
fn test_raiserror_variable_msg() {
    format_verify_and_assert_variant("RAISERROR(@ErrorMsg, 16, 1);", "MssqlRaiserror");
}

#[test]
fn test_raiserror_no_semicolon() {
    format_verify_and_assert_variant("RAISERROR('Error', 16, 1)", "MssqlRaiserror");
}

// ============================================================================
// RAISERROR — WITH options
// ============================================================================

#[test]
fn test_raiserror_with_log() {
    format_verify_and_assert_variant(
        "RAISERROR('Critical error', 20, 1) WITH LOG;",
        "MssqlRaiserror",
    );
}

#[test]
fn test_raiserror_with_nowait() {
    format_verify_and_assert_variant(
        "RAISERROR('Progress: %d%%', 0, 1, @progress) WITH NOWAIT;",
        "MssqlRaiserror",
    );
}

#[test]
fn test_raiserror_with_seterror() {
    format_verify_and_assert_variant(
        "RAISERROR('Custom error', 16, 1) WITH SETERROR;",
        "MssqlRaiserror",
    );
}

#[test]
fn test_raiserror_with_multiple_options() {
    format_verify_and_assert_variant(
        "RAISERROR('Fatal error', 20, 1) WITH LOG, NOWAIT, SETERROR;",
        "MssqlRaiserror",
    );
}

// ============================================================================
// Multi-statement scripts
// ============================================================================

#[test]
fn test_throw_and_raiserror_multi_statement() {
    let sql = r#"RAISERROR('First error', 10, 1);
THROW 50000, 'Second error', 1;
RAISERROR('Third error', 16, 1) WITH LOG;"#;
    let config = mssql_config();

    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Should parse 3 statements");
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlRaiserror");
    assert_eq!(ast_variant_name(&stmts[1]), "MssqlThrow");
    assert_eq!(ast_variant_name(&stmts[2]), "MssqlRaiserror");

    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}

// ============================================================================
// Inside BEGIN...END / TRY...CATCH
// ============================================================================

#[test]
fn test_throw_raiserror_in_try_catch() {
    let sql = r#"BEGIN TRY
    SELECT 1 / 0;
END TRY
BEGIN CATCH
    RAISERROR('Division by zero caught', 16, 1) WITH LOG;
    THROW;
END CATCH;"#;
    let config = mssql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}

#[test]
fn test_raiserror_in_procedure() {
    let sql = r#"CREATE OR ALTER PROCEDURE dbo.usp_Validate
AS
BEGIN
    IF @count = 0
        RAISERROR('No records found', 16, 1);
    ELSE
        PRINT 'Records found';
END;"#;
    let config = mssql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}
