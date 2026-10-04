// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL SET option ON/OFF statement support.
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
        AstStmt::MssqlSetOption(_) => "MssqlSetOption",
        AstStmt::SetVariable { .. } => "SetVariable",
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
// Basic SET option ON/OFF
// ============================================================================

#[test]
fn test_set_nocount_on() {
    format_verify_and_assert_variant("SET NOCOUNT ON;", "MssqlSetOption");
}

#[test]
fn test_set_nocount_off() {
    format_verify_and_assert_variant("SET NOCOUNT OFF;", "MssqlSetOption");
}

#[test]
fn test_set_ansi_nulls_on() {
    format_verify_and_assert_variant("SET ANSI_NULLS ON;", "MssqlSetOption");
}

#[test]
fn test_set_ansi_nulls_off() {
    format_verify_and_assert_variant("SET ANSI_NULLS OFF;", "MssqlSetOption");
}

#[test]
fn test_set_quoted_identifier_on() {
    format_verify_and_assert_variant("SET QUOTED_IDENTIFIER ON;", "MssqlSetOption");
}

#[test]
fn test_set_quoted_identifier_off() {
    format_verify_and_assert_variant("SET QUOTED_IDENTIFIER OFF;", "MssqlSetOption");
}

#[test]
fn test_set_xact_abort_on() {
    format_verify_and_assert_variant("SET XACT_ABORT ON;", "MssqlSetOption");
}

#[test]
fn test_set_xact_abort_off() {
    format_verify_and_assert_variant("SET XACT_ABORT OFF;", "MssqlSetOption");
}

#[test]
fn test_set_concat_null_yields_null_on() {
    format_verify_and_assert_variant("SET CONCAT_NULL_YIELDS_NULL ON;", "MssqlSetOption");
}

#[test]
fn test_set_arithabort_on() {
    format_verify_and_assert_variant("SET ARITHABORT ON;", "MssqlSetOption");
}

#[test]
fn test_set_ansi_padding_on() {
    format_verify_and_assert_variant("SET ANSI_PADDING ON;", "MssqlSetOption");
}

#[test]
fn test_set_ansi_warnings_on() {
    format_verify_and_assert_variant("SET ANSI_WARNINGS ON;", "MssqlSetOption");
}

#[test]
fn test_set_numeric_roundabort_off() {
    format_verify_and_assert_variant("SET NUMERIC_ROUNDABORT OFF;", "MssqlSetOption");
}

// ============================================================================
// IDENTITY_INSERT (table name between option and ON/OFF)
// ============================================================================

#[test]
fn test_set_identity_insert_on() {
    format_verify_and_assert_variant("SET IDENTITY_INSERT dbo.MyTable ON;", "MssqlSetOption");
}

#[test]
fn test_set_identity_insert_off() {
    format_verify_and_assert_variant("SET IDENTITY_INSERT dbo.MyTable OFF;", "MssqlSetOption");
}

#[test]
fn test_set_identity_insert_unqualified() {
    format_verify_and_assert_variant("SET IDENTITY_INSERT MyTable ON;", "MssqlSetOption");
}

#[test]
fn test_set_identity_insert_three_part() {
    format_verify_and_assert_variant("SET IDENTITY_INSERT mydb.dbo.MyTable ON;", "MssqlSetOption");
}

// ============================================================================
// Without semicolons
// ============================================================================

#[test]
fn test_set_nocount_on_no_semi() {
    format_verify_and_assert_variant("SET NOCOUNT ON", "MssqlSetOption");
}

#[test]
fn test_set_ansi_nulls_off_no_semi() {
    format_verify_and_assert_variant("SET ANSI_NULLS OFF", "MssqlSetOption");
}

// ============================================================================
// Case insensitivity
// ============================================================================

#[test]
fn test_set_nocount_lower_case() {
    format_verify_and_assert_variant("set nocount on;", "MssqlSetOption");
}

#[test]
fn test_set_mixed_case() {
    format_verify_and_assert_variant("Set Nocount On;", "MssqlSetOption");
}

// ============================================================================
// Multi-statement scripts
// ============================================================================

#[test]
fn test_multi_set_options() {
    let sql = "\
SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;";

    let config = mssql_config();
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Should parse 3 statements");

    for (i, stmt) in stmts.iter().enumerate() {
        let name = ast_variant_name(stmt);
        assert_eq!(
            name, "MssqlSetOption",
            "Statement {} should be MssqlSetOption, got {}",
            i, name
        );
    }

    let formatted = format_sql_with_config(sql, &config).expect("format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("formatting should be safe");
}

#[test]
fn test_set_option_mixed_with_variable_assignment() {
    let sql = "\
SET NOCOUNT ON;
SET @count = 0;";

    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 2, "Should parse 2 statements");
    assert_eq!(
        ast_variant_name(&stmts[0]),
        "MssqlSetOption",
        "First should be MssqlSetOption"
    );
    // The second is a SET @var = expr — should be SetVariable, not MssqlSetOption
    assert_ne!(
        ast_variant_name(&stmts[1]),
        "MssqlSetOption",
        "Second should NOT be MssqlSetOption (it's a variable assignment)"
    );
}

// ============================================================================
// Inside procedure bodies
// ============================================================================

#[test]
fn test_set_option_in_procedure() {
    let sql = "\
CREATE PROCEDURE dbo.MyProc
AS
BEGIN
    SET NOCOUNT ON;
    SELECT 1;
END;";

    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config).expect("format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("formatting should be safe");

    // Verify the SET NOCOUNT ON is preserved in the output
    assert!(
        formatted.contains("SET NOCOUNT ON"),
        "Formatted output should contain SET NOCOUNT ON\nFormatted: {}",
        formatted
    );
}

// ============================================================================
// Negative cases: things that should NOT be MssqlSetOption
// ============================================================================

#[test]
fn test_set_variable_not_set_option() {
    // SET @var = expr should NOT parse as MssqlSetOption
    let stmts = parse_mssql("SET @result = 42;");
    assert_ne!(
        ast_variant_name(&stmts[0]),
        "MssqlSetOption",
        "SET @var = expr should NOT be MssqlSetOption"
    );
}
