// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL CREATE OR ALTER support.
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

/// Parses SQL with MSSQL dialect and returns the AST statements.
fn parse_mssql(sql: &str) -> Vec<AstStmt> {
    let dialect = mssql();
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    script.stmts
}

/// Formats SQL, verifies token preservation, AND asserts the expected
/// AST variant was produced (not OpaqueContent).
fn format_verify_and_assert_variant(sql: &str, expected_variant: &str) {
    let config = mssql_config();

    // 1. Assert correct AST variant
    let stmts = parse_mssql(sql);
    assert!(!stmts.is_empty(), "Should parse at least one statement");
    let variant_name = ast_variant_name(&stmts[0]);
    assert_eq!(
        variant_name, expected_variant,
        "Expected AST variant {}, got {} — parser likely fell back to OpaqueContent\nSQL: {}",
        expected_variant, variant_name, sql
    );

    // 2. Format and verify token preservation
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

fn ast_variant_name(stmt: &AstStmt) -> &'static str {
    match stmt {
        AstStmt::CreateProcedure(_) => "CreateProcedure",
        AstStmt::CreateFunction(_) => "CreateFunction",
        AstStmt::CreateView(_) => "CreateView",
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

// ============================================================================
// CREATE OR ALTER PROCEDURE
// ============================================================================

#[test]
fn test_create_or_alter_procedure_basic() {
    let sql = r#"CREATE OR ALTER PROCEDURE dbo.usp_GetUsers
AS
BEGIN
    SELECT * FROM Users;
END;"#;
    format_verify_and_assert_variant(sql, "CreateProcedure");
}

#[test]
fn test_create_or_alter_procedure_with_params() {
    let sql = r#"CREATE OR ALTER PROCEDURE dbo.usp_InsertUser
    @Name NVARCHAR(100),
    @Email NVARCHAR(255)
AS
BEGIN
    INSERT INTO Users (Name, Email) VALUES (@Name, @Email);
END;"#;
    format_verify_and_assert_variant(sql, "CreateProcedure");
}

#[test]
fn test_create_or_alter_procedure_qualified_name() {
    let sql = r#"CREATE OR ALTER PROCEDURE MyDB.dbo.usp_DoWork
AS
BEGIN
    SELECT 1;
END;"#;
    format_verify_and_assert_variant(sql, "CreateProcedure");
}

#[test]
fn test_create_or_alter_procedure_no_begin_end() {
    // MSSQL: bare SQL statement body without BEGIN/END
    let sql = "CREATE OR ALTER PROCEDURE dbo.usp_Simple AS SELECT 1;";
    format_verify_and_assert_variant(sql, "CreateProcedure");
}

// ============================================================================
// CREATE OR ALTER FUNCTION
// ============================================================================

#[test]
fn test_create_or_alter_function_scalar() {
    let sql = r#"CREATE OR ALTER FUNCTION dbo.fn_GetFullName(@First NVARCHAR(50), @Last NVARCHAR(50))
RETURNS NVARCHAR(101)
AS
BEGIN
    RETURN @First + ' ' + @Last;
END;"#;
    format_verify_and_assert_variant(sql, "CreateFunction");
}

#[test]
fn test_create_or_alter_function_table_valued() {
    let sql = r#"CREATE OR ALTER FUNCTION dbo.fn_GetActiveUsers()
RETURNS TABLE
AS
RETURN (SELECT * FROM Users WHERE Active = 1);"#;
    format_verify_and_assert_variant(sql, "CreateFunction");
}

#[test]
fn test_create_or_alter_function_qualified_name() {
    let sql = r#"CREATE OR ALTER FUNCTION sales.fn_CalcTax(@Amount DECIMAL(10,2))
RETURNS DECIMAL(10,2)
AS
BEGIN
    RETURN @Amount * 0.08;
END;"#;
    format_verify_and_assert_variant(sql, "CreateFunction");
}

// ============================================================================
// CREATE OR ALTER VIEW
// ============================================================================

#[test]
fn test_create_or_alter_view_basic() {
    let sql = r#"CREATE OR ALTER VIEW dbo.vw_ActiveUsers
AS
SELECT * FROM Users WHERE Active = 1;"#;
    format_verify_and_assert_variant(sql, "CreateView");
}

#[test]
fn test_create_or_alter_view_with_columns() {
    let sql = r#"CREATE OR ALTER VIEW dbo.vw_UserSummary (UserId, FullName)
AS
SELECT Id, FirstName + ' ' + LastName FROM Users;"#;
    format_verify_and_assert_variant(sql, "CreateView");
}

#[test]
fn test_create_or_alter_view_qualified_name() {
    let sql = r#"CREATE OR ALTER VIEW sales.vw_Revenue
AS
SELECT SUM(Amount) AS TotalRevenue FROM Orders;"#;
    format_verify_and_assert_variant(sql, "CreateView");
}

// ============================================================================
// Regression: OR REPLACE still works
// ============================================================================

#[test]
fn test_create_or_replace_procedure_still_works() {
    // Snowflake-style OR REPLACE — should still work
    let sql = "CREATE OR REPLACE PROCEDURE my_proc() RETURNS STRING LANGUAGE SQL AS 'SELECT 1';";
    let config = FormatterConfig::default(); // Snowflake dialect
    let formatted = format_sql_with_config(sql, &config)
        .expect("CREATE OR REPLACE PROCEDURE should still work");
    lexega_syntax::verify_formatting_safe(sql, &formatted)
        .expect("Verification should pass for OR REPLACE");
}

#[test]
fn test_create_or_replace_view_still_works() {
    let sql = "CREATE OR REPLACE VIEW my_view AS SELECT 1;";
    let config = FormatterConfig::default();
    let formatted =
        format_sql_with_config(sql, &config).expect("CREATE OR REPLACE VIEW should still work");
    lexega_syntax::verify_formatting_safe(sql, &formatted)
        .expect("Verification should pass for OR REPLACE VIEW");
}

#[test]
fn test_create_or_replace_function_still_works() {
    let sql = "CREATE OR REPLACE FUNCTION my_func() RETURNS INT LANGUAGE SQL AS 'SELECT 1';";
    let config = FormatterConfig::default();
    let formatted =
        format_sql_with_config(sql, &config).expect("CREATE OR REPLACE FUNCTION should still work");
    lexega_syntax::verify_formatting_safe(sql, &formatted)
        .expect("Verification should pass for OR REPLACE FUNCTION");
}

// ============================================================================
// Plain CREATE (no OR ALTER/REPLACE) still works
// ============================================================================

#[test]
fn test_plain_create_procedure_still_works() {
    let sql = r#"CREATE PROCEDURE dbo.usp_Simple
AS
BEGIN
    SELECT 1;
END;"#;
    format_verify_and_assert_variant(sql, "CreateProcedure");
}

#[test]
fn test_plain_create_view_still_works() {
    let sql = "CREATE VIEW dbo.vw_Simple AS SELECT 1;";
    format_verify_and_assert_variant(sql, "CreateView");
}

// ============================================================================
// Multi-statement scripts
// ============================================================================

#[test]
fn test_multi_statement_create_or_alter() {
    let sql = r#"CREATE OR ALTER VIEW dbo.vw_Users AS SELECT * FROM Users;

CREATE OR ALTER PROCEDURE dbo.usp_GetUsers
AS
BEGIN
    SELECT * FROM dbo.vw_Users;
END;"#;
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 2, "Should parse as two statements");
    assert_eq!(ast_variant_name(&stmts[0]), "CreateView");
    assert_eq!(ast_variant_name(&stmts[1]), "CreateProcedure");

    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config).expect("Format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("Verification should pass");
}

#[test]
fn test_mixed_create_styles() {
    // Mix of plain CREATE and CREATE OR ALTER in one script
    let sql = r#"CREATE VIEW dbo.vw_Old AS SELECT 1;

CREATE OR ALTER VIEW dbo.vw_New AS SELECT 2;"#;
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 2, "Should parse as two statements");
    assert_eq!(ast_variant_name(&stmts[0]), "CreateView");
    assert_eq!(ast_variant_name(&stmts[1]), "CreateView");

    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config).expect("Format should succeed");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("Verification should pass");
}

// ============================================================================
// AST verification
// ============================================================================

#[test]
fn test_ast_create_or_alter_procedure_has_or_alter_span() {
    let sql = r#"CREATE OR ALTER PROCEDURE dbo.usp_Test
AS
BEGIN
    SELECT 1;
END;"#;
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1, "Should parse as a single statement");
    match &stmts[0] {
        AstStmt::CreateProcedure(proc) => {
            assert!(proc.or_alter_span.is_some(), "or_alter_span should be set");
            assert!(
                proc.or_replace_span.is_none(),
                "or_replace_span should be None"
            );
        }
        other => panic!(
            "Expected CreateProcedure, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_ast_create_or_alter_function_has_or_alter_span() {
    let sql = r#"CREATE OR ALTER FUNCTION dbo.fn_Test()
RETURNS INT
AS
BEGIN
    RETURN 1;
END;"#;
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1, "Should parse as a single statement");
    match &stmts[0] {
        AstStmt::CreateFunction(func) => {
            assert!(func.or_alter_span.is_some(), "or_alter_span should be set");
            assert!(
                func.or_replace_span.is_none(),
                "or_replace_span should be None"
            );
        }
        other => panic!(
            "Expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_ast_create_or_alter_view_has_or_alter_span() {
    let sql = "CREATE OR ALTER VIEW dbo.vw_Test AS SELECT 1;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1, "Should parse as a single statement");
    match &stmts[0] {
        AstStmt::CreateView(view) => {
            assert!(view.or_alter_span.is_some(), "or_alter_span should be set");
            assert!(
                view.or_replace_span.is_none(),
                "or_replace_span should be None"
            );
        }
        other => panic!(
            "Expected CreateView, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_ast_plain_create_has_neither_span() {
    let sql = r#"CREATE PROCEDURE dbo.usp_Test
AS
BEGIN
    SELECT 1;
END;"#;
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    match &stmts[0] {
        AstStmt::CreateProcedure(proc) => {
            assert!(
                proc.or_alter_span.is_none(),
                "or_alter_span should be None for plain CREATE"
            );
            assert!(
                proc.or_replace_span.is_none(),
                "or_replace_span should be None for plain CREATE"
            );
        }
        other => panic!(
            "Expected CreateProcedure, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}
