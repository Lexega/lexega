// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL DECLARE @var TABLE(...) — table variable support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
///
/// Covers:
///   1. Basic table variable with simple columns
///   2. Multiple column types (VARCHAR, INT, DECIMAL, etc.)
///   3. Column constraints (NOT NULL, PRIMARY KEY, DEFAULT)
///   4. Nested parentheses in type definitions (DECIMAL(10,2), VARCHAR(50))
///   5. Multi-statement scripts mixing DECLARE TABLE with regular DECLARE
///   6. Mixed case
use lexega_core::ast::AstStmt;
use lexega_core::dialect::mssql;
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

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
        AstStmt::DeclareTable { .. } => "DeclareTable",
        AstStmt::Declare { .. } => "Declare",
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

fn format_and_verify(sql: &str) {
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for MSSQL: {}\nSQL: {}", e, sql));

    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Formatting safety check FAILED:\n{}\n\nOriginal:\n{}\n\nFormatted:\n{}",
                e, sql, formatted
            )
        });
}

// ============================================================================
// 1. Basic table variable
// ============================================================================

#[test]
fn test_declare_table_basic() {
    let sql = "DECLARE @t TABLE(id INT, name VARCHAR(50));";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1, "Expected 1 statement");
    assert_eq!(
        ast_variant_name(&stmts[0]),
        "DeclareTable",
        "Expected DeclareTable, got {}",
        ast_variant_name(&stmts[0])
    );
    format_and_verify(sql);
}

// ============================================================================
// 2. Multiple column types
// ============================================================================

#[test]
fn test_declare_table_multiple_types() {
    let sql = "DECLARE @results TABLE(\n    user_id INT,\n    username NVARCHAR(100),\n    score DECIMAL(10, 2),\n    created_at DATETIME\n);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "DeclareTable");
    format_and_verify(sql);
}

// ============================================================================
// 3. Column constraints
// ============================================================================

#[test]
fn test_declare_table_with_constraints() {
    let sql = "DECLARE @data TABLE(\n    id INT PRIMARY KEY,\n    name NVARCHAR(255) NOT NULL,\n    val DECIMAL(10, 2) DEFAULT 0.0\n);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "DeclareTable");
    format_and_verify(sql);
}

// ============================================================================
// 4. Single column
// ============================================================================

#[test]
fn test_declare_table_single_column() {
    let sql = "DECLARE @ids TABLE(id INT);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "DeclareTable");
    format_and_verify(sql);
}

// ============================================================================
// 5. Multi-statement with regular DECLARE
// ============================================================================

#[test]
fn test_declare_table_with_regular_declare() {
    let sql =
        "DECLARE @x INT;\nDECLARE @t TABLE(id INT, name VARCHAR(50));\nDECLARE @y VARCHAR(100);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Expected 3 statements, got {}", stmts.len());
    assert_eq!(ast_variant_name(&stmts[0]), "Declare");
    assert_eq!(ast_variant_name(&stmts[1]), "DeclareTable");
    assert_eq!(ast_variant_name(&stmts[2]), "Declare");
    format_and_verify(sql);
}

// ============================================================================
// 6. Mixed case
// ============================================================================

#[test]
fn test_declare_table_mixed_case() {
    let sql = "declare @T table(Id int, Name varchar(50));";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "DeclareTable");
    format_and_verify(sql);
}

// ============================================================================
// 7. DEFAULT with function call
// ============================================================================

#[test]
fn test_declare_table_default_function() {
    let sql = "DECLARE @log TABLE(\n    id INT,\n    created_at DATETIME DEFAULT GETDATE()\n);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "DeclareTable");
    format_and_verify(sql);
}

// ============================================================================
// 8. No semicolon (valid MSSQL)
// ============================================================================

#[test]
fn test_declare_table_no_semicolon() {
    let sql = "DECLARE @t TABLE(id INT)";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "DeclareTable");
    format_and_verify(sql);
}

// ============================================================================
// 9. Risk analysis — all statements analyzed
// ============================================================================

#[test]
fn test_declare_table_risk_analysis() {
    let sql = "DECLARE @t TABLE(id INT, name VARCHAR(50));\nDECLARE @x INT;\nDECLARE @r TABLE(val DECIMAL(10,2));";
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mssql());
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("analysis should succeed");
    assert_eq!(
        report.summary.statements_analyzed, 3,
        "All 3 statements should be analyzed"
    );
}
