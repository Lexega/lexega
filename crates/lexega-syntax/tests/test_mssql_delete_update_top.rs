// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL DELETE TOP / UPDATE TOP support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
///
/// Covers:
///   - DELETE TOP (n) FROM table
///   - DELETE TOP (n) PERCENT FROM table
///   - DELETE TOP n FROM table (bare number)
///   - UPDATE TOP (n) table SET ...
///   - UPDATE TOP (n) PERCENT table SET ...
///   - UPDATE TOP n table SET ... (bare number)
///   - Multi-statement scripts
///   - SELECT TOP still works (regression)
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
        AstStmt::Delete(_) => "Delete",
        AstStmt::Update(_) => "Update",
        AstStmt::Select(_) => "Select",
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

fn format_and_verify(sql: &str) {
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for MSSQL: {}\nSQL: {}", e, sql));

    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
}

// ============================================================================
// DELETE TOP
// ============================================================================

#[test]
fn test_delete_top_parenthesized() {
    let sql = "DELETE TOP (10) FROM dbo.MyTable WHERE Status = 'old';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_delete_top_percent() {
    let sql = "DELETE TOP (10) PERCENT FROM dbo.MyTable WHERE Active = 0;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_delete_top_bare_number() {
    let sql = "DELETE TOP 5 FROM MyTable;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_delete_top_no_where() {
    let sql = "DELETE TOP (100) FROM staging.temp_data;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

// ============================================================================
// UPDATE TOP
// ============================================================================

#[test]
fn test_update_top_parenthesized() {
    let sql = "UPDATE TOP (10) dbo.MyTable SET Status = 'active' WHERE Id > 100;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

#[test]
fn test_update_top_percent() {
    let sql = "UPDATE TOP (25) PERCENT dbo.Employees SET Bonus = 500;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

#[test]
fn test_update_top_bare_number() {
    let sql = "UPDATE TOP 5 MyTable SET col1 = 1;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

#[test]
fn test_update_top_with_from_join() {
    let sql = "UPDATE TOP (10) t SET t.Status = 'done' FROM dbo.Tasks t JOIN dbo.Projects p ON t.ProjectId = p.Id WHERE p.Active = 1;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}

// ============================================================================
// Multi-statement
// ============================================================================

#[test]
fn test_multi_statement_top() {
    let sql = "\
DELETE TOP (10) FROM dbo.OldData;
UPDATE TOP (5) dbo.Records SET Processed = 1;
SELECT TOP 3 * FROM dbo.Results;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Expected 3 statements");
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    assert_eq!(ast_variant_name(&stmts[1]), "Update");
    assert_eq!(ast_variant_name(&stmts[2]), "Select");
    format_and_verify(sql);
}

// ============================================================================
// SELECT TOP still parses alongside DELETE/UPDATE TOP
// ============================================================================

#[test]
fn test_select_top_still_works() {
    let sql = "SELECT TOP 10 * FROM MyTable;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Select");
    format_and_verify(sql);
}

#[test]
fn test_select_top_percent_with_ties() {
    let sql = "SELECT TOP 10 PERCENT WITH TIES col1 FROM MyTable ORDER BY col1;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Select");
    format_and_verify(sql);
}

#[test]
fn test_select_top_parenthesized() {
    let sql = "SELECT TOP (5) a, b FROM t;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Select");
    format_and_verify(sql);
}

// ============================================================================
// Mixed case
// ============================================================================

#[test]
fn test_delete_top_mixed_case() {
    let sql = "delete top (10) from MyTable where id > 5;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Delete");
    format_and_verify(sql);
}

#[test]
fn test_update_top_mixed_case() {
    let sql = "update Top (3) MyTable set col1 = 'x';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "Update");
    format_and_verify(sql);
}
