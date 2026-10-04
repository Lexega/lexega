// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL BULK INSERT statement support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
///
/// Covers:
///   1. Basic BULK INSERT with simple table name
///   2. Schema-qualified table name (dbo.MyTable)
///   3. Bracket-quoted identifiers ([dbo].[SalesData])
///   4. Temp table (#TempTable)
///   5. WITH options clause (KEY = VALUE pairs)
///   6. WITH options clause (flag-only: TABLOCK, CHECK_CONSTRAINTS)
///   7. Mixed case
///   8. Multi-statement scripts
///   9. Without semicolon (valid MSSQL)
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
        AstStmt::MssqlBulkInsert(_) => "MssqlBulkInsert",
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
// 1. Basic BULK INSERT
// ============================================================================

#[test]
fn test_bulk_insert_basic() {
    let sql = "BULK INSERT MyTable FROM 'data.csv';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1, "Expected 1 statement");
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 2. Schema-qualified table name
// ============================================================================

#[test]
fn test_bulk_insert_schema_qualified() {
    let sql = "BULK INSERT dbo.MyTable FROM 'C:\\data\\file.csv';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

#[test]
fn test_bulk_insert_three_part_name() {
    let sql = "BULK INSERT MyDB.dbo.MyTable FROM 'file.csv';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 3. Bracket-quoted identifiers
// ============================================================================

#[test]
fn test_bulk_insert_bracket_quoted() {
    let sql = "BULK INSERT [dbo].[SalesData] FROM 'D:\\imports\\sales.dat';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 4. Temp table
// ============================================================================

#[test]
fn test_bulk_insert_temp_table() {
    let sql = "BULK INSERT #TempTable FROM 'data.csv';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 5. WITH options (KEY = VALUE pairs)
// ============================================================================

#[test]
fn test_bulk_insert_with_options_kv() {
    let sql = "BULK INSERT MyTable FROM 'data.csv' WITH (FIELDTERMINATOR = ',', ROWTERMINATOR = '\\n', FIRSTROW = 2);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

#[test]
fn test_bulk_insert_with_formatfile() {
    let sql = "BULK INSERT MyTable FROM 'data.dat' WITH (FORMATFILE = 'D:\\formats\\sales.fmt');";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 6. WITH options (flag-only)
// ============================================================================

#[test]
fn test_bulk_insert_with_flags() {
    let sql =
        "BULK INSERT MyTable FROM 'data.csv' WITH (TABLOCK, CHECK_CONSTRAINTS, FIRE_TRIGGERS);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 7. Mixed case
// ============================================================================

#[test]
fn test_bulk_insert_mixed_case() {
    let sql = "Bulk Insert dbo.MyTable From 'file.csv';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 8. Multi-statement scripts
// ============================================================================

#[test]
fn test_bulk_insert_multi_statement() {
    let sql = "BULK INSERT dbo.Table1 FROM 'file1.csv';\nBULK INSERT dbo.Table2 FROM 'file2.csv' WITH (TABLOCK);";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 2, "Expected 2 statements");
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    assert_eq!(ast_variant_name(&stmts[1]), "MssqlBulkInsert");
    format_and_verify(sql);
}

#[test]
fn test_bulk_insert_mixed_with_other_statements() {
    let sql =
        "SELECT 1;\nBULK INSERT MyTable FROM 'data.csv' WITH (FIELDTERMINATOR = ',');\nSELECT 2;";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Expected 3 statements");
    assert_eq!(ast_variant_name(&stmts[1]), "MssqlBulkInsert");
    format_and_verify(sql);
}

// ============================================================================
// 9. Without semicolon (valid MSSQL)
// ============================================================================

#[test]
fn test_bulk_insert_no_semicolon() {
    let sql = "BULK INSERT MyTable FROM 'data.csv'";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}

#[test]
fn test_bulk_insert_with_options_no_semicolon() {
    let sql = "BULK INSERT dbo.Tbl FROM 'f.csv' WITH (TABLOCK)";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlBulkInsert");
    format_and_verify(sql);
}
