// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL WAITFOR statement support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
///
/// Covers:
///   1. Basic WAITFOR DELAY
///   2. Basic WAITFOR TIME
///   3. WAITFOR without semicolon (valid MSSQL)
///   4. Mixed case
///   5. Multi-statement scripts
///   6. WAITFOR inside BEGIN...END
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
        AstStmt::MssqlWaitfor(_) => "MssqlWaitfor",
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
// 1. Basic WAITFOR DELAY
// ============================================================================

#[test]
fn test_waitfor_delay_basic() {
    let sql = "WAITFOR DELAY '00:00:05';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1, "Expected 1 statement");
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

#[test]
fn test_waitfor_delay_long_interval() {
    let sql = "WAITFOR DELAY '01:30:00';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

// ============================================================================
// 2. Basic WAITFOR TIME
// ============================================================================

#[test]
fn test_waitfor_time_basic() {
    let sql = "WAITFOR TIME '23:00:00';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1, "Expected 1 statement");
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

#[test]
fn test_waitfor_time_midnight() {
    let sql = "WAITFOR TIME '00:00:00';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

// ============================================================================
// 3. WAITFOR without semicolon (valid MSSQL)
// ============================================================================

#[test]
fn test_waitfor_delay_no_semicolon() {
    let sql = "WAITFOR DELAY '00:00:01'";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

#[test]
fn test_waitfor_time_no_semicolon() {
    let sql = "WAITFOR TIME '12:00:00'";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

// ============================================================================
// 4. Mixed case
// ============================================================================

#[test]
fn test_waitfor_lowercase() {
    let sql = "waitfor delay '00:05:00';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

#[test]
fn test_waitfor_mixed_case() {
    let sql = "Waitfor Time '12:30:00';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    format_and_verify(sql);
}

// ============================================================================
// 5. Multi-statement scripts
// ============================================================================

#[test]
fn test_waitfor_multi_statement() {
    let sql = "\
PRINT 'Starting wait...';
WAITFOR DELAY '00:00:05';
PRINT 'Done waiting';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Expected 3 statements");
    assert_eq!(ast_variant_name(&stmts[1]), "MssqlWaitfor");
    format_and_verify(sql);
}

#[test]
fn test_waitfor_both_kinds() {
    let sql = "\
WAITFOR DELAY '00:00:01';
WAITFOR TIME '23:59:59';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 2, "Expected 2 statements");
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlWaitfor");
    assert_eq!(ast_variant_name(&stmts[1]), "MssqlWaitfor");
    format_and_verify(sql);
}

// ============================================================================
// 6. WAITFOR inside BEGIN...END
// ============================================================================

#[test]
fn test_waitfor_in_begin_end() {
    let sql = "\
BEGIN
    WAITFOR DELAY '00:00:02';
    SELECT 1;
END;";
    // This is valid MSSQL — WAITFOR inside a block
    format_and_verify(sql);
}

// ============================================================================
// 7. AST span check — kind_span and value_span are populated
// ============================================================================

#[test]
fn test_waitfor_spans() {
    let sql = "WAITFOR DELAY '00:00:05';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    if let AstStmt::MssqlWaitfor(ref w) = stmts[0] {
        let kind_text = &sql[w.kind_span.start as usize..w.kind_span.end as usize];
        assert_eq!(kind_text, "DELAY");
        let value_text = &sql[w.value_span.start as usize..w.value_span.end as usize];
        assert_eq!(value_text, "'00:00:05'");
    } else {
        panic!(
            "Expected MssqlWaitfor, got {:?}",
            ast_variant_name(&stmts[0])
        );
    }
}

#[test]
fn test_waitfor_time_spans() {
    let sql = "WAITFOR TIME '23:00:00';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 1);
    if let AstStmt::MssqlWaitfor(ref w) = stmts[0] {
        let kind_text = &sql[w.kind_span.start as usize..w.kind_span.end as usize];
        assert_eq!(kind_text, "TIME");
        let value_text = &sql[w.value_span.start as usize..w.value_span.end as usize];
        assert_eq!(value_text, "'23:00:00'");
    } else {
        panic!(
            "Expected MssqlWaitfor, got {:?}",
            ast_variant_name(&stmts[0])
        );
    }
}
