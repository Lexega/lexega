// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `TABLE tbl [ORDER BY col] [LIMIT n [OFFSET m]]` statement coverage.
//!
//! It is query-bearing — sugar for `SELECT * FROM tbl ...` — so it is parsed
//! into an `AstSelect` tagged with `table_syntax_span`, inheriting lowering,
//! lineage, taint and the query-rule corpus, and composing in every query
//! context (set-op, subquery, INSERT source, CTAS body).
//!
//! Covers:
//!   1. Round-trip safety (standalone + tails + all composition contexts)
//!   2. AST structure (Select + Star projection + table marker)
//!   3. Composition (UNION / subquery / INSERT / CTAS)
//!   4. Dialect gating + query-bearing (analyzed, not opaque)

use lexega_core::ast::{AstProjectionKind, AstStmt};
use lexega_core::dialect::{mysql, snowflake};
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

fn mysql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mysql();
    config
}

fn format_and_verify(sql: &str) {
    let config = mysql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("MySQL formatting verification failed: {}", e));
}

fn parse_mysql(sql: &str) -> lexega_core::ast::AstScript {
    parse_sql_with_dialect(sql, mysql().as_ref())
        .unwrap_or_else(|e| panic!("MySQL parse failed for {:?}: {:?}", sql, e))
}

fn stmt_name(stmt: &AstStmt) -> String {
    let dbg = format!("{:?}", stmt);
    dbg.split(|c: char| c == '(' || c == '{' || c.is_whitespace())
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

fn single(sql: &str) -> AstStmt {
    let mut script = parse_mysql(sql);
    assert_eq!(
        script.stmts.len(),
        1,
        "expected one statement for {:?}",
        sql
    );
    script.stmts.remove(0)
}

fn assert_snowflake_opaque(sql: &str) {
    let script = parse_sql_with_dialect(sql, snowflake().as_ref())
        .unwrap_or_else(|e| panic!("script-level parse should not hard-fail: {:?}", e));
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "Snowflake should degrade {:?}, got {:?}",
        sql,
        script.stmts.iter().map(stmt_name).collect::<Vec<_>>()
    );
}

// ============================================================================
// 1. Round-trip safety
// ============================================================================

#[test]
fn test_roundtrip_table_bare() {
    format_and_verify("TABLE t1;");
}

#[test]
fn test_roundtrip_table_order_by() {
    format_and_verify("TABLE t1 ORDER BY id;");
}

#[test]
fn test_roundtrip_table_order_limit() {
    format_and_verify("TABLE t1 ORDER BY id LIMIT 5;");
}

#[test]
fn test_roundtrip_table_limit_offset() {
    format_and_verify("TABLE t1 LIMIT 5 OFFSET 10;");
}

#[test]
fn test_roundtrip_table_limit_comma() {
    format_and_verify("TABLE t1 LIMIT 10, 5;");
}

#[test]
fn test_roundtrip_table_qualified() {
    format_and_verify("TABLE mydb.t1 ORDER BY id LIMIT 5;");
}

#[test]
fn test_roundtrip_union_table() {
    format_and_verify("SELECT a FROM t2 UNION TABLE t1;");
}

#[test]
fn test_roundtrip_subquery_table() {
    format_and_verify("SELECT * FROM (TABLE t1) AS x;");
}

#[test]
fn test_roundtrip_insert_table() {
    format_and_verify("INSERT INTO t2 TABLE t1;");
}

#[test]
fn test_roundtrip_ctas_table() {
    format_and_verify("CREATE TABLE t3 AS TABLE t1;");
}

// ============================================================================
// 2. AST structure — query-bearing: an AstSelect with a Star projection
// ============================================================================

#[test]
fn test_table_is_select_with_star_and_marker() {
    match single("TABLE t1 ORDER BY id LIMIT 5;") {
        AstStmt::Select(s) => {
            assert!(
                s.table_syntax_span.is_some(),
                "TABLE form must carry the table_syntax_span marker"
            );
            assert!(
                matches!(s.projection.kind, AstProjectionKind::Star(_)),
                "TABLE desugars to SELECT * — projection must be Star"
            );
            assert_eq!(s.from.len(), 1, "single FROM table");
            assert!(s.order_by.is_some(), "ORDER BY tail captured");
            assert!(s.limit.is_some(), "LIMIT tail captured");
        }
        other => panic!("TABLE must parse to Select, got {}", stmt_name(&other)),
    }
}

#[test]
fn test_plain_select_has_no_table_marker() {
    match single("SELECT * FROM t1;") {
        AstStmt::Select(s) => assert!(s.table_syntax_span.is_none()),
        other => panic!("expected Select, got {}", stmt_name(&other)),
    }
}

// ============================================================================
// 3. Composition
// ============================================================================

#[test]
fn test_union_table_is_set_select() {
    assert_eq!(
        stmt_name(&single("SELECT a FROM t2 UNION TABLE t1;")),
        "SetSelect"
    );
}

#[test]
fn test_insert_table_is_insert() {
    assert_eq!(stmt_name(&single("INSERT INTO t2 TABLE t1;")), "Insert");
}

#[test]
fn test_ctas_table_is_create_table() {
    assert_eq!(
        stmt_name(&single("CREATE TABLE t3 AS TABLE t1;")),
        "CreateTable"
    );
}

#[test]
fn test_subquery_table_is_select() {
    // Outer is a Select; the (TABLE t1) derived table parsed without shearing.
    assert_eq!(
        stmt_name(&single("SELECT * FROM (TABLE t1) AS x;")),
        "Select"
    );
}

// ============================================================================
// 4. Dialect gating + query-bearing
// ============================================================================

#[test]
fn test_snowflake_rejects_table_statement() {
    assert_snowflake_opaque("TABLE t1 ORDER BY id LIMIT 5;");
}

#[test]
fn test_table_statement_is_analyzed_not_opaque() {
    // Query-bearing: the analyzer lowers it (no panic, statement analyzed),
    // unlike an opaque fragment.
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mysql());
    let report = lexega_core::api::analyze_risk_with_policy_config("TABLE orders;", &config)
        .expect("analysis should succeed");
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "TABLE statement should be analyzed as a query, got {:?}",
        report.summary.statements_analyzed
    );
}
