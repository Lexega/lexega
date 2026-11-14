// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL prepared-statement coverage.
//!
//! PREPARE, EXECUTE (`EXECUTE s [USING @v, ...]`) and DEALLOCATE share one
//! prepared-statement representation, and `DROP PREPARE` is a deallocate
//! rather than a generic DROP.
//!
//! Covers:
//!   1. Format round-trip safety
//!   2. AST structure: EXECUTE USING tail, DROP PREPARE → PgDeallocate
//!   3. Dialect gating: MySQL EXECUTE-name surface degrades under Snowflake
//!   4. Dynamic-SQL injection detection fires on PREPARE FROM CONCAT

use lexega_core::analyzer::RuleMatch;
use lexega_core::ast::AstStmt;
use lexega_core::dialect::{mysql, snowflake};
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};
use std::collections::HashSet;

fn mysql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: mysql(),
        ..Default::default()
    }
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
        "Snowflake should degrade {:?} (at least one opaque), got {:?}",
        sql,
        script.stmts.iter().map(stmt_name).collect::<Vec<_>>()
    );
}

fn mysql_rule_ids(sql: &str) -> HashSet<String> {
    let config = lexega_core::analyzer::AnalysisConfig {
        dialect: Some(mysql()),
        ..Default::default()
    };
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .unwrap_or_else(|e| panic!("analysis failed for {:?}: {:?}", sql, e));
    report
        .findings
        .iter()
        .map(|m| match m {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
        })
        .collect()
}

// ============================================================================
// 1. Round-trip safety
// ============================================================================

#[test]
fn test_roundtrip_prepare_from_literal() {
    format_and_verify("PREPARE stmt1 FROM 'SELECT * FROM customers WHERE id = ?';");
}

#[test]
fn test_roundtrip_prepare_from_var() {
    format_and_verify("PREPARE stmt2 FROM @sql;");
}

#[test]
fn test_roundtrip_execute_bare() {
    format_and_verify("EXECUTE stmt1;");
}

#[test]
fn test_roundtrip_execute_using() {
    format_and_verify("EXECUTE stmt1 USING @cid, @status;");
}

#[test]
fn test_roundtrip_deallocate() {
    format_and_verify("DEALLOCATE PREPARE stmt1;");
}

#[test]
fn test_roundtrip_drop_prepare() {
    format_and_verify("DROP PREPARE stmt2;");
}

#[test]
fn test_roundtrip_execute_quoted_name() {
    format_and_verify("EXECUTE `my stmt` USING @v;");
}

// ============================================================================
// 2. AST structure
// ============================================================================

#[test]
fn test_execute_bare_is_pg_execute() {
    assert_eq!(stmt_name(&single("EXECUTE stmt1;")), "PgExecute");
}

#[test]
fn test_execute_using_typed() {
    match single("EXECUTE stmt1 USING @cid, @status;") {
        AstStmt::PgExecute(e) => {
            assert!(e.using_span.is_some(), "USING tail should be captured");
            assert!(e.args_span.is_none(), "no parenthesized args in MySQL form");
        }
        other => panic!("expected PgExecute, got {}", stmt_name(&other)),
    }
}

#[test]
fn test_drop_prepare_is_deallocate() {
    match single("DROP PREPARE stmt2;") {
        AstStmt::PgDeallocate(d) => {
            assert!(d.prepare_span.is_some(), "PREPARE keyword span expected");
        }
        other => panic!(
            "DROP PREPARE should type as deallocate, got {}",
            stmt_name(&other)
        ),
    }
}

// ============================================================================
// 3. Dialect gating
// ============================================================================

#[test]
fn test_snowflake_rejects_execute_name_using() {
    // Snowflake routes EXECUTE to EXECUTE IMMEDIATE; `stmt USING ...` degrades.
    assert_snowflake_opaque("EXECUTE stmt1 USING @cid;");
}

// ============================================================================
// 4. Flagship: dynamic-SQL injection detection on prepared statements
// ============================================================================

#[test]
fn test_prepare_from_concat_flags_injection() {
    let ids = mysql_rule_ids(
        "PREPARE stmt FROM CONCAT('SELECT * FROM users WHERE name = ''', @input, '''');\n\
         EXECUTE stmt USING @input;",
    );
    assert!(
        ids.contains("DYNSQL-CONCAT"),
        "concatenated prepared-statement body must flag DYNSQL-CONCAT, got {:?}",
        ids
    );
    // DYNSQL-CONCAT reports the concatenated body; DYNSQL does not again.
    assert!(
        !ids.contains("DYNSQL"),
        "a concatenated body is DYNSQL-CONCAT's alone, got {:?}",
        ids
    );
}

#[test]
fn a_prepared_body_built_by_concat_ws_is_a_concatenation() {
    // `CONCAT_WS` joins its operands with the separator: the body is built
    // from the variable as `CONCAT` builds it.
    let ids = mysql_rule_ids(
        "PREPARE stmt FROM CONCAT_WS(' ', 'SELECT * FROM users WHERE name =', @input);\n\
         EXECUTE stmt;",
    );
    assert!(
        ids.contains("DYNSQL-CONCAT"),
        "a body CONCAT_WS builds must flag DYNSQL-CONCAT, got {:?}",
        ids
    );
}

#[test]
fn test_prepare_from_static_literal_no_concat_finding() {
    // A fully static literal body is not a concatenation-injection vector.
    let ids = mysql_rule_ids("PREPARE stmt FROM 'SELECT 1';");
    assert!(
        !ids.contains("DYNSQL-CONCAT"),
        "static literal body must not flag DYNSQL-CONCAT, got {:?}",
        ids
    );
}
