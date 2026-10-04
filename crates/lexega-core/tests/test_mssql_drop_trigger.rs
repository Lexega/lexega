// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
/// Tests for MSSQL DROP TRIGGER statement support.
///
/// Tests cover:
///   1. Parsing produces AstDropMssqlTrigger (not OpaqueContent)
///   2. Formatting preserves semantic tokens
///   3. Risk analysis emits TRIG-DROP signals
use lexega_core::ast::AstStmt;
use lexega_core::dialect::mssql;
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig, MsSqlDialect};
use std::collections::HashSet;
use std::sync::Arc;

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
        AstStmt::DropMssqlTrigger(_) => "DropMssqlTrigger",
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
    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
}

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_mssql(sql: &str) -> HashSet<String> {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(MsSqlDialect));
    match analyze_risk_with_policy_config(sql, &config) {
        Ok(report) => extract_rule_ids(&report.signals),
        Err(e) => {
            eprintln!("Risk analysis error (MSSQL dialect): {:?}", e);
            HashSet::new()
        }
    }
}

// ============================================================================
// Basic DROP TRIGGER parsing
// ============================================================================

#[test]
fn test_drop_trigger_simple() {
    format_verify_and_assert_variant("DROP TRIGGER trg_audit;", "DropMssqlTrigger");
}

#[test]
fn test_drop_trigger_schema_qualified() {
    format_verify_and_assert_variant("DROP TRIGGER dbo.trg_audit;", "DropMssqlTrigger");
}

#[test]
fn test_drop_trigger_if_exists() {
    format_verify_and_assert_variant("DROP TRIGGER IF EXISTS trg_audit;", "DropMssqlTrigger");
}

#[test]
fn test_drop_trigger_if_exists_schema_qualified() {
    format_verify_and_assert_variant("DROP TRIGGER IF EXISTS dbo.trg_audit;", "DropMssqlTrigger");
}

// ============================================================================
// Comma-separated multi-drop
// ============================================================================

#[test]
fn test_drop_trigger_comma_list() {
    format_verify_and_assert_variant(
        "DROP TRIGGER trg_one, trg_two, trg_three;",
        "DropMssqlTrigger",
    );
}

#[test]
fn test_drop_trigger_comma_list_schema_qualified() {
    format_verify_and_assert_variant(
        "DROP TRIGGER dbo.trg_one, sales.trg_two;",
        "DropMssqlTrigger",
    );
}

#[test]
fn test_drop_trigger_if_exists_comma_list() {
    format_verify_and_assert_variant("DROP TRIGGER IF EXISTS trg_a, trg_b;", "DropMssqlTrigger");
}

// ============================================================================
// DDL trigger scopes: ON DATABASE, ON ALL SERVER
// ============================================================================

#[test]
fn test_drop_trigger_on_database() {
    format_verify_and_assert_variant("DROP TRIGGER trg_ddl ON DATABASE;", "DropMssqlTrigger");
}

#[test]
fn test_drop_trigger_on_all_server() {
    format_verify_and_assert_variant("DROP TRIGGER trg_server ON ALL SERVER;", "DropMssqlTrigger");
}

#[test]
fn test_drop_trigger_if_exists_on_database() {
    format_verify_and_assert_variant(
        "DROP TRIGGER IF EXISTS trg_ddl ON DATABASE;",
        "DropMssqlTrigger",
    );
}

#[test]
fn test_drop_trigger_if_exists_on_all_server() {
    format_verify_and_assert_variant(
        "DROP TRIGGER IF EXISTS trg_srv ON ALL SERVER;",
        "DropMssqlTrigger",
    );
}

#[test]
fn test_drop_trigger_comma_on_database() {
    format_verify_and_assert_variant("DROP TRIGGER trg_a, trg_b ON DATABASE;", "DropMssqlTrigger");
}

// ============================================================================
// Risk analysis — TRIG-DROP signal
// ============================================================================

#[test]
fn test_drop_trigger_emits_trig_drop() {
    let rules = analyze_mssql("DROP TRIGGER trg_audit;");
    assert!(
        rules.contains("TRIG-DROP"),
        "TRIG-DROP should fire for MSSQL DROP TRIGGER. Got: {:?}",
        rules
    );
}

#[test]
fn test_drop_trigger_if_exists_emits_trig_drop() {
    let rules = analyze_mssql("DROP TRIGGER IF EXISTS trg_audit;");
    assert!(
        rules.contains("TRIG-DROP"),
        "TRIG-DROP should fire for MSSQL DROP TRIGGER IF EXISTS. Got: {:?}",
        rules
    );
}

#[test]
fn test_drop_trigger_multi_emits_trig_drop() {
    let rules = analyze_mssql("DROP TRIGGER trg_a, trg_b, trg_c;");
    assert!(
        rules.contains("TRIG-DROP"),
        "TRIG-DROP should fire for MSSQL DROP TRIGGER with comma list. Got: {:?}",
        rules
    );
}

#[test]
fn test_drop_trigger_on_database_emits_trig_drop() {
    let rules = analyze_mssql("DROP TRIGGER trg_ddl ON DATABASE;");
    assert!(
        rules.contains("TRIG-DROP"),
        "TRIG-DROP should fire for MSSQL DROP TRIGGER ON DATABASE. Got: {:?}",
        rules
    );
}

// ============================================================================
// Multi-statement tests (evidence count)
// ============================================================================

#[test]
fn test_drop_trigger_multi_statement_evidence() {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(MsSqlDialect));
    let sql = "DROP TRIGGER trg_a;\nDROP TRIGGER trg_b;";
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(g) if g.matched_rule == "TRIG-DROP"))
        .map(|f| match f {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Should have evidence for each DROP TRIGGER. Got evidence: {}",
        total_evidence
    );
}

// ============================================================================
// PG DROP TRIGGER still routes correctly (regression)
// ============================================================================

#[test]
fn test_pg_drop_trigger_not_affected() {
    // PG DROP TRIGGER uses ON table_name syntax — should NOT become DropMssqlTrigger
    let sql = "DROP TRIGGER audit_trigger ON orders;";
    let stmts = parse_mssql(sql); // using mssql dialect, but ON <table> → PG path
    assert!(!stmts.is_empty());
    // Should parse as PG trigger (DropPgTrigger), not MSSQL
    let variant = ast_variant_name(&stmts[0]);
    assert_ne!(
        variant, "DropMssqlTrigger",
        "PG-style DROP TRIGGER ON table should NOT parse as MSSQL. Got: {}",
        variant
    );
}
