// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A top-level SELECT with a row-cap clause (T-SQL `TOP`, `LIMIT`,
//! `OFFSET … FETCH`) must be analyzed, not flagged as
//! `UnimplementedStatementType`.
//!
//! Lowering wraps the inner plan in `RelPlan::Limit { … span: clause_span }`
//! where the span covers only the row-cap clause, and the analyzer ledger
//! indexes facts by `source_span.start`. When `Limit` is the *root* of a
//! top-level SELECT (no outer Insert / CTE wrapper), the facts must carry
//! the AST statement's outer span — `derive_facts_from_query_plan_with_catalog`
//! takes it — or the ledger lookup misses and the statement is annotated as
//! skipped. Wrapped variants (`INSERT INTO … SELECT TOP …`,
//! `WITH cte AS (SELECT TOP …) SELECT …`) are covered by the outer plan's
//! own span.

use lexega_core::{analyzer::AnalysisConfig, dialect::dialect_from_name};

use lexega_core::api::analyze_risk_with_policy_config;

fn analyze(sql: &str, dialect_name: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: dialect_from_name(dialect_name),
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn assert_analyzed(sql: &str, dialect: &str, label: &str) {
    let report = analyze(sql, dialect);
    assert_eq!(
        report.summary.statements_skipped, 0,
        "{label} ({dialect}): expected 0 skipped, got {}. skipped_details={:?}",
        report.summary.statements_skipped, report.skipped_details
    );
    assert!(
        report.skipped_details.is_empty(),
        "{label} ({dialect}): expected no skipped_details, got {:?}",
        report.skipped_details
    );
    assert!(
        report.summary.statements_analyzed >= 1,
        "{label} ({dialect}): expected at least 1 analyzed statement, got {}",
        report.summary.statements_analyzed
    );
}

// ============================================================================
// T-SQL TOP — every variant
// ============================================================================

#[test]
fn mssql_select_top_n_is_analyzed() {
    assert_analyzed("SELECT TOP 10 x FROM t;", "mssql", "TOP n");
}

#[test]
fn mssql_select_top_n_parens_is_analyzed() {
    assert_analyzed("SELECT TOP (10) x FROM t;", "mssql", "TOP (n)");
}

#[test]
fn mssql_select_top_n_percent_is_analyzed() {
    assert_analyzed(
        "SELECT TOP (10) PERCENT x FROM t;",
        "mssql",
        "TOP n PERCENT",
    );
}

#[test]
fn mssql_select_top_n_with_ties_is_analyzed() {
    assert_analyzed(
        "SELECT TOP 10 WITH TIES x FROM t ORDER BY x;",
        "mssql",
        "TOP n WITH TIES",
    );
}

#[test]
fn mssql_select_top_with_brackets_and_system_var_is_analyzed() {
    assert_analyzed(
        "SELECT TOP 10 [a].[Label], @@ROWCOUNT AS rc \
         FROM [dbo].[Accounts] AS [a] WHERE [a].[Enabled] = 1;",
        "mssql",
        "T-SQL gnarly TOP + @@ROWCOUNT",
    );
}

// ============================================================================
// ANSI LIMIT (Snowflake / PostgreSQL / BigQuery / Databricks / MSSQL accept it)
// ============================================================================

#[test]
fn snowflake_select_limit_is_analyzed() {
    assert_analyzed("SELECT * FROM t LIMIT 10;", "snowflake", "LIMIT n");
}

#[test]
fn mssql_select_limit_is_analyzed() {
    assert_analyzed("SELECT * FROM t LIMIT 10;", "mssql", "LIMIT n (mssql)");
}

// ============================================================================
// ANSI OFFSET … FETCH
// ============================================================================

#[test]
fn snowflake_select_offset_fetch_is_analyzed() {
    assert_analyzed(
        "SELECT * FROM t ORDER BY x OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY;",
        "snowflake",
        "OFFSET … FETCH NEXT n ROWS ONLY",
    );
}

// ============================================================================
// Wrapped row-caps take the outer plan's span; assert they stay
// analyzed too.
// ============================================================================

#[test]
fn mssql_insert_from_select_top_is_analyzed() {
    assert_analyzed(
        "INSERT INTO t SELECT TOP 10 x FROM s;",
        "mssql",
        "INSERT … SELECT TOP",
    );
}

#[test]
fn mssql_cte_wrapping_select_top_is_analyzed() {
    assert_analyzed(
        "WITH cte AS (SELECT TOP 10 x FROM t) SELECT * FROM cte;",
        "mssql",
        "WITH cte AS (SELECT TOP …)",
    );
}

#[test]
fn mssql_plain_select_without_row_cap_is_analyzed() {
    // Baseline: a vanilla SELECT must still come through clean.
    assert_analyzed("SELECT x FROM t WHERE x = 1;", "mssql", "plain SELECT");
}
