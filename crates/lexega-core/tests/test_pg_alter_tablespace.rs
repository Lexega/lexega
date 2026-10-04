// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for ALTER TABLESPACE (PostgreSQL storage management).
//!
//! Verifies: parsing, formatting, semantic analysis, governance signal (PG-TBLSPC-CHG).

use lexega_core::{
    analyzer::{AnalysisConfig, RuleMatch},
    dialect, format_sql_with_config, verify_formatting_safe, FormatterConfig, PostgresDialect,
};

use lexega_core::api::analyze_risk_with_policy_config;
use std::sync::Arc;

/// PG-dialect analysis helper with trace mode.
fn pg_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(PostgresDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| match s {
        RuleMatch::Analysis(g) => g.matched_rule == rule_id,
    })
}

fn pg_format(sql: &str) -> String {
    let config = FormatterConfig {
        dialect: dialect::postgres(),
        ..Default::default()
    };
    format_sql_with_config(sql, &config).expect("should format")
}

// ── Formatting tests ────────────────────────────────────────────────────

#[test]
fn test_alter_tablespace_set_formats() {
    let sql = "ALTER TABLESPACE my_space SET (random_page_cost = 1.0);";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
}

#[test]
fn test_alter_tablespace_reset_formats() {
    let sql = "ALTER TABLESPACE my_space RESET (seq_page_cost);";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
}

#[test]
fn test_alter_tablespace_rename_formats() {
    let sql = "ALTER TABLESPACE pg_global RENAME TO fast_space;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
}

#[test]
fn test_alter_tablespace_owner_formats() {
    let sql = "ALTER TABLESPACE my_space OWNER TO new_owner;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
}

// ── Risk analysis tests ─────────────────────────────────────────────────

#[test]
fn test_alter_tablespace_fires_pg_c041() {
    let sql = "ALTER TABLESPACE my_space SET (random_page_cost = 1.0);";
    let report = pg_analyze(sql);

    assert!(
        has_rule(&report, "PG-TBLSPC-CHG"),
        "Should fire PG-TBLSPC-CHG for ALTER TABLESPACE. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.as_str(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_alter_tablespace_classified_as_ddl() {
    let sql = "ALTER TABLESPACE my_space SET (random_page_cost = 1.0);";
    let report = pg_analyze(sql);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "ALTER TABLESPACE should be classified as DDL"
    );
}

#[test]
fn test_alter_tablespace_analyzed_not_skipped() {
    let sql = "ALTER TABLESPACE my_space SET (random_page_cost = 1.0);";
    let report = pg_analyze(sql);
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "ALTER TABLESPACE should be analyzed (not skipped)"
    );
    assert_eq!(
        report.summary.statements_skipped, 0,
        "ALTER TABLESPACE should NOT be skipped"
    );
}

// ── Multi-statement test (catch NodeId collision bugs) ──────────────────

#[test]
fn test_alter_tablespace_multi_statement() {
    let sql = r#"
        ALTER TABLESPACE space1 SET (random_page_cost = 1.0);
        ALTER TABLESPACE space2 RENAME TO fast_space;
        ALTER TABLESPACE space3 OWNER TO admin;
    "#;
    let report = pg_analyze(sql);

    assert_eq!(
        report.summary.statements_analyzed, 3,
        "All 3 ALTER TABLESPACE statements should be analyzed"
    );

    // Count total evidence for PG-TBLSPC-CHG
    let evidence_count: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "PG-TBLSPC-CHG"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        evidence_count >= 3,
        "Should have evidence for all 3 ALTER TABLESPACE statements, got {}",
        evidence_count
    );
}
