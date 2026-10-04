// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks COMMENT ON parsing, formatting, and risk analysis.
//!
//! Covers:
//! - COMMENT ON CATALOG / TABLE / COLUMN / SCHEMA / DATABASE
//! - COMMENT ON VOLUME / CONNECTION / SHARE / RECIPIENT / PROVIDER
//! - COMMENT ON ... IS NULL (comment removal)
//! - Qualified names (catalog.schema.table.column)
//! - Signal emission with object-kind-specific surfaces
//! - YAML rule matching: INFO-COMMENT-CHG (generic), INFO-DBX-CAT-COMMENT-CHG..INFO-DBX-CONN-COMMENT-CHG

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, verify_formatting_safe, DatabricksDialect,
    FormatterConfig,
};
use std::sync::Arc;

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    }
}

fn dbx_format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &dbx_config())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn signal_evidence_count(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> usize {
    report
        .signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(g) if g.matched_rule == rule_id => {
                Some(g.evidence_count.unwrap_or(1))
            }
            _ => None,
        })
        .sum()
}

// ─── FORMATTING: Basic Object Kinds ─────────────────────────────────────────

#[test]
fn test_comment_on_catalog_format() {
    dbx_format_and_verify("COMMENT ON CATALOG my_catalog IS 'This is my catalog';");
}

#[test]
fn test_comment_on_column_format() {
    dbx_format_and_verify("COMMENT ON COLUMN my_table.c1 IS 'This is my column';");
}

#[test]
fn test_comment_on_connection_format() {
    dbx_format_and_verify("COMMENT ON CONNECTION mysql_connection IS 'mysql conn';");
}

#[test]
fn test_comment_on_schema_format() {
    dbx_format_and_verify("COMMENT ON SCHEMA my_schema IS 'This is my schema';");
}

#[test]
fn test_comment_on_database_format() {
    dbx_format_and_verify("COMMENT ON DATABASE my_db IS 'This is my database';");
}

#[test]
fn test_comment_on_table_format() {
    dbx_format_and_verify("COMMENT ON TABLE my_table IS 'This is my table';");
}

#[test]
fn test_comment_on_share_format() {
    dbx_format_and_verify("COMMENT ON SHARE my_share IS 'A good share';");
}

#[test]
fn test_comment_on_recipient_format() {
    dbx_format_and_verify("COMMENT ON RECIPIENT my_recipient IS 'A good recipient';");
}

#[test]
fn test_comment_on_provider_format() {
    dbx_format_and_verify("COMMENT ON PROVIDER my_provider IS 'A good provider';");
}

#[test]
fn test_comment_on_volume_format() {
    dbx_format_and_verify("COMMENT ON VOLUME my_volume IS 'Huge volume';");
}

// ─── FORMATTING: IS NULL (Comment Removal) ──────────────────────────────────

#[test]
fn test_comment_on_table_is_null_format() {
    dbx_format_and_verify("COMMENT ON TABLE my_table IS NULL;");
}

#[test]
fn test_comment_on_catalog_is_null_format() {
    dbx_format_and_verify("COMMENT ON CATALOG my_catalog IS NULL;");
}

// ─── FORMATTING: Qualified Names ────────────────────────────────────────────

#[test]
fn test_comment_on_column_qualified_format() {
    dbx_format_and_verify(
        "COMMENT ON COLUMN catalog.schema.my_table.c1 IS 'Fully qualified column';",
    );
}

#[test]
fn test_comment_on_table_qualified_format() {
    dbx_format_and_verify("COMMENT ON TABLE catalog.schema.my_table IS 'Fully qualified table';");
}

#[test]
fn test_comment_on_volume_qualified_format() {
    dbx_format_and_verify("COMMENT ON VOLUME catalog.schema.my_volume IS 'A volume';");
}

// ─── RISK ANALYSIS: Generic Signal (INFO-COMMENT-CHG) ───────────────────────────────

#[test]
fn test_comment_on_generic_signal() {
    let sql = "COMMENT ON TABLE my_table IS 'desc';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG (generic COMMENT ON) should fire for TABLE. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_comment_on_column_generic_signal() {
    let sql = "COMMENT ON COLUMN my_table.c1 IS 'col desc';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG should fire for COLUMN"
    );
}

#[test]
fn test_comment_on_schema_generic_signal() {
    let sql = "COMMENT ON SCHEMA my_schema IS 'schema desc';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG should fire for SCHEMA"
    );
}

// ─── RISK ANALYSIS: Databricks-Specific Rules ──────────────────────────────

#[test]
fn test_comment_on_catalog_dbx_signal() {
    let sql = "COMMENT ON CATALOG my_catalog IS 'This is my catalog';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "INFO-DBX-CAT-COMMENT-CHG"),
        "INFO-DBX-CAT-COMMENT-CHG (Catalog Comment Changed) should fire. Signals: {:?}",
        report.signals
    );
    // Generic INFO-COMMENT-CHG should also fire
    assert!(
        has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG should also fire for CATALOG"
    );
}

#[test]
fn test_comment_on_volume_dbx_signal() {
    let sql = "COMMENT ON VOLUME my_volume IS 'Huge volume';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "INFO-DBX-VOL-COMMENT-CHG"),
        "INFO-DBX-VOL-COMMENT-CHG (Volume Comment Changed) should fire. Signals: {:?}",
        report.signals
    );
    assert!(
        has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG should also fire for VOLUME"
    );
}

#[test]
fn test_comment_on_connection_dbx_signal() {
    let sql = "COMMENT ON CONNECTION mysql_connection IS 'mysql conn';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "INFO-DBX-CONN-COMMENT-CHG"),
        "INFO-DBX-CONN-COMMENT-CHG (Connection Comment Changed) should fire. Signals: {:?}",
        report.signals
    );
    assert!(
        has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG should also fire for CONNECTION"
    );
}

// ─── RISK ANALYSIS: Non-DBX Objects Only Get INFO-COMMENT-CHG ───────────────────────

#[test]
fn test_comment_on_share_only_generic() {
    let sql = "COMMENT ON SHARE my_share IS 'A good share';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG should fire for SHARE"
    );
    // SHARE/RECIPIENT/PROVIDER use Metadata surface — no specific DBX rule
    assert!(
        !has_signal(&report, "INFO-DBX-CAT-COMMENT-CHG"),
        "INFO-DBX-CAT-COMMENT-CHG should not fire for SHARE"
    );
    assert!(
        !has_signal(&report, "INFO-DBX-VOL-COMMENT-CHG"),
        "INFO-DBX-VOL-COMMENT-CHG should not fire for SHARE"
    );
    assert!(
        !has_signal(&report, "INFO-DBX-CONN-COMMENT-CHG"),
        "INFO-DBX-CONN-COMMENT-CHG should not fire for SHARE"
    );
}

// ─── RISK ANALYSIS: IS NULL (Comment Removal) ──────────────────────────────

#[test]
fn test_comment_on_is_null_still_signals() {
    let sql = "COMMENT ON TABLE my_table IS NULL;";
    let report = dbx_analyze(sql);
    assert!(has_signal(&report, "INFO-COMMENT-CHG"),
        "INFO-COMMENT-CHG should fire even for IS NULL (comment removal is still a metadata change)");
}

// ─── RISK ANALYSIS: Multi-Statement Evidence Counting ───────────────────────

#[test]
fn test_comment_on_multi_statement_evidence() {
    let sql = r#"
        COMMENT ON CATALOG cat1 IS 'desc1';
        COMMENT ON CATALOG cat2 IS 'desc2';
        COMMENT ON CATALOG cat3 IS 'desc3';
    "#;
    let report = dbx_analyze(sql);

    // INFO-COMMENT-CHG should have evidence for all 3
    let generic_evidence = signal_evidence_count(&report, "INFO-COMMENT-CHG");
    assert!(
        generic_evidence >= 3,
        "INFO-COMMENT-CHG should have at least 3 evidence entries, got {}",
        generic_evidence
    );

    // INFO-DBX-CAT-COMMENT-CHG should also have evidence for all 3 (they're all CATALOG)
    let catalog_evidence = signal_evidence_count(&report, "INFO-DBX-CAT-COMMENT-CHG");
    assert!(
        catalog_evidence >= 3,
        "INFO-DBX-CAT-COMMENT-CHG should have at least 3 evidence entries, got {}",
        catalog_evidence
    );
}

#[test]
fn test_comment_on_mixed_objects_evidence() {
    let sql = r#"
        COMMENT ON CATALOG my_catalog IS 'cat desc';
        COMMENT ON VOLUME my_volume IS 'vol desc';
        COMMENT ON CONNECTION my_conn IS 'conn desc';
        COMMENT ON TABLE my_table IS 'table desc';
    "#;
    let report = dbx_analyze(sql);

    // INFO-COMMENT-CHG matches all 4
    let generic_evidence = signal_evidence_count(&report, "INFO-COMMENT-CHG");
    assert!(
        generic_evidence >= 4,
        "INFO-COMMENT-CHG should have at least 4 evidence entries, got {}",
        generic_evidence
    );

    // Each DBX rule should have exactly 1
    assert!(
        has_signal(&report, "INFO-DBX-CAT-COMMENT-CHG"),
        "Should have CATALOG signal"
    );
    assert!(
        has_signal(&report, "INFO-DBX-VOL-COMMENT-CHG"),
        "Should have VOLUME signal"
    );
    assert!(
        has_signal(&report, "INFO-DBX-CONN-COMMENT-CHG"),
        "Should have CONNECTION signal"
    );
}
