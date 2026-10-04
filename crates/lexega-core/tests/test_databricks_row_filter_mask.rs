// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql_with_dialect,
    verify_formatting_safe, AstStmt, DatabricksDialect, FormatterConfig,
};
use std::sync::Arc;

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

fn parse_without_opaque(sql: &str) {
    let dialect = DatabricksDialect;
    let script = parse_sql_with_dialect(sql, &dialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
}

fn roundtrip(sql: &str) {
    let config = FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
}

#[test]
fn test_parse_set_row_filter() {
    parse_without_opaque("ALTER TABLE t SET ROW FILTER rf_fn ON (c1);");
}

#[test]
fn test_parse_drop_row_filter() {
    parse_without_opaque("ALTER TABLE t DROP ROW FILTER;");
}

#[test]
fn test_parse_set_and_drop_column_mask() {
    parse_without_opaque("ALTER TABLE t ALTER COLUMN c1 SET MASK mask_fn;");
    parse_without_opaque("ALTER TABLE t ALTER COLUMN c1 DROP MASK;");
}

#[test]
fn test_roundtrip_row_filter_and_mask_variants() {
    roundtrip("ALTER TABLE t SET ROW FILTER rf_fn ON (c1);");
    roundtrip("ALTER TABLE t DROP ROW FILTER;");
    roundtrip("ALTER TABLE t ALTER COLUMN c1 SET MASK mask_fn;");
    roundtrip("ALTER TABLE t ALTER COLUMN c1 DROP MASK;");
}

#[test]
fn test_parse_databricks_create_function_return_form() {
    parse_without_opaque("CREATE FUNCTION rf_fn(x INT) RETURNS BOOLEAN RETURN x > 0;");
    parse_without_opaque("CREATE FUNCTION mask_fn(x STRING) RETURNS STRING RETURN '***';");
}

#[test]
fn test_roundtrip_databricks_create_function_return_form() {
    roundtrip("CREATE FUNCTION rf_fn(x INT) RETURNS BOOLEAN RETURN x > 0;");
    roundtrip("CREATE FUNCTION mask_fn(x STRING) RETURNS STRING RETURN '***';");
}

#[test]
fn test_create_function_return_plus_row_filter_still_emits_governance_signal() {
    let sql = r#"
        CREATE FUNCTION rf_fn(x INT) RETURNS BOOLEAN RETURN x > 0;
        ALTER TABLE t SET ROW FILTER rf_fn ON (c1);
    "#;
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "TBL-RAP-ADD"),
        "Expected TBL-RAP-ADD for row filter attachment even with preceding CREATE FUNCTION RETURN syntax. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_row_filter_set_emits_tbl_rap_add() {
    let report = dbx_analyze("ALTER TABLE t SET ROW FILTER rf_fn ON (c1);");
    assert!(
        has_signal(&report, "TBL-RAP-ADD"),
        "Expected TBL-RAP-ADD for row filter attachment. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_row_filter_drop_emits_tbl_rap_rmv() {
    let report = dbx_analyze("ALTER TABLE t DROP ROW FILTER;");
    assert!(
        has_signal(&report, "TBL-RAP-RMV"),
        "Expected TBL-RAP-RMV for row filter removal. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_column_mask_set_emits_tbl_mask_add() {
    let report = dbx_analyze("ALTER TABLE t ALTER COLUMN c1 SET MASK mask_fn;");
    assert!(
        has_signal(&report, "TBL-MASK-ADD"),
        "Expected TBL-MASK-ADD for column mask attachment. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_column_mask_drop_emits_tbl_mask_rmv() {
    let report = dbx_analyze("ALTER TABLE t ALTER COLUMN c1 DROP MASK;");
    assert!(
        has_signal(&report, "TBL-MASK-RMV"),
        "Expected TBL-MASK-RMV for column mask removal. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_multi_statement_column_mask_drop_evidence_count() {
    let sql = r#"
        ALTER TABLE t1 ALTER COLUMN c1 DROP MASK;
        ALTER TABLE t2 ALTER COLUMN c2 DROP MASK;
    "#;
    let report = dbx_analyze(sql);

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "TBL-MASK-RMV"))
        .map(|s| {
            let RuleMatch::Analysis(g) = s;
            g.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Expected evidence_count >= 2 for two DROP MASK statements, got {}",
        total_evidence
    );
}
