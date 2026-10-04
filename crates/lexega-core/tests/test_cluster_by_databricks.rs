// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt,
    DatabricksDialect, FormatterConfig,
};
use std::sync::Arc;

// ─── helpers ────────────────────────────────────────────────────────────────

fn dbx_format_and_verify(sql: &str) -> String {
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

fn parses_as_alter_table(sql: &str) -> bool {
    let script = parse_sql(sql).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::AlterTable(_)))
}

// ============================================================================
// Parsing tests — CLUSTER BY NONE / AUTO
// ============================================================================

#[test]
fn test_cluster_by_none_parses() {
    assert!(parses_as_alter_table("ALTER TABLE t CLUSTER BY NONE;"));
}

#[test]
fn test_cluster_by_none_qualified_parses() {
    assert!(parses_as_alter_table(
        "ALTER TABLE catalog.schema.t CLUSTER BY NONE;"
    ));
}

#[test]
fn test_cluster_by_auto_parses() {
    assert!(parses_as_alter_table("ALTER TABLE t CLUSTER BY AUTO;"));
}

#[test]
fn test_cluster_by_columns_still_parses() {
    assert!(parses_as_alter_table("ALTER TABLE t CLUSTER BY (a, b);"));
}

// ============================================================================
// Formatting tests — CLUSTER BY NONE / AUTO round-trip
// ============================================================================

#[test]
fn test_cluster_by_none_formats() {
    dbx_format_and_verify("ALTER TABLE t CLUSTER BY NONE;");
}

#[test]
fn test_cluster_by_none_qualified_formats() {
    dbx_format_and_verify("ALTER TABLE catalog.schema.my_table CLUSTER BY NONE;");
}

#[test]
fn test_cluster_by_auto_formats() {
    dbx_format_and_verify("ALTER TABLE t CLUSTER BY AUTO;");
}

#[test]
fn test_cluster_by_columns_formats() {
    dbx_format_and_verify("ALTER TABLE t CLUSTER BY (col1, col2);");
}

#[test]
fn test_cluster_by_none_idempotent() {
    let sql = "ALTER TABLE my_catalog.my_schema.t CLUSTER BY NONE;";
    let config = FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    };
    let formatted1 = format_sql_with_config(sql, &config).expect("first format");
    let formatted2 = format_sql_with_config(&formatted1, &config).expect("second format");
    assert_eq!(formatted1, formatted2, "Formatting should be idempotent");
}

// ============================================================================
// Risk analysis — CLUSTER BY NONE should trigger DBX-TBL-CLUSTER-OFF
// ============================================================================

#[test]
fn test_cluster_by_none_risk_signal() {
    let report = dbx_analyze("ALTER TABLE t CLUSTER BY NONE;");

    assert!(
        has_signal(&report, "DBX-TBL-CLUSTER-OFF"),
        "CLUSTER BY NONE should generate DBX-TBL-CLUSTER-OFF (clustering removed). Signals: {:?}",
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
fn test_cluster_by_none_risk_level() {
    let report = dbx_analyze("ALTER TABLE t CLUSTER BY NONE;");

    assert!(
        report.summary.high_count >= 1,
        "CLUSTER BY NONE should produce at least one High signal. Got: high={}",
        report.summary.high_count
    );
}

#[test]
fn test_cluster_by_columns_info_signal() {
    let report = dbx_analyze("ALTER TABLE t CLUSTER BY (a, b);");

    assert!(
        has_signal(&report, "INFO-DBX-TBL-CLUSTER-CFG"),
        "CLUSTER BY (cols) should generate INFO-DBX-TBL-CLUSTER-CFG (clustering configured). Signals: {:?}",
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
fn test_cluster_by_auto_info_signal() {
    let report = dbx_analyze("ALTER TABLE t CLUSTER BY AUTO;");

    // AUTO is not NONE, so it should emit "configured", not "disabled"
    assert!(
        has_signal(&report, "INFO-DBX-TBL-CLUSTER-CFG"),
        "CLUSTER BY AUTO should generate INFO-DBX-TBL-CLUSTER-CFG (clustering configured). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );

    // AUTO should NOT trigger the "disabled" rule
    assert!(
        !has_signal(&report, "DBX-TBL-CLUSTER-OFF"),
        "CLUSTER BY AUTO should NOT generate DBX-TBL-CLUSTER-OFF (that's for NONE only)"
    );
}

#[test]
fn test_cluster_by_none_not_on_columns() {
    let report = dbx_analyze("ALTER TABLE t CLUSTER BY (a, b);");

    // Setting columns should NOT trigger the "disabled" rule
    assert!(
        !has_signal(&report, "DBX-TBL-CLUSTER-OFF"),
        "CLUSTER BY (cols) should NOT generate DBX-TBL-CLUSTER-OFF (that's for NONE only)"
    );
}

#[test]
fn test_cluster_by_multi_statement() {
    let sql = r#"
        ALTER TABLE t1 CLUSTER BY NONE;
        ALTER TABLE t2 CLUSTER BY (x, y);
        ALTER TABLE t3 CLUSTER BY AUTO;
    "#;
    let report = dbx_analyze(sql);

    // t1 should trigger clustering disabled
    let disabled_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-TBL-CLUSTER-OFF"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        disabled_evidence >= 1,
        "Should have at least 1 clustering-disabled evidence. Got {}",
        disabled_evidence
    );

    // t2 and t3 should trigger clustering configured
    let configured_evidence: usize = report
        .signals
        .iter()
        .filter(
            |s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "INFO-DBX-TBL-CLUSTER-CFG"),
        )
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        configured_evidence >= 2,
        "Should have at least 2 clustering-configured evidence (t2 + t3). Got {}",
        configured_evidence
    );
}
