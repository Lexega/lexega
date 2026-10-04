// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks Delta MERGE semantics.
//!
//! Covers:
//! - WITH SCHEMA EVOLUTION capture
//! - UPDATE SET * and INSERT * action parsing
//! - NOT MATCHED BY TARGET / BY SOURCE clause kinds
//! - Roundtrip formatting safety under Databricks dialect
//! - Analysis path execution under Databricks dialect

use lexega_core::{
    analyzer::AnalysisConfig,
    ast::{AstMergeActionKind, AstMergeClauseKind, AstStmt},
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe, DatabricksDialect,
    FormatterConfig,
};

use lexega_core::api::analyze_risk_with_policy_config;
use std::sync::Arc;

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    }
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_analysis_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(
        |s| matches!(s, lexega_core::analyzer::RuleMatch::Analysis(g) if g.matched_rule == rule_id),
    )
}

fn parse_single_merge(sql: &str) -> lexega_core::ast::AstMerge {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    assert_eq!(script.stmts.len(), 1, "expected exactly one statement");

    match &script.stmts[0] {
        AstStmt::Merge(merge) => (**merge).clone(),
        other => panic!("expected AstStmt::Merge, got: {:?}", other),
    }
}

#[test]
fn parse_merge_with_schema_evolution_and_star_actions() {
    let sql = r#"
MERGE WITH SCHEMA EVOLUTION INTO target t
USING source s
ON t.id = s.id
WHEN MATCHED THEN UPDATE SET *
WHEN NOT MATCHED THEN INSERT *;
"#;

    let merge = parse_single_merge(sql);

    assert!(
        merge.with_schema_evolution_span.is_some(),
        "expected WITH SCHEMA EVOLUTION span"
    );
    assert_eq!(merge.clauses.len(), 2, "expected two WHEN clauses");

    assert!(matches!(
        merge.clauses[0].action,
        AstMergeActionKind::UpdateSetStar { .. }
    ));
    assert!(matches!(
        merge.clauses[1].action,
        AstMergeActionKind::InsertStar { .. }
    ));
}

#[test]
fn parse_merge_not_matched_by_target_and_source_forms() {
    let sql = r#"
MERGE INTO target t
USING source s
ON t.id = s.id
WHEN NOT MATCHED BY TARGET THEN INSERT *
WHEN NOT MATCHED BY SOURCE THEN UPDATE SET t.status = 'inactive';
"#;

    let merge = parse_single_merge(sql);
    assert_eq!(merge.clauses.len(), 2, "expected two WHEN clauses");

    assert_eq!(
        merge.clauses[0].kind,
        AstMergeClauseKind::NotMatchedByTarget,
        "first clause should be NOT MATCHED BY TARGET"
    );
    assert_eq!(
        merge.clauses[1].kind,
        AstMergeClauseKind::NotMatchedBySource,
        "second clause should be NOT MATCHED BY SOURCE"
    );

    assert!(matches!(
        merge.clauses[0].action,
        AstMergeActionKind::InsertStar { .. }
    ));
    assert!(matches!(
        merge.clauses[1].action,
        AstMergeActionKind::UpdateSet { .. }
    ));
}

#[test]
fn format_merge_delta_roundtrip_safe() {
    let sql = r#"
MERGE WITH SCHEMA EVOLUTION INTO target t
USING source s
ON t.id = s.id
WHEN MATCHED THEN UPDATE SET *
WHEN NOT MATCHED BY TARGET THEN INSERT *
WHEN NOT MATCHED BY SOURCE AND t.is_active = true THEN UPDATE SET t.status = 'inactive';
"#;

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("formatting should preserve semantics");
}

#[test]
fn analyze_merge_delta_databricks_dialect_executes() {
    let sql = r#"
MERGE WITH SCHEMA EVOLUTION INTO target t
USING source s
ON t.id = s.id
WHEN MATCHED THEN UPDATE SET *
WHEN NOT MATCHED THEN INSERT *;
"#;

    let report = dbx_analyze(sql);

    assert!(
        report.summary.statements_parsed >= 1,
        "expected at least one parsed statement, got {}",
        report.summary.statements_parsed
    );
    assert!(
        report.summary.statements_analyzed >= 1,
        "expected at least one analyzed statement, got {}",
        report.summary.statements_analyzed
    );

    assert!(
        has_analysis_rule(&report, "DBX-MERGE-SCHEMA-EVO"),
        "expected DBX-MERGE-SCHEMA-EVO for MERGE WITH SCHEMA EVOLUTION"
    );
}
