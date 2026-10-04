// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql_with_dialect,
    verify_formatting_safe, AstStmt, DatabricksDialect, FormatterConfig,
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
    let dialect = DatabricksDialect;
    let script = parse_sql_with_dialect(sql, &dialect).expect("should parse");
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
// Parsing tests — SET TBLPROPERTIES
// ============================================================================

#[test]
fn test_set_tblproperties_basic_parses() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table SET TBLPROPERTIES ('delta.appendOnly' = 'true');"
    ));
}

#[test]
fn test_set_tblproperties_multiple_parses() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table SET TBLPROPERTIES ('delta.appendOnly' = 'true', 'delta.logRetentionDuration' = 'interval 30 days');"
    ));
}

#[test]
fn test_set_tblproperties_dotted_identifier_keys() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table SET TBLPROPERTIES (delta.appendOnly = true, delta.logRetentionDuration = 'interval 30 days');"
    ));
}

#[test]
fn test_set_tblproperties_qualified_table_name() {
    assert!(parses_as_alter_table(
        "ALTER TABLE catalog1.schema1.my_table SET TBLPROPERTIES ('owner_team' = 'data-eng');"
    ));
}

#[test]
fn test_set_tblproperties_integer_value() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table SET TBLPROPERTIES ('delta.dataSkippingNumIndexedCols' = 8);"
    ));
}

#[test]
fn test_set_tblproperties_boolean_value() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table SET TBLPROPERTIES ('delta.appendOnly' = true);"
    ));
}

#[test]
fn test_set_tblproperties_mixed_key_types() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table SET TBLPROPERTIES (this.is.my.key = 14, 'this.is.my.key2' = false);"
    ));
}

// ============================================================================
// Parsing tests — UNSET TBLPROPERTIES
// ============================================================================

#[test]
fn test_unset_tblproperties_basic_parses() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table UNSET TBLPROPERTIES ('delta.appendOnly');"
    ));
}

#[test]
fn test_unset_tblproperties_multiple_keys() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table UNSET TBLPROPERTIES ('delta.appendOnly', 'delta.logRetentionDuration');"
    ));
}

#[test]
fn test_unset_tblproperties_if_exists() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table UNSET TBLPROPERTIES IF EXISTS ('delta.appendOnly');"
    ));
}

#[test]
fn test_unset_tblproperties_if_exists_multiple() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table UNSET TBLPROPERTIES IF EXISTS ('delta.appendOnly', 'delta.logRetentionDuration');"
    ));
}

#[test]
fn test_unset_tblproperties_dotted_keys() {
    assert!(parses_as_alter_table(
        "ALTER TABLE my_table UNSET TBLPROPERTIES (this.is.my.key, 'this.is.my.key2');"
    ));
}

// ============================================================================
// Formatting tests — SET TBLPROPERTIES
// ============================================================================

#[test]
fn test_set_tblproperties_format_roundtrip() {
    dbx_format_and_verify("ALTER TABLE my_table SET TBLPROPERTIES ('delta.appendOnly' = 'true');");
}

#[test]
fn test_set_tblproperties_multiple_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE t SET TBLPROPERTIES ('delta.appendOnly' = 'true', 'delta.logRetentionDuration' = 'interval 30 days');"
    );
}

#[test]
fn test_set_tblproperties_dotted_keys_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE t SET TBLPROPERTIES (delta.appendOnly = true, delta.logRetentionDuration = 'interval 30 days');"
    );
}

#[test]
fn test_set_tblproperties_qualified_name_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE catalog1.schema1.my_table SET TBLPROPERTIES ('owner_team' = 'data-eng');",
    );
}

#[test]
fn test_set_tblproperties_integer_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE t SET TBLPROPERTIES ('delta.dataSkippingNumIndexedCols' = 8);",
    );
}

#[test]
fn test_set_tblproperties_retention_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE my_table SET TBLPROPERTIES ('delta.deletedFileRetentionDuration' = 'interval 0 days');"
    );
}

// ============================================================================
// Formatting tests — UNSET TBLPROPERTIES
// ============================================================================

#[test]
fn test_unset_tblproperties_format_roundtrip() {
    dbx_format_and_verify("ALTER TABLE my_table UNSET TBLPROPERTIES ('delta.appendOnly');");
}

#[test]
fn test_unset_tblproperties_multiple_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE my_table UNSET TBLPROPERTIES ('delta.appendOnly', 'delta.logRetentionDuration');"
    );
}

#[test]
fn test_unset_tblproperties_if_exists_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE my_table UNSET TBLPROPERTIES IF EXISTS ('delta.appendOnly');",
    );
}

#[test]
fn test_unset_tblproperties_if_exists_multiple_format_roundtrip() {
    dbx_format_and_verify(
        "ALTER TABLE my_table UNSET TBLPROPERTIES IF EXISTS ('delta.appendOnly', 'delta.logRetentionDuration');"
    );
}

// ============================================================================
// Risk analysis tests — signals
// ============================================================================

#[test]
fn test_set_tblproperties_signal_dbx_tbl_props_chg() {
    let report =
        dbx_analyze("ALTER TABLE my_table SET TBLPROPERTIES ('delta.appendOnly' = 'true');");
    assert!(
        has_signal(&report, "DBX-TBL-PROPS-CHG"),
        "Should find DBX-TBL-PROPS-CHG (Table Properties Modified). Signals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| {
                let RuleMatch::Analysis(g) = s;
                Some(&g.matched_rule)
            })
            .collect::<Vec<_>>()
    );
    assert!(
        report.summary.medium_count >= 1,
        "SET TBLPROPERTIES should be Medium severity"
    );
}

#[test]
fn test_unset_tblproperties_signal_dbx_c040() {
    let report = dbx_analyze("ALTER TABLE my_table UNSET TBLPROPERTIES ('delta.appendOnly');");
    assert!(
        has_signal(&report, "DBX-TBL-PROPS-RMV"),
        "Should find DBX-TBL-PROPS-RMV (Table Properties Removed). Signals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| {
                let RuleMatch::Analysis(g) = s;
                Some(&g.matched_rule)
            })
            .collect::<Vec<_>>()
    );
    assert!(
        report.summary.high_count >= 1,
        "UNSET TBLPROPERTIES should be High severity"
    );
}

#[test]
fn test_unset_tblproperties_if_exists_signal() {
    let report =
        dbx_analyze("ALTER TABLE my_table UNSET TBLPROPERTIES IF EXISTS ('delta.appendOnly');");
    assert!(
        has_signal(&report, "DBX-TBL-PROPS-RMV"),
        "UNSET TBLPROPERTIES IF EXISTS should also emit DBX-TBL-PROPS-RMV"
    );
}

// ============================================================================
// Multi-statement tests — evidence count
// ============================================================================

#[test]
fn test_multi_statement_tblproperties() {
    let sql = r#"
        ALTER TABLE t1 SET TBLPROPERTIES ('delta.appendOnly' = 'true');
        ALTER TABLE t2 SET TBLPROPERTIES ('delta.logRetentionDuration' = 'interval 7 days');
        ALTER TABLE t3 UNSET TBLPROPERTIES ('delta.appendOnly');
    "#;
    let report = dbx_analyze(sql);

    // Should have both SET and UNSET signals
    assert!(
        has_signal(&report, "DBX-TBL-PROPS-CHG"),
        "Should find DBX-TBL-PROPS-CHG for SET TBLPROPERTIES"
    );
    assert!(
        has_signal(&report, "DBX-TBL-PROPS-RMV"),
        "Should find DBX-TBL-PROPS-RMV for UNSET TBLPROPERTIES"
    );

    // Count total evidence for SET signals
    let set_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-TBL-PROPS-CHG"))
        .map(|s| {
            let RuleMatch::Analysis(ref p) = s;
            p.evidence_count.unwrap_or(1)
        })
        .sum();
    assert!(
        set_evidence >= 2,
        "Should have evidence for 2 SET TBLPROPERTIES, got {}",
        set_evidence
    );
}

// ============================================================================
// Safe patterns — should NOT trigger
// ============================================================================

#[test]
fn test_regular_alter_table_no_tblproperties_signal() {
    // Regular ALTER TABLE SET (Snowflake parameter) should NOT trigger DBX-TBL-PROPS-CHG
    let report = dbx_analyze("ALTER TABLE t SET DATA_RETENTION_TIME_IN_DAYS = 90;");
    assert!(
        !has_signal(&report, "DBX-TBL-PROPS-CHG"),
        "Regular SET should not trigger DBX-TBL-PROPS-CHG"
    );
    assert!(
        !has_signal(&report, "DBX-TBL-PROPS-RMV"),
        "Regular SET should not trigger DBX-TBL-PROPS-RMV"
    );
}

#[test]
fn test_alter_table_set_tag_no_tblproperties_signal() {
    // SET TAG should NOT trigger TBLPROPERTIES signals
    let report = dbx_analyze("ALTER TABLE t SET TAG owner = 'team';");
    assert!(
        !has_signal(&report, "DBX-TBL-PROPS-CHG"),
        "SET TAG should not trigger DBX-TBL-PROPS-CHG"
    );
}
