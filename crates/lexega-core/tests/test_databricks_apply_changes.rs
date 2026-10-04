// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Regression tests for Databricks Lakeflow `CREATE FLOW ... AS APPLY CHANGES INTO ...`.

use lexega_core::{
    analyzer::{AnalysisConfig, RuleMatch},
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect, AstStmt,
    DatabricksDialect, FormatterConfig,
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

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

#[test]
fn parse_apply_changes_into_not_opaque() {
    let sql = r#"
APPLY CHANGES INTO LIVE.events_scd
FROM STREAM(bronze.events_cdf)
KEYS (id)
APPLY AS DELETE WHEN op = 'DELETE'
APPLY AS TRUNCATE WHEN op = 'TRUNCATE'
SEQUENCE BY sequence_num
COLUMNS * EXCEPT (op, sequence_num)
STORED AS SCD TYPE 1;
"#;

    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");

    assert_eq!(script.stmts.len(), 1, "expected single statement");
    assert!(
        !matches!(script.stmts[0], AstStmt::OpaqueContent { .. }),
        "CREATE FLOW ... APPLY CHANGES INTO should not fall back to OpaqueContent"
    );
}

#[test]
fn format_apply_changes_into_roundtrip_safe() {
    let sql = r#"
APPLY CHANGES INTO LIVE.events_scd
FROM STREAM(bronze.events_cdf)
KEYS (id)
APPLY AS DELETE WHEN op = 'DELETE'
APPLY AS TRUNCATE WHEN op = 'TRUNCATE'
SEQUENCE BY sequence_num
COLUMNS * EXCEPT (op, sequence_num)
STORED AS SCD TYPE 1;
"#;

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("format should succeed");
    verify_formatting_safe_with_dialect(sql, &formatted, &DatabricksDialect)
        .expect("formatting should be safe under Databricks dialect");
}

#[test]
fn risk_create_flow_apply_changes_signal() {
    let sql = r#"
CREATE FLOW flow_events_scd_apply
AS APPLY CHANGES INTO LIVE.events_scd_apply
FROM STREAM(LIVE.events_cdc)
KEYS (id)
SEQUENCE BY event_ts
STORED AS SCD TYPE 2;
"#;

    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "DBX-FLOW-NEW"),
        "CREATE FLOW should trigger DBX-FLOW-NEW"
    );
}

#[test]
fn risk_create_flow_auto_cdc_signal() {
    let sql = r#"
CREATE FLOW flow_events_scd_auto
AS AUTO CDC INTO LIVE.events_scd_auto
FROM STREAM(LIVE.events_cdc)
KEYS (id)
SEQUENCE BY event_ts
STORED AS SCD TYPE 1;
"#;

    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "DBX-FLOW-NEW"),
        "AUTO CDC CREATE FLOW should trigger DBX-FLOW-NEW"
    );
}
