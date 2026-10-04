// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Regression tests for Databricks DLT `CREATE OR REFRESH LIVE TABLE ... AS SELECT ...`.

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect, AstStmt,
    DatabricksDialect, FormatterConfig,
};

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::databricks(),
        ..Default::default()
    }
}

#[test]
fn parse_create_or_refresh_live_table_not_opaque() {
    let sql = r#"
CREATE OR REFRESH LIVE TABLE dlt_events_enriched
AS
SELECT id, user_id, event_ts, payload
FROM STREAM(LIVE.events_raw)
WHERE event_ts >= current_timestamp() - INTERVAL 7 DAYS;
"#;

    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");

    assert_eq!(script.stmts.len(), 1, "expected single statement");
    assert!(
        !matches!(script.stmts[0], AstStmt::OpaqueContent { .. }),
        "CREATE OR REFRESH LIVE TABLE should not fall back to OpaqueContent"
    );
}

#[test]
fn format_create_or_refresh_live_table_roundtrip_safe() {
    let sql = r#"
CREATE OR REFRESH LIVE TABLE dlt_events_enriched
AS
SELECT id, user_id, event_ts, payload
FROM STREAM(LIVE.events_raw)
WHERE event_ts >= current_timestamp() - INTERVAL 7 DAYS;
"#;

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("format should succeed");
    verify_formatting_safe_with_dialect(sql, &formatted, &DatabricksDialect)
        .expect("formatting should be safe under Databricks dialect");
}
