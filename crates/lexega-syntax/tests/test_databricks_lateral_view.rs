// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Regression tests for Databricks/Spark `LATERAL VIEW [OUTER] explode(...)` parsing.

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
fn parse_lateral_view_outer_explode_not_opaque() {
    let sql = r#"
SELECT
  f.id,
  f.item.col AS item_col,
  f.item.val AS item_val
FROM main.analytics.events_raw f,
LATERAL VIEW OUTER explode(from_json(f.payload, 'array<struct<col:string,val:string>>')) exploded AS item
WHERE f.event_date >= DATE '2024-06-01';
"#;

    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");

    assert_eq!(script.stmts.len(), 1, "expected single statement");
    assert!(
        !matches!(script.stmts[0], AstStmt::OpaqueContent { .. }),
        "LATERAL VIEW OUTER explode should not fall back to OpaqueContent"
    );
}

#[test]
fn format_lateral_view_outer_explode_roundtrip_safe() {
    let sql = r#"
SELECT
  f.id,
  f.item.col AS item_col,
  f.item.val AS item_val
FROM main.analytics.events_raw f,
LATERAL VIEW OUTER explode(from_json(f.payload, 'array<struct<col:string,val:string>>')) exploded AS item
WHERE f.event_date >= DATE '2024-06-01';
"#;

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("format should succeed");

    verify_formatting_safe_with_dialect(sql, &formatted, &DatabricksDialect)
        .expect("formatting should be safe under Databricks dialect");

    assert!(
        formatted
            .to_ascii_uppercase()
            .contains("LATERAL VIEW OUTER"),
        "formatted SQL should preserve LATERAL VIEW OUTER construct: {}",
        formatted
    );
}
