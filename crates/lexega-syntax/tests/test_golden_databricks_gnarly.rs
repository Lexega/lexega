// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! GOLDEN + GAP-DISCOVERY test for Databricks SQL.
//!
//! This fixture is intentionally broad and hostile: it mixes valid Databricks
//! SQL with edge grammar forms to expose parser fallback gaps (OpaqueContent).

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, span_to_line_col, AstStmt, DatabricksDialect,
    FormatterConfig,
};

const INPUT: &str = include_str!("fixtures/dbx_golden_gnarly.sql");
const EXPECTED: &str = include_str!("fixtures/dbx_golden_gnarly_formatted.sql");

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::databricks(),
        ..Default::default()
    }
}

#[test]
fn test_databricks_gnarly_golden_default() {
    let formatted = format_sql_with_config(INPUT, &dbx_config())
        .expect("formatting should succeed for gnarly Databricks fixture");

    assert_eq!(
        formatted.trim(),
        EXPECTED.trim(),
        "Formatted output should match dbx_golden_gnarly_formatted.sql"
    );
}

#[test]
fn test_databricks_gnarly_idempotent() {
    let formatted_once =
        format_sql_with_config(INPUT, &dbx_config()).expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &dbx_config())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Formatting should be idempotent for gnarly Databricks fixture"
    );
}

#[test]
fn test_databricks_gnarly_no_opaque_fallbacks() {
    let script = parse_sql_with_dialect(INPUT, &DatabricksDialect)
        .expect("script parsing should return an AstScript");

    let mut opaque_reports = Vec::new();

    for (index, stmt) in script.stmts.iter().enumerate() {
        if matches!(stmt, AstStmt::OpaqueContent { .. }) {
            let span = stmt.span();
            let (start, end) = span_to_line_col(INPUT, span);
            let start_idx = span.start as usize;
            let end_idx = (span.end as usize).min(INPUT.len());
            let raw_snippet = if start_idx < end_idx {
                &INPUT[start_idx..end_idx]
            } else {
                "<empty-span>"
            };
            let snippet = raw_snippet.lines().next().unwrap_or("<empty>").trim();

            opaque_reports.push(format!(
                "stmt#{idx} lines {l1}:{c1}-{l2}:{c2} => {snip}",
                idx = index,
                l1 = start.line,
                c1 = start.col,
                l2 = end.line,
                c2 = end.col,
                snip = snippet
            ));
        }
    }

    assert!(
        opaque_reports.is_empty(),
        "Databricks parser gap(s) detected in gnarly fixture:\n{}\n\nIf these are expected gaps, keep the fixture and close them incrementally.",
        opaque_reports.join("\n")
    );
}
