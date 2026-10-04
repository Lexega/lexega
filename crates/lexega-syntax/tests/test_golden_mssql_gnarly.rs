// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Golden and gap-inventory test for MSSQL/T-SQL.
//!
//! The fixture holds both syntax the parser covers and syntax it does not, so
//! the test pins parser/formatter coverage.

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, span_to_line_col, AstStmt, FormatterConfig,
    MsSqlDialect,
};

const INPUT: &str = include_str!("fixtures/mssql_golden_gnarly.sql");
const EXPECTED: &str = include_str!("fixtures/mssql_golden_gnarly_formatted.sql");
const SEMICOLONLESS_BOUNDARIES: &str = include_str!("fixtures/mssql_semicolonless_boundaries.sql");

fn mssql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::mssql(),
        ..Default::default()
    }
}

#[test]
fn test_mssql_gnarly_golden_default() {
    let formatted = format_sql_with_config(INPUT, &mssql_config())
        .expect("formatting should succeed for gnarly MSSQL fixture");

    assert_eq!(
        formatted.trim(),
        EXPECTED.trim(),
        "Formatted output should match mssql_golden_gnarly_formatted.sql"
    );
}

#[test]
fn test_mssql_gnarly_idempotent() {
    let formatted_once =
        format_sql_with_config(INPUT, &mssql_config()).expect("first format should succeed");
    let formatted_twice = format_sql_with_config(&formatted_once, &mssql_config())
        .expect("second format should succeed");

    assert_eq!(
        formatted_once.trim(),
        formatted_twice.trim(),
        "Formatting should be idempotent for gnarly MSSQL fixture"
    );
}

#[test]
fn test_mssql_gnarly_known_opaque_inventory() {
    let script = parse_sql_with_dialect(INPUT, &MsSqlDialect)
        .expect("script parsing should return an AstScript");

    assert!(
        script
            .stmts
            .iter()
            .any(|stmt| matches!(stmt, AstStmt::GoBatchSeparator { .. })),
        "Expected GO batch separator to parse as AstStmt::GoBatchSeparator"
    );

    let mut opaque_reports = Vec::new();
    let mut opaque_snippets = Vec::new();

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
            opaque_snippets.push(snippet.to_string());

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

    assert_eq!(
        opaque_snippets.len(),
        0,
        "Unexpected MSSQL opaque inventory size:\n{}",
        opaque_reports.join("\n")
    );
}

#[test]
fn test_mssql_semicolonless_select_go_boundary() {
    let script = parse_sql_with_dialect(SEMICOLONLESS_BOUNDARIES, &MsSqlDialect)
        .expect("semicolonless MSSQL boundary fixture should parse");

    assert!(
        script.stmts.len() >= 5,
        "Expected fixture to contain at least 5 statements"
    );
    assert!(matches!(script.stmts[0], AstStmt::Select(_)));
    assert!(matches!(script.stmts[1], AstStmt::GoBatchSeparator { .. }));
    assert!(matches!(script.stmts[2], AstStmt::Select(_)));
}

#[test]
fn test_mssql_semicolonless_create_view_query_boundary() {
    let script = parse_sql_with_dialect(SEMICOLONLESS_BOUNDARIES, &MsSqlDialect)
        .expect("semicolonless MSSQL boundary fixture should parse");

    assert!(matches!(script.stmts[3], AstStmt::CreateView(_)));
    assert!(matches!(script.stmts[4], AstStmt::Select(_)));
}
