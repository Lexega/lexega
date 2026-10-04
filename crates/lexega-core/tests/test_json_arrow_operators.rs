// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! JSON `->>` (text-extract) operator recognition in PostgreSQL / MySQL.
//!
//! `->>` is also the source text of the Snowflake/BigQuery pipe-chain
//! operator. In dialects that use it for JSON extraction (PostgreSQL / MySQL)
//! the lexer emits the dedicated `MinusGtGt` operator, as it does for `->` /
//! `#>` / `#>>`, and leaves the pipe-chain meaning intact elsewhere. A SELECT
//! touching a JSON column via `->>` therefore parses, and the whole query
//! reaches the rule corpus.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::lexer::tokenize_with_dialect;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    Operator, TokenKind,
};

fn cfg(d: lexega_core::DialectRef) -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    }
}

/// Parses with no opaque fallback and round-trips token-safe (the SELECT body
/// is pretty-printed, so byte-exactness is not asserted — only that no token,
/// the `->>` operator included, is lost).
fn parses_token_safe(sql: &str, d: lexega_core::DialectRef) {
    let mut config = FormatterConfig::default();
    config.dialect = d.clone();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("formatter must preserve all tokens");
    let report = analyze_risk_with_policy_config(sql, &cfg(d)).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "the JSON-operator query must be parsed, not skipped: {sql}"
    );
}

#[test]
fn test_text_extract_operator_parses_pg_and_mysql() {
    for d in [dialect::postgres(), dialect::mysql()] {
        parses_token_safe("SELECT a->>'k' FROM t;", d.clone());
        // All four arrow operators together.
        parses_token_safe(
            "SELECT a->'k', b->>'k', c#>'{d}', e#>>'{f}' FROM t;",
            d.clone(),
        );
        // In a predicate — exercises precedence against `=` and `AND`.
        parses_token_safe("SELECT 1 FROM t WHERE a->>'k' = 'v' AND b > 1;", d.clone());
        // Chained / cast around the extract.
        parses_token_safe("SELECT (payload->>'amount')::int FROM events;", d);
    }
}

#[test]
fn test_mysql_json_path_extract_query_reaches_analysis() {
    // The whole statement must be analyzed, not skipped as opaque.
    let report = analyze_risk_with_policy_config(
        "SELECT id, data->>'$.email' AS email FROM users WHERE data->>'$.role' = 'admin';",
        &cfg(dialect::mysql()),
    )
    .expect("should analyze");
    assert_eq!(report.summary.statements_skipped, 0);
}

// ── Lexer-level dialect split (the load-bearing decision) ─────────────────

fn has_op(sql: &str, d: lexega_core::DialectRef, op: Operator) -> bool {
    tokenize_with_dialect(sql, d.as_ref())
        .tokens
        .iter()
        .any(|t| matches!(t.kind, TokenKind::Operator(o) if o == op))
}

#[test]
fn test_arrow_text_lexes_to_json_operator_in_json_dialects() {
    // PostgreSQL / MySQL: `->>` is the dedicated JSON text-extract operator.
    for d in [dialect::postgres(), dialect::mysql()] {
        assert!(
            has_op("SELECT a->>'k' FROM t;", d.clone(), Operator::MinusGtGt),
            "->> must lex to MinusGtGt in a JSON dialect"
        );
        assert!(
            !has_op("SELECT a->>'k' FROM t;", d, Operator::Pipe),
            "->> must NOT lex to the pipe operator in a JSON dialect"
        );
    }
}

#[test]
fn test_arrow_text_stays_pipe_in_non_json_dialects() {
    // Snowflake / BigQuery: `->>` keeps its pipe-chain meaning (the `Pipe`
    // token), unaffected by the JSON change.
    for d in [dialect::snowflake(), dialect::bigquery()] {
        assert!(
            has_op("SELECT 1 ->> SELECT 2;", d.clone(), Operator::Pipe),
            "->> must remain the Pipe operator in a non-JSON dialect"
        );
        assert!(
            !has_op("SELECT 1 ->> SELECT 2;", d, Operator::MinusGtGt),
            "->> must NOT become the JSON operator in a non-JSON dialect"
        );
    }
}
