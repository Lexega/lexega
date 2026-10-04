// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL `OPENROWSET(BULK '<file>', …)` recognition.
//!
//! `OPENROWSET` reads from an external data source in a query's FROM clause.
//! The remote-server forms (`OPENROWSET('provider', 'connstr', 'query')`)
//! drive the inline-credential rule. The `BULK` form — which reads a file from
//! the database server's filesystem — puts a `BULK` identifier prefix on the
//! first argument, with no comma before the file literal, so it is not a
//! generic function-argument list. It parses into a dedicated argument shape;
//! the file-path literal flows into the OPENROWSET call facts (composing with
//! any content-pattern rule), and the whole query reaches the corpus.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mssql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mssql()),
        ..Default::default()
    }
}

fn mssql_cfg_with_overlay(custom_yaml: &str) -> AnalysisConfig {
    let custom = load_v1_rules(custom_yaml).expect("custom rules parse");
    let merged = build_v1_rule_corpus(custom, /* include_builtins = */ true)
        .expect("merge against built-ins succeeds");
    AnalysisConfig {
        dialect: Some(dialect::mssql()),
        custom_rules: Some(merged),
        ..Default::default()
    }
}

fn rule_ids_with(sql: &str, cfg: &AnalysisConfig) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, cfg).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn rule_ids(sql: &str) -> Vec<String> {
    rule_ids_with(sql, &mssql_cfg())
}

/// Parses with no opaque fallback and round-trips token-safe (the SELECT body
/// is pretty-printed, so byte-exactness is not asserted — only that no token,
/// the `BULK` keyword included, is lost).
fn parses_token_safe(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mssql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("formatter must preserve all tokens (including BULK)");
    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "the OPENROWSET BULK query must be parsed, not skipped: {sql}"
    );
}

// ── Recognition ───────────────────────────────────────────────────────────

#[test]
fn test_bulk_forms_parse() {
    // BULK + file literal only.
    parses_token_safe("SELECT * FROM OPENROWSET(BULK 'C:\\data.txt') AS x;");
    // BULK + bare option keyword.
    parses_token_safe("SELECT * FROM OPENROWSET(BULK 'C:\\data.txt', SINGLE_CLOB) AS x;");
    // BULK + key = value options.
    parses_token_safe(
        "SELECT * FROM OPENROWSET(BULK 'C:\\d.csv', FORMATFILE = 'C:\\f.fmt', CODEPAGE = '65001') AS y;",
    );
    // In a JOIN with a regular table — exercises the surrounding FROM grammar.
    parses_token_safe(
        "SELECT t.id FROM dbo.t JOIN OPENROWSET(BULK 'C:\\d.txt', SINGLE_CLOB) AS r ON 1 = 1;",
    );
}

// ── The file-path literal is captured into the OPENROWSET call facts ───────

const BULK_FILE_RULE: &str = r#"
rules:
  - id: TEST-OPENROWSET-BULK-FILE
    risk_level: info
    message: "openrowset bulk file path captured"
    triggers:
      all_of:
        - query.openrowset_calls:
            exists:
              string_args:
                exists:
                  any_of:
                    - value:
                        matches: "*secrets*"
"#;

#[test]
fn test_bulk_file_path_is_captured() {
    let cfg = mssql_cfg_with_overlay(BULK_FILE_RULE);
    let ids = rule_ids_with(
        "SELECT * FROM OPENROWSET(BULK 'C:\\secrets.txt', SINGLE_CLOB) AS x;",
        &cfg,
    );
    assert!(
        ids.contains(&"TEST-OPENROWSET-BULK-FILE".to_string()),
        "the BULK file-path literal must be captured in the OPENROWSET call facts. Got: {ids:?}"
    );
}

// ── Soundness: the inline-credential rule is unaffected ────────────────────

#[test]
fn test_remote_form_cred_rule_still_fires() {
    let ids =
        rule_ids("SELECT a.* FROM OPENROWSET('SQLNCLI', 'Server=x;PWD=secret;', 'SELECT 1') AS a;");
    assert!(
        ids.contains(&"MSSQL-OPENROWSET-INLINE-CRED".to_string()),
        "the remote-server inline-credential rule must still fire. Got: {ids:?}"
    );
}

#[test]
fn test_bulk_file_path_does_not_false_positive_cred() {
    // A BULK file path is not a connection string; it must not trip the
    // inline-credential rule.
    let ids = rule_ids("SELECT * FROM OPENROWSET(BULK 'C:\\data.txt', SINGLE_CLOB) AS x;");
    assert!(
        !ids.contains(&"MSSQL-OPENROWSET-INLINE-CRED".to_string()),
        "a BULK file read must not fire the inline-credential rule. Got: {ids:?}"
    );
}
