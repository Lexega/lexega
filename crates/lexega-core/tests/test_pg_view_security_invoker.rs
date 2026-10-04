// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! PostgreSQL `CREATE VIEW ... WITH ( option [= value], ... )` — the
//! `security_invoker` / `security_barrier` / `check_option` option list.
//!
//! `security_invoker = false` (the PostgreSQL default, stated explicitly) runs
//! the view as its OWNER, so row-level security on the underlying tables is
//! evaluated against the owner — an RLS bypass.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn pg_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::postgres()),
        ..Default::default()
    }
}

fn rule_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &pg_cfg()).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

/// Parses (no opaque fallback) and round-trips token-safe.
fn parses_token_safe(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::postgres();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("formatter must preserve all tokens");
    let report = analyze_risk_with_policy_config(sql, &pg_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "the view must be parsed, not skipped: {sql}"
    );
}

fn assert_fires(sql: &str, rule: &str) {
    let ids = rule_ids(sql);
    assert!(
        ids.contains(&rule.to_string()),
        "expected {rule} to fire. Got: {ids:?}\nSQL: {sql}"
    );
}

fn assert_silent(sql: &str, rule: &str) {
    let ids = rule_ids(sql);
    assert!(
        !ids.contains(&rule.to_string()),
        "expected {rule} NOT to fire. Got: {ids:?}\nSQL: {sql}"
    );
}

// ── Recognition (was discarded) ───────────────────────────────────────────

#[test]
fn test_with_options_forms_recognized() {
    parses_token_safe("CREATE VIEW v WITH (security_invoker = false) AS SELECT a FROM t;");
    parses_token_safe("CREATE VIEW v WITH (security_invoker) AS SELECT a FROM t;");
    parses_token_safe(
        "CREATE VIEW v WITH (security_barrier = true, check_option = cascaded) AS SELECT a FROM t;",
    );
    parses_token_safe("CREATE OR REPLACE VIEW s.v WITH (security_invoker = 'off') AS SELECT 1;");
}

// ── Governance (recognition / policy split) ───────────────────────────────

#[test]
fn test_security_invoker_false_fires() {
    assert_fires(
        "CREATE VIEW v WITH (security_invoker = false) AS SELECT * FROM t;",
        "PG-VIEW-SECINV-OFF",
    );
}

#[test]
fn test_security_invoker_false_spellings_fire() {
    // PostgreSQL boolean option literals normalize at recognition.
    for value in ["off", "0", "no", "'false'"] {
        assert_fires(
            &format!("CREATE VIEW v WITH (security_invoker = {value}) AS SELECT * FROM t;"),
            "PG-VIEW-SECINV-OFF",
        );
    }
}

#[test]
fn test_security_invoker_true_is_silent() {
    // Invoker-rights views evaluate RLS against the caller — no bypass.
    assert_silent(
        "CREATE VIEW v WITH (security_invoker = true) AS SELECT * FROM t;",
        "PG-VIEW-SECINV-OFF",
    );
    // A bare option name enables it.
    assert_silent(
        "CREATE VIEW v WITH (security_invoker) AS SELECT * FROM t;",
        "PG-VIEW-SECINV-OFF",
    );
}

#[test]
fn test_other_options_are_silent() {
    assert_silent(
        "CREATE VIEW v WITH (security_barrier = true, check_option = local) AS SELECT * FROM t;",
        "PG-VIEW-SECINV-OFF",
    );
}

#[test]
fn test_plain_view_is_silent() {
    assert_silent("CREATE VIEW v AS SELECT * FROM t;", "PG-VIEW-SECINV-OFF");
}

// ── The RLS-bypass shape ──────────────────────────────────────────────────

#[test]
fn test_rls_bypass_fixture_shape_fires() {
    let sql = "CREATE VIEW pii.everyone_view\n  WITH (security_invoker = false)\nAS SELECT * FROM pii.customers;\n\nGRANT SELECT ON pii.everyone_view TO analyst_role;";
    assert_fires(sql, "PG-VIEW-SECINV-OFF");
    let report = analyze_risk_with_policy_config(sql, &pg_cfg()).expect("should analyze");
    assert_eq!(report.summary.statements_skipped, 0);
}
