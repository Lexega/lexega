// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `CREATE VIEW` security-context prelude — `ALGORITHM`, `DEFINER`, and
//! `SQL SECURITY { DEFINER | INVOKER }`.
//!
//! The governance signal for a view is the DEFINER account plus the SQL
//! SECURITY mode — together they decide whose privileges the view's query runs
//! under. A view with SQL SECURITY DEFINER (the MySQL default) can expose rows
//! the caller could not read directly. The clauses are parsed into typed
//! primitives (not skipped), and two low findings flag the
//! privilege-delegation cases. ALGORITHM is a perf hint, recognized for
//! round-trip only (no governance fact).

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mysql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    }
}

fn rule_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &mysql_cfg()).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

/// Parses (no opaque fallback) and round-trips token-safe. The view's `AS`
/// query is pretty-printed (Pattern B), so byte-exactness is not asserted —
/// only token preservation + that nothing was skipped.
fn parses_token_safe(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mysql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("formatter must preserve all tokens");
    let report = analyze_risk_with_policy_config(sql, &mysql_cfg()).expect("should analyze");
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

// ── Recognition (was opaque) ──────────────────────────────────────────────

#[test]
fn test_view_prelude_forms_recognized() {
    parses_token_safe("CREATE DEFINER=root@localhost VIEW v AS SELECT * FROM t;");
    parses_token_safe("CREATE ALGORITHM=MERGE VIEW v AS SELECT * FROM t;");
    parses_token_safe("CREATE SQL SECURITY INVOKER VIEW v AS SELECT * FROM t;");
    parses_token_safe(
        "CREATE ALGORITHM=UNDEFINED DEFINER='a'@'%' SQL SECURITY DEFINER VIEW v AS SELECT a FROM t;",
    );
    // Spacing + backtick variants.
    parses_token_safe(
        "CREATE ALGORITHM = MERGE DEFINER = `u`@`%` SQL SECURITY INVOKER VIEW w AS SELECT 1;",
    );
    // OR REPLACE coexists with the prelude.
    parses_token_safe("CREATE OR REPLACE DEFINER=CURRENT_USER VIEW v AS SELECT * FROM t;");
}

// ── Governance (recognition / policy split) ───────────────────────────────

#[test]
fn test_explicit_definer_fires() {
    assert_fires(
        "CREATE DEFINER='admin'@'localhost' VIEW v AS SELECT * FROM t;",
        "MYSQL-VIEW-DEFINER",
    );
}

#[test]
fn test_sql_security_definer_fires() {
    assert_fires(
        "CREATE SQL SECURITY DEFINER VIEW v AS SELECT * FROM t;",
        "MYSQL-VIEW-SQL-SECURITY-DEFINER",
    );
}

#[test]
fn test_sql_security_invoker_is_silent() {
    // INVOKER runs with the caller's own rights — no delegation.
    assert_silent(
        "CREATE SQL SECURITY INVOKER VIEW v AS SELECT * FROM t;",
        "MYSQL-VIEW-SQL-SECURITY-DEFINER",
    );
}

#[test]
fn test_current_user_definer_is_silent() {
    assert_silent(
        "CREATE DEFINER=CURRENT_USER VIEW v AS SELECT * FROM t;",
        "MYSQL-VIEW-DEFINER",
    );
}

#[test]
fn test_plain_view_is_silent() {
    let ids = rule_ids("CREATE VIEW v AS SELECT * FROM t;");
    assert!(
        !ids.iter().any(|r| r.starts_with("MYSQL-VIEW-")),
        "a plain view with no prelude must raise no MYSQL-VIEW finding; got {ids:?}"
    );
}

// ── DEFINER principal + SQL SECURITY VALUE capture (policy pinning) ───────

fn custom_rule_ids(sql: &str, custom_yaml: &str) -> Vec<String> {
    let custom = load_v1_rules(custom_yaml).expect("custom rules parse");
    let corpus =
        build_v1_rule_corpus(custom, /* include_builtins = */ false).expect("corpus builds");
    let cfg = AnalysisConfig {
        dialect: Some(dialect::mysql()),
        custom_rules: Some(corpus),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

const VIEW_PIN_RULE: &str = r#"
rules:
  - id: TEST-VIEW-DEFINER-USER
    risk_level: critical
    message: "view definer.user is admin"
    triggers:
      all_of:
        - kind: create_view
        - ddl.view.definer.user: admin
  - id: TEST-VIEW-SECURITY-INVOKER
    risk_level: critical
    message: "view sql_security is invoker"
    triggers:
      all_of:
        - kind: create_view
        - ddl.view.sql_security: invoker
"#;

#[test]
fn test_view_definer_user_value_is_pinnable() {
    let hit = custom_rule_ids(
        "CREATE DEFINER='admin'@'localhost' VIEW v AS SELECT * FROM t;",
        VIEW_PIN_RULE,
    );
    assert!(
        hit.contains(&"TEST-VIEW-DEFINER-USER".to_string()),
        "definer.user='admin' must be captured + matchable; got {hit:?}"
    );
    let miss = custom_rule_ids(
        "CREATE DEFINER='other'@'localhost' VIEW v AS SELECT * FROM t;",
        VIEW_PIN_RULE,
    );
    assert!(
        !miss.contains(&"TEST-VIEW-DEFINER-USER".to_string()),
        "pin must not fire on a different user; got {miss:?}"
    );
}

#[test]
fn test_view_sql_security_invoker_value_is_matchable() {
    // The INVOKER mode value reaches the facts and discriminates from DEFINER.
    let hit = custom_rule_ids(
        "CREATE SQL SECURITY INVOKER VIEW v AS SELECT * FROM t;",
        VIEW_PIN_RULE,
    );
    assert!(
        hit.contains(&"TEST-VIEW-SECURITY-INVOKER".to_string()),
        "sql_security=invoker must be captured + matchable; got {hit:?}"
    );
    let miss = custom_rule_ids(
        "CREATE SQL SECURITY DEFINER VIEW v AS SELECT * FROM t;",
        VIEW_PIN_RULE,
    );
    assert!(
        !miss.contains(&"TEST-VIEW-SECURITY-INVOKER".to_string()),
        "invoker pin must not match a definer-security view; got {miss:?}"
    );
}
