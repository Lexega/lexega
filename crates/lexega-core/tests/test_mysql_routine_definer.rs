// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `DEFINER =` clause on `CREATE PROCEDURE` / `CREATE FUNCTION`.
//!
//! DEFINER is the routine's privilege-delegation primitive (the body runs
//! under that account's privileges regardless of the caller / invoker — MySQL
//! SQL SECURITY DEFINER), so it is PARSED into the typed security-context
//! primitive, not skipped. Covers recognition (parse + token-safe round-trip,
//! not skipped), the explicit-vs-CURRENT_USER recognition/policy split, and
//! the body analysis carrying through (the governance payoff).

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

/// The routine must parse (no opaque fallback) and round-trip token-safe.
/// Procedure/function bodies are pretty-printed (Pattern B), so byte-exactness
/// is not asserted here — only token preservation + that nothing was skipped.
fn parses_token_safe(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mysql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("formatter must preserve all tokens");
    let report = analyze_risk_with_policy_config(sql, &mysql_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "the routine must be parsed, not skipped: {sql}"
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
fn test_definer_procedure_forms_recognized() {
    parses_token_safe("CREATE DEFINER='admin'@'localhost' PROCEDURE p() BEGIN SELECT 1; END;");
    // Unquoted user@host — the host lexes as a single @host token.
    parses_token_safe("CREATE DEFINER=root@localhost PROCEDURE q() BEGIN SELECT 2; END;");
    // CURRENT_USER form.
    parses_token_safe("CREATE DEFINER = CURRENT_USER PROCEDURE r() BEGIN SELECT 3; END;");
}

#[test]
fn test_definer_function_forms_recognized() {
    parses_token_safe("CREATE DEFINER=root@localhost FUNCTION f() RETURNS INT RETURN 1;");
    parses_token_safe("CREATE DEFINER=`adm`@`%` FUNCTION g() RETURNS INT RETURN 2;");
}

#[test]
fn test_definer_function_single_line_byte_exact() {
    // A RETURN-form function body is emitted verbatim, so the whole statement —
    // DEFINER clause included — must round-trip byte-for-byte.
    let sql = "CREATE DEFINER=root@localhost FUNCTION f() RETURNS INT RETURN 1;";
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mysql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    assert_eq!(out, sql, "byte-exact round-trip expected");
}

// ── DEFINER governance (recognition / policy split) ───────────────────────

#[test]
fn test_explicit_definer_fires_proc() {
    assert_fires(
        "CREATE DEFINER='admin'@'localhost' PROCEDURE p() BEGIN SELECT 1; END;",
        "MYSQL-PROC-DEFINER",
    );
}

#[test]
fn test_explicit_definer_fires_func() {
    assert_fires(
        "CREATE DEFINER=root@localhost FUNCTION f() RETURNS INT RETURN 1;",
        "MYSQL-FUNC-DEFINER",
    );
}

#[test]
fn test_current_user_definer_silent() {
    // CURRENT_USER is definer.explicit:false — no named privilege-delegation.
    assert_silent(
        "CREATE DEFINER = CURRENT_USER PROCEDURE q() BEGIN SELECT 2; END;",
        "MYSQL-PROC-DEFINER",
    );
}

#[test]
fn test_no_definer_clause_silent() {
    assert_silent(
        "CREATE PROCEDURE r() BEGIN SELECT 3; END;",
        "MYSQL-PROC-DEFINER",
    );
    assert_silent(
        "CREATE FUNCTION s() RETURNS INT RETURN 1;",
        "MYSQL-FUNC-DEFINER",
    );
}

// ── DEFINER principal VALUE capture (policy pinning works) ────────────────
//
// The rule messages tell customers to pin privileged-account names via
// `ddl.{procedure,function}.definer.user`. That guidance is only truthful if
// the user/host VALUES (not merely the `explicit` flag) reach the facts and
// are matchable by a custom rule. These pin a value-matching custom rule and
// assert it discriminates — the recognition/policy split: flipping the matched
// scalar reverses the finding.

/// Run `sql` under a custom-only corpus built from `custom_yaml` and return the
/// matched rule IDs. Mirrors `--custom-rules … --no-builtin`.
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

const USER_PIN_RULE: &str = r#"
rules:
  - id: TEST-PROC-DEFINER-USER
    risk_level: critical
    message: "procedure definer.user is admin"
    triggers:
      all_of:
        - kind: create_procedure
        - ddl.procedure.definer.user: admin
"#;

const HOST_PIN_RULE: &str = r#"
rules:
  - id: TEST-FUNC-DEFINER-HOST
    risk_level: critical
    message: "function definer.host is localhost"
    triggers:
      all_of:
        - kind: create_function
        - ddl.function.definer.host: localhost
"#;

#[test]
fn test_definer_user_value_is_captured_and_pinnable() {
    // Quoted user matching the pin fires; a different user does not — the
    // dequoted user value reaches the facts and is matchable.
    let hit = custom_rule_ids(
        "CREATE DEFINER='admin'@'localhost' PROCEDURE p() BEGIN SELECT 1; END;",
        USER_PIN_RULE,
    );
    assert!(
        hit.contains(&"TEST-PROC-DEFINER-USER".to_string()),
        "definer.user='admin' must be captured + matchable; got {hit:?}"
    );
    let miss = custom_rule_ids(
        "CREATE DEFINER='other'@'localhost' PROCEDURE p() BEGIN SELECT 1; END;",
        USER_PIN_RULE,
    );
    assert!(
        !miss.contains(&"TEST-PROC-DEFINER-USER".to_string()),
        "pin must not fire on a different user (recognition/policy split); got {miss:?}"
    );
}

#[test]
fn test_definer_host_value_is_captured_unquoted() {
    // Unquoted `root@localhost` — the host arrives via the @host AtVariable
    // strip path; its value must still reach the facts.
    let hit = custom_rule_ids(
        "CREATE DEFINER=root@localhost FUNCTION f() RETURNS INT RETURN 1;",
        HOST_PIN_RULE,
    );
    assert!(
        hit.contains(&"TEST-FUNC-DEFINER-HOST".to_string()),
        "definer.host='localhost' must be captured from the unquoted form; got {hit:?}"
    );
}

// ── Body analysis carries through the DEFINER routine (the payoff) ────────

#[test]
fn test_drop_in_definer_procedure_body_fires() {
    assert_fires(
        "CREATE DEFINER='a'@'%' PROCEDURE p() BEGIN DROP TABLE audit_log; END;",
        "TBL-DROP",
    );
}
