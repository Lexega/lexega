// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL legacy impersonation: `SETUSER ['username'] [WITH { NORESET | RESET }]`.
//!
//! SETUSER is the deprecated equivalent of `EXECUTE AS USER`; recognition
//! reuses the shared `ImpersonationFacts` carrier, so the impersonated
//! principal is surfaced for custom rules exactly as for `EXECUTE AS`. This
//! covers recognition (parse + round-trip, not skipped), the impersonation
//! gradient (named principal vs the bare revert form), the principal being
//! pinnable through the reused carrier, and that `EXECUTE AS` is unaffected.

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

fn roundtrip_not_skipped(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mssql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "must be analyzed, not skipped: {sql}"
    );
}

fn roundtrip_byte_exact(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mssql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    assert_eq!(out, sql, "single-statement round-trip must be byte-exact");
    roundtrip_not_skipped(sql);
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_setuser_shapes_recognized() {
    roundtrip_byte_exact("SETUSER 'dbo';");
    roundtrip_byte_exact("SETUSER 'payroll_admin';");
    roundtrip_byte_exact("SETUSER;");
    roundtrip_byte_exact("SETUSER 'dbo' WITH NORESET;");
}

// ── Governance ─────────────────────────────────────────────────────────

#[test]
fn test_named_principal_fires_impersonation() {
    for sql in ["SETUSER 'dbo';", "SETUSER 'app_user' WITH NORESET;"] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-SETUSER-IMPERSONATION".to_string()),
            "{sql} must fire the impersonation rule. Got: {ids:?}"
        );
        assert!(
            ids.contains(&"INFO-MSSQL-SETUSER".to_string()),
            "{sql} should also fire INFO. Got: {ids:?}"
        );
    }
}

#[test]
fn test_bare_setuser_is_info_only() {
    // The bare revert form has no impersonated principal — INFO only.
    let ids = rule_ids("SETUSER;");
    assert!(
        ids.contains(&"INFO-MSSQL-SETUSER".to_string()),
        "bare SETUSER should fire INFO. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MSSQL-SETUSER-IMPERSONATION".to_string()),
        "bare SETUSER (revert) is not an impersonation. Got: {ids:?}"
    );
}

// ── Recognition vs. policy: principal pinnable through the reused carrier ────

const PRINCIPAL_PIN_RULE: &str = r#"
rules:
  - id: TEST-SETUSER-SENSITIVE
    risk_level: high
    message: "setuser to a sensitive account"
    triggers:
      all_of:
        - kind: mssql_setuser
        - impersonation.principal:
            in: [payroll_admin]
"#;

#[test]
fn test_principal_is_pinnable() {
    let cfg = mssql_cfg_with_overlay(PRINCIPAL_PIN_RULE);

    let ids = rule_ids_with("SETUSER 'payroll_admin';", &cfg);
    assert!(
        ids.contains(&"TEST-SETUSER-SENSITIVE".to_string()),
        "the impersonated principal must be surfaced and matchable. Got: {ids:?}"
    );

    // A different principal must NOT match the pin.
    let ids = rule_ids_with("SETUSER 'dbo';", &cfg);
    assert!(
        !ids.contains(&"TEST-SETUSER-SENSITIVE".to_string()),
        "a non-pinned principal must not match. Got: {ids:?}"
    );
}

// ── Regression: EXECUTE AS unaffected ───────────────────────────────────────

#[test]
fn test_execute_as_user_unaffected() {
    let ids = rule_ids("EXECUTE AS USER = 'dbo';");
    assert!(
        ids.contains(&"MSSQL-EXECAS-USER".to_string()),
        "EXECUTE AS USER must still fire its own rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MSSQL-SETUSER-IMPERSONATION".to_string()),
        "EXECUTE AS must not fire the SETUSER rule. Got: {ids:?}"
    );
}
