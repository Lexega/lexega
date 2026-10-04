// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL Service Master Key rotation: `ALTER SERVICE MASTER KEY { [FORCE]
//! REGENERATE | WITH { OLD | NEW }_ACCOUNT/_PASSWORD = '…' }`.
//!
//! This covers recognition (parse + round-trip, not skipped), the
//! recognition-vs-policy split (operation / force / password are pinnable
//! primitives; the verdict is pure YAML), secret redaction, and that the
//! Snowflake `ALTER SERVICE` and T-SQL `ALTER MASTER KEY` forms are
//! unaffected.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};
use lexega_core::{
    dialect, format_sql_with_config, redact_secrets_for_display,
    verify_formatting_safe_with_dialect, FormatterConfig,
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
fn test_smk_shapes_recognized() {
    roundtrip_byte_exact("ALTER SERVICE MASTER KEY REGENERATE;");
    roundtrip_byte_exact("ALTER SERVICE MASTER KEY FORCE REGENERATE;");
    roundtrip_byte_exact(
        "ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'corp\\svc', NEW_PASSWORD = 'p@ss';",
    );
}

// ── Governance ─────────────────────────────────────────────────────────

#[test]
fn test_regenerate_fires_high() {
    let ids = rule_ids("ALTER SERVICE MASTER KEY REGENERATE;");
    assert!(
        ids.contains(&"MSSQL-SERVICE-MASTER-KEY-REGENERATE".to_string()),
        "REGENERATE must fire the re-key rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MSSQL-SERVICE-MASTER-KEY-FORCE-REGENERATE".to_string()),
        "a non-forced regenerate must not fire the force rule. Got: {ids:?}"
    );
}

#[test]
fn test_force_regenerate_fires_both() {
    let ids = rule_ids("ALTER SERVICE MASTER KEY FORCE REGENERATE;");
    assert!(
        ids.contains(&"MSSQL-SERVICE-MASTER-KEY-FORCE-REGENERATE".to_string())
            && ids.contains(&"MSSQL-SERVICE-MASTER-KEY-REGENERATE".to_string()),
        "FORCE REGENERATE must fire both the force (data-loss) and re-key rules. Got: {ids:?}"
    );
}

#[test]
fn test_account_change_password_fires_high() {
    let ids =
        rule_ids("ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'corp\\svc', NEW_PASSWORD = 'p@ss';");
    assert!(
        ids.contains(&"MSSQL-SERVICE-MASTER-KEY-INLINE-PASSWORD".to_string()),
        "a hardcoded service-account password must fire the credential rule. Got: {ids:?}"
    );
    // It is an account change, not a regenerate.
    assert!(
        !ids.contains(&"MSSQL-SERVICE-MASTER-KEY-REGENERATE".to_string()),
        "an account change must not fire the regenerate rule. Got: {ids:?}"
    );
}

#[test]
fn test_info_fires_for_all() {
    for sql in [
        "ALTER SERVICE MASTER KEY REGENERATE;",
        "ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'a', NEW_PASSWORD = 'p';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-SERVICE-MASTER-KEY".to_string()),
            "INFO should fire for {sql}. Got: {ids:?}"
        );
    }
}

// ── Secret redaction ──────────────────────────────────────────────────────

#[test]
fn test_account_password_redacted() {
    let sql =
        "ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'corp\\svc', NEW_PASSWORD = 'smk_secret_qq';";
    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    let json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        !json.contains("smk_secret_qq"),
        "service-account password leaked into report"
    );
    let display = redact_secrets_for_display(sql);
    assert!(
        !display.contains("smk_secret_qq"),
        "service-account password leaked into display surface: {display}"
    );
}

// ── Recognition vs. policy: force pinnable, verdict pure YAML ────────────────

const FORCE_PIN_RULE: &str = r#"
rules:
  - id: TEST-SMK-IS-FORCED
    risk_level: info
    message: "a forced regenerate"
    triggers:
      all_of:
        - kind: mssql_service_master_key
        - mssql_service_master_key.force: true
"#;

#[test]
fn test_force_is_captured_and_pinnable() {
    let cfg = mssql_cfg_with_overlay(FORCE_PIN_RULE);

    let ids = rule_ids_with("ALTER SERVICE MASTER KEY FORCE REGENERATE;", &cfg);
    assert!(
        ids.contains(&"TEST-SMK-IS-FORCED".to_string()),
        "a forced regenerate must be captured and matchable. Got: {ids:?}"
    );

    let ids = rule_ids_with("ALTER SERVICE MASTER KEY REGENERATE;", &cfg);
    assert!(
        !ids.contains(&"TEST-SMK-IS-FORCED".to_string()),
        "a plain regenerate must not match the force pin. Got: {ids:?}"
    );
}

// ── Regression: ALTER SERVICE / ALTER MASTER KEY unaffected ─────────────────

#[test]
fn test_snowflake_alter_service_unaffected() {
    let cfg = AnalysisConfig {
        dialect: Some(dialect::snowflake()),
        ..Default::default()
    };
    let ids = rule_ids_with("ALTER SERVICE svc RESUME;", &cfg);
    assert!(
        !ids.contains(&"INFO-MSSQL-SERVICE-MASTER-KEY".to_string()),
        "Snowflake ALTER SERVICE must not emit SMK findings. Got: {ids:?}"
    );
}

#[test]
fn test_alter_master_key_unaffected() {
    // ALTER MASTER KEY (database master key) is a different statement, handled
    // by the security-object parser — it must not emit SMK findings.
    let ids = rule_ids("ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = 'p';");
    assert!(
        !ids.contains(&"INFO-MSSQL-SERVICE-MASTER-KEY".to_string()),
        "ALTER MASTER KEY (DMK) must not emit service-master-key findings. Got: {ids:?}"
    );
}
