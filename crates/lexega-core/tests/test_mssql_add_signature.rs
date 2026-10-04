// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL module signing: `ADD [COUNTER] SIGNATURE TO module BY { CERTIFICATE |
//! ASYMMETRIC KEY } …`.
//!
//! This covers recognition (parse + round-trip, not skipped), the
//! recognition-vs-policy split (counter / signer-kind / password are pinnable
//! primitives; the delegation/credential verdict is pure YAML), secret
//! redaction, and that a stray `ADD` (e.g. `ALTER TABLE … ADD col`) is not
//! hijacked.

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
fn test_signature_shapes_recognized() {
    roundtrip_byte_exact("ADD SIGNATURE TO dbo.escalate_proc BY CERTIFICATE signing_cert;");
    roundtrip_byte_exact("ADD SIGNATURE TO dbo.proc BY ASYMMETRIC KEY ak;");
    roundtrip_byte_exact("ADD COUNTER SIGNATURE TO dbo.proc BY CERTIFICATE c;");
    roundtrip_byte_exact("ADD SIGNATURE TO dbo.proc BY CERTIFICATE c WITH PASSWORD = 'p@ss';");
}

// ── Governance ─────────────────────────────────────────────────────────

#[test]
fn test_any_signature_fires_medium() {
    for sql in [
        "ADD SIGNATURE TO dbo.proc BY CERTIFICATE c;",
        "ADD SIGNATURE TO dbo.proc BY ASYMMETRIC KEY ak;",
        "ADD COUNTER SIGNATURE TO dbo.proc BY CERTIFICATE c;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-MODULE-SIGNATURE-ADDED".to_string()),
            "{sql} must fire the delegation rule. Got: {ids:?}"
        );
    }
}

#[test]
fn test_inline_password_fires_high() {
    let ids = rule_ids("ADD SIGNATURE TO dbo.proc BY CERTIFICATE c WITH PASSWORD = 'p@ss';");
    assert!(
        ids.contains(&"MSSQL-SIGNATURE-INLINE-PASSWORD".to_string()),
        "a hardcoded private-key password must fire the credential rule. Got: {ids:?}"
    );
}

#[test]
fn test_no_password_no_credential_rule() {
    // Soundness: a signature with no inline password is delegation (medium) but
    // not a credential leak.
    let ids = rule_ids("ADD SIGNATURE TO dbo.proc BY CERTIFICATE c;");
    assert!(
        !ids.contains(&"MSSQL-SIGNATURE-INLINE-PASSWORD".to_string()),
        "no inline password → credential rule must not fire. Got: {ids:?}"
    );
}

// ── Secret redaction ──────────────────────────────────────────────────────

#[test]
fn test_inline_password_redacted() {
    let sql = "ADD SIGNATURE TO dbo.proc BY CERTIFICATE c WITH PASSWORD = 'sig_secret_zz';";
    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    let json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        !json.contains("sig_secret_zz"),
        "signing password leaked into report"
    );
    let display = redact_secrets_for_display(sql);
    assert!(
        !display.contains("sig_secret_zz"),
        "signing password leaked into display surface: {display}"
    );
}

// ── Recognition vs. policy: primitives pinnable, verdict pure YAML ──────────

const COUNTER_PIN_RULE: &str = r#"
rules:
  - id: TEST-SIG-IS-COUNTER
    risk_level: info
    message: "a counter-signature"
    triggers:
      all_of:
        - kind: mssql_add_signature
        - mssql_add_signature.counter: true
"#;

#[test]
fn test_counter_is_captured_and_pinnable() {
    let cfg = mssql_cfg_with_overlay(COUNTER_PIN_RULE);

    let ids = rule_ids_with("ADD COUNTER SIGNATURE TO dbo.proc BY CERTIFICATE c;", &cfg);
    assert!(
        ids.contains(&"TEST-SIG-IS-COUNTER".to_string()),
        "a counter-signature must be captured and matchable. Got: {ids:?}"
    );

    // A plain signature must NOT match the counter pin.
    let ids = rule_ids_with("ADD SIGNATURE TO dbo.proc BY CERTIFICATE c;", &cfg);
    assert!(
        !ids.contains(&"TEST-SIG-IS-COUNTER".to_string()),
        "a plain signature must not match a counter pin. Got: {ids:?}"
    );
}

// ── Regression: stray ADD not hijacked ──────────────────────────────────────

#[test]
fn test_alter_table_add_not_hijacked() {
    // `ALTER TABLE … ADD col` — ADD is not a statement-leading token here and
    // must not emit module-signing findings.
    let ids = rule_ids("ALTER TABLE t ADD c int;");
    assert!(
        !ids.contains(&"MSSQL-MODULE-SIGNATURE-ADDED".to_string()),
        "ALTER TABLE ADD must not emit signing findings. Got: {ids:?}"
    );
}
