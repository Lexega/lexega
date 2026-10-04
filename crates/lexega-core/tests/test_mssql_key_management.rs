// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL encryption-key activation: `OPEN`/`CLOSE { MASTER KEY | SYMMETRIC KEY
//! | ALL SYMMETRIC KEYS }`.
//!
//! A hardcoded `DECRYPTION BY PASSWORD = '…'` must be both analyzed and
//! redacted, or it is a credential leak. This covers recognition (parse +
//! round-trip, not skipped), the recognition-vs-policy split (verb / key-kind
//! / password-present are pinnable primitives; severity is pure YAML), the
//! secret-redaction invariant, and disambiguation from cursor `OPEN`/`CLOSE`.

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

/// Single-statement byte-exact round-trip — the Pattern-A span-only formatter
/// must reproduce the source verbatim.
fn roundtrip_byte_exact(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mssql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    assert_eq!(out, sql, "single-statement round-trip must be byte-exact");
    roundtrip_not_skipped(sql);
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_key_shapes_recognized() {
    roundtrip_byte_exact("OPEN MASTER KEY DECRYPTION BY PASSWORD = 'p@ss';");
    roundtrip_byte_exact("OPEN SYMMETRIC KEY sk DECRYPTION BY CERTIFICATE c;");
    roundtrip_byte_exact("OPEN SYMMETRIC KEY sk DECRYPTION BY PASSWORD = 'p@ss';");
    roundtrip_byte_exact("CLOSE MASTER KEY;");
    roundtrip_byte_exact("CLOSE SYMMETRIC KEY sk;");
    roundtrip_byte_exact("CLOSE ALL SYMMETRIC KEYS;");
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "OPEN MASTER KEY DECRYPTION BY PASSWORD = 'p@ss';\n\
         OPEN SYMMETRIC KEY sk DECRYPTION BY CERTIFICATE c;\n\
         CLOSE ALL SYMMETRIC KEYS;",
    );
}

// ── Governance ─────────────────────────────────────────────────────────

#[test]
fn test_inline_password_fires_high_rule() {
    for sql in [
        "OPEN MASTER KEY DECRYPTION BY PASSWORD = 'p@ss';",
        "OPEN SYMMETRIC KEY sk DECRYPTION BY PASSWORD = 'p@ss';",
        "OPEN SYMMETRIC KEY sk DECRYPTION BY CERTIFICATE c WITH PASSWORD = 'p@ss';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-KEY-OPEN-INLINE-PASSWORD".to_string()),
            "{sql} must fire the hardcoded-password rule. Got: {ids:?}"
        );
    }
}

#[test]
fn test_open_master_key_fires_medium() {
    // No password, but opening the DMK is still a key-activation surface.
    let ids = rule_ids("OPEN MASTER KEY DECRYPTION BY PASSWORD = 'p@ss';");
    assert!(
        ids.contains(&"MSSQL-OPEN-MASTER-KEY".to_string()),
        "OPEN MASTER KEY must fire the DMK rule. Got: {ids:?}"
    );
}

#[test]
fn test_certificate_open_no_password_rule() {
    // Symmetric key opened by a certificate carries no inline credential — the
    // password rule must stay silent (soundness of password_present).
    let ids = rule_ids("OPEN SYMMETRIC KEY sk DECRYPTION BY CERTIFICATE c;");
    assert!(
        !ids.contains(&"MSSQL-KEY-OPEN-INLINE-PASSWORD".to_string()),
        "no inline password → password rule must not fire. Got: {ids:?}"
    );
    assert!(
        ids.contains(&"INFO-MSSQL-KEY-MANAGEMENT".to_string()),
        "still recognized → INFO fires. Got: {ids:?}"
    );
}

#[test]
fn test_close_is_info_only() {
    for sql in [
        "CLOSE MASTER KEY;",
        "CLOSE SYMMETRIC KEY sk;",
        "CLOSE ALL SYMMETRIC KEYS;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-KEY-MANAGEMENT".to_string()),
            "{sql} should fire INFO. Got: {ids:?}"
        );
        assert!(
            !ids.contains(&"MSSQL-KEY-OPEN-INLINE-PASSWORD".to_string())
                && !ids.contains(&"MSSQL-OPEN-MASTER-KEY".to_string()),
            "{sql} is a CLOSE — no open/password verdict. Got: {ids:?}"
        );
    }
}

// ── Secret redaction ──────────────────────────────────────────────────────

#[test]
fn test_inline_password_redacted() {
    // The credential VALUE must never reach an output surface.
    let report = analyze_risk_with_policy_config(
        "OPEN MASTER KEY DECRYPTION BY PASSWORD = 'dmk_secret_xyz';",
        &mssql_cfg(),
    )
    .expect("should analyze");
    let json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        !json.contains("dmk_secret_xyz"),
        "DMK password leaked into report"
    );

    let display =
        redact_secrets_for_display("OPEN MASTER KEY DECRYPTION BY PASSWORD = 'dmk_secret_xyz';");
    assert!(
        !display.contains("dmk_secret_xyz"),
        "DMK password leaked into display surface: {display}"
    );
}

// ── Recognition vs. policy: key kind is pinnable, verdict is pure YAML ──────

const KIND_PIN_RULE: &str = r#"
rules:
  - id: TEST-KEY-IS-SYMMETRIC
    risk_level: info
    message: "key kind is symmetric"
    triggers:
      all_of:
        - kind: mssql_key_management
        - mssql_key_management.key_kind: symmetric
"#;

#[test]
fn test_key_kind_is_captured_and_pinnable() {
    let cfg = mssql_cfg_with_overlay(KIND_PIN_RULE);

    let ids = rule_ids_with("OPEN SYMMETRIC KEY sk DECRYPTION BY CERTIFICATE c;", &cfg);
    assert!(
        ids.contains(&"TEST-KEY-IS-SYMMETRIC".to_string()),
        "symmetric key kind must be captured and matchable. Got: {ids:?}"
    );

    // A master-key statement must NOT match the symmetric pin.
    let ids = rule_ids_with("OPEN MASTER KEY DECRYPTION BY PASSWORD = 'p@ss';", &cfg);
    assert!(
        !ids.contains(&"TEST-KEY-IS-SYMMETRIC".to_string()),
        "MASTER KEY must not match a symmetric pin. Got: {ids:?}"
    );
}

// ── Negative: cursor OPEN/CLOSE not hijacked ────────────────────────────────

#[test]
fn test_cursor_open_close_not_hijacked() {
    // A real cursor OPEN/CLOSE (name follows, no MASTER/SYMMETRIC+KEY) must not
    // emit key-management findings.
    for sql in ["OPEN my_cursor;", "CLOSE my_cursor;"] {
        let ids = rule_ids(sql);
        assert!(
            !ids.contains(&"INFO-MSSQL-KEY-MANAGEMENT".to_string()),
            "{sql} is a cursor op, not key management. Got: {ids:?}"
        );
    }
}
