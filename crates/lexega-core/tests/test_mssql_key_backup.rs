// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL encryption key-material protection: `BACKUP`/`RESTORE { SERVICE
//! MASTER KEY | MASTER KEY | CERTIFICATE | ASYMMETRIC KEY }`.
//!
//! This covers recognition (parse + round-trip, not skipped), the
//! recognition-vs-policy split (verb / key-object / password are pinnable
//! primitives; the export/restore/credential verdicts are pure YAML), the
//! secret-redaction invariant (including the two-password RESTORE form), and
//! disambiguation from `BACKUP/RESTORE DATABASE`.

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
fn test_key_backup_shapes_recognized() {
    roundtrip_byte_exact(
        "BACKUP SERVICE MASTER KEY TO FILE = 'c:\\smk.bak' ENCRYPTION BY PASSWORD = 'p@ss';",
    );
    roundtrip_byte_exact(
        "RESTORE SERVICE MASTER KEY FROM FILE = 'c:\\smk.bak' DECRYPTION BY PASSWORD = 'p@ss';",
    );
    roundtrip_byte_exact(
        "BACKUP MASTER KEY TO FILE = 'c:\\dmk.bak' ENCRYPTION BY PASSWORD = 'p@ss';",
    );
    roundtrip_byte_exact(
        "BACKUP CERTIFICATE c TO FILE = 'c:\\c.cer' WITH PRIVATE KEY (FILE = 'c:\\c.pvk', ENCRYPTION BY PASSWORD = 'p@ss');",
    );
}

// ── Governance ─────────────────────────────────────────────────────────

#[test]
fn test_master_key_export_fires_high() {
    for sql in [
        "BACKUP SERVICE MASTER KEY TO FILE = 'c:\\smk.bak' ENCRYPTION BY PASSWORD = 'p@ss';",
        "BACKUP MASTER KEY TO FILE = 'c:\\dmk.bak' ENCRYPTION BY PASSWORD = 'p@ss';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-MASTER-KEY-EXPORT".to_string()),
            "{sql} must fire the root-key export rule. Got: {ids:?}"
        );
    }
}

#[test]
fn test_master_key_restore_fires_high() {
    let ids = rule_ids(
        "RESTORE SERVICE MASTER KEY FROM FILE = 'c:\\smk.bak' DECRYPTION BY PASSWORD = 'p@ss';",
    );
    assert!(
        ids.contains(&"MSSQL-MASTER-KEY-RESTORE".to_string()),
        "restore must fire the re-key rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MSSQL-MASTER-KEY-EXPORT".to_string()),
        "a restore must not fire the export rule. Got: {ids:?}"
    );
}

#[test]
fn test_inline_password_fires_high() {
    let ids =
        rule_ids("BACKUP MASTER KEY TO FILE = 'c:\\dmk.bak' ENCRYPTION BY PASSWORD = 'p@ss';");
    assert!(
        ids.contains(&"MSSQL-KEY-BACKUP-INLINE-PASSWORD".to_string()),
        "hardcoded password must fire the credential rule. Got: {ids:?}"
    );
}

#[test]
fn test_certificate_export_not_root_key() {
    // A certificate backup is sensitive (INFO + credential) but is NOT the
    // root-key export — the EXPORT verdict scopes to SMK/DMK in YAML.
    let ids = rule_ids(
        "BACKUP CERTIFICATE c TO FILE = 'c:\\c.cer' WITH PRIVATE KEY (FILE = 'c:\\c.pvk', ENCRYPTION BY PASSWORD = 'p@ss');",
    );
    assert!(
        !ids.contains(&"MSSQL-MASTER-KEY-EXPORT".to_string()),
        "a certificate is not a root key — export rule must not fire. Got: {ids:?}"
    );
    assert!(
        ids.contains(&"MSSQL-KEY-BACKUP-INLINE-PASSWORD".to_string())
            && ids.contains(&"INFO-MSSQL-KEY-BACKUP".to_string()),
        "certificate backup still fires the credential + info rules. Got: {ids:?}"
    );
}

// ── Secret redaction (including the two-password RESTORE form) ──────────────

#[test]
fn test_both_passwords_redacted() {
    let sql = "RESTORE MASTER KEY FROM FILE = 'c:\\dmk.bak' \
               DECRYPTION BY PASSWORD = 'decrypt_secret_aa' \
               ENCRYPTION BY PASSWORD = 'encrypt_secret_bb';";
    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    let json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        !json.contains("decrypt_secret_aa") && !json.contains("encrypt_secret_bb"),
        "a RESTORE password leaked into the report"
    );

    let display = redact_secrets_for_display(sql);
    assert!(
        !display.contains("decrypt_secret_aa") && !display.contains("encrypt_secret_bb"),
        "a RESTORE password leaked into the display surface: {display}"
    );
}

// ── Recognition vs. policy: key object pinnable, verdict pure YAML ──────────

const OBJ_PIN_RULE: &str = r#"
rules:
  - id: TEST-KEY-IS-SMK
    risk_level: info
    message: "key object is the service master key"
    triggers:
      all_of:
        - kind: mssql_key_backup
        - mssql_key_backup.key_object: service_master_key
"#;

#[test]
fn test_key_object_is_captured_and_pinnable() {
    let cfg = mssql_cfg_with_overlay(OBJ_PIN_RULE);

    let ids = rule_ids_with(
        "BACKUP SERVICE MASTER KEY TO FILE = 'c:\\smk.bak' ENCRYPTION BY PASSWORD = 'p@ss';",
        &cfg,
    );
    assert!(
        ids.contains(&"TEST-KEY-IS-SMK".to_string()),
        "the service master key object must be captured and matchable. Got: {ids:?}"
    );

    // The database master key must NOT match the SMK pin.
    let ids = rule_ids_with(
        "BACKUP MASTER KEY TO FILE = 'c:\\dmk.bak' ENCRYPTION BY PASSWORD = 'p@ss';",
        &cfg,
    );
    assert!(
        !ids.contains(&"TEST-KEY-IS-SMK".to_string()),
        "MASTER KEY must not match a service-master-key pin. Got: {ids:?}"
    );
}

// ── Regression: data-protection BACKUP/RESTORE not hijacked ─────────────────

#[test]
fn test_database_backup_not_hijacked() {
    // BACKUP DATABASE stays in the data-protection family, not key-material.
    let ids = rule_ids("BACKUP DATABASE mydb TO DISK = 'c:\\m.bak';");
    assert!(
        ids.contains(&"INFO-MSSQL-BACKUP".to_string()),
        "BACKUP DATABASE must stay the data-protection backup. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"INFO-MSSQL-KEY-BACKUP".to_string()),
        "BACKUP DATABASE must not emit key-material findings. Got: {ids:?}"
    );
}
