// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL `BACKUP { DATABASE | LOG } … TO { DISK | URL | TAPE } = '…'`.
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped) and
//! governance — including the soundness checks that the offsite-backup rule
//! fires only for the URL destination, and that the encryption flag
//! distinguishes encrypted from plain backups.

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

/// mssql config whose corpus is built-ins overlaid with `custom_yaml`.
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

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_all_destinations_recognized() {
    roundtrip_not_skipped("BACKUP DATABASE mydb TO DISK = 'x.bak';");
    roundtrip_not_skipped(
        "BACKUP DATABASE mydb TO URL = 'https://acct.blob.core.windows.net/c/x.bak';",
    );
    roundtrip_not_skipped("BACKUP DATABASE mydb TO TAPE = '\\\\.\\tape0';");
    roundtrip_not_skipped("BACKUP LOG mydb TO DISK = N'\\\\share\\x.trn';");
}

#[test]
fn test_clauses_and_qualified_names_recognized() {
    // WITH ENCRYPTION (parenthesised options).
    roundtrip_not_skipped(
        "BACKUP DATABASE mydb TO DISK = 'x.bak' \
         WITH ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = cert1);",
    );
    // Multiple (mirrored) destinations + WITH option list.
    roundtrip_not_skipped(
        "BACKUP DATABASE mydb TO DISK = 'a.bak', DISK = 'b.bak' \
         WITH COMPRESSION, COPY_ONLY, FORMAT;",
    );
    // FILE / FILEGROUP clause before TO.
    roundtrip_not_skipped("BACKUP DATABASE mydb FILE = 'f1' TO DISK = 'x.bak';");
    // Qualified name.
    roundtrip_not_skipped("BACKUP LOG [my db] TO DISK = 'x.trn';");
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "BACKUP DATABASE a TO DISK = 'a.bak';\n\
         BACKUP LOG b TO DISK = 'b.trn';\n\
         BACKUP DATABASE c TO URL = 'https://acct.blob.core.windows.net/c/c.bak';",
    );
}

// ── Governance: destination ─────────────────────────────────────────────

#[test]
fn test_url_destination_fires_offsite_rule() {
    let ids =
        rule_ids("BACKUP DATABASE mydb TO URL = 'https://acct.blob.core.windows.net/c/x.bak';");
    assert!(
        ids.contains(&"MSSQL-BACKUP-TO-URL".to_string()),
        "URL destination should fire the offsite-backup rule. Got: {ids:?}"
    );
}

#[test]
fn test_disk_and_tape_do_not_fire_offsite_rule() {
    // Soundness: the offsite rule keys on the typed destination class, not on
    // text — DISK and TAPE must stay silent.
    for sql in [
        "BACKUP DATABASE mydb TO DISK = 'x.bak';",
        "BACKUP DATABASE mydb TO TAPE = '\\\\.\\tape0';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            !ids.contains(&"MSSQL-BACKUP-TO-URL".to_string()),
            "non-URL destination must NOT fire the offsite rule for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_info_backup_fires_for_every_destination() {
    for sql in [
        "BACKUP DATABASE mydb TO DISK = 'x.bak';",
        "BACKUP DATABASE mydb TO URL = 'https://acct.blob.core.windows.net/c/x.bak';",
        "BACKUP LOG mydb TO TAPE = '\\\\.\\tape0';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-BACKUP".to_string()),
            "INFO-MSSQL-BACKUP should fire for {sql}. Got: {ids:?}"
        );
    }
}

// ── Governance: encryption flag ─────────────────────────────────────────

const ENCRYPTION_RULE: &str = r#"
rules:
  - id: TEST-BACKUP-ENCRYPTED
    risk_level: info
    message: "encrypted backup"
    triggers:
      all_of:
        - kind: mssql_backup
        - mssql_backup.encryption: true
"#;

#[test]
fn test_encryption_flag_captured() {
    let cfg = mssql_cfg_with_overlay(ENCRYPTION_RULE);

    let encrypted = "BACKUP DATABASE mydb TO DISK = 'x.bak' \
         WITH ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = cert1);";
    let ids = rule_ids_with(encrypted, &cfg);
    assert!(
        ids.contains(&"TEST-BACKUP-ENCRYPTED".to_string()),
        "WITH ENCRYPTION must set the encryption fact. Got: {ids:?}"
    );

    // Soundness: a plain backup must NOT report encryption.
    let plain = "BACKUP DATABASE mydb TO DISK = 'x.bak';";
    let ids = rule_ids_with(plain, &cfg);
    assert!(
        !ids.contains(&"TEST-BACKUP-ENCRYPTED".to_string()),
        "plain backup must NOT set the encryption fact. Got: {ids:?}"
    );
}

// ── Negative cases ──────────────────────────────────────────────────────

#[test]
fn test_unsupported_backup_form_does_not_produce_backup_findings() {
    // BACKUP CERTIFICATE has a different grammar; it must degrade to
    // OpaqueContent rather than be mis-parsed into a partial BACKUP — and a
    // partial parse must never emit a backup finding.
    let ids = rule_ids("BACKUP CERTIFICATE c TO FILE = 'c.cer';");
    assert!(
        !ids.contains(&"INFO-MSSQL-BACKUP".to_string())
            && !ids.contains(&"MSSQL-BACKUP-TO-URL".to_string()),
        "unsupported BACKUP form must not emit backup findings. Got: {ids:?}"
    );
}

#[test]
fn test_stray_backup_identifier_not_hijacked() {
    // `backup` as a column reference must not be parsed as a BACKUP statement.
    let sql = "SELECT backup FROM t;";
    roundtrip_not_skipped(sql);
    let ids = rule_ids(sql);
    assert!(
        !ids.contains(&"INFO-MSSQL-BACKUP".to_string()),
        "a stray `backup` identifier must not trigger backup findings. Got: {ids:?}"
    );
}
