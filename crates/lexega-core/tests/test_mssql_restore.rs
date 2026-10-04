// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL `RESTORE { DATABASE | LOG } … FROM { DISK | URL | TAPE } = '…'`.
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped), governance
//! — including the soundness checks that the offsite-source rule fires only
//! for `URL` and the overwrite rule only for `WITH REPLACE` — and the
//! non-regression of the Databricks RESTORE form.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mssql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mssql()),
        ..Default::default()
    }
}

fn rule_ids_cfg(sql: &str, cfg: &AnalysisConfig) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, cfg).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn rule_ids(sql: &str) -> Vec<String> {
    rule_ids_cfg(sql, &mssql_cfg())
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
fn test_all_sources_recognized() {
    roundtrip_not_skipped("RESTORE DATABASE mydb FROM DISK = 'x.bak';");
    roundtrip_not_skipped(
        "RESTORE DATABASE mydb FROM URL = 'https://a.blob.core.windows.net/c/x.bak';",
    );
    roundtrip_not_skipped("RESTORE DATABASE mydb FROM TAPE = '\\\\.\\tape0';");
    roundtrip_not_skipped("RESTORE LOG mydb FROM DISK = N'\\\\share\\x.trn';");
}

#[test]
fn test_clauses_and_qualified_names_recognized() {
    // WITH REPLACE, RECOVERY.
    roundtrip_not_skipped(
        "RESTORE DATABASE mydb FROM URL = 'https://a.blob.core.windows.net/c/x.bak' \
         WITH REPLACE, RECOVERY;",
    );
    // WITH NORECOVERY, MOVE … TO ….
    roundtrip_not_skipped(
        "RESTORE LOG mydb FROM DISK = N'\\\\share\\x.trn' WITH NORECOVERY, MOVE 'd' TO 'e';",
    );
    // Multiple (striped) sources.
    roundtrip_not_skipped(
        "RESTORE DATABASE mydb FROM DISK = 'a.bak', DISK = 'b.bak' WITH RECOVERY;",
    );
    // Bare recovery form — no FROM clause.
    roundtrip_not_skipped("RESTORE DATABASE mydb WITH RECOVERY;");
    // Qualified / quoted name.
    roundtrip_not_skipped("RESTORE DATABASE [my db] FROM DISK = 'x.bak';");
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "RESTORE DATABASE a FROM DISK = 'a.bak' WITH NORECOVERY;\n\
         RESTORE LOG a FROM DISK = 'a.trn' WITH RECOVERY;\n\
         RESTORE DATABASE c FROM URL = 'https://a.blob.core.windows.net/c/c.bak';",
    );
}

// ── Governance: source ──────────────────────────────────────────────────

#[test]
fn test_url_source_fires_offsite_rule() {
    let ids =
        rule_ids("RESTORE DATABASE mydb FROM URL = 'https://a.blob.core.windows.net/c/x.bak';");
    assert!(
        ids.contains(&"MSSQL-RESTORE-FROM-URL".to_string()),
        "URL source should fire the offsite-restore rule. Got: {ids:?}"
    );
}

#[test]
fn test_disk_and_tape_do_not_fire_offsite_rule() {
    for sql in [
        "RESTORE DATABASE mydb FROM DISK = 'x.bak';",
        "RESTORE DATABASE mydb FROM TAPE = '\\\\.\\tape0';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            !ids.contains(&"MSSQL-RESTORE-FROM-URL".to_string()),
            "non-URL source must NOT fire the offsite rule for {sql}. Got: {ids:?}"
        );
    }
}

// ── Governance: WITH REPLACE ────────────────────────────────────────────

#[test]
fn test_replace_fires_overwrite_rule() {
    let ids = rule_ids("RESTORE DATABASE mydb FROM DISK = 'x.bak' WITH REPLACE;");
    assert!(
        ids.contains(&"MSSQL-RESTORE-REPLACE".to_string()),
        "WITH REPLACE should fire the overwrite rule. Got: {ids:?}"
    );
}

#[test]
fn test_no_replace_does_not_fire_overwrite_rule() {
    // Soundness: the overwrite rule keys on the typed REPLACE flag, not text —
    // a restore without WITH REPLACE must stay silent.
    let ids = rule_ids("RESTORE DATABASE mydb FROM DISK = 'x.bak' WITH RECOVERY;");
    assert!(
        !ids.contains(&"MSSQL-RESTORE-REPLACE".to_string()),
        "a restore without WITH REPLACE must NOT fire the overwrite rule. Got: {ids:?}"
    );
}

#[test]
fn test_info_restore_fires_for_every_source() {
    for sql in [
        "RESTORE DATABASE mydb FROM DISK = 'x.bak';",
        "RESTORE DATABASE mydb FROM URL = 'https://a.blob.core.windows.net/c/x.bak';",
        "RESTORE LOG mydb FROM TAPE = '\\\\.\\tape0';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-RESTORE".to_string()),
            "INFO-MSSQL-RESTORE should fire for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_url_and_replace_compose() {
    let ids = rule_ids(
        "RESTORE DATABASE mydb FROM URL = 'https://a.blob.core.windows.net/c/x.bak' WITH REPLACE;",
    );
    assert!(
        ids.contains(&"MSSQL-RESTORE-FROM-URL".to_string())
            && ids.contains(&"MSSQL-RESTORE-REPLACE".to_string()),
        "URL + REPLACE should fire both rules. Got: {ids:?}"
    );
}

// ── Non-regression: Databricks time-travel RESTORE ──────────────────────

#[test]
fn test_databricks_restore_not_hijacked() {
    // `RESTORE [TABLE] name TO {VERSION|TIMESTAMP} AS OF …` must still parse on
    // Databricks and must not produce a T-SQL restore finding.
    let mut config = FormatterConfig::default();
    config.dialect = dialect::databricks();
    let dbx_cfg = AnalysisConfig {
        dialect: Some(dialect::databricks()),
        ..Default::default()
    };

    for sql in [
        "RESTORE TABLE t TO VERSION AS OF 5;",
        "RESTORE t TO TIMESTAMP AS OF '2024-01-01';",
    ] {
        let out = format_sql_with_config(sql, &config).expect("should format");
        verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
            .expect("should preserve tokens");
        let report = analyze_risk_with_policy_config(sql, &dbx_cfg).expect("should analyze");
        assert_eq!(
            report.summary.statements_skipped, 0,
            "Databricks RESTORE must still be analyzed, not skipped: {sql}"
        );
        let ids = rule_ids_cfg(sql, &dbx_cfg);
        assert!(
            !ids.contains(&"INFO-MSSQL-RESTORE".to_string()),
            "Databricks time-travel RESTORE must not fire a T-SQL restore finding: {sql}. Got: {ids:?}"
        );
    }
}
