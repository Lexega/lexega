// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL `ALTER SERVER CONFIGURATION SET …` (SQL Server instance config).
//!
//! Unrelated to the SQL/MED foreign-server family — it must NOT be
//! mis-recognized as a foreign server named CONFIGURATION. Covers recognition
//! (parse + byte-exact round-trip, not skipped), the subsystem discriminator,
//! and the recognition-vs-policy split on which subsystems are sensitive.

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

fn rule_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
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
fn test_configuration_forms_recognized() {
    roundtrip_not_skipped("ALTER SERVER CONFIGURATION SET PROCESS AFFINITY CPU = AUTO;");
    roundtrip_not_skipped("ALTER SERVER CONFIGURATION SET DIAGNOSTICS LOG PATH = '/var/log/x';");
    roundtrip_not_skipped(
        "ALTER SERVER CONFIGURATION SET BUFFER POOL EXTENSION ON (FILENAME = 'f.bpe', SIZE = 16 GB);",
    );
    roundtrip_not_skipped("ALTER SERVER CONFIGURATION SET HADR CLUSTER CONTEXT = 'grp';");
    roundtrip_not_skipped("ALTER SERVER CONFIGURATION SET SOFTNUMA OFF;");
}

// ── Governance: subsystem discriminator + recognition/policy split ──────

#[test]
fn test_info_fires_for_every_subsystem() {
    for sql in [
        "ALTER SERVER CONFIGURATION SET PROCESS AFFINITY CPU = AUTO;",
        "ALTER SERVER CONFIGURATION SET SOFTNUMA OFF;",
        "ALTER SERVER CONFIGURATION SET DIAGNOSTICS LOG PATH = '/x';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-SERVER-CONFIG".to_string()),
            "INFO-MSSQL-SERVER-CONFIG should fire for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_sensitive_subsystems_fire_medium() {
    for sql in [
        "ALTER SERVER CONFIGURATION SET DIAGNOSTICS LOG PATH = '/var/log/x';",
        "ALTER SERVER CONFIGURATION SET BUFFER POOL EXTENSION ON (FILENAME = 'f.bpe', SIZE = 16 GB);",
        "ALTER SERVER CONFIGURATION SET HADR CLUSTER CONTEXT = 'grp';",
        "ALTER SERVER CONFIGURATION SET FAILOVER CLUSTER PROPERTY VerboseLogging = '1';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-SERVER-CONFIG-SENSITIVE".to_string()),
            "a filesystem/availability subsystem should fire the sensitive rule for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_benign_subsystems_stay_info_only() {
    // Recognition vs policy: which subsystems are sensitive lives in the YAML
    // `in:` set — perf-tuning subsystems must not fire the medium rule.
    for sql in [
        "ALTER SERVER CONFIGURATION SET PROCESS AFFINITY CPU = AUTO;",
        "ALTER SERVER CONFIGURATION SET SOFTNUMA ON;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            !ids.contains(&"MSSQL-SERVER-CONFIG-SENSITIVE".to_string()),
            "a benign perf subsystem must NOT fire the sensitive rule: {sql}. Got: {ids:?}"
        );
    }
}

// ── Non-regression: foreign server / SERVER ROLE not hijacked ───────────

#[test]
fn test_configuration_not_recognized_as_foreign_server() {
    let ids = rule_ids("ALTER SERVER CONFIGURATION SET DIAGNOSTICS LOG PATH = '/x';");
    assert!(
        !ids.iter()
            .any(|id| id.starts_with("PG-FDW-SERVER") || id == "INFO-PG-FDW-SERVER-ALTER"),
        "ALTER SERVER CONFIGURATION must not be mis-recognized as a foreign server. Got: {ids:?}"
    );
}

#[test]
fn test_foreign_server_named_configuration_is_not_hijacked() {
    // Soundness of the structural guard: the T-SQL config dispatch keys on
    // `CONFIGURATION SET`, so a foreign server coincidentally NAMED
    // "configuration" (followed by OPTIONS, not SET) must route to the
    // foreign-server parser — on ANY dialect, since the discriminator is the
    // token shape, not the dialect.
    let ids = rule_ids("ALTER SERVER configuration OPTIONS (SET host 'h');");
    assert!(
        ids.contains(&"PG-FDW-SERVER-OPTIONS-MODIFIED".to_string())
            && !ids.contains(&"INFO-MSSQL-SERVER-CONFIG".to_string()),
        "a foreign server named 'configuration' must route to the FDW parser, not the config parser. Got: {ids:?}"
    );
}
