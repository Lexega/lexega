// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL `DBCC <command> [ ( args ) ] [WITH options]`.
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped) and the
//! recognition-vs-policy split: the command verb is the only surfaced
//! primitive, and which commands fire the sensitive / write-page verdicts is a
//! YAML list — flipping it reverses the finding without touching Rust (proven
//! by the custom-overlay pin tests).

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

/// Token-safe round-trip + not-skipped. Used for multi-statement inputs, where
/// the formatter applies its own inter-statement blank-line policy (tokens
/// preserved, bytes not necessarily identical).
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
    assert_eq!(
        out, sql,
        "DBCC single-statement round-trip must be byte-exact"
    );
    roundtrip_not_skipped(sql);
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_dbcc_shapes_recognized() {
    // No-arg form.
    roundtrip_byte_exact("DBCC FREEPROCCACHE;");
    // Single quoted/ident arg.
    roundtrip_byte_exact("DBCC CHECKDB('mydb');");
    // Multiple args, including negative numerics.
    roundtrip_byte_exact("DBCC TRACEON(3604, -1);");
    // Args + WITH options.
    roundtrip_byte_exact("DBCC CHECKDB('mydb') WITH NO_INFOMSGS, ALL_ERRORMSGS;");
    // Nested parens in the argument list.
    roundtrip_byte_exact("DBCC WRITEPAGE('mydb', 1, 100, 0, 1, 0x0000, 1);");
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "DBCC CHECKDB('a');\n\
         DBCC TRACEON(3604);\n\
         DBCC FREEPROCCACHE;",
    );
}

// ── Governance: severity gradient ─────────────────────────────────────────

#[test]
fn test_writepage_fires_high_rule() {
    let ids = rule_ids("DBCC WRITEPAGE('mydb', 1, 100, 0, 1, 0x00, 1);");
    assert!(
        ids.contains(&"MSSQL-DBCC-WRITEPAGE".to_string()),
        "WRITEPAGE must fire the high-severity data-tampering rule. Got: {ids:?}"
    );
    // It is NOT in the SENSITIVE bucket (own dedicated rule).
    assert!(
        !ids.contains(&"MSSQL-DBCC-SENSITIVE".to_string()),
        "WRITEPAGE is its own rule, not the SENSITIVE bucket. Got: {ids:?}"
    );
}

#[test]
fn test_sensitive_commands_fire_medium_rule() {
    for cmd in [
        "DBCC TRACEON(3604);",
        "DBCC TRACEOFF(3604);",
        "DBCC SHRINKDATABASE('mydb', 10);",
        "DBCC SHRINKFILE('f', 1);",
        "DBCC FREEPROCCACHE;",
        "DBCC DROPCLEANBUFFERS;",
        "DBCC CHECKIDENT('t', RESEED, 0);",
    ] {
        let ids = rule_ids(cmd);
        assert!(
            ids.contains(&"MSSQL-DBCC-SENSITIVE".to_string()),
            "{cmd} should fire MSSQL-DBCC-SENSITIVE. Got: {ids:?}"
        );
    }
}

#[test]
fn test_benign_commands_info_only() {
    // Read-only integrity / diagnostic commands fire INFO only — soundness
    // that the SENSITIVE verdict keys on the typed command, not on "any DBCC".
    for cmd in [
        "DBCC CHECKDB('mydb');",
        "DBCC CHECKTABLE('t');",
        "DBCC OPENTRAN;",
        "DBCC SQLPERF(LOGSPACE);",
    ] {
        let ids = rule_ids(cmd);
        assert!(
            ids.contains(&"INFO-MSSQL-DBCC".to_string()),
            "{cmd} should fire INFO-MSSQL-DBCC. Got: {ids:?}"
        );
        assert!(
            !ids.contains(&"MSSQL-DBCC-SENSITIVE".to_string())
                && !ids.contains(&"MSSQL-DBCC-WRITEPAGE".to_string()),
            "{cmd} must not fire a sensitive/write rule. Got: {ids:?}"
        );
    }
}

#[test]
fn test_info_dbcc_fires_for_every_command() {
    for cmd in [
        "DBCC CHECKDB('mydb');",
        "DBCC WRITEPAGE('mydb', 1, 100, 0, 1, 0x00, 1);",
        "DBCC TRACEON(3604);",
    ] {
        let ids = rule_ids(cmd);
        assert!(
            ids.contains(&"INFO-MSSQL-DBCC".to_string()),
            "INFO-MSSQL-DBCC should fire for {cmd}. Got: {ids:?}"
        );
    }
}

// ── Recognition vs. policy: the command verb is pinnable, the verdict is
//    pure YAML ───────────────────────────────────────────────────────────

const COMMAND_PIN_RULE: &str = r#"
rules:
  - id: TEST-DBCC-IS-CHECKDB
    risk_level: info
    message: "command is checkdb"
    triggers:
      all_of:
        - kind: mssql_dbcc
        - mssql_dbcc.command: checkdb
"#;

#[test]
fn test_command_verb_is_captured_and_pinnable() {
    let cfg = mssql_cfg_with_overlay(COMMAND_PIN_RULE);

    // Case-insensitive in source; the captured primitive is normalized lower.
    let ids = rule_ids_with("DBCC CheckDB('mydb');", &cfg);
    assert!(
        ids.contains(&"TEST-DBCC-IS-CHECKDB".to_string()),
        "command verb must be captured (normalized lowercase) and matchable. Got: {ids:?}"
    );

    // A different command must NOT match the pinned scalar — proves the field
    // carries the actual verb, not a blanket flag.
    let ids = rule_ids_with("DBCC TRACEON(3604);", &cfg);
    assert!(
        !ids.contains(&"TEST-DBCC-IS-CHECKDB".to_string()),
        "TRACEON must not match a checkdb pin. Got: {ids:?}"
    );
}

// ── Negative case ─────────────────────────────────────────────────────────

#[test]
fn test_bare_dbcc_identifier_not_hijacked() {
    // `DBCC` used as a column reference (no command verb follows) must not be
    // parsed as a DBCC statement / emit DBCC findings.
    let ids = rule_ids("SELECT DBCC FROM t;");
    assert!(
        !ids.contains(&"INFO-MSSQL-DBCC".to_string()),
        "a `DBCC` identifier in a SELECT must not emit DBCC findings. Got: {ids:?}"
    );
}
