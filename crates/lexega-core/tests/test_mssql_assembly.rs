// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL CLR assembly: `CREATE`/`ALTER ASSEMBLY … WITH PERMISSION_SET = …`.
//!
//! This covers recognition (parse + round-trip, not skipped), the
//! recognition-vs-policy split (verb / permission-set / from-file are pinnable
//! primitives; the UNSAFE / EXTERNAL_ACCESS verdict is pure YAML), and that
//! the permission gradient is sound.

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
fn test_assembly_shapes_recognized() {
    roundtrip_byte_exact("CREATE ASSEMBLY util FROM 'D:\\u.dll' WITH PERMISSION_SET = UNSAFE;");
    roundtrip_byte_exact(
        "CREATE ASSEMBLY util AUTHORIZATION dbo FROM 0x4D5A WITH PERMISSION_SET = SAFE;",
    );
    roundtrip_byte_exact("CREATE ASSEMBLY util FROM 'D:\\u.dll';");
    roundtrip_byte_exact("ALTER ASSEMBLY util WITH PERMISSION_SET = EXTERNAL_ACCESS;");
}

// ── Governance: permission gradient ────────────────────────────────────────

#[test]
fn test_unsafe_fires_high() {
    for sql in [
        "CREATE ASSEMBLY util FROM 'D:\\u.dll' WITH PERMISSION_SET = UNSAFE;",
        "ALTER ASSEMBLY util WITH PERMISSION_SET = UNSAFE;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-CLR-ASSEMBLY-UNSAFE".to_string()),
            "{sql} must fire the UNSAFE rule. Got: {ids:?}"
        );
        assert!(
            !ids.contains(&"MSSQL-CLR-ASSEMBLY-EXTERNAL-ACCESS".to_string()),
            "{sql} is UNSAFE, not EXTERNAL_ACCESS. Got: {ids:?}"
        );
    }
}

#[test]
fn test_external_access_fires_medium() {
    let ids = rule_ids("ALTER ASSEMBLY util WITH PERMISSION_SET = EXTERNAL_ACCESS;");
    assert!(
        ids.contains(&"MSSQL-CLR-ASSEMBLY-EXTERNAL-ACCESS".to_string()),
        "EXTERNAL_ACCESS must fire the medium rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MSSQL-CLR-ASSEMBLY-UNSAFE".to_string()),
        "EXTERNAL_ACCESS is not UNSAFE. Got: {ids:?}"
    );
}

#[test]
fn test_safe_and_default_info_only() {
    // SAFE, and the no-PERMISSION_SET form (defaults to SAFE), are sound — the
    // permission verdict keys on the typed value, not "any assembly".
    for sql in [
        "CREATE ASSEMBLY util FROM 0x4D5A WITH PERMISSION_SET = SAFE;",
        "CREATE ASSEMBLY util FROM 'D:\\u.dll';",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-CLR-ASSEMBLY".to_string()),
            "{sql} should fire INFO. Got: {ids:?}"
        );
        assert!(
            !ids.contains(&"MSSQL-CLR-ASSEMBLY-UNSAFE".to_string())
                && !ids.contains(&"MSSQL-CLR-ASSEMBLY-EXTERNAL-ACCESS".to_string()),
            "{sql} is SAFE — no elevated-permission verdict. Got: {ids:?}"
        );
    }
}

// ── Recognition vs. policy: primitives pinnable, verdict pure YAML ──────────

const FROM_FILE_PIN_RULE: &str = r#"
rules:
  - id: TEST-ASM-FROM-FILE
    risk_level: info
    message: "assembly loaded from a filesystem path"
    triggers:
      all_of:
        - kind: mssql_assembly
        - mssql_assembly.from_file: true
"#;

#[test]
fn test_from_file_is_captured_and_pinnable() {
    let cfg = mssql_cfg_with_overlay(FROM_FILE_PIN_RULE);

    let ids = rule_ids_with(
        "CREATE ASSEMBLY util FROM 'D:\\u.dll' WITH PERMISSION_SET = SAFE;",
        &cfg,
    );
    assert!(
        ids.contains(&"TEST-ASM-FROM-FILE".to_string()),
        "a filesystem-path source must be captured and matchable. Got: {ids:?}"
    );

    // An inline 0x binary must NOT match the from-file pin.
    let ids = rule_ids_with(
        "CREATE ASSEMBLY util FROM 0x4D5A WITH PERMISSION_SET = SAFE;",
        &cfg,
    );
    assert!(
        !ids.contains(&"TEST-ASM-FROM-FILE".to_string()),
        "an inline binary must not match a from-file pin. Got: {ids:?}"
    );
}

// ── Regression: ordinary CREATE not hijacked ────────────────────────────────

#[test]
fn test_create_table_not_hijacked() {
    let ids = rule_ids("CREATE TABLE t (a int);");
    assert!(
        !ids.contains(&"INFO-MSSQL-CLR-ASSEMBLY".to_string()),
        "CREATE TABLE must not emit assembly findings. Got: {ids:?}"
    );
}
