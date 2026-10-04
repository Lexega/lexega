// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL Row-Level Security: `CREATE`/`ALTER SECURITY POLICY`.
//!
//! The row-level-security control surface includes a policy shipped disabled
//! and an existing one turned off. This covers
//! recognition (parse + round-trip, not skipped), the recognition-vs-policy
//! split (verb / state / predicate-kind are pinnable primitives; the
//! disabled-control verdict is pure YAML), and disambiguation from `CREATE
//! SECURITY INTEGRATION`.

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
fn test_policy_shapes_recognized() {
    roundtrip_byte_exact(
        "CREATE SECURITY POLICY dbo.pol ADD FILTER PREDICATE dbo.fn(uid) ON dbo.t WITH (STATE = ON);",
    );
    roundtrip_byte_exact(
        "CREATE SECURITY POLICY pol ADD BLOCK PREDICATE dbo.fn(uid) ON dbo.t AFTER INSERT;",
    );
    roundtrip_byte_exact("ALTER SECURITY POLICY pol WITH (STATE = OFF);");
    roundtrip_byte_exact("ALTER SECURITY POLICY pol ADD FILTER PREDICATE dbo.fn(c) ON dbo.t2;");
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "CREATE SECURITY POLICY pol ADD FILTER PREDICATE dbo.fn(uid) ON dbo.t WITH (STATE = ON);\n\
         ALTER SECURITY POLICY pol WITH (STATE = OFF);",
    );
}

// ── Governance: severity gradient ─────────────────────────────────────────

#[test]
fn test_alter_disable_fires_high() {
    let ids = rule_ids("ALTER SECURITY POLICY pol WITH (STATE = OFF);");
    assert!(
        ids.contains(&"MSSQL-RLS-POLICY-DISABLED".to_string()),
        "disabling an existing policy must fire the high rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MSSQL-RLS-POLICY-CREATED-DISABLED".to_string()),
        "an ALTER must not fire the create-disabled rule. Got: {ids:?}"
    );
}

#[test]
fn test_create_disabled_fires_medium() {
    // Explicit STATE = OFF, and the no-STATE form (defaults to OFF).
    for sql in [
        "CREATE SECURITY POLICY pol ADD FILTER PREDICATE dbo.fn(uid) ON dbo.t WITH (STATE = OFF);",
        "CREATE SECURITY POLICY pol ADD FILTER PREDICATE dbo.fn(uid) ON dbo.t;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-RLS-POLICY-CREATED-DISABLED".to_string()),
            "{sql} should fire the created-disabled rule. Got: {ids:?}"
        );
        assert!(
            !ids.contains(&"MSSQL-RLS-POLICY-DISABLED".to_string()),
            "a CREATE must not fire the alter-disable rule. Got: {ids:?}"
        );
    }
}

#[test]
fn test_enabled_policy_info_only() {
    // An enabled policy (create or alter STATE = ON) is sound — INFO only.
    for sql in [
        "CREATE SECURITY POLICY pol ADD FILTER PREDICATE dbo.fn(uid) ON dbo.t WITH (STATE = ON);",
        "ALTER SECURITY POLICY pol WITH (STATE = ON);",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-SECURITY-POLICY".to_string()),
            "{sql} should fire INFO. Got: {ids:?}"
        );
        assert!(
            !ids.contains(&"MSSQL-RLS-POLICY-DISABLED".to_string())
                && !ids.contains(&"MSSQL-RLS-POLICY-CREATED-DISABLED".to_string()),
            "{sql} is enabled — no disabled-control verdict. Got: {ids:?}"
        );
    }
}

// ── Recognition vs. policy: primitives pinnable, verdict pure YAML ──────────

const PRED_PIN_RULE: &str = r#"
rules:
  - id: TEST-RLS-HAS-BLOCK
    risk_level: info
    message: "policy binds a block predicate"
    triggers:
      all_of:
        - kind: mssql_security_policy
        - mssql_security_policy.has_block_predicate: true
"#;

#[test]
fn test_predicate_kind_is_captured_and_pinnable() {
    let cfg = mssql_cfg_with_overlay(PRED_PIN_RULE);

    let ids = rule_ids_with(
        "CREATE SECURITY POLICY pol ADD BLOCK PREDICATE dbo.fn(uid) ON dbo.t AFTER INSERT;",
        &cfg,
    );
    assert!(
        ids.contains(&"TEST-RLS-HAS-BLOCK".to_string()),
        "a block predicate must be captured and matchable. Got: {ids:?}"
    );

    // A filter-only policy must NOT match the block pin.
    let ids = rule_ids_with(
        "CREATE SECURITY POLICY pol ADD FILTER PREDICATE dbo.fn(uid) ON dbo.t WITH (STATE = ON);",
        &cfg,
    );
    assert!(
        !ids.contains(&"TEST-RLS-HAS-BLOCK".to_string()),
        "a filter-only policy must not match a block pin. Got: {ids:?}"
    );
}

// ── Negative: SECURITY INTEGRATION not hijacked ─────────────────────────────

#[test]
fn test_security_integration_not_hijacked() {
    // Snowflake CREATE SECURITY INTEGRATION must not be read as a security
    // policy (it has its own parser).
    let cfg = AnalysisConfig {
        dialect: Some(dialect::snowflake()),
        ..Default::default()
    };
    let ids = rule_ids_with("CREATE SECURITY INTEGRATION si TYPE = SAML2;", &cfg);
    assert!(
        !ids.contains(&"INFO-MSSQL-SECURITY-POLICY".to_string()),
        "SECURITY INTEGRATION must not emit security-policy findings. Got: {ids:?}"
    );
}
