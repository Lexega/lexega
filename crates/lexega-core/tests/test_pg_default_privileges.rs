// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! PostgreSQL `ALTER DEFAULT PRIVILEGES`:
//! `ALTER DEFAULT PRIVILEGES [FOR {ROLE|USER} r[,…]] [IN SCHEMA s[,…]]
//!   { GRANT privs ON class TO grantee[,…] [WITH GRANT OPTION]
//!   | REVOKE [GRANT OPTION FOR] privs ON class FROM grantee[,…] [CASCADE|RESTRICT] }`.
//!
//! This covers recognition (parse + byte-exact round-trip, not
//! skipped/fragmented), the recognition-vs-policy split (action /
//! all_privileges / global_scope / grantees are pinnable primitives; the
//! verdict is pure YAML), and that a plain GRANT and a Snowflake `GRANT … ON
//! FUTURE` are unaffected.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn pg_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::postgres()),
        ..Default::default()
    }
}

fn pg_cfg_with_overlay(custom_yaml: &str) -> AnalysisConfig {
    let custom = load_v1_rules(custom_yaml).expect("custom rules parse");
    let merged = build_v1_rule_corpus(custom, /* include_builtins = */ true)
        .expect("merge against built-ins succeeds");
    AnalysisConfig {
        dialect: Some(dialect::postgres()),
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
    rule_ids_with(sql, &pg_cfg())
}

fn roundtrip_not_skipped(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::postgres();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let report = analyze_risk_with_policy_config(sql, &pg_cfg()).expect("should analyze");
    // The hallmark of the prior fragmentation bug: one statement splitting into
    // one analyzed fragment plus two skipped (Unrecognized) ones. A recognized
    // ALTER DEFAULT PRIVILEGES is exactly one analyzed statement, zero skipped.
    assert_eq!(
        report.summary.statements_skipped, 0,
        "must be analyzed, not skipped/fragmented: {sql}"
    );
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "must be a single analyzed statement, not fragmented: {sql}"
    );
}

fn roundtrip_byte_exact(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::postgres();
    let out = format_sql_with_config(sql, &config).expect("should format");
    assert_eq!(out, sql, "single-statement round-trip must be byte-exact");
    roundtrip_not_skipped(sql);
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_adp_shapes_recognized() {
    roundtrip_byte_exact("ALTER DEFAULT PRIVILEGES IN SCHEMA s GRANT SELECT ON TABLES TO bob;");
    roundtrip_byte_exact("ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO PUBLIC;");
    roundtrip_byte_exact(
        "ALTER DEFAULT PRIVILEGES FOR ROLE app, ops IN SCHEMA s, t GRANT ALL PRIVILEGES ON FUNCTIONS TO PUBLIC WITH GRANT OPTION;",
    );
    roundtrip_byte_exact("ALTER DEFAULT PRIVILEGES GRANT USAGE ON SEQUENCES TO app_role;");
    roundtrip_byte_exact(
        "ALTER DEFAULT PRIVILEGES REVOKE GRANT OPTION FOR SELECT ON TABLES FROM bob CASCADE;",
    );
    roundtrip_byte_exact(
        "ALTER DEFAULT PRIVILEGES FOR USER u GRANT EXECUTE ON ROUTINES TO PUBLIC;",
    );
}

// ── Governance ─────────────────────────────────────────────────────────

#[test]
fn test_default_to_public_fires_high() {
    let ids = rule_ids("ALTER DEFAULT PRIVILEGES IN SCHEMA s GRANT SELECT ON TABLES TO PUBLIC;");
    assert!(
        ids.contains(&"PG-DEFAULT-PRIV-TO-PUBLIC".to_string()),
        "a default grant to PUBLIC must fire the PUBLIC rule. Got: {ids:?}"
    );
    // Scoped (IN SCHEMA) and a named privilege — neither global nor ALL.
    assert!(
        !ids.contains(&"PG-DEFAULT-PRIV-GLOBAL".to_string())
            && !ids.contains(&"PG-DEFAULT-PRIV-ALL".to_string()),
        "a scoped, named-privilege default must not fire GLOBAL/ALL. Got: {ids:?}"
    );
}

#[test]
fn test_default_all_fires_medium() {
    let ids = rule_ids("ALTER DEFAULT PRIVILEGES IN SCHEMA s GRANT ALL ON TABLES TO app_role;");
    assert!(
        ids.contains(&"PG-DEFAULT-PRIV-ALL".to_string()),
        "a default grant of ALL must fire the ALL rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"PG-DEFAULT-PRIV-TO-PUBLIC".to_string()),
        "a grant to a named role must not fire the PUBLIC rule. Got: {ids:?}"
    );
}

#[test]
fn test_default_global_scope_fires_low() {
    let ids = rule_ids("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO app_role;");
    assert!(
        ids.contains(&"PG-DEFAULT-PRIV-GLOBAL".to_string()),
        "an unscoped (no IN SCHEMA) default must fire the GLOBAL rule. Got: {ids:?}"
    );
}

#[test]
fn test_info_fires_for_all_adp() {
    for sql in [
        "ALTER DEFAULT PRIVILEGES IN SCHEMA s GRANT SELECT ON TABLES TO bob;",
        "ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM bob;",
        "ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO PUBLIC;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-PG-DEFAULT-PRIVILEGES".to_string()),
            "INFO should fire for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_revoke_from_public_is_not_flagged() {
    // Revoking from PUBLIC is a hardening action, not a risk: the action gate
    // (action: grant) keeps the PUBLIC / ALL / GLOBAL rules silent.
    let ids = rule_ids("ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;");
    assert!(
        !ids.contains(&"PG-DEFAULT-PRIV-TO-PUBLIC".to_string())
            && !ids.contains(&"PG-DEFAULT-PRIV-ALL".to_string())
            && !ids.contains(&"PG-DEFAULT-PRIV-GLOBAL".to_string()),
        "a REVOKE (hardening) must not fire the grant-risk rules. Got: {ids:?}"
    );
    assert!(
        ids.contains(&"INFO-PG-DEFAULT-PRIVILEGES".to_string()),
        "INFO should still surface the statement. Got: {ids:?}"
    );
}

// ── Recognition vs. policy: primitives pinnable, verdict pure YAML ───────────

const PIN_RULES: &str = r#"
rules:
  - id: TEST-ADP-GLOBAL-PUBLIC
    risk_level: info
    message: "an unscoped default grant to PUBLIC"
    triggers:
      all_of:
        - kind: pg_default_privileges
        - pg_default_privileges.action: grant
        - pg_default_privileges.global_scope: true
        - pg_default_privileges.grantees:
            exists:
              name.normalized:
                in: [PUBLIC]
"#;

#[test]
fn test_primitives_captured_and_pinnable() {
    let cfg = pg_cfg_with_overlay(PIN_RULES);

    let ids = rule_ids_with(
        "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;",
        &cfg,
    );
    assert!(
        ids.contains(&"TEST-ADP-GLOBAL-PUBLIC".to_string()),
        "an unscoped default grant to PUBLIC must match the composed pin. Got: {ids:?}"
    );

    // Add an IN SCHEMA clause: no longer global_scope, so the pin must not match.
    let ids = rule_ids_with(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA s GRANT SELECT ON TABLES TO PUBLIC;",
        &cfg,
    );
    assert!(
        !ids.contains(&"TEST-ADP-GLOBAL-PUBLIC".to_string()),
        "a schema-scoped grant must not match the global pin. Got: {ids:?}"
    );
}

// ── Regression: plain GRANT and Snowflake ON FUTURE unaffected ───────────────

#[test]
fn test_plain_grant_unaffected() {
    let ids = rule_ids("GRANT SELECT ON TABLE t TO PUBLIC;");
    assert!(
        !ids.iter()
            .any(|id| id.starts_with("PG-DEFAULT-PRIV") || id == "INFO-PG-DEFAULT-PRIVILEGES"),
        "a plain GRANT must not emit ALTER DEFAULT PRIVILEGES findings. Got: {ids:?}"
    );
}

#[test]
fn test_snowflake_future_grant_unaffected() {
    let cfg = AnalysisConfig {
        dialect: Some(dialect::snowflake()),
        ..Default::default()
    };
    let ids = rule_ids_with("GRANT SELECT ON FUTURE TABLES IN SCHEMA s TO ROLE r;", &cfg);
    assert!(
        !ids.iter()
            .any(|id| id.starts_with("PG-DEFAULT-PRIV") || id == "INFO-PG-DEFAULT-PRIVILEGES"),
        "a Snowflake GRANT ON FUTURE must not emit ALTER DEFAULT PRIVILEGES findings. Got: {ids:?}"
    );
}
