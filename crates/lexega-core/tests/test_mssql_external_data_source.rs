// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL / PolyBase `CREATE EXTERNAL DATA SOURCE <name> WITH (LOCATION = '…'
//! [, TYPE = …] [, CREDENTIAL = …] [, PUSHDOWN = …])`.
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped), governance
//! — including the soundness checks that the public-endpoint rule fires only
//! for internet-reachable schemes and the credential rule only when a
//! CREDENTIAL is named — and the non-regression of the sibling `CREATE
//! EXTERNAL ACCESS INTEGRATION` / `CREATE EXTERNAL TABLE` forms.

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
fn test_all_type_classes_recognized() {
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE h WITH (LOCATION = 'hdfs://nn:8020', TYPE = HADOOP, \
         CREDENTIAL = c);",
    );
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE a WITH (LOCATION = 'wasbs://x@a.blob.core.windows.net', \
         CREDENTIAL = c, TYPE = BLOB_STORAGE);",
    );
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE r WITH (LOCATION = 'sqlserver://remote:1433', \
         PUSHDOWN = ON, CREDENTIAL = c, TYPE = RDBMS);",
    );
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE s WITH (LOCATION = 'sqlserver://shardmap', \
         CREDENTIAL = c, TYPE = SHARD_MAP_MANAGER, SHARD_MAP_NAME = 'sm');",
    );
}

#[test]
fn test_minimal_and_qualified_names_recognized() {
    // Minimal: LOCATION only, no TYPE / CREDENTIAL.
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE m WITH (LOCATION = 'https://x.dfs.core.windows.net');",
    );
    // No-scheme location (driverless / bare path).
    roundtrip_not_skipped("CREATE EXTERNAL DATA SOURCE b WITH (LOCATION = 'mydatasource');");
    // PUSHDOWN = OFF.
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE p WITH (LOCATION = 'sqlserver://h', PUSHDOWN = OFF);",
    );
    // Quoted / bracketed name.
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE [my src] WITH (LOCATION = 'hdfs://nn:8020');",
    );
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE a WITH (LOCATION = 'hdfs://nn:8020', TYPE = HADOOP);\n\
         CREATE EXTERNAL DATA SOURCE b WITH (LOCATION = 'wasbs://c@a.blob.core.windows.net', \
         CREDENTIAL = cred, TYPE = BLOB_STORAGE);\n\
         CREATE EXTERNAL DATA SOURCE c WITH (LOCATION = 'sqlserver://h', CREDENTIAL = cred2);",
    );
}

// ── CREATE OR ALTER / IF NOT EXISTS modifiers ───────────────────────────

#[test]
fn test_or_alter_and_if_not_exists_modifiers_recognized() {
    roundtrip_not_skipped(
        "CREATE OR ALTER EXTERNAL DATA SOURCE eds WITH (LOCATION = 'hdfs://nn:8020');",
    );
    roundtrip_not_skipped(
        "CREATE EXTERNAL DATA SOURCE IF NOT EXISTS eds WITH (LOCATION = 'hdfs://nn:8020');",
    );
    // Both modifiers together.
    roundtrip_not_skipped(
        "CREATE OR ALTER EXTERNAL DATA SOURCE IF NOT EXISTS eds \
         WITH (LOCATION = 'hdfs://nn:8020', TYPE = HADOOP);",
    );
}

#[test]
fn test_security_rules_carry_over_to_modified_create() {
    // The recognition primitives (and thus the governance rules) must be the
    // same whether or not a CREATE OR ALTER / IF NOT EXISTS modifier is present.
    let ids = rule_ids(
        "CREATE OR ALTER EXTERNAL DATA SOURCE eds \
         WITH (LOCATION = 'wasbs://c@a.blob.core.windows.net', CREDENTIAL = c);",
    );
    assert!(
        ids.contains(&"MSSQL-EXT-DATA-SOURCE-PUBLIC-ENDPOINT".to_string())
            && ids.contains(&"MSSQL-EXT-DATA-SOURCE-CREDENTIAL".to_string()),
        "CREATE OR ALTER must still surface the public-endpoint and credential \
         findings. Got: {ids:?}"
    );
}

// ── Governance: credential ──────────────────────────────────────────────

#[test]
fn test_credential_fires_rule() {
    let ids = rule_ids(
        "CREATE EXTERNAL DATA SOURCE h WITH (LOCATION = 'hdfs://nn:8020', CREDENTIAL = c);",
    );
    assert!(
        ids.contains(&"MSSQL-EXT-DATA-SOURCE-CREDENTIAL".to_string()),
        "a CREDENTIAL reference should fire the credential rule. Got: {ids:?}"
    );
}

#[test]
fn test_no_credential_does_not_fire_rule() {
    // Soundness: the credential rule keys on the typed `credential_referenced`
    // flag, not text — a source without CREDENTIAL must stay silent.
    let ids = rule_ids("CREATE EXTERNAL DATA SOURCE h WITH (LOCATION = 'hdfs://nn:8020');");
    assert!(
        !ids.contains(&"MSSQL-EXT-DATA-SOURCE-CREDENTIAL".to_string()),
        "a source with no CREDENTIAL must NOT fire the credential rule. Got: {ids:?}"
    );
}

// ── Governance: public endpoint ─────────────────────────────────────────

#[test]
fn test_public_scheme_fires_rule() {
    for sql in [
        "CREATE EXTERNAL DATA SOURCE a WITH (LOCATION = 'wasbs://c@a.blob.core.windows.net');",
        "CREATE EXTERNAL DATA SOURCE b WITH (LOCATION = 'https://x.dfs.core.windows.net');",
        "CREATE EXTERNAL DATA SOURCE c WITH (LOCATION = 's3://bucket/key');",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-EXT-DATA-SOURCE-PUBLIC-ENDPOINT".to_string()),
            "public scheme should fire the public-endpoint rule for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_internal_scheme_does_not_fire_public_rule() {
    // Soundness: hdfs / sqlserver are not internet-reachable object stores —
    // the public-endpoint rule keys on the typed scheme set, so they stay silent.
    for sql in [
        "CREATE EXTERNAL DATA SOURCE a WITH (LOCATION = 'hdfs://nn:8020');",
        "CREATE EXTERNAL DATA SOURCE b WITH (LOCATION = 'sqlserver://remote:1433');",
    ] {
        let ids = rule_ids(sql);
        assert!(
            !ids.contains(&"MSSQL-EXT-DATA-SOURCE-PUBLIC-ENDPOINT".to_string()),
            "internal scheme must NOT fire the public-endpoint rule for {sql}. Got: {ids:?}"
        );
    }
}

// ── Governance: INFO + composition ──────────────────────────────────────

#[test]
fn test_info_fires_for_every_source() {
    for sql in [
        "CREATE EXTERNAL DATA SOURCE a WITH (LOCATION = 'hdfs://nn:8020');",
        "CREATE EXTERNAL DATA SOURCE b WITH (LOCATION = 'wasbs://c@a.blob.core.windows.net', \
         CREDENTIAL = cred, TYPE = BLOB_STORAGE);",
        "CREATE EXTERNAL DATA SOURCE c WITH (LOCATION = 'mydatasource');",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-EXT-DATA-SOURCE".to_string()),
            "INFO-MSSQL-EXT-DATA-SOURCE should fire for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_public_and_credential_compose() {
    let ids = rule_ids(
        "CREATE EXTERNAL DATA SOURCE a WITH (LOCATION = 'wasbs://c@a.blob.core.windows.net', \
         CREDENTIAL = cred, TYPE = BLOB_STORAGE);",
    );
    assert!(
        ids.contains(&"MSSQL-EXT-DATA-SOURCE-PUBLIC-ENDPOINT".to_string())
            && ids.contains(&"MSSQL-EXT-DATA-SOURCE-CREDENTIAL".to_string()),
        "public + credential should fire both rules. Got: {ids:?}"
    );
}

// ── Non-regression: sibling CREATE EXTERNAL constructs ───────────────────

#[test]
fn test_external_access_integration_not_hijacked() {
    // The `is_external_data_source` branch sits directly in front of the
    // `CREATE EXTERNAL ACCESS INTEGRATION` fallback — that fallback must still
    // parse and must not pick up a data-source finding.
    let cfg = AnalysisConfig {
        dialect: Some(dialect::snowflake()),
        ..Default::default()
    };
    let sql = "CREATE EXTERNAL ACCESS INTEGRATION eai ALLOWED_NETWORK_RULES = (r1) ENABLED = TRUE;";
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "CREATE EXTERNAL ACCESS INTEGRATION must still be analyzed: {sql}"
    );
    let ids = rule_ids_cfg(sql, &cfg);
    assert!(
        !ids.iter().any(|id| id.starts_with("MSSQL-EXT-DATA-SOURCE")
            || id == "INFO-MSSQL-EXT-DATA-SOURCE"),
        "access integration must not fire a data-source finding: {ids:?}"
    );
}

// ── ALTER EXTERNAL DATA SOURCE ──────────────────────────────────────────
//
// `ALTER EXTERNAL DATA SOURCE name SET { LOCATION = … | CREDENTIAL = … }`. The
// ALTER uses an unparenthesized `SET` list rather than CREATE's `WITH (…)`,
// but lifts the same neutral primitives and fires the same governance rules
// (widened to `alter_external_data_source`) plus a distinct INFO-…-ALTER.

#[test]
fn test_alter_set_forms_recognized() {
    roundtrip_not_skipped(
        "ALTER EXTERNAL DATA SOURCE eds SET LOCATION = 'https://x.dfs.core.windows.net', \
         CREDENTIAL = c;",
    );
    roundtrip_not_skipped("ALTER EXTERNAL DATA SOURCE eds SET CREDENTIAL = c;");
    roundtrip_not_skipped("ALTER EXTERNAL DATA SOURCE [my src] SET LOCATION = 'sqlserver://h';");
}

#[test]
fn test_alter_set_location_public_and_credential_fire() {
    // SET LOCATION redirect to a public scheme + SET CREDENTIAL swap must
    // surface both policy rules and the ALTER-specific INFO.
    let ids = rule_ids(
        "ALTER EXTERNAL DATA SOURCE eds SET LOCATION = 'wasbs://c@a.blob.core.windows.net', \
         CREDENTIAL = c;",
    );
    assert!(
        ids.contains(&"MSSQL-EXT-DATA-SOURCE-PUBLIC-ENDPOINT".to_string())
            && ids.contains(&"MSSQL-EXT-DATA-SOURCE-CREDENTIAL".to_string())
            && ids.contains(&"INFO-MSSQL-EXT-DATA-SOURCE-ALTER".to_string()),
        "ALTER SET LOCATION (public) + CREDENTIAL must fire both policy rules and \
         the ALTER INFO. Got: {ids:?}"
    );
}

#[test]
fn test_alter_internal_scheme_and_no_credential_stay_silent() {
    // Soundness: the policy rules key on the typed scheme set / credential
    // flag, not on the ALTER kind — an internal redirect with no credential
    // fires only the recognition INFO.
    let ids = rule_ids("ALTER EXTERNAL DATA SOURCE eds SET LOCATION = 'sqlserver://remote:1433';");
    assert!(
        !ids.contains(&"MSSQL-EXT-DATA-SOURCE-PUBLIC-ENDPOINT".to_string())
            && !ids.contains(&"MSSQL-EXT-DATA-SOURCE-CREDENTIAL".to_string()),
        "internal-scheme, no-credential ALTER must not fire policy rules. Got: {ids:?}"
    );
    assert!(
        ids.contains(&"INFO-MSSQL-EXT-DATA-SOURCE-ALTER".to_string()),
        "every recognized ALTER must surface the ALTER INFO. Got: {ids:?}"
    );
}

#[test]
fn test_alter_info_is_distinct_from_create_info() {
    // The ALTER fires INFO-…-ALTER, never the CREATE INFO, and vice versa —
    // the kind discriminant (create_ vs alter_external_data_source) is honored.
    let alter_ids = rule_ids("ALTER EXTERNAL DATA SOURCE eds SET LOCATION = 'hdfs://nn:8020';");
    assert!(
        alter_ids.contains(&"INFO-MSSQL-EXT-DATA-SOURCE-ALTER".to_string())
            && !alter_ids.contains(&"INFO-MSSQL-EXT-DATA-SOURCE".to_string()),
        "ALTER must fire only the ALTER INFO. Got: {alter_ids:?}"
    );
    let create_ids =
        rule_ids("CREATE EXTERNAL DATA SOURCE eds WITH (LOCATION = 'hdfs://nn:8020');");
    assert!(
        create_ids.contains(&"INFO-MSSQL-EXT-DATA-SOURCE".to_string())
            && !create_ids.contains(&"INFO-MSSQL-EXT-DATA-SOURCE-ALTER".to_string()),
        "CREATE must fire only the CREATE INFO. Got: {create_ids:?}"
    );
}
