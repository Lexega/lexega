// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL / PolyBase `CREATE EXTERNAL TABLE … WITH (LOCATION=, DATA_SOURCE=,
//! FILE_FORMAT=, REJECTED_ROW_LOCATION=)`.
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped), the
//! DATA_SOURCE federated-access signal, the credential-leak composition, and
//! the non-regression of the BigQuery `OPTIONS(...)` external-table form.

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
    // The whole statement (including the WITH bag) must be ONE statement — if
    // the WITH clause fragmented it would show as a second (opaque) statement.
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "the WITH bag must not fragment into a second statement: {sql}"
    );
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_polybase_forms_recognized() {
    roundtrip_not_skipped(
        "CREATE EXTERNAL TABLE ext (id INT, name NVARCHAR(50)) \
         WITH (LOCATION='/data/', DATA_SOURCE=myhadoop, FILE_FORMAT=csvfmt);",
    );
    // Qualified name + REJECTED_ROW_LOCATION.
    roundtrip_not_skipped(
        "CREATE EXTERNAL TABLE dbo.ext (id INT) \
         WITH (LOCATION='wasbs://c@a.blob.core.windows.net/d', DATA_SOURCE=ds, \
         FILE_FORMAT=ff, REJECT_TYPE=VALUE, REJECT_VALUE=0, REJECTED_ROW_LOCATION='/rej');",
    );
}

// ── Governance: federated-access binding ────────────────────────────────

#[test]
fn test_data_source_binding_fires_polybase_rule() {
    let ids = rule_ids(
        "CREATE EXTERNAL TABLE ext (id INT) WITH (LOCATION='/d', DATA_SOURCE=ds, FILE_FORMAT=ff);",
    );
    assert!(
        ids.contains(&"MSSQL-POLYBASE-EXTERNAL-TABLE".to_string()),
        "a DATA_SOURCE binding should fire the PolyBase external-table rule. Got: {ids:?}"
    );
}

#[test]
fn test_hardcoded_credential_in_location_now_composes() {
    // The WITH bag goes through the literal harvest, so a hardcoded
    // credential in LOCATION reaches the external-table credential rules.
    let ids = rule_ids(
        "CREATE EXTERNAL TABLE e (id INT) \
         WITH (LOCATION='s3://b/p', DATA_SOURCE=ds, CREDENTIAL='AKIAIOSFODNN7EXAMPLE');",
    );
    assert!(
        ids.contains(&"BQ-EXTTBL-AWS-LEAK".to_string()),
        "a hardcoded AWS key in the WITH bag must now fire the leak rule. Got: {ids:?}"
    );
}

// ── Non-regression: BigQuery OPTIONS(...) external table ─────────────────

#[test]
fn test_bigquery_external_table_not_affected() {
    let bq_cfg = AnalysisConfig {
        dialect: Some(dialect::bigquery()),
        ..Default::default()
    };
    let mut config = FormatterConfig::default();
    config.dialect = dialect::bigquery();

    let sql = "CREATE EXTERNAL TABLE ds.t OPTIONS (format='CSV', uris=['gs://b/f.csv']);";
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let ids = rule_ids_cfg(sql, &bq_cfg);
    assert!(
        !ids.contains(&"MSSQL-POLYBASE-EXTERNAL-TABLE".to_string()),
        "a BigQuery external table has no DATA_SOURCE binding and must not fire the PolyBase rule. Got: {ids:?}"
    );
}
