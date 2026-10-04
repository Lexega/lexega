// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for hardcoded credential rules (CRED-*-LEAK variants) that were identified
/// as coverage gaps. Covers BigQuery EXPORT DATA, LOAD DATA, CREATE EXTERNAL TABLE,
/// BQML MODEL, and Snowflake CREATE STAGE.
use lexega_core::analyzer::{AnalysisConfig, AnalysisReport, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::bigquery;
use lexega_core::dialect::SnowflakeDialect;
use std::sync::Arc;

fn analyze_bq(sql: &str) -> AnalysisReport {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(bigquery());
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn analyze_sf(sql: &str) -> AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(SnowflakeDialect)),
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_signal(report: &AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn signal_ids(report: &AnalysisReport) -> Vec<String> {
    report
        .signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// BigQuery EXPORT DATA — BQ-EXPORT-AWS-LEAK, BQ-EXPORT-PWD-LEAK, BQ-EXPORT-APIKEY-LEAK, BQ-EXPORT-CONNSTR-LEAK
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_bq_export_aws_leak() {
    let sql = r#"EXPORT DATA OPTIONS(uri='s3://bucket/data/*', format='CSV',
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE') AS SELECT * FROM my_table;"#;
    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-EXPORT-AWS-LEAK"),
        "Hardcoded AWS key in EXPORT DATA should trigger BQ-EXPORT-AWS-LEAK. Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_c052_b_bq_hardcoded_password_in_export_data() {
    let sql = r#"EXPORT DATA OPTIONS(uri='s3://bucket/data/*', format='CSV',
        password='supersecret123') AS SELECT * FROM my_table;"#;
    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-EXPORT-PWD-LEAK"),
        "Hardcoded password in EXPORT DATA should trigger BQ-EXPORT-PWD-LEAK. Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_c052_c_bq_hardcoded_api_key_in_export_data() {
    let sql = r#"EXPORT DATA OPTIONS(uri='s3://bucket/data/*', format='CSV',
        api_key='sk-test-1234567890abcdef') AS SELECT * FROM my_table;"#;
    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-EXPORT-APIKEY-LEAK"),
        "Hardcoded API key in EXPORT DATA should trigger BQ-EXPORT-APIKEY-LEAK. Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_c052_d_bq_hardcoded_connection_string_in_export_data() {
    let sql = r#"EXPORT DATA OPTIONS(uri='s3://bucket/data/*', format='CSV',
        connection_string='postgresql://user:password123@host:5432/db') AS SELECT * FROM my_table;"#;
    let report = analyze_bq(sql);
    assert!(has_signal(&report, "BQ-EXPORT-CONNSTR-LEAK"),
        "Hardcoded connection string in EXPORT DATA should trigger BQ-EXPORT-CONNSTR-LEAK. Signals: {:?}",
        signal_ids(&report));
}

// ═══════════════════════════════════════════════════════════════════════════
// BigQuery LOAD DATA — BQ-LOAD-APIKEY-LEAK, BQ-LOAD-CONNSTR-LEAK
// (BQ-LOAD-AWS-LEAK and BQ-LOAD-PWD-LEAK already tested in test_bq_statements.rs)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_c052_c_bq_load_hardcoded_api_key_in_load_data() {
    let sql = r#"LOAD DATA INTO my_table FROM FILES(format='CSV',
        uris=['s3://bucket/*'], api_key='sk-prod-abcdefghij1234');"#;
    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-LOAD-APIKEY-LEAK"),
        "Hardcoded API key in LOAD DATA should trigger BQ-LOAD-APIKEY-LEAK. Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_c052_d_bq_load_hardcoded_connection_string_in_load_data() {
    let sql = r#"LOAD DATA INTO my_table FROM FILES(format='CSV',
        uris=['gs://bucket/*']) WITH CONNECTION 'mysql://admin:s3cret@db.host.com:3306/mydb';"#;
    let report = analyze_bq(sql);
    assert!(has_signal(&report, "BQ-LOAD-CONNSTR-LEAK"),
        "Hardcoded connection string in LOAD DATA should trigger BQ-LOAD-CONNSTR-LEAK. Signals: {:?}",
        signal_ids(&report));
}

// ═══════════════════════════════════════════════════════════════════════════
// BigQuery CREATE EXTERNAL TABLE — BQ-EXTTBL-PWD-LEAK, BQ-EXTTBL-APIKEY-LEAK, BQ-EXTTBL-CONNSTR-LEAK
// (BQ-EXTTBL-AWS-LEAK already tested in test_bq_statements.rs)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_c052_b_bq_ext_hardcoded_password_in_external_table() {
    let sql = r#"CREATE EXTERNAL TABLE my_dataset.ext_table
        OPTIONS(format='CSV', uris=['s3://bucket/*'], password='mysecretpass');"#;
    let report = analyze_bq(sql);
    assert!(has_signal(&report, "BQ-EXTTBL-PWD-LEAK"),
        "Hardcoded password in CREATE EXTERNAL TABLE should trigger BQ-EXTTBL-PWD-LEAK. Signals: {:?}",
        signal_ids(&report));
}

#[test]
fn test_c052_c_bq_ext_hardcoded_api_key_in_external_table() {
    let sql = r#"CREATE EXTERNAL TABLE my_dataset.ext_table
        OPTIONS(format='CSV', uris=['s3://bucket/*'], api_key='sk-live-abcdefghij9876');"#;
    let report = analyze_bq(sql);
    assert!(has_signal(&report, "BQ-EXTTBL-APIKEY-LEAK"),
        "Hardcoded API key in CREATE EXTERNAL TABLE should trigger BQ-EXTTBL-APIKEY-LEAK. Signals: {:?}",
        signal_ids(&report));
}

#[test]
fn test_c052_d_bq_ext_hardcoded_connection_string_in_external_table() {
    let sql = r#"CREATE EXTERNAL TABLE my_dataset.ext_table
        OPTIONS(format='CSV', uris=['s3://bucket/*'],
        connection_string='postgresql://admin:hunter2@db.example.com:5432/prod');"#;
    let report = analyze_bq(sql);
    assert!(has_signal(&report, "BQ-EXTTBL-CONNSTR-LEAK"),
        "Hardcoded connection string in CREATE EXTERNAL TABLE should trigger BQ-EXTTBL-CONNSTR-LEAK. Signals: {:?}",
        signal_ids(&report));
}

// ═══════════════════════════════════════════════════════════════════════════
// BigQuery BQML — C052-D-BQ-MODEL
// (C052-A/B/C-BQ-MODEL already tested in test_bqml_model.rs)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_bq_model_connstr_leak_hardcoded_connection_string_in_model() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
        OPTIONS(model_type='linear_reg',
        connection_string='mysql://user:pass@host:3306/db') AS
        SELECT * FROM `dataset.training_data`;"#;
    let report = analyze_bq(sql);
    assert!(has_signal(&report, "BQ-MODEL-CONNSTR-LEAK"),
        "Hardcoded connection string in CREATE MODEL should trigger BQ-MODEL-CONNSTR-LEAK. Signals: {:?}",
        signal_ids(&report));
}

// ═══════════════════════════════════════════════════════════════════════════
// Snowflake CREATE STAGE — C052-C (Hardcoded API Key)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_cred_apikey_leak_in_create_stage() {
    let sql = r#"CREATE STAGE my_stage
        URL='s3://mybucket/path/'
        CREDENTIALS=(API_KEY='sk-prod-1234567890abcdef');"#;
    let report = analyze_sf(sql);
    assert!(
        has_signal(&report, "CRED-APIKEY-LEAK"),
        "Hardcoded API key in CREATE STAGE should trigger CRED-APIKEY-LEAK. Signals: {:?}",
        signal_ids(&report)
    );
}
