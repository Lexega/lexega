// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for BigQuery CREATE/ALTER/EXPORT/DROP MODEL (BQML)

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::bigquery;
use lexega_core::{format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig};

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = bigquery();
    config
}

fn bq_analysis_config() -> AnalysisConfig {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(bigquery());
    config
}

fn format_and_verify_bq(sql: &str) {
    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("BQ format failed:\n{}\nSQL:\n{}", e, sql));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("BQ round-trip failed:\n{}\nSQL:\n{}", e, sql));
}

fn analyze_bq(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    analyze_risk_with_policy_config(sql, &bq_analysis_config()).expect("analysis should succeed")
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn signal_ids(report: &lexega_core::analyzer::AnalysisReport) -> Vec<String> {
    report
        .signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

// ─── CREATE MODEL ────────────────────────────────────────────────────────

#[test]
fn test_create_model_basic() {
    let sql = r#"CREATE MODEL `mydataset.mymodel`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `mydataset.mytable`;"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_create_model_or_replace() {
    let sql = r#"CREATE OR REPLACE MODEL `project.dataset.model`
OPTIONS(model_type='logistic_reg', max_iterations=20) AS
SELECT label, feature1, feature2 FROM `dataset.training_data`;"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_create_model_if_not_exists() {
    let sql = r#"CREATE MODEL IF NOT EXISTS `dataset.mymodel`
OPTIONS(model_type='kmeans', num_clusters=5) AS
SELECT feature1, feature2 FROM `dataset.data`;"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_create_model_with_transform() {
    let sql = r#"CREATE MODEL `dataset.model`
TRANSFORM(ML.FEATURE_CROSS(STRUCT(f1, f2)) AS cross, label)
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.training`;"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_create_model_remote_with_connection() {
    let sql = r#"CREATE MODEL `dataset.remote_model`
REMOTE WITH CONNECTION `project.us.my_connection`
OPTIONS(endpoint='https://us-central1-aiplatform.googleapis.com/v1/projects/myproject/locations/us-central1/endpoints/1234');"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_create_model_remote_with_default_connection() {
    let sql = r#"CREATE MODEL `dataset.remote_model`
REMOTE WITH CONNECTION DEFAULT
OPTIONS(endpoint='https://us-central1-aiplatform.googleapis.com');"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_create_model_with_input_output() {
    let sql = r#"CREATE MODEL `dataset.imported_model`
INPUT(f1 FLOAT64, f2 FLOAT64)
OUTPUT(label STRING)
REMOTE WITH CONNECTION `project.us.conn`
OPTIONS(endpoint='https://example.com/predict');"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_create_model_options_only() {
    let sql = r#"CREATE MODEL `dataset.model`
OPTIONS(model_type='boosted_tree_classifier');"#;
    format_and_verify_bq(sql);
}

// ─── ALTER MODEL ─────────────────────────────────────────────────────────

#[test]
fn test_alter_model_basic() {
    let sql = r#"ALTER MODEL `dataset.mymodel`
SET OPTIONS(description='Updated model description');"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_alter_model_if_exists() {
    let sql = r#"ALTER MODEL IF EXISTS `project.dataset.mymodel`
SET OPTIONS(expiration_timestamp=TIMESTAMP '2025-12-31');"#;
    format_and_verify_bq(sql);
}

// ─── EXPORT MODEL ────────────────────────────────────────────────────────

#[test]
fn test_export_model_basic() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/');"#;
    format_and_verify_bq(sql);
}

#[test]
fn test_export_model_with_trial_id() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/', TRIAL_ID=3);"#;
    format_and_verify_bq(sql);
}

// ─── DROP MODEL ──────────────────────────────────────────────────────────

#[test]
fn test_drop_model_basic() {
    let sql = "DROP MODEL `dataset.mymodel`;";
    format_and_verify_bq(sql);
}

#[test]
fn test_drop_model_if_exists() {
    let sql = "DROP MODEL IF EXISTS `project.dataset.mymodel`;";
    format_and_verify_bq(sql);
}

// ─── Risk Analysis ───────────────────────────────────────────────────────

#[test]
fn test_create_model_signals() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.mytable`;"#;

    let report = analyze_bq(sql);
    assert!(
        report.summary.total_reported_signals > 0,
        "Should generate signals for CREATE MODEL, got {}. Signals: {:?}",
        report.summary.total_reported_signals,
        signal_ids(&report),
    );
    assert!(
        has_signal(&report, "BQ-MODEL-NEW"),
        "Should find BQ-MODEL-NEW (model created). Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_create_model_remote_security_signal() {
    let sql = r#"CREATE MODEL `dataset.remote_model`
REMOTE WITH CONNECTION `project.us.my_connection`
OPTIONS(endpoint='https://us-central1-aiplatform.googleapis.com/v1/projects/myproject');"#;

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-REMOTE"),
        "Should find BQ-MODEL-REMOTE (remote connection security signal). Signals: {:?}",
        signal_ids(&report),
    );
}

#[test]
fn test_drop_model_signal() {
    let sql = "DROP MODEL `dataset.mymodel`;";

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-DROP"),
        "Should find BQ-MODEL-DROP (model dropped). Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_alter_model_signal() {
    let sql = r#"ALTER MODEL `dataset.mymodel`
SET OPTIONS(description='Updated');"#;

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-CHG"),
        "Should find BQ-MODEL-CHG (model modified). Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_export_model_signal() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/');"#;

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-EXPORT"),
        "Should find BQ-MODEL-EXPORT (model exported). Signals: {:?}",
        signal_ids(&report)
    );
}

#[test]
fn test_create_model_unbounded_training_fires_br056() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.training_data`;"#;

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-UNBOUNDED"),
        "Should find BQ-MODEL-UNBOUNDED (unbounded BQML training query). Signals: {:?}",
        signal_ids(&report),
    );
}

#[test]
fn test_create_model_bounded_training_no_br056() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.training_data` WHERE event_date >= '2025-01-01';"#;

    let report = analyze_bq(sql);
    assert!(
        !has_signal(&report, "BQ-MODEL-UNBOUNDED"),
        "Bounded BQML training query should not trigger BQ-MODEL-UNBOUNDED. Signals: {:?}",
        signal_ids(&report),
    );
}

#[test]
fn test_export_model_external_storage_fires_br057() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/');"#;

    let report = analyze_bq(sql);
    assert!(has_signal(&report, "BQ-MODEL-EXPORT-EXTSTORE"),
        "Should find BQ-MODEL-EXPORT-EXTSTORE (external cloud storage in EXPORT MODEL). Signals: {:?}",
        signal_ids(&report),
    );
}

#[test]
fn test_create_model_hardcoded_aws_key_fires_c052_a_bq_model() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg', aws_access_key_id='AKIAIOSFODNN7EXAMPLE') AS
SELECT * FROM `dataset.training_data`;"#;

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-AWS-LEAK"),
        "Should find BQ-MODEL-AWS-LEAK for CREATE MODEL. Signals: {:?}",
        signal_ids(&report),
    );
}

#[test]
fn test_alter_model_hardcoded_password_fires_bq_model_pwd_leak() {
    let sql = r#"ALTER MODEL `dataset.mymodel`
SET OPTIONS(connection_string='postgresql://user:password123@host:5432/db');"#;

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-PWD-LEAK"),
        "Should find BQ-MODEL-PWD-LEAK for ALTER MODEL. Signals: {:?}",
        signal_ids(&report),
    );
}

#[test]
fn test_export_model_hardcoded_api_key_fires_bq_model_apikey_leak() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/', api_key='sk-test-1234567890');"#;

    let report = analyze_bq(sql);
    assert!(
        has_signal(&report, "BQ-MODEL-APIKEY-LEAK"),
        "Should find BQ-MODEL-APIKEY-LEAK for EXPORT MODEL. Signals: {:?}",
        signal_ids(&report),
    );
}

// ─── Multi-statement tests ───────────────────────────────────────────────

#[test]
fn test_multi_model_statements() {
    let sql = r#"
CREATE MODEL `dataset.model1`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.data1`;

ALTER MODEL `dataset.model1`
SET OPTIONS(description='My model');

EXPORT MODEL `dataset.model1`
OPTIONS(URI='gs://bucket/export/');

DROP MODEL IF EXISTS `dataset.model1`;
"#;

    let report = analyze_bq(sql);
    let ids = signal_ids(&report);
    assert!(
        has_signal(&report, "BQ-MODEL-NEW"),
        "Should find CREATE MODEL signal. Signals: {:?}",
        ids
    );
    assert!(
        has_signal(&report, "BQ-MODEL-CHG"),
        "Should find ALTER MODEL signal. Signals: {:?}",
        ids
    );
    assert!(
        has_signal(&report, "BQ-MODEL-EXPORT"),
        "Should find EXPORT MODEL signal. Signals: {:?}",
        ids
    );
    assert!(
        has_signal(&report, "BQ-MODEL-DROP"),
        "Should find DROP MODEL signal. Signals: {:?}",
        ids
    );
}
