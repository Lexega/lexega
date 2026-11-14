// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for BigQuery CREATE/ALTER/EXPORT/DROP MODEL (BQML)

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::bigquery;
use lexega_core::{format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig};

fn bq_config() -> FormatterConfig {
    FormatterConfig {
        dialect: bigquery(),
        ..Default::default()
    }
}

fn bq_analysis_config() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(bigquery()),
        ..Default::default()
    }
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

fn has_finding(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .findings
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn has_context(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .context
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn context_ids(report: &lexega_core::analyzer::AnalysisReport) -> Vec<String> {
    report
        .context
        .iter()
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
        })
        .collect()
}

fn finding_ids(report: &lexega_core::analyzer::AnalysisReport) -> Vec<String> {
    report
        .findings
        .iter()
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
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
fn test_create_model_findings() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.mytable`;"#;

    let report = analyze_bq(sql);
    assert!(
        report.summary.total_reported_findings > 0,
        "Should generate findings for CREATE MODEL, got {}. Findings: {:?}",
        report.summary.total_reported_findings,
        finding_ids(&report),
    );
    assert!(
        has_context(&report, "BQ-MODEL-NEW"),
        "Should find BQ-MODEL-NEW (model created). Context: {:?}",
        context_ids(&report)
    );
}

#[test]
fn test_create_model_remote_security_finding() {
    let sql = r#"CREATE MODEL `dataset.remote_model`
REMOTE WITH CONNECTION `project.us.my_connection`
OPTIONS(endpoint='https://us-central1-aiplatform.googleapis.com/v1/projects/myproject');"#;

    let report = analyze_bq(sql);
    assert!(
        has_finding(&report, "BQ-MODEL-REMOTE"),
        "Should find BQ-MODEL-REMOTE (remote connection security finding). Findings: {:?}",
        finding_ids(&report),
    );
}

#[test]
fn test_drop_model_finding() {
    let sql = "DROP MODEL `dataset.mymodel`;";

    let report = analyze_bq(sql);
    assert!(
        has_finding(&report, "BQ-MODEL-DROP"),
        "Should find BQ-MODEL-DROP (model dropped). Findings: {:?}",
        finding_ids(&report)
    );
}

#[test]
fn test_alter_model_finding() {
    let sql = r#"ALTER MODEL `dataset.mymodel`
SET OPTIONS(description='Updated');"#;

    let report = analyze_bq(sql);
    assert!(
        has_context(&report, "BQ-MODEL-CHG"),
        "Should find BQ-MODEL-CHG (model modified). Context: {:?}",
        context_ids(&report)
    );
}

#[test]
fn test_export_model_finding() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/');"#;

    let report = analyze_bq(sql);
    // To a cloud storage URI: BQ-MODEL-EXPORT-EXTSTORE's alone.
    assert!(
        !has_finding(&report, "BQ-MODEL-EXPORT"),
        "BQ-MODEL-EXPORT leaves a cloud storage URI to BQ-MODEL-EXPORT-EXTSTORE. Findings: {:?}",
        finding_ids(&report)
    );
    assert!(
        has_finding(&report, "BQ-MODEL-EXPORT-EXTSTORE"),
        "Should find BQ-MODEL-EXPORT-EXTSTORE (model exported). Findings: {:?}",
        finding_ids(&report)
    );
}

#[test]
fn test_create_model_unbounded_training_fires_br056() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.training_data`;"#;

    let report = analyze_bq(sql);
    assert!(
        has_finding(&report, "BQ-MODEL-UNBOUNDED"),
        "Should find BQ-MODEL-UNBOUNDED (unbounded BQML training query). Findings: {:?}",
        finding_ids(&report),
    );
}

#[test]
fn test_create_model_bounded_training_no_br056() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg') AS
SELECT * FROM `dataset.training_data` WHERE event_date >= '2025-01-01';"#;

    let report = analyze_bq(sql);
    assert!(
        !has_finding(&report, "BQ-MODEL-UNBOUNDED"),
        "Bounded BQML training query should not trigger BQ-MODEL-UNBOUNDED. Findings: {:?}",
        finding_ids(&report),
    );
}

#[test]
fn test_export_model_external_storage_fires_br057() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/');"#;

    let report = analyze_bq(sql);
    assert!(has_finding(&report, "BQ-MODEL-EXPORT-EXTSTORE"),
        "Should find BQ-MODEL-EXPORT-EXTSTORE (external cloud storage in EXPORT MODEL). Findings: {:?}",
        finding_ids(&report),
    );
}

#[test]
fn test_create_model_hardcoded_aws_key_fires_c052_a_bq_model() {
    let sql = r#"CREATE MODEL `dataset.mymodel`
OPTIONS(model_type='linear_reg', aws_access_key_id='AKIAIOSFODNN7EXAMPLE') AS
SELECT * FROM `dataset.training_data`;"#;

    let report = analyze_bq(sql);
    assert!(
        has_finding(&report, "BQ-MODEL-AWS-LEAK"),
        "Should find BQ-MODEL-AWS-LEAK for CREATE MODEL. Findings: {:?}",
        finding_ids(&report),
    );
}

#[test]
fn test_alter_model_hardcoded_password_fires_bq_model_pwd_leak() {
    let sql = r#"ALTER MODEL `dataset.mymodel`
SET OPTIONS(connection_string='postgresql://user:password123@host:5432/db');"#;

    let report = analyze_bq(sql);
    assert!(
        has_finding(&report, "BQ-MODEL-PWD-LEAK"),
        "Should find BQ-MODEL-PWD-LEAK for ALTER MODEL. Findings: {:?}",
        finding_ids(&report),
    );
}

#[test]
fn test_export_model_hardcoded_api_key_fires_bq_model_apikey_leak() {
    let sql = r#"EXPORT MODEL `dataset.mymodel`
OPTIONS(URI='gs://bucket/model_export/', api_key='sk-test-1234567890');"#;

    let report = analyze_bq(sql);
    assert!(
        has_finding(&report, "BQ-MODEL-APIKEY-LEAK"),
        "Should find BQ-MODEL-APIKEY-LEAK for EXPORT MODEL. Findings: {:?}",
        finding_ids(&report),
    );
}

#[test]
fn test_model_password_option_placeholder_is_silent() {
    let placeholder =
        analyze_bq(r#"ALTER MODEL `dataset.mymodel` SET OPTIONS(password='REPLACE_ME');"#);
    assert!(
        !has_finding(&placeholder, "BQ-MODEL-PWD-LEAK"),
        "A placeholder password must not fire BQ-MODEL-PWD-LEAK. Findings: {:?}",
        finding_ids(&placeholder),
    );

    let real =
        analyze_bq(r#"ALTER MODEL `dataset.mymodel` SET OPTIONS(password='zq7-invented-value');"#);
    assert!(
        has_finding(&real, "BQ-MODEL-PWD-LEAK"),
        "A real-looking password should fire BQ-MODEL-PWD-LEAK. Findings: {:?}",
        finding_ids(&real),
    );
}

#[test]
fn test_model_api_key_option_placeholder_is_silent() {
    let placeholder = analyze_bq(
        r#"EXPORT MODEL `dataset.mymodel` OPTIONS(URI='gs://bucket/model_export/', api_key='REPLACE_ME');"#,
    );
    assert!(
        !has_finding(&placeholder, "BQ-MODEL-APIKEY-LEAK"),
        "A placeholder API key must not fire BQ-MODEL-APIKEY-LEAK. Findings: {:?}",
        finding_ids(&placeholder),
    );

    let real = analyze_bq(
        r#"EXPORT MODEL `dataset.mymodel` OPTIONS(URI='gs://bucket/model_export/', api_key='zq7-invented-key-1234');"#,
    );
    assert!(
        has_finding(&real, "BQ-MODEL-APIKEY-LEAK"),
        "A real-looking API key should fire BQ-MODEL-APIKEY-LEAK. Findings: {:?}",
        finding_ids(&real),
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
    let ids = finding_ids(&report);
    let context = context_ids(&report);
    assert!(
        has_context(&report, "BQ-MODEL-NEW"),
        "Should find CREATE MODEL finding. Context: {:?}",
        context
    );
    assert!(
        has_context(&report, "BQ-MODEL-CHG"),
        "Should find ALTER MODEL finding. Context: {:?}",
        context
    );
    assert!(
        has_finding(&report, "BQ-MODEL-EXPORT-EXTSTORE"),
        "Should find EXPORT MODEL finding. Findings: {:?}",
        ids
    );
    assert!(
        has_finding(&report, "BQ-MODEL-DROP"),
        "Should find DROP MODEL finding. Findings: {:?}",
        ids
    );
}

#[test]
fn a_model_is_named_by_each_part_as_written() {
    for (sql, parts) in [
        (
            "CREATE MODEL `my-proj`.`S1`.`m_churn_x` OPTIONS (model_type = 'linear_reg') AS SELECT 1 AS label;",
            "my-proj|S1|m_churn_x",
        ),
        ("DROP MODEL `my-proj`.ds.`Churn`;", "my-proj|DS|Churn"),
        ("DROP MODEL d1.s1.m_churn;", "D1|S1|M_CHURN"),
    ] {
        let mut config = bq_analysis_config();
        config.trace_mode = true;
        let report = analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed");
        let targets: Vec<String> = report
            .statement_traces
            .iter()
            .filter_map(|s| s.facts.as_ref()?.ddl.as_ref()?.target.as_ref())
            .map(|t| {
                let part = |p: Option<&lexega_core::facts::IdentName>| {
                    p.map_or(String::new(), |p| p.normalized.clone())
                };
                format!(
                    "{}|{}|{}",
                    part(t.name.database.as_ref()),
                    part(t.name.schema.as_ref()),
                    t.name.name.normalized
                )
            })
            .collect();
        assert_eq!(targets, [parts], "{sql}");
    }
}
