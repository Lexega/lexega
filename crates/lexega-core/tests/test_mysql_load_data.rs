// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `LOAD DATA [LOW_PRIORITY|CONCURRENT] [LOCAL] INFILE '<path>' INTO
//! TABLE …`.
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped), the LOCAL
//! vs server-side split, the cloud-path composition the harvest enables, and
//! the non-regression of the BigQuery `FROM FILES(...)` form.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mysql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mysql()),
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
    rule_ids_cfg(sql, &mysql_cfg())
}

fn roundtrip_not_skipped(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mysql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let report = analyze_risk_with_policy_config(sql, &mysql_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "must be analyzed, not skipped: {sql}"
    );
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "the INFILE clauses must not fragment into extra statements: {sql}"
    );
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_load_data_forms_recognized() {
    roundtrip_not_skipped(
        "LOAD DATA LOCAL INFILE '/tmp/x.csv' INTO TABLE t \
         FIELDS TERMINATED BY ',' IGNORE 1 LINES;",
    );
    roundtrip_not_skipped(
        "LOAD DATA INFILE '/var/lib/mysql-files/d.txt' INTO TABLE db.t (a, b) SET c = 1;",
    );
    roundtrip_not_skipped(
        "LOAD DATA LOW_PRIORITY LOCAL INFILE 'data.csv' REPLACE INTO TABLE t \
         CHARACTER SET utf8mb4 LINES TERMINATED BY '\\n';",
    );
}

// ── Governance: LOCAL vs server-side split ──────────────────────────────

#[test]
fn test_local_infile_fires_medium_and_info() {
    let ids = rule_ids("LOAD DATA LOCAL INFILE '/tmp/x.csv' INTO TABLE t;");
    assert!(
        ids.contains(&"MYSQL-LOAD-DATA-LOCAL-INFILE".to_string())
            && ids.contains(&"INFO-MYSQL-LOAD-DATA-INFILE".to_string()),
        "LOCAL INFILE should fire both the local (medium) and the infile (low) rules. Got: {ids:?}"
    );
}

#[test]
fn test_server_side_infile_fires_info_only() {
    // Recognition vs policy: the elevated verdict keys on the LOCAL flag, not on
    // the statement being a LOAD DATA. Server-side INFILE stays info-only.
    let ids = rule_ids("LOAD DATA INFILE '/srv/d.csv' INTO TABLE t;");
    assert!(
        ids.contains(&"INFO-MYSQL-LOAD-DATA-INFILE".to_string()),
        "server-side INFILE should fire the infile rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MYSQL-LOAD-DATA-LOCAL-INFILE".to_string()),
        "server-side INFILE (no LOCAL) must NOT fire the local rule. Got: {ids:?}"
    );
}

#[test]
fn test_cloud_path_fires_external_storage_rule() {
    // The INFILE path is cloud-classified into the typed mysql_load_data facts,
    // so a cloud URI fires the (MySQL-owned) external-storage rule.
    let ids = rule_ids("LOAD DATA LOCAL INFILE 's3://b/data.csv' INTO TABLE t;");
    assert!(
        ids.contains(&"MYSQL-LOAD-DATA-EXTERNAL-STORAGE".to_string()),
        "a cloud-URI INFILE path should fire the external-storage rule. Got: {ids:?}"
    );
    // And a local filesystem path must NOT (recognition vs policy).
    let local_ids = rule_ids("LOAD DATA LOCAL INFILE '/tmp/x.csv' INTO TABLE t;");
    assert!(
        !local_ids.contains(&"MYSQL-LOAD-DATA-EXTERNAL-STORAGE".to_string()),
        "a local filesystem path must NOT fire the external-storage rule. Got: {local_ids:?}"
    );
}

// ── Non-regression: BigQuery LOAD DATA FROM FILES ───────────────────────

#[test]
fn test_bigquery_load_data_not_affected() {
    let bq_cfg = AnalysisConfig {
        dialect: Some(dialect::bigquery()),
        ..Default::default()
    };
    let sql = "LOAD DATA INTO ds.t FROM FILES(format='CSV', uris=['gs://b/f.csv']);";
    let ids = rule_ids_cfg(sql, &bq_cfg);
    assert!(
        !ids.iter().any(|id| id.contains("MYSQL-LOAD-DATA")),
        "a BigQuery FROM FILES load has no INFILE and must not fire the MySQL rules. Got: {ids:?}"
    );
}
