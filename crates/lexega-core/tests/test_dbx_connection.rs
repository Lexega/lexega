// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks CREATE/ALTER/DROP CONNECTION parsing, formatting, and risk analysis.
//!
//! Covers:
//! - CREATE CONNECTION with TYPE, OPTIONS, and COMMENT
//! - CREATE CONNECTION IF NOT EXISTS
//! - CREATE SERVER (standards-compliant alias)
//! - ALTER CONNECTION (OWNER TO, RENAME TO, OPTIONS)
//! - DROP CONNECTION / DROP CONNECTION IF EXISTS
//! - Multi-statement evidence counting
//! - Signal emission and YAML rule matching (DBX-CONN-NEW..DBX-CONN-CHG)
//! - Formatting round-trip (verify_formatting_safe)

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, verify_formatting_safe, DatabricksDialect,
    FormatterConfig,
};
use std::sync::Arc;

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    }
}

fn dbx_format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &dbx_config())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

// ─── CREATE CONNECTION ──────────────────────────────────────────────────────────

#[test]
fn test_create_connection_basic() {
    let sql = r#"CREATE CONNECTION my_conn
TYPE POSTGRESQL
OPTIONS (
  host 'pg-demo.us-west-2.rds.amazonaws.com',
  port '5432',
  user 'pg_user',
  password 'password123'
);"#;

    dbx_format_and_verify(sql);
}

#[test]
fn test_create_connection_if_not_exists() {
    let sql = r#"CREATE CONNECTION IF NOT EXISTS my_mysql_conn
TYPE MYSQL
OPTIONS (
  host 'mysql-host.us-west-2.rds.amazonaws.com',
  port '3306',
  user 'mysql_user',
  password 'password123'
);"#;

    dbx_format_and_verify(sql);
}

#[test]
fn test_create_connection_with_comment() {
    let sql = r#"CREATE CONNECTION snowflake_conn
TYPE SNOWFLAKE
OPTIONS (
  host 'myaccount.snowflakecomputing.com',
  port '443',
  sfWarehouse 'my_wh',
  user 'admin',
  password 'pass'
)
COMMENT 'Production Snowflake connection';"#;

    dbx_format_and_verify(sql);
}

#[test]
fn test_create_connection_with_secret() {
    let sql = r#"CREATE CONNECTION pg_conn
TYPE POSTGRESQL
OPTIONS (
  host 'pg-demo.us-west-2.rds.amazonaws.com',
  port '5432',
  user secret('scope', 'pg_user'),
  password secret('secrets.r.us', 'postgresPassword')
);"#;

    dbx_format_and_verify(sql);
}

#[test]
fn test_create_connection_http_type() {
    let sql = r#"CREATE CONNECTION http_conn
TYPE HTTP
OPTIONS (
  host 'https://api.example.com',
  port '443',
  base_path '/v1/',
  bearer_token secret('scope', 'token')
);"#;

    dbx_format_and_verify(sql);
}

#[test]
fn test_create_connection_databricks_type() {
    let sql = r#"CREATE CONNECTION dbx_conn
TYPE DATABRICKS
OPTIONS (
  host 'partner.cloud.databricks.com',
  httpPath '/sql/1.0/warehouses/abc',
  personalAccessToken secret('scope', 'pat')
);"#;

    dbx_format_and_verify(sql);
}

#[test]
fn test_create_server_alias() {
    let sql = r#"CREATE SERVER redshift_conn
TYPE REDSHIFT
OPTIONS (
  host 'redshift-cluster.us-east-1.redshift.amazonaws.com',
  port '5439',
  user 'admin',
  password 'pass'
);"#;

    dbx_format_and_verify(sql);
}

// ─── ALTER CONNECTION ───────────────────────────────────────────────────────────

#[test]
fn test_alter_connection_set_owner_to() {
    let sql = "ALTER CONNECTION my_connection SET OWNER TO `alf@melmak.et`;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_alter_connection_owner_to_without_set() {
    let sql = "ALTER CONNECTION my_connection OWNER TO `admin_group`;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_alter_connection_rename_to() {
    let sql = "ALTER CONNECTION my_connection RENAME TO other_connection;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_alter_connection_options() {
    let sql = r#"ALTER CONNECTION my_connection OPTIONS (
  host 'newhost.us-west-2.rds.amazonaws.com',
  port '5432'
);"#;
    dbx_format_and_verify(sql);
}

// ─── DROP CONNECTION ────────────────────────────────────────────────────────────

#[test]
fn test_drop_connection_basic() {
    let sql = "DROP CONNECTION my_connection;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_drop_connection_if_exists() {
    let sql = "DROP CONNECTION IF EXISTS my_connection;";
    dbx_format_and_verify(sql);
}

// ─── Risk Analysis ──────────────────────────────────────────────────────────────

#[test]
fn test_create_connection_risk_signal() {
    let sql = r#"CREATE CONNECTION pg_conn
TYPE POSTGRESQL
OPTIONS (
  host 'pg-demo.us-west-2.rds.amazonaws.com',
  port '5432',
  user 'admin',
  password 'pass'
);"#;

    let report = dbx_analyze(sql);

    assert!(
        report.summary.total_reported_signals >= 1,
        "Should generate at least one signal for CREATE CONNECTION, got {}",
        report.summary.total_reported_signals
    );
    assert!(
        has_signal(&report, "DBX-CONN-NEW"),
        "Should find DBX-CONN-NEW (Connection Created). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(a) => a.matched_rule.as_str(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_drop_connection_risk_signal() {
    let sql = "DROP CONNECTION my_connection;";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.total_reported_signals >= 1,
        "Should generate at least one signal for DROP CONNECTION"
    );
    assert!(
        has_signal(&report, "DBX-CONN-DROP"),
        "Should find DBX-CONN-DROP (Connection Dropped)"
    );
}

#[test]
fn test_alter_connection_owner_risk_signal() {
    let sql = "ALTER CONNECTION my_connection SET OWNER TO `new_owner`;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-CONN-OWNER-CHG"),
        "Should find DBX-CONN-OWNER-CHG (Connection Ownership Changed)"
    );
}

#[test]
fn test_alter_connection_rename_risk_signal() {
    let sql = "ALTER CONNECTION my_connection RENAME TO other_connection;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-CONN-NAME-CHG"),
        "Should find DBX-CONN-NAME-CHG (Connection Renamed)"
    );
}

#[test]
fn test_alter_connection_options_risk_signal() {
    let sql = r#"ALTER CONNECTION my_connection OPTIONS (
  host 'newhost.us-west-2.rds.amazonaws.com',
  port '5432'
);"#;

    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-CONN-CHG"),
        "Should find DBX-CONN-CHG (Connection Options Modified)"
    );
}

// ─── Multi-Statement Evidence Count ─────────────────────────────────────────────

#[test]
fn test_multi_connection_evidence_count() {
    let sql = r#"
CREATE CONNECTION pg_conn_1 TYPE POSTGRESQL OPTIONS (host 'host1', port '5432');
CREATE CONNECTION pg_conn_2 TYPE POSTGRESQL OPTIONS (host 'host2', port '5432');
DROP CONNECTION pg_conn_3;
ALTER CONNECTION pg_conn_4 RENAME TO pg_conn_4b;
"#;

    let report = dbx_analyze(sql);

    // Count total evidence across all connection signals
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| match s {
            RuleMatch::Analysis(a) => a.matched_rule.starts_with("DBX-CONN"),
        })
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 4,
        "Should have evidence for all 4 connection statements, got {}",
        total_evidence
    );
}

// ─── Formatting Round-trip with All Variants ────────────────────────────────────

#[test]
fn test_all_connection_variants_format_roundtrip() {
    let sql = r#"CREATE CONNECTION conn1
TYPE POSTGRESQL
OPTIONS (
  host 'pg-host.amazonaws.com',
  port '5432',
  user 'admin',
  password secret('scope', 'key')
);

CREATE CONNECTION IF NOT EXISTS conn2 TYPE MYSQL OPTIONS (host 'mysql-host', port '3306') COMMENT 'MySQL connection';

CREATE SERVER conn3 TYPE REDSHIFT OPTIONS (host 'rs-host', user 'admin', password 'pass');

ALTER CONNECTION conn1 SET OWNER TO `new_owner`;

ALTER CONNECTION conn1 OWNER TO `admin_group`;

ALTER CONNECTION conn1 RENAME TO conn1_renamed;

ALTER CONNECTION conn1 OPTIONS (host 'new-host', port '5433');

DROP CONNECTION conn4;

DROP CONNECTION IF EXISTS conn5;"#;

    dbx_format_and_verify(sql);
}

// ─── Databricks Dialect Specific ────────────────────────────────────────────────

#[test]
fn test_connection_with_backtick_quoted_names() {
    let sql =
        "CREATE CONNECTION `my-special-conn` TYPE POSTGRESQL OPTIONS (host 'pghost', port '5432');";
    dbx_format_and_verify(sql);
}

#[test]
fn test_connection_risk_level_classification() {
    // DROP should be High, CREATE should be Medium
    let sql = "DROP CONNECTION critical_conn;";
    let report = dbx_analyze(sql);

    let drop_signal = report
        .signals
        .iter()
        .find(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == "DBX-CONN-DROP"));
    assert!(drop_signal.is_some(), "Should have DBX-CONN-DROP signal");
    if let Some(RuleMatch::Analysis(a)) = drop_signal {
        assert_eq!(
            a.risk_level,
            lexega_core::analyzer::RiskLevel::High,
            "DROP CONNECTION should be High risk"
        );
    }
}
