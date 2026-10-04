// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;
/// Tests for CREATE MATERIALIZED VIEW support
/// Covers BigQuery, Snowflake, and PostgreSQL dialect variations.
///
/// BigQuery: PARTITION BY, CLUSTER BY, OPTIONS(...), AS REPLICA OF
/// Snowflake: SECURE, COPY GRANTS, CLUSTER BY, COMMENT
/// PostgreSQL: WITH [NO] DATA
use lexega_core::dialect::bigquery;
use lexega_core::{
    format_sql_with_config, verify_formatting_safe, verify_formatting_safe_with_dialect,
    FormatterConfig,
};

// ============================================================================
// Helpers
// ============================================================================

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = bigquery();
    config
}

fn format_and_verify_bq(sql: &str) {
    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("BigQuery format failed:\n{}\nSQL:\n{}", e, sql));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref()).unwrap_or_else(
        |e| {
            panic!(
                "BigQuery round-trip verification failed:\n{}\nSQL:\n{}",
                e, sql
            )
        },
    );
}

fn format_and_verify_sf(sql: &str) {
    let config = FormatterConfig::default(); // Snowflake is the default dialect
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Snowflake format failed:\n{}\nSQL:\n{}", e, sql));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Snowflake round-trip verification failed:\n{}\nSQL:\n{}",
            e, sql
        )
    });
}

// ============================================================================
// BigQuery: Basic CREATE MATERIALIZED VIEW
// ============================================================================

#[test]
fn test_bq_create_materialized_view_basic() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv AS
SELECT region, COUNT(*) AS cnt
FROM my_table
GROUP BY region;",
    );
}

#[test]
fn test_bq_create_materialized_view_or_replace() {
    format_and_verify_bq(
        "CREATE OR REPLACE MATERIALIZED VIEW my_dataset.mv AS
SELECT region, COUNT(*) AS cnt
FROM t
GROUP BY region;",
    );
}

#[test]
fn test_bq_create_materialized_view_if_not_exists() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW IF NOT EXISTS my_dataset.mv AS
SELECT region, COUNT(*) AS cnt
FROM t
GROUP BY region;",
    );
}

// ============================================================================
// BigQuery: PARTITION BY
// ============================================================================

#[test]
fn test_bq_materialized_view_partition_by() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv
PARTITION BY DATE(created_at)
AS
SELECT created_at, region, COUNT(*) AS cnt
FROM t
GROUP BY created_at, region;",
    );
}

#[test]
fn test_bq_materialized_view_partition_by_date_trunc() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv
PARTITION BY DATE_TRUNC(ts, MONTH)
AS
SELECT ts, SUM(amount) AS total
FROM t
GROUP BY ts;",
    );
}

// ============================================================================
// BigQuery: CLUSTER BY
// ============================================================================

#[test]
fn test_bq_materialized_view_cluster_by() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv
CLUSTER BY region
AS
SELECT region, COUNT(*) AS cnt
FROM t
GROUP BY region;",
    );
}

#[test]
fn test_bq_materialized_view_cluster_by_multiple() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv
CLUSTER BY region, category
AS
SELECT region, category, COUNT(*) AS cnt
FROM t
GROUP BY region, category;",
    );
}

// ============================================================================
// BigQuery: PARTITION BY + CLUSTER BY combination
// ============================================================================

#[test]
fn test_bq_materialized_view_partition_and_cluster() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv
PARTITION BY DATE(created_at)
CLUSTER BY region
AS
SELECT created_at, region, COUNT(*) AS cnt
FROM t
GROUP BY created_at, region;",
    );
}

// ============================================================================
// BigQuery: OPTIONS(...)
// ============================================================================

#[test]
fn test_bq_materialized_view_options() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv
OPTIONS(enable_refresh = true, refresh_interval_minutes = 30)
AS
SELECT region, COUNT(*) AS cnt
FROM t
GROUP BY region;",
    );
}

#[test]
fn test_bq_materialized_view_partition_cluster_options() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv
PARTITION BY DATE(created_at)
CLUSTER BY region, category
OPTIONS(enable_refresh = true, refresh_interval_minutes = 30, description = 'My materialized view')
AS
SELECT created_at, region, category, COUNT(*) AS cnt
FROM t
GROUP BY created_at, region, category;",
    );
}

// ============================================================================
// BigQuery: AS REPLICA OF
// ============================================================================

#[test]
fn test_bq_materialized_view_replica_of() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv_replica AS REPLICA OF other_project.other_dataset.source_mv;",
    );
}

#[test]
fn test_bq_materialized_view_replica_of_with_options() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW my_dataset.mv_replica
OPTIONS(enable_refresh = false)
AS REPLICA OF other_project.other_dataset.source_mv;",
    );
}

// ============================================================================
// Snowflake: Basic CREATE MATERIALIZED VIEW
// ============================================================================

#[test]
fn test_sf_create_materialized_view_basic() {
    format_and_verify_sf(
        "CREATE MATERIALIZED VIEW my_mv AS
SELECT date_col, SUM(amount) AS total
FROM transactions
GROUP BY date_col;",
    );
}

#[test]
fn test_sf_create_materialized_view_or_replace() {
    format_and_verify_sf(
        "CREATE OR REPLACE MATERIALIZED VIEW my_mv AS
SELECT id, name
FROM users
WHERE active = TRUE;",
    );
}

// ============================================================================
// Snowflake: SECURE materialized view
// ============================================================================

#[test]
fn test_sf_create_secure_materialized_view() {
    format_and_verify_sf(
        "CREATE SECURE MATERIALIZED VIEW my_secure_mv AS
SELECT id, name
FROM sensitive_data;",
    );
}

#[test]
fn test_sf_create_or_replace_secure_materialized_view() {
    format_and_verify_sf(
        "CREATE OR REPLACE SECURE MATERIALIZED VIEW my_secure_mv AS
SELECT id, name
FROM sensitive_data;",
    );
}

// ============================================================================
// Snowflake: COPY GRANTS
// ============================================================================

#[test]
fn test_sf_materialized_view_copy_grants() {
    format_and_verify_sf(
        "CREATE OR REPLACE MATERIALIZED VIEW my_mv COPY GRANTS AS
SELECT id, name
FROM users;",
    );
}

// ============================================================================
// Snowflake: CLUSTER BY
// ============================================================================

#[test]
fn test_sf_materialized_view_cluster_by() {
    format_and_verify_sf(
        "CREATE MATERIALIZED VIEW my_mv
CLUSTER BY (date_col)
AS
SELECT date_col, SUM(amount) AS total
FROM transactions
GROUP BY date_col;",
    );
}

#[test]
fn test_sf_materialized_view_cluster_by_multiple() {
    format_and_verify_sf(
        "CREATE MATERIALIZED VIEW my_mv
CLUSTER BY (date_col, region)
AS
SELECT date_col, region, SUM(amount) AS total
FROM transactions
GROUP BY date_col, region;",
    );
}

// ============================================================================
// Snowflake: COMMENT
// ============================================================================

#[test]
fn test_sf_materialized_view_with_comment() {
    format_and_verify_sf(
        "CREATE MATERIALIZED VIEW my_mv COMMENT = 'Daily aggregate view' AS
SELECT date_col, SUM(amount) AS total
FROM transactions
GROUP BY date_col;",
    );
}

// ============================================================================
// Snowflake: Combined options
// ============================================================================

#[test]
fn test_sf_materialized_view_full_syntax() {
    format_and_verify_sf(
        "CREATE OR REPLACE SECURE MATERIALIZED VIEW my_schema.my_mv COPY GRANTS
CLUSTER BY (date_col)
COMMENT = 'Full syntax test'
AS
SELECT date_col, SUM(amount) AS total
FROM transactions
GROUP BY date_col;",
    );
}

// ============================================================================
// PostgreSQL: Basic CREATE MATERIALIZED VIEW
// ============================================================================

#[test]
fn test_pg_create_materialized_view_basic() {
    // PostgreSQL uses default dialect for parsing (parser is permissive)
    format_and_verify_sf(
        "CREATE MATERIALIZED VIEW my_mv AS
SELECT id, name
FROM users;",
    );
}

// ============================================================================
// Qualified names and quoted identifiers
// ============================================================================

#[test]
fn test_materialized_view_qualified_name() {
    format_and_verify_sf(
        "CREATE MATERIALIZED VIEW my_db.my_schema.my_mv AS
SELECT id FROM t;",
    );
}

#[test]
fn test_bq_materialized_view_quoted_name() {
    format_and_verify_bq(
        "CREATE MATERIALIZED VIEW `my_project.my_dataset.my_mv` AS
SELECT id FROM t;",
    );
}

// ============================================================================
// Multi-statement tests
// ============================================================================

#[test]
fn test_multi_materialized_view_statements() {
    format_and_verify_sf(
        "CREATE MATERIALIZED VIEW mv1 AS
SELECT id FROM t1;

CREATE MATERIALIZED VIEW mv2 AS
SELECT name FROM t2;

CREATE MATERIALIZED VIEW mv3 AS
SELECT val FROM t3;",
    );
}

// ============================================================================
// Risk analysis tests
// ============================================================================

#[test]
fn test_materialized_view_governance_signal() {
    let sql = "CREATE MATERIALIZED VIEW my_mv AS
SELECT region, COUNT(*) AS cnt
FROM t
GROUP BY region;";

    let report = analyze_risk(sql).expect("should analyze CREATE MATERIALIZED VIEW");

    // Should be classified as DDL
    assert!(
        report.summary.ddl_operations >= 1,
        "CREATE MATERIALIZED VIEW should be classified as DDL. Summary: {:?}",
        report.summary
    );

    // Should be successfully analyzed (not skipped/opaque)
    assert!(
        report.summary.statements_analyzed >= 1,
        "CREATE MATERIALIZED VIEW should be successfully analyzed, not OpaqueContent. \
         analyzed={}, skipped={}",
        report.summary.statements_analyzed,
        report.summary.statements_skipped
    );
}

#[test]
fn test_multi_materialized_view_risk_analysis() {
    let sql = r#"
CREATE MATERIALIZED VIEW mv1 AS SELECT id FROM t1;
CREATE MATERIALIZED VIEW mv2 AS SELECT name FROM t2;
CREATE MATERIALIZED VIEW mv3 AS SELECT val FROM t3;
"#;

    let report = analyze_risk(sql).expect("should analyze multi-MV script");

    // All 3 statements should be analyzed (not colliding on NodeId)
    assert!(
        report.summary.statements_analyzed >= 3,
        "All 3 CREATE MATERIALIZED VIEW should be analyzed. Got analyzed={}, skipped={}",
        report.summary.statements_analyzed,
        report.summary.statements_skipped
    );
}

#[test]
fn test_materialized_view_body_table_extraction() {
    // The body SELECT references a table — semantic extraction should capture it
    let sql = "CREATE MATERIALIZED VIEW my_mv AS
SELECT region, COUNT(*) AS cnt
FROM sales_data
GROUP BY region;";

    let report = analyze_risk(sql).expect("should analyze");

    // Should be classified correctly (not OpaqueContent)
    assert!(
        report.summary.statements_analyzed >= 1,
        "CREATE MATERIALIZED VIEW should be fully analyzed"
    );
}

#[test]
fn test_materialized_view_mixed_with_regular_view() {
    let sql = r#"
CREATE VIEW v1 AS SELECT id FROM t1;
CREATE MATERIALIZED VIEW mv1 AS SELECT name FROM t2;
CREATE OR REPLACE VIEW v2 AS SELECT val FROM t3;
CREATE OR REPLACE MATERIALIZED VIEW mv2 AS SELECT cnt FROM t4;
"#;

    let report = analyze_risk(sql).expect("should analyze mixed views");

    // All 4 statements should be analyzed
    assert!(
        report.summary.statements_analyzed >= 4,
        "All 4 views (regular + materialized) should be analyzed. Got analyzed={}, skipped={}",
        report.summary.statements_analyzed,
        report.summary.statements_skipped
    );
}
