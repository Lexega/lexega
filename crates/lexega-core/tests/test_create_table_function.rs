// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for CREATE TABLE FUNCTION (TVFs) and DROP TABLE FUNCTION
/// BigQuery-style table-valued function support.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::dialect::bigquery;
use lexega_core::{format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig};

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

// ============================================================================
// Formatting round-trip tests
// ============================================================================

#[test]
fn test_create_table_function_basic() {
    format_and_verify_bq(
        "CREATE TABLE FUNCTION mydataset.my_tvf(x INT64)
RETURNS TABLE<a STRING, b INT64>
AS SELECT a, b FROM my_table WHERE id = x;",
    );
}

#[test]
fn test_create_table_function_or_replace() {
    format_and_verify_bq(
        "CREATE OR REPLACE TABLE FUNCTION myproject.mydataset.my_tvf(x INT64)
RETURNS TABLE<a STRING, b INT64>
OPTIONS(description=\"A table function\")
AS SELECT a, b FROM my_table WHERE id = x;",
    );
}

#[test]
fn test_create_table_function_if_not_exists() {
    format_and_verify_bq(
        "CREATE TABLE FUNCTION IF NOT EXISTS mydataset.my_tvf(x INT64)
AS SELECT * FROM t WHERE id = x;",
    );
}

#[test]
fn test_create_table_function_table_param() {
    format_and_verify_bq(
        "CREATE TABLE FUNCTION mydataset.compute_sales(
  orders TABLE<item STRING, sales INT64>, item_name STRING)
AS (
  SELECT SUM(sales) AS total_sales, item
  FROM orders
  WHERE item = item_name
  GROUP BY item);",
    );
}

#[test]
fn test_create_table_function_any_type() {
    format_and_verify_bq(
        "CREATE TABLE FUNCTION mydataset.my_tvf(x ANY TYPE)
AS SELECT * FROM t WHERE id = x;",
    );
}

#[test]
fn test_create_table_function_multiline_body() {
    format_and_verify_bq(
        "CREATE TABLE FUNCTION mydataset.names_by_year(y INT64)
RETURNS TABLE<name STRING, year INT64, total INT64>
AS
  SELECT name, year, SUM(number) AS total
  FROM `bigquery-public-data.usa_names.usa_1910_2013`
  WHERE year = y
  GROUP BY year, name;",
    );
}

#[test]
fn test_create_table_function_multi_params() {
    format_and_verify_bq(
        "CREATE TABLE FUNCTION mydataset.filter_data(
  start_date DATE, end_date DATE, category STRING)
RETURNS TABLE<id INT64, name STRING, value FLOAT64>
AS
  SELECT id, name, value
  FROM source_table
  WHERE created BETWEEN start_date AND end_date
    AND cat = category;",
    );
}

#[test]
fn test_drop_table_function() {
    format_and_verify_bq("DROP TABLE FUNCTION mydataset.my_table_function;");
}

#[test]
fn test_drop_table_function_if_exists() {
    format_and_verify_bq("DROP TABLE FUNCTION IF EXISTS mydataset.my_table_function;");
}

// ============================================================================
// Risk analysis tests
// ============================================================================

#[test]
fn test_create_table_function_governance_signal() {
    let sql = "CREATE TABLE FUNCTION mydataset.my_tvf(x INT64)
RETURNS TABLE<a STRING, b INT64>
AS SELECT a, b FROM my_table WHERE id = x;";

    let report = analyze_risk(sql).expect("should analyze CREATE TABLE FUNCTION");

    // Should produce governance signal for function creation
    assert!(
        report.summary.total_reported_signals > 0,
        "Should generate governance signals for CREATE TABLE FUNCTION. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_create_table_function_body_table_extraction() {
    // The body SELECT references my_table — semantic extraction should capture it
    let sql = "CREATE TABLE FUNCTION mydataset.my_tvf(x INT64)
AS SELECT a, b FROM my_table WHERE id = x;";

    let report = analyze_risk(sql).expect("should analyze");

    // The function creation itself should generate at least 1 signal
    assert!(
        report.summary.total_reported_signals > 0,
        "CREATE TABLE FUNCTION should generate at least 1 governance signal"
    );
}

#[test]
fn test_multi_tvf_statements() {
    let sql = r#"
CREATE TABLE FUNCTION ds.tvf1(x INT64) AS SELECT * FROM t1;
CREATE TABLE FUNCTION ds.tvf2(y STRING) AS SELECT * FROM t2;
DROP TABLE FUNCTION ds.tvf3;
"#;

    let report = analyze_risk(sql).expect("should analyze multi-TVF script");

    // Signals are deduplicated by rule ID — test evidence_count, not signal count
    // (per BUILTIN_RULES_COOKBOOK: "Test evidence count for multi-occurrence")
    let total_evidence: usize = report
        .signals
        .iter()
        .map(|f| match f {
            RuleMatch::Analysis(ref p) => p.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Multiple CREATE TABLE FUNCTION statements should generate evidence for each. Got total evidence: {}",
        total_evidence
    );
}
