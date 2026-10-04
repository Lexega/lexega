// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk_with_policy_config;
/// Tests for Databricks Delta Lake time travel: VERSION AS OF, TIMESTAMP AS OF, and @ syntax
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

fn assert_roundtrip(sql: &str) {
    let formatted = format_sql_with_config(sql, &dbx_config())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

// ============================================================================
// VERSION AS OF — basic cases
// ============================================================================

#[test]
fn test_version_as_of_number() {
    assert_roundtrip("SELECT * FROM events VERSION AS OF 123;");
}

#[test]
fn test_version_as_of_analysis_tracks_tables_read() {
    let sql = "SELECT * FROM events VERSION AS OF 123;";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.tables_read >= 1,
        "VERSION AS OF query should track at least one table read, got {}",
        report.summary.tables_read
    );
}

#[test]
fn test_version_as_of_zero() {
    assert_roundtrip("SELECT * FROM events VERSION AS OF 0;");
}

#[test]
fn test_version_as_of_qualified_table() {
    assert_roundtrip("SELECT * FROM db.schema.events VERSION AS OF 5;");
}

#[test]
fn test_version_as_of_two_part_name() {
    assert_roundtrip("SELECT * FROM my_schema.events VERSION AS OF 42;");
}

#[test]
fn test_version_as_of_backtick_table() {
    assert_roundtrip("SELECT * FROM `my-database`.`my-table` VERSION AS OF 10;");
}

// ============================================================================
// TIMESTAMP AS OF — basic cases
// ============================================================================

#[test]
fn test_timestamp_as_of_string() {
    assert_roundtrip("SELECT * FROM events TIMESTAMP AS OF '2018-10-18';");
}

#[test]
fn test_timestamp_as_of_analysis_tracks_tables_read() {
    let sql = "SELECT * FROM events TIMESTAMP AS OF '2018-10-18';";
    let report = dbx_analyze(sql);

    assert!(
        report.summary.tables_read >= 1,
        "TIMESTAMP AS OF query should track at least one table read, got {}",
        report.summary.tables_read
    );
}

#[test]
fn test_timestamp_as_of_iso_string() {
    assert_roundtrip("SELECT * FROM events TIMESTAMP AS OF '2018-10-18T22:15:12.013Z';");
}

#[test]
fn test_timestamp_as_of_qualified_table() {
    assert_roundtrip("SELECT * FROM db.events TIMESTAMP AS OF '2024-01-01';");
}

// ============================================================================
// TIMESTAMP AS OF — complex expressions
// ============================================================================

#[test]
fn test_timestamp_as_of_function_call() {
    assert_roundtrip("SELECT * FROM events TIMESTAMP AS OF date_sub(current_date(), 1);");
}

#[test]
fn test_timestamp_as_of_cast() {
    assert_roundtrip(
        "SELECT * FROM events TIMESTAMP AS OF CAST('2018-10-18T22:15:12.013Z' AS TIMESTAMP);",
    );
}

#[test]
fn test_timestamp_as_of_current_timestamp_minus_interval() {
    assert_roundtrip(
        "SELECT * FROM events TIMESTAMP AS OF current_timestamp() - INTERVAL 12 HOURS;",
    );
}

// ============================================================================
// @ syntax
// ============================================================================

#[test]
fn test_at_version_identifier() {
    assert_roundtrip("SELECT * FROM events@v123;");
}

#[test]
fn test_at_timestamp_number() {
    assert_roundtrip("SELECT * FROM events@20190101000000000;");
}

#[test]
fn test_at_version_qualified() {
    assert_roundtrip("SELECT * FROM db.events@v5;");
}

// ============================================================================
// With aliases
// ============================================================================

#[test]
fn test_version_as_of_with_alias_before() {
    // Alias BEFORE time travel is valid Databricks syntax:
    // SELECT * FROM events e VERSION AS OF 100
    assert_roundtrip("SELECT * FROM events e VERSION AS OF 100;");
}

#[test]
fn test_timestamp_as_of_with_alias_before() {
    assert_roundtrip("SELECT * FROM events e TIMESTAMP AS OF '2024-01-01';");
}

// ============================================================================
// With JOINs
// ============================================================================

#[test]
fn test_version_as_of_join() {
    assert_roundtrip("SELECT a.*, b.* FROM events a VERSION AS OF 100 JOIN logs b ON a.id = b.id;");
}

#[test]
fn test_timestamp_as_of_join() {
    assert_roundtrip(
        "SELECT * FROM events TIMESTAMP AS OF '2024-01-01' JOIN users ON events.user_id = users.id;"
    );
}

#[test]
fn test_version_as_of_left_join() {
    assert_roundtrip(
        "SELECT * FROM events VERSION AS OF 5 LEFT JOIN logs ON events.id = logs.event_id;",
    );
}

// ============================================================================
// With WHERE clause
// ============================================================================

#[test]
fn test_version_as_of_where() {
    assert_roundtrip("SELECT * FROM events VERSION AS OF 123 WHERE id > 10;");
}

#[test]
fn test_timestamp_as_of_where() {
    assert_roundtrip("SELECT * FROM events e TIMESTAMP AS OF '2024-01-01' WHERE e.id > 10;");
}

// ============================================================================
// With GROUP BY, ORDER BY, LIMIT
// ============================================================================

#[test]
fn test_version_as_of_group_by() {
    assert_roundtrip("SELECT status, COUNT(*) FROM events VERSION AS OF 5 GROUP BY status;");
}

#[test]
fn test_version_as_of_order_limit() {
    assert_roundtrip("SELECT * FROM events VERSION AS OF 10 ORDER BY id LIMIT 100;");
}

// ============================================================================
// Case insensitivity
// ============================================================================

#[test]
fn test_version_as_of_lowercase() {
    assert_roundtrip("select * from events version as of 123;");
}

#[test]
fn test_timestamp_as_of_mixed_case() {
    assert_roundtrip("SELECT * FROM events Timestamp As Of '2024-01-01';");
}

// ============================================================================
// Multiple tables with time travel
// ============================================================================

#[test]
fn test_both_tables_time_travel() {
    assert_roundtrip(
        "SELECT * FROM events VERSION AS OF 100 JOIN users VERSION AS OF 50 ON events.user_id = users.id;",
    );
}

// ============================================================================
// Subqueries and CTEs
// ============================================================================

#[test]
fn test_version_as_of_in_subquery() {
    assert_roundtrip("SELECT * FROM (SELECT * FROM events VERSION AS OF 5) sub WHERE sub.id > 10;");
}

#[test]
fn test_version_as_of_in_cte() {
    assert_roundtrip(
        "WITH old_events AS (SELECT * FROM events VERSION AS OF 100) SELECT * FROM old_events;",
    );
}

// ============================================================================
// Snowflake time travel should still work (regression)
// ============================================================================

#[test]
fn test_snowflake_at_timestamp_not_broken() {
    let sql = "SELECT * FROM t1 AT(TIMESTAMP => '2024-01-01'::TIMESTAMP_LTZ);";
    let config = FormatterConfig::default(); // Snowflake is default
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("roundtrip safe");
}

#[test]
fn test_snowflake_before_offset_not_broken() {
    let sql = "SELECT * FROM t1 BEFORE(OFFSET => -60*5);";
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("roundtrip safe");
}

// ============================================================================
// BigQuery FOR SYSTEM_TIME AS OF should still work (regression)
// ============================================================================

#[test]
fn test_bigquery_system_time_not_broken() {
    let sql = "SELECT * FROM events FOR SYSTEM_TIME AS OF '2024-01-01';";
    let config = FormatterConfig {
        dialect: lexega_core::dialect::bigquery(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("roundtrip safe");
}
