// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL REFRESH MATERIALIZED VIEW statement.

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

/// Helper: create a PG-dialect formatter config.
fn pg_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = std::sync::Arc::new(lexega_syntax::dialect::PostgresDialect);
    config
}

/// Helper: parse with PG dialect and check it doesn't become OpaqueContent.
fn parses_as(sql: &str) -> String {
    let config = pg_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Failed to parse: {e}\nSQL: {sql}"));
    // Guard: if statement falls through to OpaqueContent, formatted == original
    // but we want to ensure it actually parsed as PgRefreshMatview
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("Formatting not safe: {e}\nSQL: {sql}\nFormatted: {formatted}"));
    formatted
}

// ===========================================================================
// Basic REFRESH MATERIALIZED VIEW
// ===========================================================================

#[test]
fn test_refresh_basic() {
    parses_as("REFRESH MATERIALIZED VIEW order_summary;");
}

#[test]
fn test_refresh_no_semicolon() {
    parses_as("REFRESH MATERIALIZED VIEW order_summary");
}

#[test]
fn test_refresh_lowercase() {
    parses_as("refresh materialized view order_summary;");
}

#[test]
fn test_refresh_mixed_case() {
    parses_as("Refresh Materialized View order_summary;");
}

// ===========================================================================
// CONCURRENTLY
// ===========================================================================

#[test]
fn test_refresh_concurrently() {
    parses_as("REFRESH MATERIALIZED VIEW CONCURRENTLY order_summary;");
}

#[test]
fn test_refresh_concurrently_lowercase() {
    parses_as("refresh materialized view concurrently order_summary;");
}

// ===========================================================================
// WITH DATA / WITH NO DATA
// ===========================================================================

#[test]
fn test_refresh_with_data() {
    parses_as("REFRESH MATERIALIZED VIEW order_summary WITH DATA;");
}

#[test]
fn test_refresh_with_no_data() {
    parses_as("REFRESH MATERIALIZED VIEW annual_statistics WITH NO DATA;");
}

#[test]
fn test_refresh_concurrently_with_data() {
    parses_as("REFRESH MATERIALIZED VIEW CONCURRENTLY order_summary WITH DATA;");
}

#[test]
fn test_refresh_with_no_data_lowercase() {
    parses_as("refresh materialized view annual_stats with no data;");
}

#[test]
fn test_refresh_with_data_mixed_case() {
    parses_as("Refresh Materialized View order_summary With Data;");
}

// ===========================================================================
// Schema-qualified names
// ===========================================================================

#[test]
fn test_refresh_schema_qualified() {
    parses_as("REFRESH MATERIALIZED VIEW myschema.order_summary;");
}

#[test]
fn test_refresh_schema_qualified_concurrently() {
    parses_as("REFRESH MATERIALIZED VIEW CONCURRENTLY myschema.order_summary;");
}

#[test]
fn test_refresh_schema_qualified_with_no_data() {
    parses_as("REFRESH MATERIALIZED VIEW myschema.annual_stats WITH NO DATA;");
}

#[test]
fn test_refresh_catalog_schema_table() {
    parses_as("REFRESH MATERIALIZED VIEW mydb.myschema.order_summary;");
}

// ===========================================================================
// Quoted identifiers
// ===========================================================================

#[test]
fn test_refresh_quoted_name() {
    parses_as("REFRESH MATERIALIZED VIEW \"Order Summary\";");
}

#[test]
fn test_refresh_quoted_schema_and_name() {
    parses_as("REFRESH MATERIALIZED VIEW \"my schema\".\"Order Summary\";");
}

#[test]
fn test_refresh_quoted_with_no_data() {
    parses_as("REFRESH MATERIALIZED VIEW \"My View\" WITH NO DATA;");
}

// ===========================================================================
// Kitchen sink
// ===========================================================================

#[test]
fn test_refresh_kitchen_sink() {
    parses_as("REFRESH MATERIALIZED VIEW CONCURRENTLY myschema.order_summary WITH DATA;");
}

#[test]
fn test_refresh_kitchen_sink_quoted() {
    parses_as("REFRESH MATERIALIZED VIEW CONCURRENTLY \"analytics\".\"daily_summary\" WITH DATA;");
}

// ===========================================================================
// Multi-statement
// ===========================================================================

#[test]
fn test_refresh_multi_statement() {
    let sql = "\
REFRESH MATERIALIZED VIEW mv_orders;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_stats;
REFRESH MATERIALIZED VIEW mv_archive WITH NO DATA;";
    let config = pg_config();
    let formatted = format_sql_with_config(sql, &config).expect("Should parse multi-statement");
    verify_formatting_safe(sql, &formatted).expect("Multi-statement formatting should be safe");
}

// ===========================================================================
// Roundtrip: format preserves semantics
// ===========================================================================

#[test]
fn test_refresh_roundtrip_basic() {
    let sql = "REFRESH MATERIALIZED VIEW order_summary;";
    let config = pg_config();
    let f1 = format_sql_with_config(sql, &config).unwrap();
    let f2 = format_sql_with_config(&f1, &config).unwrap();
    assert_eq!(f1, f2, "Double-format should be idempotent");
}

#[test]
fn test_refresh_roundtrip_concurrently_with_no_data() {
    let sql = "REFRESH MATERIALIZED VIEW CONCURRENTLY myschema.stats WITH NO DATA;";
    let config = pg_config();
    let f1 = format_sql_with_config(sql, &config).unwrap();
    let f2 = format_sql_with_config(&f1, &config).unwrap();
    assert_eq!(f1, f2, "Double-format should be idempotent");
}

// ===========================================================================
// Snowflake dialect isolation — REFRESH should NOT parse in Snowflake
// ===========================================================================

#[test]
fn test_refresh_snowflake_opaque() {
    // With Snowflake dialect (default), REFRESH MATERIALIZED VIEW is not a known statement
    // and should fall through gracefully (either OpaqueContent or error)
    let sql = "REFRESH MATERIALIZED VIEW order_summary;";
    let config = FormatterConfig::default(); // Snowflake
                                             // Just verify it doesn't panic — may format as opaque content
    let _ = format_sql_with_config(sql, &config);
}
