// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::dialect::PostgresDialect;
use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::sync::Arc;

fn postgres_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = Arc::new(PostgresDialect);
    config
}

#[test]
fn test_distinct_on_basic() {
    let sql = "SELECT DISTINCT ON (location) location, time, report FROM weather_reports ORDER BY location, time DESC;";

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format DISTINCT ON");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    // Verify DISTINCT ON is preserved
    assert!(
        formatted.contains("DISTINCT ON"),
        "Should preserve DISTINCT ON"
    );
    assert!(
        formatted.contains("location"),
        "Should preserve column name"
    );
}

#[test]
fn test_distinct_on_multiple_exprs() {
    let sql = "SELECT DISTINCT ON (a, b, c) a, b, c, d FROM table1;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DISTINCT ON with multiple expressions");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("DISTINCT ON"),
        "Should preserve DISTINCT ON"
    );
}

#[test]
fn test_distinct_on_complex_exprs() {
    let sql = "SELECT DISTINCT ON (LOWER(name), date_trunc('day', created_at)) * FROM users;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DISTINCT ON with complex expressions");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("DISTINCT ON"),
        "Should preserve DISTINCT ON"
    );
    assert!(formatted.contains("LOWER"), "Should preserve function call");
}

#[test]
fn test_distinct_on_with_order_by() {
    let sql = r#"
        SELECT DISTINCT ON (location)
            location, time, report
        FROM weather_reports
        ORDER BY location, time DESC;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DISTINCT ON with ORDER BY");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("DISTINCT ON"),
        "Should preserve DISTINCT ON"
    );
    assert!(formatted.contains("ORDER BY"), "Should preserve ORDER BY");
}

#[test]
fn test_distinct_still_works() {
    // Ensure plain DISTINCT without ON still works
    let sql = "SELECT DISTINCT location, time FROM weather_reports;";

    let config = postgres_config();
    let formatted =
        format_sql_with_config(sql, &config).expect("should parse and format plain DISTINCT");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    // Should contain DISTINCT but not DISTINCT ON
    assert!(formatted.contains("DISTINCT"), "Should preserve DISTINCT");
    assert!(
        !formatted.contains("DISTINCT ON"),
        "Should not contain DISTINCT ON"
    );
}

#[test]
fn test_distinct_on_parsed_permissively() {
    // Parser accepts DISTINCT ON syntax regardless of target dialect
    // (parse permissively, let the database reject at execution time)
    let sql = "SELECT DISTINCT ON (location) location, time FROM weather_reports;";

    let config = FormatterConfig::default(); // Uses Snowflake dialect by default

    // DISTINCT ON is parsed and formatted faithfully even in default (Snowflake) mode
    let formatted =
        format_sql_with_config(sql, &config).expect("DISTINCT ON should parse permissively");

    // Verify it round-trips correctly
    assert!(
        formatted.contains("DISTINCT ON"),
        "Should preserve DISTINCT ON syntax"
    );
    println!("Formatted: {}", formatted);
}

#[test]
fn test_distinct_on_single_expr() {
    let sql = "SELECT DISTINCT ON (customer_id) customer_id, order_date, total FROM orders;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DISTINCT ON with single expression");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("DISTINCT ON"),
        "Should preserve DISTINCT ON"
    );
    assert!(
        formatted.contains("customer_id"),
        "Should preserve expression"
    );
}

#[test]
fn test_distinct_on_with_where_and_limit() {
    let sql = r#"
        SELECT DISTINCT ON (category)
            category, product_name, price
        FROM products
        WHERE active = true
        ORDER BY category, price DESC
        LIMIT 10;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DISTINCT ON with WHERE and LIMIT");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("DISTINCT ON"),
        "Should preserve DISTINCT ON"
    );
    assert!(formatted.contains("WHERE"), "Should preserve WHERE");
    assert!(formatted.contains("LIMIT"), "Should preserve LIMIT");
}
