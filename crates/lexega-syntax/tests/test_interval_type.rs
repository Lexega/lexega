// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for compound INTERVAL data type parsing in CAST, TRY_CAST, :: cast,
//! and CREATE TABLE column definitions.

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("Format failed:\n{e}\nSQL:\n{sql}"));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("Round-trip failed:\n{e}\nFormatted:\n{formatted}"));
    formatted
}

// ============================================================================
// CAST with compound INTERVAL types
// ============================================================================

#[test]
fn test_cast_interval_year_to_month() {
    let sql = "SELECT CAST(col1 AS INTERVAL YEAR TO MONTH) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL YEAR TO MONTH"),
        "Should preserve compound interval: {fmt}"
    );
}

#[test]
fn test_cast_interval_day_to_second_with_precision() {
    let sql = "SELECT CAST(col1 AS INTERVAL DAY(2) TO SECOND(3)) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL DAY(2) TO SECOND(3)"),
        "Should preserve precision: {fmt}"
    );
}

#[test]
fn test_cast_interval_second_precision_scale() {
    let sql = "SELECT CAST(col1 AS INTERVAL SECOND(9, 3)) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL SECOND(9"),
        "Should preserve SECOND precision: {fmt}"
    );
}

#[test]
fn test_cast_interval_unit_only() {
    let sql = "SELECT CAST(col1 AS INTERVAL YEAR) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL YEAR"),
        "Should preserve single unit: {fmt}"
    );
}

#[test]
fn test_cast_interval_month_only() {
    let sql = "SELECT CAST(col1 AS INTERVAL MONTH) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL MONTH"),
        "Should preserve MONTH: {fmt}"
    );
}

#[test]
fn test_cast_interval_day_to_hour() {
    let sql = "SELECT CAST(col1 AS INTERVAL DAY TO HOUR) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL DAY TO HOUR"),
        "Should preserve DAY TO HOUR: {fmt}"
    );
}

#[test]
fn test_cast_interval_hour_to_minute() {
    let sql = "SELECT CAST(col1 AS INTERVAL HOUR TO MINUTE) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL HOUR TO MINUTE"),
        "Should preserve HOUR TO MINUTE: {fmt}"
    );
}

#[test]
fn test_cast_interval_hour_to_second() {
    let sql = "SELECT CAST(col1 AS INTERVAL HOUR TO SECOND) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL HOUR TO SECOND"),
        "Should preserve HOUR TO SECOND: {fmt}"
    );
}

#[test]
fn test_cast_interval_minute_to_second() {
    let sql = "SELECT CAST(col1 AS INTERVAL MINUTE TO SECOND) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL MINUTE TO SECOND"),
        "Should preserve MINUTE TO SECOND: {fmt}"
    );
}

// ============================================================================
// TRY_CAST with compound INTERVAL types
// ============================================================================

#[test]
fn test_try_cast_interval_year_to_month() {
    let sql = "SELECT TRY_CAST(col1 AS INTERVAL YEAR TO MONTH) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("TRY_CAST"), "Should preserve TRY_CAST: {fmt}");
    assert!(
        fmt.contains("INTERVAL YEAR TO MONTH"),
        "Should preserve compound interval: {fmt}"
    );
}

#[test]
fn test_try_cast_interval_day_precision_to_second_precision() {
    let sql = "SELECT TRY_CAST(col1 AS INTERVAL DAY(3) TO SECOND(6)) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL DAY(3) TO SECOND(6)"),
        "Should preserve precision: {fmt}"
    );
}

// ============================================================================
// :: postfix cast with compound INTERVAL types
// ============================================================================

#[test]
fn test_double_colon_interval_year_to_month() {
    let sql = "SELECT col1::INTERVAL YEAR TO MONTH FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("::INTERVAL YEAR TO MONTH"),
        "Should preserve :: cast: {fmt}"
    );
}

#[test]
fn test_double_colon_interval_day_to_second_precision() {
    let sql = "SELECT col1::INTERVAL DAY(3) TO SECOND(6) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("::INTERVAL DAY(3) TO SECOND(6)"),
        "Should preserve :: cast: {fmt}"
    );
}

#[test]
fn test_double_colon_interval_second_only() {
    let sql = "SELECT col1::INTERVAL SECOND FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("::INTERVAL SECOND"),
        "Should preserve :: cast: {fmt}"
    );
}

// ============================================================================
// CREATE TABLE columns with compound INTERVAL types
// ============================================================================

#[test]
fn test_create_table_interval_columns() {
    let sql = r#"CREATE TABLE t (
    a INTERVAL YEAR TO MONTH,
    b INTERVAL DAY(3) TO SECOND(6),
    c INTERVAL MONTH,
    d INTERVAL SECOND(9, 3),
    e INTERVAL HOUR TO MINUTE
);"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("INTERVAL YEAR TO MONTH"), "{fmt}");
    assert!(fmt.contains("INTERVAL DAY(3) TO SECOND(6)"), "{fmt}");
    assert!(fmt.contains("INTERVAL MONTH"), "{fmt}");
    assert!(fmt.contains("INTERVAL HOUR TO MINUTE"), "{fmt}");
}

// ============================================================================
// Multiple INTERVAL casts in one statement
// ============================================================================

#[test]
fn test_multi_interval_cast_expressions() {
    let sql = "SELECT CAST(a AS INTERVAL YEAR TO MONTH), TRY_CAST(b AS INTERVAL DAY TO SECOND), c::INTERVAL HOUR FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("INTERVAL YEAR TO MONTH"), "{fmt}");
    assert!(fmt.contains("INTERVAL DAY TO SECOND"), "{fmt}");
    assert!(fmt.contains("::INTERVAL HOUR"), "{fmt}");
}

// ============================================================================
// Plain INTERVAL (no unit) should still work as simple type
// ============================================================================

#[test]
fn test_cast_plain_interval() {
    let sql = "SELECT CAST(col1 AS INTERVAL) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL)"),
        "Plain INTERVAL should still work: {fmt}"
    );
}

// ============================================================================
// INTERVAL with precision on source unit only (no TO)
// ============================================================================

#[test]
fn test_cast_interval_year_with_precision() {
    let sql = "SELECT CAST(col1 AS INTERVAL YEAR(4)) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL YEAR(4)"),
        "Should preserve YEAR precision: {fmt}"
    );
}

#[test]
fn test_cast_interval_day_with_precision() {
    let sql = "SELECT CAST(col1 AS INTERVAL DAY(5)) FROM t1;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("INTERVAL DAY(5)"),
        "Should preserve DAY precision: {fmt}"
    );
}
