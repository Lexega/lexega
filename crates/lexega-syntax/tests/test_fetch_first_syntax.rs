// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

#[test]
fn test_limit_offset_traditional() {
    let sql = "SELECT * FROM users LIMIT 10 OFFSET 5";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_fetch_first_basic() {
    let sql = "SELECT * FROM users FETCH FIRST 10 ROWS ONLY";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_fetch_next() {
    let sql = "SELECT * FROM users FETCH NEXT 20 ROWS ONLY";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_offset_fetch_first() {
    let sql = "SELECT * FROM users OFFSET 5 ROWS FETCH FIRST 10 ROWS ONLY";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_offset_fetch_next() {
    let sql = "SELECT * FROM users OFFSET 5 FETCH NEXT 10 ROWS ONLY";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_fetch_first_row_singular() {
    let sql = "SELECT * FROM users FETCH FIRST 1 ROW ONLY";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_offset_without_rows_keyword() {
    let sql = "SELECT * FROM users OFFSET 5 FETCH FIRST 10 ROWS ONLY";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
