// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

#[test]
fn test_type_cast_basic() {
    let sql = "SELECT '123'::INTEGER";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_type_cast_multiple() {
    let sql = "SELECT '123'::INTEGER, now()::DATE, data::JSONB";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_type_cast_complex_type() {
    let sql = "SELECT value::VARCHAR(50), amount::NUMERIC(10, 2)";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_type_cast_in_expression() {
    let sql = "SELECT ('100'::INTEGER + '200'::INTEGER) * 2";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_type_cast_with_function() {
    let sql = "SELECT UPPER(name)::VARCHAR, COUNT(*)::BIGINT FROM users";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_cast_vs_type_cast() {
    // Both syntaxes should work
    let sql1 = "SELECT CAST('123' AS INTEGER)";
    let sql2 = "SELECT '123'::INTEGER";

    let formatted1 =
        format_sql_with_config(sql1, &FormatterConfig::default()).expect("CAST should work");
    let formatted2 =
        format_sql_with_config(sql2, &FormatterConfig::default()).expect(":: should work");

    verify_formatting_safe(sql1, &formatted1).expect("CAST should be safe");
    verify_formatting_safe(sql2, &formatted2).expect(":: should be safe");
}
