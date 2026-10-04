// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for semi-structured data access patterns in Snowflake
//! Covers nested object/array access with colon notation and casting

use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_simple_object_access() {
    let sql = r#"SELECT data:"field1" FROM table1"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_nested_object_access() {
    let sql = r#"SELECT data:"level1":"level2":"level3" FROM table1"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_array_access() {
    let sql = r#"SELECT data:"items"[0] FROM table1"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_complex_mixed_access_with_cast() {
    let sql =
        r#"SELECT data:"metadata":"items"[0]:"properties":"color"::STRING AS color FROM table1"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_very_long_chain() {
    let sql = r#"SELECT payload:"customer":"profile":"address":"shipping":"street_line_1"::STRING AS street FROM events"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_multiple_long_chains_in_projection() {
    let sql = r#"SELECT id, payload:"metadata":"source":"campaign":"id"::NUMBER AS campaign_id, payload:"metadata":"source":"campaign":"name"::STRING AS campaign_name, payload:"user":"profile":"demographics":"age"::NUMBER AS age FROM events"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_semi_structured_in_where_clause() {
    let sql = r#"SELECT * FROM events WHERE payload:"status"::STRING = 'ACTIVE' AND payload:"metadata":"priority"::NUMBER > 5"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_semi_structured_with_functions() {
    let sql = r#"SELECT COALESCE(data:"field1"::STRING, 'default') AS value FROM table1"#;
    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}
