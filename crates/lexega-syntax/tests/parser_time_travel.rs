// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::parse_stmt_from_str;

/// Test AT with TIMESTAMP parameter
#[test]
fn parse_time_travel_at_timestamp() {
    let sql = "SELECT * FROM my_table AT (TIMESTAMP => '2024-01-01 00:00:00'::TIMESTAMP);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel AT with TIMESTAMP"
    );
}

/// Test AT with OFFSET parameter
#[test]
fn parse_time_travel_at_offset() {
    let sql = "SELECT * FROM my_table AT (OFFSET => -3600);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel AT with OFFSET"
    );
}

/// Test AT with STATEMENT parameter
#[test]
fn parse_time_travel_at_statement() {
    let sql = "SELECT * FROM my_table AT (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726');";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel AT with STATEMENT"
    );
}

/// Test AT with STREAM parameter
#[test]
fn parse_time_travel_at_stream() {
    let sql = "SELECT * FROM my_table AT (STREAM => 'my_stream');";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel AT with STREAM"
    );
}

/// Test BEFORE with TIMESTAMP parameter
#[test]
fn parse_time_travel_before_timestamp() {
    let sql = "SELECT * FROM my_table BEFORE (TIMESTAMP => '2024-01-01 00:00:00'::TIMESTAMP);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel BEFORE with TIMESTAMP"
    );
}

/// Test BEFORE with OFFSET parameter
#[test]
fn parse_time_travel_before_offset() {
    let sql = "SELECT * FROM my_table BEFORE (OFFSET => -60*5);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel BEFORE with OFFSET"
    );
}

/// Test BEFORE with STATEMENT parameter
#[test]
fn parse_time_travel_before_statement() {
    let sql = "SELECT * FROM my_table BEFORE (STATEMENT => 'query-id-12345');";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel BEFORE with STATEMENT"
    );
}

/// Test BEFORE with STREAM parameter
#[test]
fn parse_time_travel_before_stream() {
    let sql = "SELECT * FROM my_table BEFORE (STREAM => 'stream_archive');";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel BEFORE with STREAM"
    );
}

/// Test time travel with table alias
#[test]
fn parse_time_travel_with_alias() {
    let sql = "SELECT * FROM my_table AS t AT (OFFSET => -60*5) WHERE t.flag = 'valid';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse time travel with alias");
}

/// Test time travel with JOIN
#[test]
fn parse_time_travel_with_join() {
    let sql =
        "SELECT * FROM t1 AT (TIMESTAMP => '2024-01-01'::TIMESTAMP) JOIN t2 ON t1.id = t2.id;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse time travel with JOIN");
}

/// Test time travel on both sides of JOIN
#[test]
fn parse_time_travel_both_sides_join() {
    let sql = "SELECT * FROM t1 AT (OFFSET => -100) JOIN t2 BEFORE (STATEMENT => 'abc') ON t1.id = t2.id;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse time travel on both sides of JOIN"
    );
}

/// Test time travel in subquery
#[test]
fn parse_time_travel_in_subquery() {
    let sql =
        "SELECT * FROM (SELECT * FROM my_table AT (TIMESTAMP => '2024-01-01'::TIMESTAMP)) AS sub;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse time travel in subquery");
}

/// Test table without time travel (should be None)
#[test]
fn parse_table_without_time_travel() {
    let sql = "SELECT * FROM my_table;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse table without time travel"
    );
}

/// Test multiple tables, one with time travel
#[test]
fn parse_multiple_tables_mixed_time_travel() {
    let sql = "SELECT * FROM t1 AT (OFFSET => -100), t2, t3 BEFORE (TIMESTAMP => '2024-01-01'::TIMESTAMP);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse multiple tables with mixed time travel"
    );
}

/// Test Snowflake documentation example 1
#[test]
fn parse_snowflake_doc_example_1() {
    let sql =
        "SELECT * FROM my_table AT(TIMESTAMP => 'Wed, 26 Jun 2024 09:20:00 -0700'::TIMESTAMP_LTZ);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse Snowflake doc example with TIMESTAMP_LTZ"
    );
}
