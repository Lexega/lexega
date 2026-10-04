// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test Time Travel formatting

use lexega_syntax::{format_sql, parse_stmt_from_str};

#[test]
fn test_time_travel_at_timestamp() {
    let sql = "SELECT * FROM sales AT(TIMESTAMP => '2024-01-01 00:00:00')";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("AT"));
    assert!(formatted.contains("TIMESTAMP"));
    assert!(formatted.contains("=>"));
    assert!(formatted.contains("2024-01-01"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_time_travel_before_offset() {
    let sql = "SELECT * FROM inventory BEFORE(OFFSET => -3600)";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("BEFORE"));
    assert!(formatted.contains("OFFSET"));
    assert!(formatted.contains("=>"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_time_travel_at_statement() {
    let sql = "SELECT * FROM orders AT(STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("AT"));
    assert!(formatted.contains("STATEMENT"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_sample_bernoulli_percentage() {
    let sql = "SELECT * FROM large_table SAMPLE BERNOULLI (10)";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("SAMPLE"));
    assert!(formatted.contains("BERNOULLI"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_sample_system_rows_with_seed() {
    let sql = "SELECT * FROM data SAMPLE (10 ROWS)";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    println!("Formatted:\n{}", formatted);
    assert!(formatted.contains("SAMPLE"));
    assert!(formatted.contains("ROWS"));
}

#[test]
fn test_sample_system_percentage_with_seed() {
    let sql = "SELECT * FROM data SAMPLE SYSTEM (3) SEED (82)";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    println!("Formatted:\n{}", formatted);
    assert!(formatted.contains("SAMPLE"));
    assert!(formatted.contains("SYSTEM"));
    assert!(formatted.contains("SEED"));
}

#[test]
fn test_changes_default() {
    let sql =
        "SELECT * FROM stream_data CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01')";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("CHANGES"));
    assert!(formatted.contains("INFORMATION"));
    assert!(formatted.contains("DEFAULT"));
    assert!(formatted.contains("AT"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_changes_append_only_with_end() {
    let sql = "SELECT * FROM cdc_table CHANGES(INFORMATION => APPEND_ONLY) AT(TIMESTAMP => '2024-01-01') END(TIMESTAMP => '2024-01-02')";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("CHANGES"));
    assert!(formatted.contains("APPEND_ONLY"));
    assert!(formatted.contains("AT"));
    assert!(formatted.contains("END"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_combined_time_travel_and_sample() {
    let sql = "SELECT * FROM history AT(TIMESTAMP => '2024-01-01') SAMPLE BERNOULLI (5)";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("AT"));
    assert!(formatted.contains("TIMESTAMP"));
    assert!(formatted.contains("SAMPLE"));
    assert!(formatted.contains("BERNOULLI"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_connect_by_simple() {
    let sql = "SELECT * FROM employees CONNECT BY PRIOR employee_id = manager_id";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("CONNECT"));
    assert!(formatted.contains("BY"));
    assert!(formatted.contains("PRIOR"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_connect_by_with_start_with() {
    let sql = "SELECT * FROM employees START WITH manager_id IS NULL CONNECT BY PRIOR employee_id = manager_id";
    let ast = parse_stmt_from_str(sql);
    assert!(ast.is_some(), "Parse failed");

    let formatted = format_sql(sql).expect("Format failed");
    assert!(formatted.contains("START"));
    assert!(formatted.contains("WITH"));
    assert!(formatted.contains("CONNECT"));
    assert!(formatted.contains("BY"));
    println!("Formatted:\n{}", formatted);
}

#[test]
fn test_sample_rows_variations() {
    // Test different SAMPLE ROWS formats
    let test_cases = vec![
        "SELECT * FROM t SAMPLE (10 ROWS)",
        "SELECT * FROM t SAMPLE (100 ROWS)",
        "SELECT * FROM t SAMPLE SYSTEM (50 ROWS)",
        "SELECT * FROM t SAMPLE BERNOULLI (25 ROWS)",
    ];

    for sql in test_cases {
        let ast = parse_stmt_from_str(sql);
        assert!(ast.is_some(), "Failed to parse: {}", sql);

        let formatted = format_sql(sql).expect(&format!("Failed to format: {}", sql));
        assert!(
            formatted.contains("SAMPLE"),
            "Missing SAMPLE in: {}",
            formatted
        );
        assert!(formatted.contains("ROWS"), "Missing ROWS in: {}", formatted);
        println!("Input:  {}", sql);
        println!("Output: {}\n", formatted);
    }
}
