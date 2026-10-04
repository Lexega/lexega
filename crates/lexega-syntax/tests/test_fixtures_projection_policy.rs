// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

#[test]
fn test_projection_policy_create_basic() {
    let sql = fs::read_to_string("tests/fixtures/projection_policy_create_basic.sql")
        .expect("failed to read projection_policy_create_basic.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "projection_policy_create_basic.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("projection_policy_create_basic.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("projection_policy_create_basic.sql formatting should be safe");
}

#[test]
fn test_projection_policy_create_case() {
    let sql = fs::read_to_string("tests/fixtures/projection_policy_create_case.sql")
        .expect("failed to read projection_policy_create_case.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "projection_policy_create_case.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("projection_policy_create_case.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("projection_policy_create_case.sql formatting should be safe");
}

#[test]
fn test_projection_policy_alter_all() {
    let sql = fs::read_to_string("tests/fixtures/projection_policy_alter_all.sql")
        .expect("failed to read projection_policy_alter_all.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "projection_policy_alter_all.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("projection_policy_alter_all.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("projection_policy_alter_all.sql formatting should be safe");
}

#[test]
fn test_projection_policy_multi_statement() {
    let sql = fs::read_to_string("tests/fixtures/projection_policy_multi_statement.sql")
        .expect("failed to read projection_policy_multi_statement.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "projection_policy_multi_statement.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("projection_policy_multi_statement.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("projection_policy_multi_statement.sql formatting should be safe");
}
