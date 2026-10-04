// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::fs;

#[test]
fn test_alter_row_access_policy_fixtures() {
    let sql = fs::read_to_string("tests/fixtures/alter_row_access_policy.sql")
        .expect("failed to read fixture file");

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("should parse and format ALTER ROW ACCESS POLICY statements");

    verify_formatting_safe(&sql, &formatted).expect("formatting should preserve semantics");
}

#[test]
fn test_alter_row_access_policy_rename() {
    let sql = "ALTER ROW ACCESS POLICY policy1 RENAME TO policy1_v2;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse RENAME");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_row_access_policy_set_body() {
    let sql = "ALTER ROW ACCESS POLICY p SET BODY -> user_id = 1;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse SET BODY");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_row_access_policy_set_tag() {
    let sql = "ALTER ROW ACCESS POLICY p SET TAG owner = 'team';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse SET TAG");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_row_access_policy_unset_tag() {
    let sql = "ALTER ROW ACCESS POLICY p UNSET TAG old_tag;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse UNSET TAG");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_row_access_policy_set_comment() {
    let sql = "ALTER ROW ACCESS POLICY p SET COMMENT = 'Updated policy';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse SET COMMENT");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_row_access_policy_if_exists() {
    let sql = "ALTER ROW ACCESS POLICY IF EXISTS p RENAME TO p2;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse IF EXISTS");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
