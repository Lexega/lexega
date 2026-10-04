// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test ALTER STAGE governance integration

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::fs;

#[test]
fn test_alter_stage_encryption_disabled() {
    let sql = "ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'NONE');";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_stage_encryption_enabled() {
    let sql = "ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'AWS_SSE_KMS' KMS_KEY_ID = 'my-key');";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_stage_tag_operations() {
    let sql = r#"
ALTER STAGE my_stage SET TAG cost_center = 'engineering', environment = 'prod';
ALTER STAGE my_stage UNSET TAG cost_center;
    "#
    .trim();

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_stage_credentials() {
    let sql =
        "ALTER STAGE my_stage SET CREDENTIALS = (AWS_KEY_ID = 'key' AWS_SECRET_KEY = 'secret');";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_stage_directory() {
    let sql = "ALTER STAGE my_stage SET DIRECTORY = (ENABLE = TRUE);";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_stage_comprehensive() {
    let sql = fs::read_to_string("tests/fixtures/alter_stage_comprehensive.sql")
        .expect("failed to read alter_stage_comprehensive.sql");

    let formatted =
        format_sql_with_config(&sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(&sql, &formatted).expect("should preserve semantics");
}
