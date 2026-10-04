// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

#[test]
fn test_password_policy_create_basic() {
    let sql = "CREATE PASSWORD POLICY test_policy\n  PASSWORD_MIN_LENGTH = 12\n  PASSWORD_MAX_AGE_DAYS = 90\n  COMMENT = 'Test policy';";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format CREATE PASSWORD POLICY");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_password_policy_create_all_properties() {
    let sql = "CREATE PASSWORD POLICY comprehensive_policy\n  PASSWORD_MIN_LENGTH = 12\n  PASSWORD_MAX_LENGTH = 128\n  PASSWORD_MIN_UPPER_CASE_CHARS = 2\n  PASSWORD_MIN_LOWER_CASE_CHARS = 2\n  PASSWORD_MIN_NUMERIC_CHARS = 1\n  PASSWORD_MIN_SPECIAL_CHARS = 1\n  PASSWORD_MIN_AGE_DAYS = 1\n  PASSWORD_MAX_AGE_DAYS = 90\n  PASSWORD_MAX_RETRIES = 5\n  PASSWORD_LOCKOUT_TIME_MINS = 15\n  PASSWORD_HISTORY = 10\n  COMMENT = 'Comprehensive policy';";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format comprehensive policy");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_password_policy_alter_set() {
    let sql = "ALTER PASSWORD POLICY test_policy SET PASSWORD_MAX_RETRIES = 3;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format ALTER PASSWORD POLICY SET");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_password_policy_alter_unset() {
    let sql = "ALTER PASSWORD POLICY test_policy UNSET PASSWORD_MIN_LENGTH;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format ALTER PASSWORD POLICY UNSET");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_password_policy_alter_rename() {
    let sql = "ALTER PASSWORD POLICY old_policy RENAME TO new_policy;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format ALTER PASSWORD POLICY RENAME");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_password_policy_drop() {
    let sql = "DROP PASSWORD POLICY test_policy;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format DROP PASSWORD POLICY");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_password_policy_drop_if_exists() {
    let sql = "DROP PASSWORD POLICY IF EXISTS test_policy;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format DROP PASSWORD POLICY IF EXISTS");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_password_policy_multi_statement() {
    let sql = "
        CREATE PASSWORD POLICY policy1 PASSWORD_MIN_LENGTH = 10;
        CREATE PASSWORD POLICY policy2 PASSWORD_MAX_AGE_DAYS = 60;
        ALTER PASSWORD POLICY policy1 SET PASSWORD_MAX_AGE_DAYS = 90;
    ";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format multiple PASSWORD POLICY statements");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
