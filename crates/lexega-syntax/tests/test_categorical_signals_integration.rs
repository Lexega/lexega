// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Governance-bearing DDL (stage encryption, network policies, …) parses and formats cleanly.

use lexega_syntax::{format_sql_with_config, FormatterConfig};

#[test]
fn test_categorical_signals_encryption() {
    let sql = "ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'NONE');";

    // Should parse and format without errors
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format with categorical signals");

    // Formatted output should be valid
    assert!(formatted.contains("ENCRYPTION"));
    assert!(formatted.contains("NONE"));
}

#[test]
fn test_categorical_signals_password_policy() {
    let sql = r#"
        CREATE PASSWORD POLICY weak_password
          PASSWORD_MIN_LENGTH = 4
          PASSWORD_MAX_AGE_DAYS = 999;
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format weak password policy");

    assert!(formatted.contains("PASSWORD POLICY"));
    assert!(formatted.contains("PASSWORD_MIN_LENGTH"));
}

#[test]
fn test_categorical_signals_masking_policy() {
    let sql = r#"
        CREATE MASKING POLICY ssn_mask AS (val STRING) RETURNS STRING ->
          CASE WHEN CURRENT_ROLE() IN ('ADMIN') THEN val ELSE '***' END
          EXEMPT_OTHER_POLICIES = TRUE;
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format masking policy");

    assert!(formatted.contains("MASKING POLICY"));
    assert!(formatted.contains("EXEMPT_OTHER_POLICIES"));
}

#[test]
fn test_categorical_signals_network_policy() {
    let sql = r#"
        CREATE NETWORK POLICY test_policy
          ALLOWED_IP_LIST = ('192.168.1.0/24');
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format network policy");

    assert!(formatted.contains("NETWORK POLICY"));
    assert!(formatted.contains("ALLOWED_IP_LIST"));
}

#[test]
fn test_categorical_signals_tag_operations() {
    let sql = "ALTER STAGE my_stage SET TAG owner = 'data_team';";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format tag operation");

    assert!(formatted.contains("SET TAG"));
}

#[test]
fn test_categorical_signals_multiple_statements() {
    let sql = r#"
        CREATE NETWORK POLICY test_policy ALLOWED_IP_LIST = ('192.168.1.0/24');
        ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'NONE');
        CREATE PASSWORD POLICY weak_password PASSWORD_MIN_LENGTH = 4;
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format multiple statements with categorical signals");

    // All statements should be present
    assert!(formatted.contains("NETWORK POLICY"));
    assert!(formatted.contains("ENCRYPTION"));
    assert!(formatted.contains("PASSWORD POLICY"));
}
