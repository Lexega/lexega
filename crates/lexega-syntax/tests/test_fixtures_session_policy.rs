// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for SESSION POLICY statements
//! Covers CREATE SESSION POLICY, ALTER SESSION POLICY, DROP SESSION POLICY

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

#[test]
fn test_create_session_policy() {
    let sql = r#"
CREATE SESSION POLICY my_policy
  SESSION_IDLE_TIMEOUT_MINS = 30
  SESSION_UI_IDLE_TIMEOUT_MINS = 15
  ALLOWED_SECONDARY_ROLES = ('ROLE1', 'ROLE2')
  BLOCKED_SECONDARY_ROLES = ('ROLE3')
  COMMENT = 'Test policy';
"#;

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "CREATE SESSION POLICY should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("CREATE SESSION POLICY should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("CREATE SESSION POLICY formatting should be safe");
}

#[test]
fn test_create_or_replace_session_policy() {
    let sql = r#"
CREATE OR REPLACE SESSION POLICY prod_policy
  SESSION_IDLE_TIMEOUT_MINS = 60
  ALLOWED_SECONDARY_ROLES = ('ALL')
  BLOCKED_SECONDARY_ROLES = ();
"#;

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "CREATE OR REPLACE SESSION POLICY should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("CREATE OR REPLACE SESSION POLICY should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("CREATE OR REPLACE SESSION POLICY formatting should be safe");
}

#[test]
fn test_create_if_not_exists_session_policy() {
    let sql = r#"
CREATE SESSION POLICY IF NOT EXISTS dev_policy
  SESSION_IDLE_TIMEOUT_MINS = 5;
"#;

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "CREATE SESSION POLICY IF NOT EXISTS should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("CREATE SESSION POLICY IF NOT EXISTS should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("CREATE SESSION POLICY IF NOT EXISTS formatting should be safe");
}

#[test]
fn test_alter_session_policy_rename() {
    let sql = "ALTER SESSION POLICY my_policy RENAME TO new_policy;";

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "ALTER SESSION POLICY RENAME should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("ALTER SESSION POLICY RENAME should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("ALTER SESSION POLICY RENAME formatting should be safe");
}

#[test]
fn test_alter_session_policy_set_properties() {
    let sql = r#"
ALTER SESSION POLICY IF EXISTS my_policy SET
  SESSION_IDLE_TIMEOUT_MINS = 45
  SESSION_UI_IDLE_TIMEOUT_MINS = 20
  ALLOWED_SECONDARY_ROLES = ('ADMIN', 'DEVELOPER')
  BLOCKED_SECONDARY_ROLES = ('GUEST')
  COMMENT = 'Updated policy';
"#;

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "ALTER SESSION POLICY SET should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("ALTER SESSION POLICY SET should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("ALTER SESSION POLICY SET formatting should be safe");
}

#[test]
fn test_alter_session_policy_set_tag() {
    let sql = "ALTER SESSION POLICY my_policy SET TAG owner = 'team', environment = 'prod';";

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "ALTER SESSION POLICY SET TAG should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("ALTER SESSION POLICY SET TAG should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("ALTER SESSION POLICY SET TAG formatting should be safe");
}

#[test]
fn test_alter_session_policy_unset_properties() {
    let sql = r#"
ALTER SESSION POLICY my_policy UNSET
  SESSION_IDLE_TIMEOUT_MINS
  SESSION_UI_IDLE_TIMEOUT_MINS
  ALLOWED_SECONDARY_ROLES
  BLOCKED_SECONDARY_ROLES
  COMMENT;
"#;

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "ALTER SESSION POLICY UNSET should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("ALTER SESSION POLICY UNSET should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("ALTER SESSION POLICY UNSET formatting should be safe");
}

#[test]
fn test_alter_session_policy_unset_tag() {
    let sql = "ALTER SESSION POLICY my_policy UNSET TAG owner, environment;";

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "ALTER SESSION POLICY UNSET TAG should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("ALTER SESSION POLICY UNSET TAG should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("ALTER SESSION POLICY UNSET TAG formatting should be safe");
}

#[test]
fn test_drop_session_policy() {
    let sql = "DROP SESSION POLICY my_policy;";

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "DROP SESSION POLICY should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("DROP SESSION POLICY should format successfully");

    verify_formatting_safe(sql, &formatted).expect("DROP SESSION POLICY formatting should be safe");
}

#[test]
fn test_drop_session_policy_if_exists() {
    let sql = "DROP SESSION POLICY IF EXISTS old_policy;";

    let parsed = parse_sql(sql);
    assert!(
        parsed.is_ok(),
        "DROP SESSION POLICY IF EXISTS should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("DROP SESSION POLICY IF EXISTS should format successfully");

    verify_formatting_safe(sql, &formatted)
        .expect("DROP SESSION POLICY IF EXISTS formatting should be safe");
}

#[test]
fn test_session_policy_comprehensive() {
    let sql = fs::read_to_string("tests/fixtures/test_session_policy_comprehensive.sql")
        .expect("failed to read test_session_policy_comprehensive.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_session_policy_comprehensive.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_session_policy_comprehensive.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_session_policy_comprehensive.sql formatting should be safe");
}
