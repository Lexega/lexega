// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for AUTHENTICATION POLICY parsing and semantic extraction.
//!
//! These tests verify:
//! - CREATE AUTHENTICATION POLICY parsing
//! - ALTER AUTHENTICATION POLICY parsing
//! - DROP AUTHENTICATION POLICY parsing
//! - Semantic extraction and signal generation

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, FormatterConfig};

/// Helper to check if a signal with given rule ID is present
fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| {
        let RuleMatch::Analysis(ref p) = s;
        p.matched_rule == rule_id
    })
}

// ============================================================================
// CREATE AUTHENTICATION POLICY Tests
// ============================================================================

#[test]
fn test_create_authentication_policy_basic() {
    let sql = r#"
        CREATE AUTHENTICATION POLICY my_auth_policy
            AUTHENTICATION_METHODS = ('PASSWORD', 'KEYPAIR')
            MFA_ENROLLMENT = REQUIRED;
    "#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    // Basic verification: formatting should preserve content
    assert!(formatted.contains("CREATE"));
    assert!(formatted.contains("AUTHENTICATION"));
    assert!(formatted.contains("POLICY"));
    assert!(formatted.contains("my_auth_policy"));
}

#[test]
fn test_create_authentication_policy_with_all_options() {
    // Per Snowflake docs:
    // - MFA_ENROLLMENT is a simple value: 'REQUIRED' | 'REQUIRED_PASSWORD_ONLY' | 'OPTIONAL'
    // - MFA_POLICY, PAT_POLICY, WORKLOAD_IDENTITY_POLICY need parentheses with nested properties
    let sql = r#"
        CREATE OR REPLACE AUTHENTICATION POLICY IF NOT EXISTS prod_auth_policy
            AUTHENTICATION_METHODS = ('PASSWORD', 'SAML', 'OAUTH')
            CLIENT_TYPES = ('SNOWFLAKE_UI', 'DRIVERS')
            MFA_ENROLLMENT = 'REQUIRED'
            MFA_POLICY = (ALLOWED_METHODS = ('TOTP', 'PASSKEY'))
            PAT_POLICY = (DEFAULT_EXPIRY_IN_DAYS = 30 MAX_EXPIRY_IN_DAYS = 365)
            WORKLOAD_IDENTITY_POLICY = (ALLOWED_PROVIDERS = (AWS, AZURE))
            SECURITY_INTEGRATIONS = ('azure_ad_integration')
            COMMENT = 'Production authentication policy';
    "#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    assert!(formatted.contains("OR REPLACE"));
    assert!(formatted.contains("IF NOT EXISTS"));
    assert!(formatted.contains("AUTHENTICATION_METHODS"));
    assert!(formatted.contains("MFA_ENROLLMENT"));
}

#[test]
fn test_create_authentication_policy_risk_signals() {
    let sql = r#"
        CREATE AUTHENTICATION POLICY weak_auth_policy
            AUTHENTICATION_METHODS = ('PASSWORD');
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should generate "created" signal (SNW-AUTHPOL-NEW)
    assert!(
        has_signal(&report, "SNW-AUTHPOL-NEW"),
        "Should generate SNW-AUTHPOL-NEW signal for policy creation"
    );
}

// ============================================================================
// ALTER AUTHENTICATION POLICY Tests
// ============================================================================

#[test]
fn test_alter_authentication_policy_set() {
    let sql = r#"
        ALTER AUTHENTICATION POLICY my_auth_policy
            SET MFA_ENROLLMENT = REQUIRED;
    "#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    assert!(formatted.contains("ALTER"));
    assert!(formatted.contains("AUTHENTICATION"));
    assert!(formatted.contains("POLICY"));
    assert!(formatted.contains("SET"));
}

#[test]
fn test_alter_authentication_policy_unset() {
    let sql = r#"
        ALTER AUTHENTICATION POLICY IF EXISTS my_auth_policy
            UNSET MFA_ENROLLMENT;
    "#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    assert!(formatted.contains("ALTER"));
    assert!(formatted.contains("IF EXISTS"));
    assert!(formatted.contains("UNSET"));
}

#[test]
fn test_alter_authentication_policy_rename() {
    let sql = r#"
        ALTER AUTHENTICATION POLICY my_auth_policy
            RENAME TO new_auth_policy;
    "#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    assert!(formatted.contains("RENAME TO"));
    assert!(formatted.contains("new_auth_policy"));
}

#[test]
fn test_alter_authentication_policy_mfa_changed_signal() {
    let sql = r#"
        ALTER AUTHENTICATION POLICY my_auth_policy
            SET MFA_ENROLLMENT = OPTIONAL;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should generate "mfa_changed" signal (SNW-AUTHPOL-MFA-CHG)
    assert!(
        has_signal(&report, "SNW-AUTHPOL-MFA-CHG"),
        "Should generate SNW-AUTHPOL-MFA-CHG signal for MFA change"
    );
}

#[test]
fn test_alter_authentication_policy_methods_changed_signal() {
    let sql = r#"
        ALTER AUTHENTICATION POLICY my_auth_policy
            SET AUTHENTICATION_METHODS = ('PASSWORD');
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should generate "methods_changed" signal (SNW-AUTHPOL-METHODS-CHG)
    assert!(
        has_signal(&report, "SNW-AUTHPOL-METHODS-CHG"),
        "Should generate SNW-AUTHPOL-METHODS-CHG signal for authentication methods change"
    );
}

#[test]
fn test_alter_authentication_policy_security_integrations_changed_signal() {
    let sql = r#"
        ALTER AUTHENTICATION POLICY my_auth_policy
            SET SECURITY_INTEGRATIONS = ('new_sso_integration');
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should generate "security_integrations_changed" signal (SNW-AUTHPOL-SECINTG-CHG)
    assert!(
        has_signal(&report, "SNW-AUTHPOL-SECINTG-CHG"),
        "Should generate SNW-AUTHPOL-SECINTG-CHG signal for security integrations change"
    );
}

// ============================================================================
// DROP AUTHENTICATION POLICY Tests
// ============================================================================

#[test]
fn test_drop_authentication_policy_basic() {
    let sql = "DROP AUTHENTICATION POLICY my_auth_policy;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    assert!(formatted.contains("DROP"));
    assert!(formatted.contains("AUTHENTICATION"));
    assert!(formatted.contains("POLICY"));
}

#[test]
fn test_drop_authentication_policy_if_exists() {
    let sql = "DROP AUTHENTICATION POLICY IF EXISTS my_auth_policy;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    assert!(formatted.contains("IF EXISTS"));
}

#[test]
fn test_drop_authentication_policy_risk_signal() {
    let sql = "DROP AUTHENTICATION POLICY my_auth_policy;";

    let report = analyze_risk(sql).expect("should analyze");

    // Should generate "dropped" signal (SNW-AUTHPOL-DROP)
    assert!(
        has_signal(&report, "SNW-AUTHPOL-DROP"),
        "Should generate SNW-AUTHPOL-DROP signal for policy drop"
    );
}

// ============================================================================
// Multi-Statement Tests
// ============================================================================

#[test]
fn test_multiple_authentication_policy_statements() {
    let sql = r#"
        CREATE AUTHENTICATION POLICY policy1 AUTHENTICATION_METHODS = ('PASSWORD');
        ALTER AUTHENTICATION POLICY policy2 SET MFA_ENROLLMENT = 'REQUIRED';
        DROP AUTHENTICATION POLICY IF EXISTS policy3;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should analyze all 3 statements
    let stmt_count = report.summary.statements_analyzed;
    assert!(
        stmt_count >= 3,
        "Should analyze at least 3 statements, got {}",
        stmt_count
    );
}

// ============================================================================
// Comprehensive Snowflake Documentation Syntax Tests
// ============================================================================

/// Test all documented CREATE AUTHENTICATION POLICY syntax variants
#[test]
fn test_create_authentication_policy_comprehensive_syntax() {
    // Per Snowflake docs: https://docs.snowflake.com/en/sql-reference/sql/create-authentication-policy
    let sql = r#"
        CREATE AUTHENTICATION POLICY comprehensive_policy
            AUTHENTICATION_METHODS = ('PASSWORD', 'SAML', 'OAUTH', 'KEYPAIR', 'PROGRAMMATIC_ACCESS_TOKEN', 'WORKLOAD_IDENTITY')
            CLIENT_TYPES = ('SNOWFLAKE_UI', 'DRIVERS', 'SNOWFLAKE_CLI', 'SNOWSQL')
            CLIENT_POLICY = (
                GO_DRIVER = (MINIMUM_VERSION = '1.14.1'),
                JDBC_DRIVER = (MINIMUM_VERSION = '3.25.0')
            )
            SECURITY_INTEGRATIONS = ('my_saml_integration')
            MFA_ENROLLMENT = 'REQUIRED'
            MFA_POLICY = (
                ALLOWED_METHODS = ('TOTP', 'PASSKEY', 'OTP', 'DUO')
                ENFORCE_MFA_ON_EXTERNAL_AUTHENTICATION = 'NONE'
            )
            PAT_POLICY = (
                DEFAULT_EXPIRY_IN_DAYS = 30
                MAX_EXPIRY_IN_DAYS = 365
                NETWORK_POLICY_EVALUATION = ENFORCED_REQUIRED
                REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS = TRUE
            )
            WORKLOAD_IDENTITY_POLICY = (
                ALLOWED_PROVIDERS = (AWS, AZURE, GCP, OIDC)
                ALLOWED_AWS_ACCOUNTS = ('123456789012')
                ALLOWED_AZURE_ISSUERS = ('https://login.microsoftonline.com/8c7832f5-de56-4d9f-ba94-3b2c361abe6b/v2.0')
                ALLOWED_OIDC_ISSUERS = ('https://my.custom.oidc.issuer/')
            )
            COMMENT = 'Comprehensive authentication policy';
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse comprehensive syntax");

    assert!(formatted.contains("AUTHENTICATION_METHODS"));
    assert!(formatted.contains("CLIENT_TYPES"));
    assert!(formatted.contains("CLIENT_POLICY"));
    assert!(formatted.contains("SECURITY_INTEGRATIONS"));
    assert!(formatted.contains("MFA_ENROLLMENT"));
    assert!(formatted.contains("MFA_POLICY"));
    assert!(formatted.contains("PAT_POLICY"));
    assert!(formatted.contains("WORKLOAD_IDENTITY_POLICY"));
    assert!(formatted.contains("COMMENT"));
}

/// Test CREATE OR ALTER variant (preview feature)
#[test]
fn test_create_or_alter_authentication_policy() {
    let sql = r#"
        CREATE OR ALTER AUTHENTICATION POLICY my_policy
            AUTHENTICATION_METHODS = ('PASSWORD')
            MFA_ENROLLMENT = 'OPTIONAL';
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse CREATE OR ALTER variant");

    assert!(formatted.contains("CREATE OR ALTER"));
    assert!(formatted.contains("AUTHENTICATION POLICY"));
}

/// Test SECURITY_INTEGRATIONS with ALL value
#[test]
fn test_security_integrations_all() {
    let sql = r#"
        CREATE AUTHENTICATION POLICY test_policy
            AUTHENTICATION_METHODS = ('SAML')
            SECURITY_INTEGRATIONS = ALL;
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse SECURITY_INTEGRATIONS = ALL");

    assert!(formatted.contains("SECURITY_INTEGRATIONS"));
}

/// Test MFA_ENROLLMENT values: REQUIRED, REQUIRED_PASSWORD_ONLY, OPTIONAL
#[test]
fn test_mfa_enrollment_values() {
    let sql1 = "CREATE AUTHENTICATION POLICY p1 MFA_ENROLLMENT = 'REQUIRED';";
    let sql2 = "CREATE AUTHENTICATION POLICY p2 MFA_ENROLLMENT = 'REQUIRED_PASSWORD_ONLY';";
    let sql3 = "CREATE AUTHENTICATION POLICY p3 MFA_ENROLLMENT = 'OPTIONAL';";

    format_sql_with_config(sql1, &FormatterConfig::default())
        .expect("should parse MFA_ENROLLMENT = 'REQUIRED'");
    format_sql_with_config(sql2, &FormatterConfig::default())
        .expect("should parse MFA_ENROLLMENT = 'REQUIRED_PASSWORD_ONLY'");
    format_sql_with_config(sql3, &FormatterConfig::default())
        .expect("should parse MFA_ENROLLMENT = 'OPTIONAL'");
}

/// Test CLIENT_POLICY with multiple driver versions
#[test]
fn test_client_policy_multiple_drivers() {
    let sql = r#"
        CREATE AUTHENTICATION POLICY driver_policy
            CLIENT_TYPES = ('DRIVERS')
            CLIENT_POLICY = (
                JDBC_DRIVER = (MINIMUM_VERSION = '3.25.0'),
                ODBC_DRIVER = (MINIMUM_VERSION = '2.25.0'),
                PYTHON_DRIVER = (MINIMUM_VERSION = '3.0.0'),
                GO_DRIVER = (MINIMUM_VERSION = '1.14.1')
            );
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse CLIENT_POLICY with multiple drivers");

    assert!(formatted.contains("CLIENT_POLICY"));
    assert!(formatted.contains("JDBC_DRIVER"));
}
