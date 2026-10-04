// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test fixtures for EXTERNAL ACCESS INTEGRATION statements.
//!
//! This module tests:
//! - CREATE EXTERNAL ACCESS INTEGRATION parsing and formatting
//! - ALTER EXTERNAL ACCESS INTEGRATION parsing and formatting
//! - DROP EXTERNAL ACCESS INTEGRATION parsing and formatting
//! - Risk analysis signals for External Access Integration (SNW-EXTACC-*)

use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

// =============================================================================
// Helper Functions
// =============================================================================

/// Helper to extract rule IDs from signals
fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

/// Helper to run analysis and get rule IDs
fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => extract_rule_ids(&report.signals),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

// =============================================================================
// CREATE EXTERNAL ACCESS INTEGRATION - Parsing & Formatting Tests
// =============================================================================

#[test]
fn test_create_external_access_integration_basic() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_with_secrets() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ALLOWED_AUTHENTICATION_SECRETS = (my_secret, another_secret)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_with_all_secrets() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ALLOWED_AUTHENTICATION_SECRETS = (ALL)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_with_none_secrets() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ALLOWED_AUTHENTICATION_SECRETS = (NONE)
  ENABLED = FALSE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_with_api_auth() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ALLOWED_API_AUTHENTICATION_INTEGRATIONS = (my_api_int)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_with_comment() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ENABLED = TRUE
  COMMENT = 'Production external access for API calls';"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_or_replace() {
    let sql = r#"CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_if_not_exists() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_multiple_network_rules() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (rule1, rule2, rule3)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_external_access_integration_qualified_names() {
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_db.my_schema.my_ext_access
  ALLOWED_NETWORK_RULES = (my_db.my_schema.my_network_rule)
  ENABLED = TRUE;"#;

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// =============================================================================
// ALTER EXTERNAL ACCESS INTEGRATION - Parsing & Formatting Tests
// =============================================================================

#[test]
fn test_alter_external_access_integration_set_enabled_true() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_set_enabled_false() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ENABLED = FALSE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_if_exists() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION IF EXISTS my_ext_access SET ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_set_network_rules() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ALLOWED_NETWORK_RULES = (new_rule1, new_rule2);";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_set_secrets() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ALLOWED_AUTHENTICATION_SECRETS = (secret1, secret2);";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_set_comment() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET COMMENT = 'Updated comment';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_unset_comment() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access UNSET COMMENT;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_set_tag() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET TAG cost_center = 'engineering', env = 'prod';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_alter_external_access_integration_unset_tag() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access UNSET TAG cost_center, env;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// =============================================================================
// DROP EXTERNAL ACCESS INTEGRATION - Parsing & Formatting Tests
// =============================================================================

#[test]
fn test_drop_external_access_integration_basic() {
    let sql = "DROP EXTERNAL ACCESS INTEGRATION my_ext_access;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_drop_external_access_integration_if_exists() {
    let sql = "DROP EXTERNAL ACCESS INTEGRATION IF EXISTS my_ext_access;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_drop_integration_short_form() {
    // Short form: DROP INTEGRATION (without EXTERNAL ACCESS keywords)
    let sql = "DROP INTEGRATION my_ext_access;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// =============================================================================
// RISK ANALYSIS - Signal Tests (SNW-EXTACC-*)
// =============================================================================

#[test]
fn test_snw_extacc_new_external_access_integration_created() {
    // SNW-EXTACC-NEW: External access integration created
    let sql = r#"CREATE EXTERNAL ACCESS INTEGRATION my_ext_access
  ALLOWED_NETWORK_RULES = (my_network_rule)
  ENABLED = TRUE;"#;

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-NEW"),
        "SNW-EXTACC-NEW should fire for external access integration created. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_drop_external_access_integration_dropped() {
    // SNW-EXTACC-DROP: External access integration dropped
    let sql = "DROP EXTERNAL ACCESS INTEGRATION my_ext_access;";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-DROP"),
        "SNW-EXTACC-DROP should fire for external access integration dropped. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_off_external_access_integration_disabled() {
    // SNW-EXTACC-OFF: External access integration disabled
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ENABLED = FALSE;";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-OFF"),
        "SNW-EXTACC-OFF should fire for external access integration disabled. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_on_external_access_integration_enabled() {
    // SNW-EXTACC-ON: External access integration enabled
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ENABLED = TRUE;";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-ON"),
        "SNW-EXTACC-ON should fire for external access integration enabled. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_netrules_chg_external_access_network_rules_changed() {
    // SNW-EXTACC-NETRULES-CHG: External access network rules changed
    let sql =
        "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ALLOWED_NETWORK_RULES = (new_rule);";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-NETRULES-CHG"),
        "SNW-EXTACC-NETRULES-CHG should fire for network rules changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_secrets_chg_external_access_secrets_changed() {
    // SNW-EXTACC-SECRETS-CHG: External access allowed secrets changed
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ALLOWED_AUTHENTICATION_SECRETS = (new_secret);";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-SECRETS-CHG"),
        "SNW-EXTACC-SECRETS-CHG should fire for secrets changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_secret_rmv() {
    // SNW-EXTACC-SECRET-RMV: External access secret removed (via UNSET)
    let sql =
        "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access UNSET ALLOWED_AUTHENTICATION_SECRETS;";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-SECRET-RMV"),
        "SNW-EXTACC-SECRET-RMV should fire for secret removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_netrule_rmv() {
    // SNW-EXTACC-NETRULE-RMV: Network rule removed (via UNSET)
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access UNSET ALLOWED_NETWORK_RULES;";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-NETRULE-RMV"),
        "SNW-EXTACC-NETRULE-RMV should fire for network rule removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_comment_chg() {
    // SNW-EXTACC-COMMENT-CHG: External access comment changed
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET COMMENT = 'New comment';";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-COMMENT-CHG"),
        "SNW-EXTACC-COMMENT-CHG should fire for comment changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_tag_add() {
    // SNW-EXTACC-TAG-ADD: Tag added to external access integration
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET TAG env = 'prod';";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-TAG-ADD"),
        "SNW-EXTACC-TAG-ADD should fire for tag added. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_extacc_tag_rmv() {
    // SNW-EXTACC-TAG-RMV: Tag removed from external access integration
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access UNSET TAG env;";

    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-EXTACC-TAG-RMV"),
        "SNW-EXTACC-TAG-RMV should fire for tag removed. Got: {:?}",
        rules
    );
}

// =============================================================================
// MULTI-STATEMENT TESTS
// =============================================================================

#[test]
fn test_multi_statement_external_access_integration() {
    // Test that multiple statements in one script all produce distinct signals
    let sql = r#"
        CREATE EXTERNAL ACCESS INTEGRATION ext1
          ALLOWED_NETWORK_RULES = (rule1)
          ENABLED = TRUE;
        
        ALTER EXTERNAL ACCESS INTEGRATION ext1 SET ENABLED = FALSE;
        
        DROP EXTERNAL ACCESS INTEGRATION ext2;
    "#;

    let report = analyze_risk(sql).expect("Should analyze multi-statement");

    // Should have signals for all three statements
    let rules = extract_rule_ids(&report.signals);

    assert!(
        rules.contains("SNW-EXTACC-NEW"),
        "Should fire SNW-EXTACC-NEW for CREATE"
    );
    assert!(
        rules.contains("SNW-EXTACC-OFF"),
        "Should fire SNW-EXTACC-OFF for ENABLED=FALSE"
    );
    assert!(
        rules.contains("SNW-EXTACC-DROP"),
        "Should fire SNW-EXTACC-DROP for DROP"
    );
}
