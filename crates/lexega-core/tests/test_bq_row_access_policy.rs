// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for BigQuery-style ROW ACCESS POLICY statements
//!
//! BigQuery syntax:
//!   CREATE [OR REPLACE] ROW ACCESS POLICY [IF NOT EXISTS] name ON table
//!     [GRANT TO (grantees)] FILTER USING (expr)
//!   DROP ROW ACCESS POLICY [IF EXISTS] name ON table
//!   DROP ALL ROW ACCESS POLICIES ON table

use lexega_core::analyzer::{RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

// =============================================================================
// CREATE ROW ACCESS POLICY (BigQuery) - PARSING AND FORMATTING
// =============================================================================

#[test]
fn test_bq_create_row_access_policy_minimal() {
    let sql = "CREATE ROW ACCESS POLICY my_filter ON my_dataset.my_table FILTER USING (session_user() = owner);";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery CREATE ROW ACCESS POLICY");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery CREATE ROW ACCESS POLICY should preserve semantics");
}

#[test]
fn test_bq_create_row_access_policy_with_grant_to() {
    let sql = "CREATE ROW ACCESS POLICY my_filter ON my_dataset.my_table GRANT TO ('user@example.com', 'group:analysts@example.com') FILTER USING (country = 'US');";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery CREATE ROW ACCESS POLICY with GRANT TO");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery CREATE ROW ACCESS POLICY with GRANT TO should preserve semantics");
}

#[test]
fn test_bq_create_row_access_policy_or_replace() {
    let sql = "CREATE OR REPLACE ROW ACCESS POLICY region_filter ON sales.transactions FILTER USING (region = 'EU');";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery CREATE OR REPLACE ROW ACCESS POLICY");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery CREATE OR REPLACE ROW ACCESS POLICY should preserve semantics");
}

#[test]
fn test_bq_create_row_access_policy_if_not_exists() {
    let sql =
        "CREATE ROW ACCESS POLICY IF NOT EXISTS new_filter ON dataset.table FILTER USING (TRUE);";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery CREATE ROW ACCESS POLICY IF NOT EXISTS");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery CREATE ROW ACCESS POLICY IF NOT EXISTS should preserve semantics");
}

#[test]
fn test_bq_create_row_access_policy_or_replace_if_not_exists() {
    let sql = "CREATE OR REPLACE ROW ACCESS POLICY IF NOT EXISTS filter ON tbl GRANT TO ('allAuthenticatedUsers') FILTER USING (dept = 'sales');";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery CREATE OR REPLACE ... IF NOT EXISTS");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery OR REPLACE IF NOT EXISTS should preserve semantics");
}

#[test]
fn test_bq_create_row_access_policy_complex_filter() {
    let sql = "CREATE ROW ACCESS POLICY access_ctrl ON analytics.events FILTER USING (region IN ('US', 'EU') AND user_role = 'admin');";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery policy with complex filter expression");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery policy with complex filter should preserve semantics");
}

#[test]
fn test_bq_create_row_access_policy_multiple_grantees() {
    let sql = "CREATE ROW ACCESS POLICY multi_grant ON dataset.table GRANT TO ('user1@example.com', 'user2@example.com', 'group:admins@example.com') FILTER USING (TRUE);";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery policy with multiple grantees");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery policy with multiple grantees should preserve semantics");
}

// =============================================================================
// DROP ROW ACCESS POLICY ON table (BigQuery) - PARSING AND FORMATTING
// =============================================================================

#[test]
fn test_bq_drop_row_access_policy_on_table() {
    let sql = "DROP ROW ACCESS POLICY my_filter ON my_dataset.my_table;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery DROP ROW ACCESS POLICY ON table");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery DROP ROW ACCESS POLICY ON table should preserve semantics");
}

#[test]
fn test_bq_drop_row_access_policy_if_exists_on_table() {
    let sql = "DROP ROW ACCESS POLICY IF EXISTS my_filter ON my_dataset.my_table;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery DROP ROW ACCESS POLICY IF EXISTS ON table");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery DROP ROW ACCESS POLICY IF EXISTS ON table should preserve semantics");
}

#[test]
fn test_bq_drop_row_access_policy_simple_names() {
    let sql = "DROP ROW ACCESS POLICY policy_name ON table_name;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery DROP with simple names");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery DROP with simple names should preserve semantics");
}

// =============================================================================
// DROP ALL ROW ACCESS POLICIES ON table (BigQuery) - PARSING AND FORMATTING
// =============================================================================

#[test]
fn test_bq_drop_all_row_access_policies() {
    let sql = "DROP ALL ROW ACCESS POLICIES ON my_dataset.my_table;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery DROP ALL ROW ACCESS POLICIES");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery DROP ALL ROW ACCESS POLICIES should preserve semantics");
}

#[test]
fn test_bq_drop_all_row_access_policies_simple_name() {
    let sql = "DROP ALL ROW ACCESS POLICIES ON my_table;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery DROP ALL on simple table");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery DROP ALL on simple table should preserve semantics");
}

#[test]
fn test_bq_drop_all_row_access_policies_qualified() {
    let sql = "DROP ALL ROW ACCESS POLICIES ON project.dataset.table;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse BigQuery DROP ALL on fully qualified table");

    verify_formatting_safe(sql, &formatted)
        .expect("BigQuery DROP ALL on fully qualified table should preserve semantics");
}

// =============================================================================
// RISK ANALYSIS - BigQuery CREATE
// =============================================================================

#[test]
fn test_bq_create_row_access_policy_risk() {
    let sql = "CREATE ROW ACCESS POLICY my_filter ON my_dataset.my_table FILTER USING (session_user() = owner);";

    let report = analyze_risk(sql).expect("should analyze BigQuery CREATE ROW ACCESS POLICY");

    // CREATE ROW ACCESS POLICY should generate info-level positive signal
    assert!(
        report.summary.total_reported_signals > 0,
        "BigQuery CREATE ROW ACCESS POLICY should generate signals (got {})",
        report.summary.total_reported_signals
    );
}

#[test]
fn test_bq_create_row_access_policy_true_filter_is_critical() {
    let sql = "CREATE ROW ACCESS POLICY p ON t FILTER USING (TRUE);";

    let report = analyze_risk(sql)
        .expect("should analyze BigQuery CREATE ROW ACCESS POLICY with TRUE filter");

    assert!(
        report.summary.critical_count >= 1,
        "FILTER USING (TRUE) should be critical because policy is effectively no-op"
    );

    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "RAP-ALLOW-ALL"
        }),
        "Should find RAP-ALLOW-ALL for no-op allow-all row access policy"
    );
}

#[test]
fn test_bq_create_row_access_policy_1eq1_filter_is_critical() {
    let sql = "CREATE ROW ACCESS POLICY p ON t FILTER USING (1 = 1);";

    let report = analyze_risk(sql)
        .expect("should analyze BigQuery CREATE ROW ACCESS POLICY with 1=1 filter");

    assert!(
        report.summary.critical_count >= 1,
        "FILTER USING (1=1) should be critical because policy is effectively no-op"
    );

    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "RAP-ALLOW-ALL"
        }),
        "Should find RAP-ALLOW-ALL for 1=1 allow-all row access policy"
    );
}

// =============================================================================
// RISK ANALYSIS - BigQuery DROP
// =============================================================================

#[test]
fn test_bq_drop_row_access_policy_risk() {
    let sql = "DROP ROW ACCESS POLICY my_filter ON my_dataset.my_table;";

    let report = analyze_risk(sql).expect("should analyze BigQuery DROP ROW ACCESS POLICY");

    // Dropping a policy is critical
    assert!(
        report.summary.critical_count >= 1,
        "BigQuery DROP ROW ACCESS POLICY should be critical"
    );

    // Should find RAP-DROP violation
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "RAP-DROP"
        }),
        "Should find RAP-DROP (row access policy dropped) for BigQuery DROP"
    );
}

#[test]
fn test_bq_drop_all_row_access_policies_risk() {
    let sql = "DROP ALL ROW ACCESS POLICIES ON my_dataset.my_table;";

    let report = analyze_risk(sql).expect("should analyze BigQuery DROP ALL ROW ACCESS POLICIES");

    // Dropping all policies is critical
    assert!(
        report.summary.critical_count >= 1,
        "BigQuery DROP ALL ROW ACCESS POLICIES should be critical"
    );
}

// =============================================================================
// MULTI-STATEMENT TESTS
// =============================================================================

#[test]
fn test_bq_multi_statement_row_access_policies() {
    let sql = r#"
        CREATE ROW ACCESS POLICY filter1 ON dataset.table1 FILTER USING (region = 'US');
        CREATE ROW ACCESS POLICY filter2 ON dataset.table2 GRANT TO ('admin@corp.com') FILTER USING (dept = 'eng');
        DROP ROW ACCESS POLICY filter1 ON dataset.table1;
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse multiple BigQuery ROW ACCESS POLICY statements");

    verify_formatting_safe(sql, &formatted)
        .expect("multiple BigQuery ROW ACCESS POLICY statements should preserve semantics");
}

#[test]
fn test_bq_multi_statement_risk_analysis() {
    let sql = r#"
        DROP ROW ACCESS POLICY filter1 ON dataset.table1;
        DROP ALL ROW ACCESS POLICIES ON dataset.table2;
        CREATE ROW ACCESS POLICY filter3 ON dataset.table3 FILTER USING (TRUE);
    "#;

    let report = analyze_risk(sql).expect("should analyze multiple BigQuery policy statements");

    // Should have at least 2 critical signals (DROP + DROP ALL)
    let total_critical_evidence: usize = report
        .signals
        .iter()
        .filter(|f| matches!(f.risk_level(), RiskLevel::Critical))
        .map(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_critical_evidence >= 2,
        "Should have at least 2 critical evidence entries (DROP + DROP ALL), got {}",
        total_critical_evidence
    );
}

// =============================================================================
// MIXED DIALECT TESTS - Snowflake and BigQuery in same script
// =============================================================================

#[test]
fn test_mixed_sf_bq_row_access_policies() {
    let sql = r#"
        CREATE ROW ACCESS POLICY sf_policy AS (uid INT) RETURNS BOOLEAN -> uid = CURRENT_USER();
        CREATE ROW ACCESS POLICY bq_policy ON dataset.table FILTER USING (region = 'US');
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse mixed Snowflake/BigQuery ROW ACCESS POLICY statements");

    verify_formatting_safe(sql, &formatted)
        .expect("mixed dialect ROW ACCESS POLICY statements should preserve semantics");
}

// =============================================================================
// SNOWFLAKE BACKWARD COMPATIBILITY - Ensure original syntax still works
// =============================================================================

#[test]
fn test_sf_create_still_works_after_bq_changes() {
    let sql = "CREATE ROW ACCESS POLICY p AS (uid INT) RETURNS BOOLEAN -> uid = 1;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Snowflake CREATE ROW ACCESS POLICY should still work");

    verify_formatting_safe(sql, &formatted)
        .expect("Snowflake syntax should be backward compatible");
}

#[test]
fn test_sf_drop_still_works_after_bq_changes() {
    let sql = "DROP ROW ACCESS POLICY my_policy;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Snowflake DROP ROW ACCESS POLICY should still work");

    verify_formatting_safe(sql, &formatted)
        .expect("Snowflake DROP syntax should be backward compatible");
}

#[test]
fn test_sf_drop_if_exists_still_works() {
    let sql = "DROP ROW ACCESS POLICY IF EXISTS my_policy;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Snowflake DROP ROW ACCESS POLICY IF EXISTS should still work");

    verify_formatting_safe(sql, &formatted)
        .expect("Snowflake IF EXISTS syntax should be backward compatible");
}
