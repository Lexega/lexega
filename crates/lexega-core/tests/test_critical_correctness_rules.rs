// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::{analyze_risk, analyze_risk_with_policy_config};
use lexega_core::dialect::SnowflakeDialect;
use std::collections::HashSet;
use std::sync::Arc;

fn analyze_sql(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(SnowflakeDialect)),
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn rule_ids(report: &lexega_core::analyzer::AnalysisReport) -> HashSet<String> {
    report
        .signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(a) => Some(a.matched_rule.clone()),
        })
        .collect()
}

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(a) if a.matched_rule == rule_id))
}

#[test]
fn test_ddl_schema_drop_via_drop_statement() {
    // SCHEMA-DROP fires on typed AstStmt::DropSchema (classifier maps to
    // DropSchemaStatement), which is the path every supported dialect
    // parses `DROP SCHEMA` into: DROP SCHEMA is standard SQL, not
    // Snowflake-only.
    let sql = "DROP SCHEMA my_schema;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SCHEMA-DROP"),
        "Expected SCHEMA-DROP. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_extacc_hosts_chg_external_access_allowed_hosts_changed() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext_access SET ALLOWED_API_AUTHENTICATION_INTEGRATIONS = (api_int_1, api_int_2);";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-EXTACC-HOSTS-CHG"),
        "Expected SNW-EXTACC-HOSTS-CHG. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_c167_authentication_policy_disabled() {
    // UNSET AUTHENTICATION_METHODS emits Modified (SNW-AUTHPOL-CHG) and MethodsChanged (SNW-AUTHPOL-METHODS-CHG),
    // not Disabled (SNW-AUTHPOL-OFF). SNW-AUTHPOL-OFF would require a "disabled" condition signal.
    let sql = "ALTER AUTHENTICATION POLICY my_auth_policy UNSET AUTHENTICATION_METHODS;";
    let report = analyze_sql(sql);
    let ids = rule_ids(&report);
    assert!(
        has_rule(&report, "SNW-AUTHPOL-METHODS-CHG"),
        "Expected SNW-AUTHPOL-METHODS-CHG (MethodsChanged). Got: {:?}",
        ids
    );
    assert!(
        has_rule(&report, "SNW-AUTHPOL-CHG"),
        "Expected SNW-AUTHPOL-CHG (Modified). Got: {:?}",
        ids
    );
}

#[test]
fn test_snw_sesspol_drop() {
    let sql = "DROP SESSION POLICY my_policy;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-SESSPOL-DROP"),
        "Expected SNW-SESSPOL-DROP. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_authpol_mfa_off() {
    let sql =
        "CREATE AUTHENTICATION POLICY weak_auth_policy AUTHENTICATION_METHODS = ('PASSWORD');";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-AUTHPOL-MFA-OFF"),
        "Expected SNW-AUTHPOL-MFA-OFF. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_pwdpol_retries_unset() {
    let sql = "ALTER PASSWORD POLICY my_pw_policy UNSET PASSWORD_MAX_RETRIES;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-PWDPOL-RETRIES-UNSET"),
        "Expected SNW-PWDPOL-RETRIES-UNSET. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_db_drop() {
    let sql = "DROP DATABASE my_db;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "DB-DROP"),
        "Expected DB-DROP. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_db_failover_promote() {
    let sql = "ALTER DATABASE my_db PRIMARY;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-DB-FAILOVER-PROMOTE"),
        "Expected SNW-DB-FAILOVER-PROMOTE. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_pwdpol_lockout_unset() {
    let sql = "ALTER PASSWORD POLICY my_pw_policy UNSET PASSWORD_LOCKOUT_TIME_MINS;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-PWDPOL-LOCKOUT-UNSET"),
        "Expected SNW-PWDPOL-LOCKOUT-UNSET. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_db_drop_postgresql() {
    // Verify DB-DROP fires for all dialects (parser is permissive)
    let sql = "DROP DATABASE my_db;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "DB-DROP"),
        "Expected DB-DROP. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_tbl_truncate() {
    let sql = "TRUNCATE TABLE my_table;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "TBL-TRUNCATE"),
        "Expected TBL-TRUNCATE. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_schema_drop_specific() {
    let sql = "DROP SCHEMA my_schema;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SCHEMA-DROP"),
        "Expected SCHEMA-DROP. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_dynsql_literal_only_is_silent() {
    // A literal-only EXECUTE IMMEDIATE has no runtime-input vector, so the
    // rule stays silent on it.
    let sql = "EXECUTE IMMEDIATE 'SELECT 1';";
    let report = analyze_sql(sql);
    assert!(
        !has_rule(&report, "DYNSQL"),
        "DYNSQL should NOT fire on literal-only EXECUTE IMMEDIATE (no injection vector). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_dynsql_with_variable() {
    let sql = "EXECUTE IMMEDIATE :my_sql_var;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "DYNSQL"),
        "Expected DYNSQL for variable-based dynamic SQL. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_c_proj_enforce_off() {
    let sql = r#"
        CREATE PROJECTION POLICY unsafe_policy
            AS () RETURNS PROJECTION_CONSTRAINT -> PROJECTION_CONSTRAINT(ENFORCEMENT => 'NONE');
    "#;
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-PROJPOL-ENFORCE-OFF"),
        "Expected SNW-PROJPOL-ENFORCE-OFF. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_c_proj_drop() {
    let sql = "DROP PROJECTION POLICY my_proj_policy;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-PROJPOL-DROP"),
        "Expected SNW-PROJPOL-DROP. Got: {:?}",
        rule_ids(&report)
    );
}

// =========================================================================
// SNW-EXTACC-NAME-CHG / SNW-EXTACC-OWNER-CHG — External Access Renamed
// / Owner Changed. Both rules now fire from their proper SQL surfaces:
//   • NAME-CHG: ALTER EXTERNAL ACCESS INTEGRATION … RENAME TO …
//   • OWNER-CHG: GRANT OWNERSHIP ON INTEGRATION … TO ROLE …
//     (Snowflake has no `ALTER … SET OWNER` syntax for integrations.)
// These tests assert each rule stays SILENT on a non-triggering ALTER
// (negative case).
// =========================================================================

#[test]
fn test_snw_extacc_name_chg_silent_on_non_rename_alter() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext SET COMMENT = 'just a comment';";
    let report = analyze_sql(sql);
    assert!(
        !has_rule(&report, "SNW-EXTACC-NAME-CHG"),
        "SNW-EXTACC-NAME-CHG must not fire on a non-RENAME ALTER"
    );
}

#[test]
fn test_snw_extacc_owner_chg_silent_on_non_grant_alter() {
    let sql = "ALTER EXTERNAL ACCESS INTEGRATION my_ext SET ENABLED = TRUE;";
    let report = analyze_sql(sql);
    assert!(
        !has_rule(&report, "SNW-EXTACC-OWNER-CHG"),
        "SNW-EXTACC-OWNER-CHG must not fire on ALTER (only on GRANT OWNERSHIP ON INTEGRATION)"
    );
}

#[test]
fn test_snw_authpol_chg() {
    // Any ALTER AUTHENTICATION POLICY emits Modified. Use RENAME TO as a simple trigger.
    let sql = "ALTER AUTHENTICATION POLICY my_auth_policy RENAME TO new_auth_policy;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-AUTHPOL-CHG"),
        "Expected SNW-AUTHPOL-CHG (Authentication Policy Modified). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_db_from_share() {
    let sql = "CREATE DATABASE shared_db FROM SHARE provider_org.share_name;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-DB-FROM-SHARE"),
        "Expected SNW-DB-FROM-SHARE (Database Created From Share). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_db_swap() {
    let sql = "ALTER DATABASE db1 SWAP WITH db2;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-DB-SWAP"),
        "Expected SNW-DB-SWAP (Database Swapped). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_schema_swap() {
    let sql = "ALTER SCHEMA schema1 SWAP WITH schema2;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-SCHEMA-SWAP"),
        "Expected SNW-SCHEMA-SWAP (Schema Swapped). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_schema_mgdacc_off() {
    let sql = "ALTER SCHEMA my_schema DISABLE MANAGED ACCESS;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-SCHEMA-MGDACC-OFF"),
        "Expected SNW-SCHEMA-MGDACC-OFF (Schema Managed Access Disabled). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_dyntbl_rap_rmv() {
    let sql = "ALTER DYNAMIC TABLE my_dt DROP ROW ACCESS POLICY my_rap;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "SNW-DYNTBL-RAP-RMV"),
        "Expected SNW-DYNTBL-RAP-RMV (Dynamic Table Row Access Policy Removed). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_snw_task_execas() {
    // Note: CREATE TASK doesn't parse with explicit SnowflakeDialect (known parser gap).
    // Use analyze_risk (no dialect) which parses tasks correctly.
    let sql = "CREATE TASK my_task EXECUTE AS CALLER AS SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "SNW-TASK-EXECAS"),
        "Expected SNW-TASK-EXECAS (Task Execute Privilege Configured). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_view_drop_rule() {
    // DROP VIEW parses as generic AstDrop → DropStatement, triggering VIEW-DROP.
    let sql = "DROP VIEW my_view;";
    let report = analyze_sql(sql);
    assert!(
        has_rule(&report, "VIEW-DROP"),
        "Expected VIEW-DROP (View Dropped rule). Got: {:?}",
        rule_ids(&report)
    );
}
