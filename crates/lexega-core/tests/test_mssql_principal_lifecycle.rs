// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL principal-lifecycle statements on the dialect-neutral principal
//! substrate: `ALTER [SERVER] ROLE ... ADD/DROP MEMBER`, `ALTER LOGIN`
//! (enable/disable/password), `DROP LOGIN`, `CREATE [SERVER|APPLICATION]
//! ROLE`, and `ALTER AUTHORIZATION` ownership transfer on the privilege
//! substrate. Typed-statement counterparts of the proc-based rules in
//! `test_mssql_role_member_spconfig_rules.rs`.

use lexega_core::analyzer::{AnalysisConfig, RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{dialect::mssql, parse_sql_with_dialect, AstStmt, MsSqlDialect};

fn analyze(sql: &str) -> Vec<(String, RiskLevel)> {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(mssql());
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .signals
        .iter()
        .map(|s| match s {
            RuleMatch::Analysis(g) => (g.matched_rule.clone(), g.risk_level),
        })
        .collect()
}

fn fires(signals: &[(String, RiskLevel)], rule_id: &str) -> bool {
    signals.iter().any(|(id, _)| id == rule_id)
}

fn fires_with_level(signals: &[(String, RiskLevel)], rule_id: &str, level: RiskLevel) -> bool {
    signals.iter().any(|(id, l)| id == rule_id && *l == level)
}

/// Statement must parse typed — an OpaqueContent fallback means the
/// dispatcher or parser regressed.
fn assert_not_opaque(sql: &str) {
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("parse");
    for stmt in &script.stmts {
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "statement fell to OpaqueContent: {sql}"
        );
    }
}

// ── ALTER SERVER ROLE ... ADD MEMBER ────────────────────────────────────────

#[test]
fn alter_server_role_add_member_fires_high() {
    let sql = "ALTER SERVER ROLE diskadmin ADD MEMBER [corp\\bob];";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SRVROLE-MEMBER-ADD", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-SRVROLE-SYSADMIN"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_server_role_sysadmin_add_member_fires_critical() {
    let sql = "ALTER SERVER ROLE sysadmin ADD MEMBER svc_app;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SRVROLE-SYSADMIN", RiskLevel::Critical),
        "Got: {:?}",
        signals
    );
    assert!(
        fires(&signals, "MSSQL-SRVROLE-MEMBER-ADD"),
        "Got: {:?}",
        signals
    );
}

// ── ALTER ROLE ... ADD/DROP MEMBER ──────────────────────────────────────────

#[test]
fn alter_role_add_member_fires_medium() {
    let sql = "ALTER ROLE db_datareader ADD MEMBER reporting_user;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-ROLE-MEMBER-ADD", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-DBROLE-ADMIN-ADD"),
        "Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-SRVROLE-MEMBER-ADD"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_role_db_owner_add_member_fires_high() {
    let sql = "ALTER ROLE db_owner ADD MEMBER app_user;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-DBROLE-ADMIN-ADD", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(
        fires(&signals, "MSSQL-ROLE-MEMBER-ADD"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_role_drop_member_fires_medium() {
    let sql = "ALTER ROLE db_datawriter DROP MEMBER app_user;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-ROLE-MEMBER-DROP", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-ROLE-MEMBER-ADD"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_role_without_membership_clause_silent() {
    // Snowflake-style ALTER ROLE with an options body — no membership
    // clause, so none of the membership rules fire.
    let signals = analyze("ALTER ROLE analyst SET COMMENT = 'team role';");
    for id in [
        "MSSQL-ROLE-MEMBER-ADD",
        "MSSQL-ROLE-MEMBER-DROP",
        "MSSQL-DBROLE-ADMIN-ADD",
        "MSSQL-SRVROLE-MEMBER-ADD",
    ] {
        assert!(
            !fires(&signals, id),
            "{id} should not fire. Got: {:?}",
            signals
        );
    }
}

// ── ALTER AUTHORIZATION ─────────────────────────────────────────────────────

#[test]
fn alter_authorization_on_object_fires_high() {
    let sql = "ALTER AUTHORIZATION ON OBJECT::dbo.payroll TO etl_admin;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-OWNER-XFER", RiskLevel::High),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_authorization_on_database_fires() {
    let sql = "ALTER AUTHORIZATION ON DATABASE::finance TO [corp\\dba];";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-OWNER-XFER"), "Got: {:?}", signals);
}

#[test]
fn alter_authorization_implicit_class_to_schema_owner_fires() {
    let sql = "ALTER AUTHORIZATION ON dbo.orders TO SCHEMA OWNER;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-OWNER-XFER"), "Got: {:?}", signals);
}

// ── ALTER LOGIN / DROP LOGIN ────────────────────────────────────────────────

#[test]
fn alter_login_disable_fires() {
    let sql = "ALTER LOGIN sa DISABLE;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-LOGIN-DISABLE", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-LOGIN-CHG"), "Got: {:?}", signals);
    assert!(!fires(&signals, "MSSQL-LOGIN-ENABLE"), "Got: {:?}", signals);
}

#[test]
fn alter_login_enable_fires() {
    let sql = "ALTER LOGIN [legacy_svc] ENABLE;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-LOGIN-ENABLE"), "Got: {:?}", signals);
    assert!(
        !fires(&signals, "MSSQL-LOGIN-DISABLE"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_login_password_literal_fires_pwd_chg_and_cred_leak() {
    let sql = "ALTER LOGIN app_login WITH PASSWORD = 'Sup3rS3cret!';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-LOGIN-PWD-CHG", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(
        fires_with_level(&signals, "CRED-PWD-LEAK", RiskLevel::Critical),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_login_default_db_fires_only_catchall() {
    let sql = "ALTER LOGIN app_login WITH DEFAULT_DATABASE = reporting;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-LOGIN-CHG"), "Got: {:?}", signals);
    for id in [
        "MSSQL-LOGIN-DISABLE",
        "MSSQL-LOGIN-ENABLE",
        "MSSQL-LOGIN-PWD-CHG",
    ] {
        assert!(
            !fires(&signals, id),
            "{id} should not fire. Got: {:?}",
            signals
        );
    }
}

#[test]
fn drop_login_fires_medium() {
    let sql = "DROP LOGIN old_contractor;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-LOGIN-DROP", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
}

// ── CREATE SERVER ROLE / APPLICATION ROLE ───────────────────────────────────

#[test]
fn create_server_role_parses_typed() {
    assert_not_opaque("CREATE SERVER ROLE auditors;");
}

#[test]
fn create_application_role_fires_approle_and_cred_leak() {
    let sql = "CREATE APPLICATION ROLE weekly_receipts WITH PASSWORD = '987Gbv8$76sPYY5m23';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-APPROLE-NEW", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "CRED-PWD-LEAK"), "Got: {:?}", signals);
}

#[test]
fn drop_server_role_parses_typed() {
    assert_not_opaque("DROP SERVER ROLE auditors;");
}

// ── Databricks CREATE SERVER must keep routing to the connection parser ────

#[test]
fn databricks_create_server_not_hijacked() {
    // Regression guard: the SERVER ROLE dispatcher branch must not
    // swallow Unity Catalog CREATE SERVER.
    let script = lexega_core::parse_sql_with_dialect(
        "CREATE SERVER my_pg OPTIONS (host 'h', port '5432');",
        &lexega_core::DatabricksDialect,
    )
    .expect("parse");
    assert!(
        !script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::CreatePrincipal(_))),
        "CREATE SERVER must not parse as a principal statement"
    );
}

// ── EXECUTE AS / REVERT ─────────────────────────────────────────────────────

#[test]
fn execute_as_login_fires_high() {
    let sql = "EXECUTE AS LOGIN = 'corp\\admin';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-EXECAS-LOGIN", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(!fires(&signals, "MSSQL-EXECAS-USER"), "Got: {:?}", signals);
}

#[test]
fn execute_as_user_fires_medium() {
    let sql = "EXEC AS USER = 'report_reader';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-EXECAS-USER", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
}

#[test]
fn execute_as_with_no_revert_fires_high() {
    let sql = "EXECUTE AS USER = 'app' WITH NO REVERT;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-EXECAS-NO-REVERT", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-EXECAS-USER"), "Got: {:?}", signals);
}

#[test]
fn execute_as_with_cookie_no_norevert_rule() {
    let sql = "EXECUTE AS LOGIN = 'svc' WITH COOKIE INTO @c;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        !fires(&signals, "MSSQL-EXECAS-NO-REVERT"),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-EXECAS-LOGIN"), "Got: {:?}", signals);
}

#[test]
fn revert_parses_typed_and_fires_nothing() {
    let sql = "REVERT;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    for id in [
        "MSSQL-EXECAS-LOGIN",
        "MSSQL-EXECAS-USER",
        "MSSQL-EXECAS-NO-REVERT",
    ] {
        assert!(
            !fires(&signals, id),
            "{id} should not fire. Got: {:?}",
            signals
        );
    }
}

#[test]
fn revert_with_cookie_parses_typed() {
    assert_not_opaque("REVERT WITH COOKIE = @c;");
}

#[test]
fn exec_proc_not_misparsed_as_execute_as() {
    // EXEC of an ordinary proc must keep routing to the procedure-call
    // form (INFO-MSSQL-EXEC-PROC), not the impersonation statement.
    let sql = "EXEC dbo.refresh_cache;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(!fires(&signals, "MSSQL-EXECAS-USER"), "Got: {:?}", signals);
    assert!(!fires(&signals, "MSSQL-EXECAS-LOGIN"), "Got: {:?}", signals);
}
