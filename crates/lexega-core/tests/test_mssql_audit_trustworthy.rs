// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL audit lifecycle (`CREATE/ALTER/DROP SERVER AUDIT
//! [SPECIFICATION]` / `DATABASE AUDIT SPECIFICATION`) and ALTER DATABASE
//! switch options (`TRUSTWORTHY`, `ENCRYPTION`, `DB_CHAINING`).

use lexega_core::analyzer::{AnalysisConfig, RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{dialect::mssql, parse_sql_with_dialect, AstStmt, MsSqlDialect};

fn analyze(sql: &str) -> Vec<(String, RiskLevel)> {
    let config = AnalysisConfig {
        dialect: Some(mssql()),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .entries()
        .map(|s| match s {
            RuleMatch::Analysis(g) => (g.matched_rule.clone(), g.risk_level),
        })
        .collect()
}

fn fires(findings: &[(String, RiskLevel)], rule_id: &str) -> bool {
    findings.iter().any(|(id, _)| id == rule_id)
}

fn fires_with_level(findings: &[(String, RiskLevel)], rule_id: &str, level: RiskLevel) -> bool {
    findings.iter().any(|(id, l)| id == rule_id && *l == level)
}

fn assert_not_opaque(sql: &str) {
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("parse");
    for stmt in &script.stmts {
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "statement fell to OpaqueContent: {sql}"
        );
    }
}

// ── Audit lifecycle ─────────────────────────────────────────────────────────

#[test]
fn create_server_audit_fires_info() {
    let sql = "CREATE SERVER AUDIT compliance_audit TO FILE (FILEPATH = 'D:\\audit\\');";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "INFO-MSSQL-AUDIT-NEW", RiskLevel::Info),
        "Got: {:?}",
        findings
    );
}

#[test]
fn create_database_audit_specification_fires_info() {
    let sql = "CREATE DATABASE AUDIT SPECIFICATION dml_spec FOR SERVER AUDIT compliance_audit \
               ADD (SELECT ON dbo.payroll BY public) WITH (STATE = ON);";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires(&findings, "INFO-MSSQL-AUDIT-NEW"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn alter_server_audit_state_off_fires_high() {
    let sql = "ALTER SERVER AUDIT compliance_audit WITH (STATE = OFF);";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-AUDIT-DISABLE", RiskLevel::High),
        "Got: {:?}",
        findings
    );
    assert!(fires(&findings, "MSSQL-AUDIT-CHG"), "Got: {:?}", findings);
}

#[test]
fn alter_audit_state_on_no_disable_rule() {
    let sql = "ALTER SERVER AUDIT SPECIFICATION login_spec WITH (STATE = ON);";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        !fires(&findings, "MSSQL-AUDIT-DISABLE"),
        "Got: {:?}",
        findings
    );
    assert!(fires(&findings, "MSSQL-AUDIT-CHG"), "Got: {:?}", findings);
}

#[test]
fn drop_server_audit_fires_high() {
    let sql = "DROP SERVER AUDIT compliance_audit;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-AUDIT-DROP", RiskLevel::High),
        "Got: {:?}",
        findings
    );
}

#[test]
fn drop_database_audit_specification_fires_high() {
    let sql = "DROP DATABASE AUDIT SPECIFICATION dml_spec;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(fires(&findings, "MSSQL-AUDIT-DROP"), "Got: {:?}", findings);
}

#[test]
fn plain_drop_database_not_hijacked() {
    // DROP DATABASE without AUDIT must keep routing to the database
    // parser (DB-DROP), not the audit parser.
    let sql = "DROP DATABASE old_reporting;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(!fires(&findings, "MSSQL-AUDIT-DROP"), "Got: {:?}", findings);
    assert!(fires(&findings, "DB-DROP"), "Got: {:?}", findings);
}

// ── ALTER DATABASE switch options ───────────────────────────────────────────

#[test]
fn trustworthy_on_fires_critical() {
    let sql = "ALTER DATABASE finance SET TRUSTWORTHY ON;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-DB-TRUSTWORTHY-ON", RiskLevel::Critical),
        "Got: {:?}",
        findings
    );
}

#[test]
fn trustworthy_off_silent() {
    let findings = analyze("ALTER DATABASE finance SET TRUSTWORTHY OFF;");
    assert!(
        !fires(&findings, "MSSQL-DB-TRUSTWORTHY-ON"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn db_chaining_on_fires_high() {
    let sql = "ALTER DATABASE finance SET DB_CHAINING ON;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-DB-CHAINING-ON", RiskLevel::High),
        "Got: {:?}",
        findings
    );
}

#[test]
fn encryption_off_fires_critical_on_fires_info() {
    let off = analyze("ALTER DATABASE finance SET ENCRYPTION OFF;");
    assert!(
        fires_with_level(&off, "MSSQL-DB-ENCRYPTION-OFF", RiskLevel::Critical),
        "Got: {:?}",
        off
    );
    let on = analyze("ALTER DATABASE finance SET ENCRYPTION ON;");
    assert!(fires(&on, "INFO-MSSQL-DB-ENCRYPTION-ON"), "Got: {:?}", on);
    assert!(!fires(&on, "MSSQL-DB-ENCRYPTION-OFF"), "Got: {:?}", on);
}

#[test]
fn snowflake_retention_property_unaffected() {
    // Regression guard: the KEY=value path keeps producing keys.
    let findings = analyze("ALTER DATABASE finance SET DATA_RETENTION_TIME_IN_DAYS = 0;");
    for id in [
        "MSSQL-DB-TRUSTWORTHY-ON",
        "MSSQL-DB-CHAINING-ON",
        "MSSQL-DB-ENCRYPTION-OFF",
    ] {
        assert!(
            !fires(&findings, id),
            "{id} should not fire. Got: {:?}",
            findings
        );
    }
}
