// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL audit lifecycle (`CREATE/ALTER/DROP SERVER AUDIT
//! [SPECIFICATION]` / `DATABASE AUDIT SPECIFICATION`) and ALTER DATABASE
//! switch options (`TRUSTWORTHY`, `ENCRYPTION`, `DB_CHAINING`).

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
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "INFO-MSSQL-AUDIT-NEW", RiskLevel::Info),
        "Got: {:?}",
        signals
    );
}

#[test]
fn create_database_audit_specification_fires_info() {
    let sql = "CREATE DATABASE AUDIT SPECIFICATION dml_spec FOR SERVER AUDIT compliance_audit \
               ADD (SELECT ON dbo.payroll BY public) WITH (STATE = ON);";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires(&signals, "INFO-MSSQL-AUDIT-NEW"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_server_audit_state_off_fires_high() {
    let sql = "ALTER SERVER AUDIT compliance_audit WITH (STATE = OFF);";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-AUDIT-DISABLE", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-AUDIT-CHG"), "Got: {:?}", signals);
}

#[test]
fn alter_audit_state_on_no_disable_rule() {
    let sql = "ALTER SERVER AUDIT SPECIFICATION login_spec WITH (STATE = ON);";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        !fires(&signals, "MSSQL-AUDIT-DISABLE"),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-AUDIT-CHG"), "Got: {:?}", signals);
}

#[test]
fn drop_server_audit_fires_high() {
    let sql = "DROP SERVER AUDIT compliance_audit;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-AUDIT-DROP", RiskLevel::High),
        "Got: {:?}",
        signals
    );
}

#[test]
fn drop_database_audit_specification_fires_high() {
    let sql = "DROP DATABASE AUDIT SPECIFICATION dml_spec;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-AUDIT-DROP"), "Got: {:?}", signals);
}

#[test]
fn plain_drop_database_not_hijacked() {
    // DROP DATABASE without AUDIT must keep routing to the database
    // parser (DB-DROP), not the audit parser.
    let sql = "DROP DATABASE old_reporting;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(!fires(&signals, "MSSQL-AUDIT-DROP"), "Got: {:?}", signals);
    assert!(fires(&signals, "DB-DROP"), "Got: {:?}", signals);
}

// ── ALTER DATABASE switch options ───────────────────────────────────────────

#[test]
fn trustworthy_on_fires_critical() {
    let sql = "ALTER DATABASE finance SET TRUSTWORTHY ON;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-DB-TRUSTWORTHY-ON", RiskLevel::Critical),
        "Got: {:?}",
        signals
    );
}

#[test]
fn trustworthy_off_silent() {
    let signals = analyze("ALTER DATABASE finance SET TRUSTWORTHY OFF;");
    assert!(
        !fires(&signals, "MSSQL-DB-TRUSTWORTHY-ON"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn db_chaining_on_fires_high() {
    let sql = "ALTER DATABASE finance SET DB_CHAINING ON;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-DB-CHAINING-ON", RiskLevel::High),
        "Got: {:?}",
        signals
    );
}

#[test]
fn encryption_off_fires_high_on_fires_info() {
    let off = analyze("ALTER DATABASE finance SET ENCRYPTION OFF;");
    assert!(
        fires_with_level(&off, "MSSQL-DB-ENCRYPTION-OFF", RiskLevel::High),
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
    let signals = analyze("ALTER DATABASE finance SET DATA_RETENTION_TIME_IN_DAYS = 0;");
    for id in [
        "MSSQL-DB-TRUSTWORTHY-ON",
        "MSSQL-DB-CHAINING-ON",
        "MSSQL-DB-ENCRYPTION-OFF",
    ] {
        assert!(
            !fires(&signals, id),
            "{id} should not fire. Got: {:?}",
            signals
        );
    }
}
