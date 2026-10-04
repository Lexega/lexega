// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL security-object lifecycle: MASTER KEY / SYMMETRIC KEY /
//! ASYMMETRIC KEY / CERTIFICATE / [DATABASE SCOPED] CREDENTIAL.

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

#[test]
fn create_master_key_with_password_fires_info_and_cred_leak() {
    let sql = "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'S3cret!Pass';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires(&signals, "INFO-MSSQL-CRYPTO-NEW"),
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
fn create_symmetric_key_fires_info() {
    let sql = "CREATE SYMMETRIC KEY ssn_key WITH ALGORITHM = AES_256 \
               ENCRYPTION BY CERTIFICATE ssn_cert;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires(&signals, "INFO-MSSQL-CRYPTO-NEW"),
        "Got: {:?}",
        signals
    );
    // Certificate-protected key: no literal secret in SQL text.
    assert!(!fires(&signals, "CRED-PWD-LEAK"), "Got: {:?}", signals);
}

#[test]
fn create_certificate_fires_info() {
    let sql = "CREATE CERTIFICATE signing_cert WITH SUBJECT = 'module signing';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires(&signals, "INFO-MSSQL-CRYPTO-NEW"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn drop_certificate_fires_high() {
    let sql = "DROP CERTIFICATE signing_cert;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-CRYPTO-DROP", RiskLevel::High),
        "Got: {:?}",
        signals
    );
}

#[test]
fn drop_master_key_fires_high() {
    let sql = "DROP MASTER KEY;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-CRYPTO-DROP"), "Got: {:?}", signals);
}

#[test]
fn alter_master_key_regenerate_fires_chg() {
    let sql = "ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = 'N3w!Passw0rd';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-CRYPTO-CHG", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "CRED-PWD-LEAK"), "Got: {:?}", signals);
}

#[test]
fn create_database_scoped_credential_with_secret_fires_cred_rules() {
    let sql =
        "CREATE DATABASE SCOPED CREDENTIAL blob_cred WITH IDENTITY = 'SHARED ACCESS SIGNATURE', \
               SECRET = 'sv=2024-01-01&sig=abc123';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-CRED-NEW", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "CRED-PWD-LEAK"), "Got: {:?}", signals);
}

#[test]
fn create_server_credential_fires_cred_new() {
    let sql = "CREATE CREDENTIAL agent_proxy WITH IDENTITY = 'corp\\svc_agent', SECRET = 'pw!1';";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-CRED-NEW"), "Got: {:?}", signals);
}

#[test]
fn drop_credential_fires_medium() {
    let sql = "DROP CREDENTIAL agent_proxy;";
    assert_not_opaque(sql);
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-CRED-DROP", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
    assert!(!fires(&signals, "MSSQL-CRYPTO-DROP"), "Got: {:?}", signals);
}

#[test]
fn alter_database_not_hijacked_by_scoped_lookahead() {
    // Plain ALTER DATABASE must keep routing to the database parser.
    let sql = "ALTER DATABASE finance SET TRUSTWORTHY ON;";
    let signals = analyze(sql);
    assert!(!fires(&signals, "MSSQL-CRYPTO-CHG"), "Got: {:?}", signals);
    assert!(
        fires(&signals, "MSSQL-DB-TRUSTWORTHY-ON"),
        "Got: {:?}",
        signals
    );
}
