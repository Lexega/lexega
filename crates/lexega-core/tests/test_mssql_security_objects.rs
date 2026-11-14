// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL security-object lifecycle: MASTER KEY / SYMMETRIC KEY /
//! ASYMMETRIC KEY / CERTIFICATE / [DATABASE SCOPED] CREDENTIAL.

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

#[test]
fn create_master_key_with_password_fires_info_and_cred_leak() {
    let sql = "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'S3cret!Pass';";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires(&findings, "INFO-MSSQL-CRYPTO-NEW"),
        "Got: {:?}",
        findings
    );
    assert!(
        fires_with_level(&findings, "CRED-PWD-LEAK", RiskLevel::Critical),
        "Got: {:?}",
        findings
    );
}

#[test]
fn create_symmetric_key_fires_info() {
    let sql = "CREATE SYMMETRIC KEY ssn_key WITH ALGORITHM = AES_256 \
               ENCRYPTION BY CERTIFICATE ssn_cert;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires(&findings, "INFO-MSSQL-CRYPTO-NEW"),
        "Got: {:?}",
        findings
    );
    // Certificate-protected key: no literal secret in SQL text.
    assert!(!fires(&findings, "CRED-PWD-LEAK"), "Got: {:?}", findings);
}

#[test]
fn create_certificate_fires_info() {
    let sql = "CREATE CERTIFICATE signing_cert WITH SUBJECT = 'module signing';";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires(&findings, "INFO-MSSQL-CRYPTO-NEW"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn drop_certificate_fires_high() {
    let sql = "DROP CERTIFICATE signing_cert;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-CRYPTO-DROP", RiskLevel::High),
        "Got: {:?}",
        findings
    );
}

#[test]
fn drop_master_key_fires_high() {
    let sql = "DROP MASTER KEY;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(fires(&findings, "MSSQL-CRYPTO-DROP"), "Got: {:?}", findings);
}

#[test]
fn alter_master_key_regenerate_fires_chg() {
    let sql = "ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = 'N3w!Passw0rd';";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-CRYPTO-CHG", RiskLevel::Medium),
        "Got: {:?}",
        findings
    );
    assert!(fires(&findings, "CRED-PWD-LEAK"), "Got: {:?}", findings);
}

#[test]
fn create_database_scoped_credential_with_secret_fires_cred_rules() {
    let sql =
        "CREATE DATABASE SCOPED CREDENTIAL blob_cred WITH IDENTITY = 'SHARED ACCESS SIGNATURE', \
               SECRET = 'sv=2024-01-01&sig=abc123';";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-CRED-NEW", RiskLevel::Medium),
        "Got: {:?}",
        findings
    );
    assert!(fires(&findings, "CRED-PWD-LEAK"), "Got: {:?}", findings);
}

#[test]
fn create_server_credential_fires_cred_new() {
    let sql = "CREATE CREDENTIAL agent_proxy WITH IDENTITY = 'corp\\svc_agent', SECRET = 'pw!1';";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(fires(&findings, "MSSQL-CRED-NEW"), "Got: {:?}", findings);
}

#[test]
fn drop_credential_fires_medium() {
    let sql = "DROP CREDENTIAL agent_proxy;";
    assert_not_opaque(sql);
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-CRED-DROP", RiskLevel::Medium),
        "Got: {:?}",
        findings
    );
    assert!(
        !fires(&findings, "MSSQL-CRYPTO-DROP"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn drop_database_encryption_key_is_not_drop_database() {
    for sql in [
        "DROP DATABASE ENCRYPTION KEY;",
        "drop database encryption key",
        "USE finance;\nGO\nDROP DATABASE ENCRYPTION KEY;",
    ] {
        assert_not_opaque(sql);
        let findings = analyze(sql);
        assert!(!fires(&findings, "DB-DROP"), "{sql}: {findings:?}");
        assert!(
            fires_with_level(&findings, "MSSQL-DEK-DROP", RiskLevel::High),
            "{sql}: {findings:?}"
        );
        assert!(
            !fires(&findings, "MSSQL-CRYPTO-DROP"),
            "{sql}: {findings:?}"
        );
    }
}

#[test]
fn drop_database_by_name_still_drops_the_database() {
    let findings = analyze("DROP DATABASE finance;");
    assert!(fires(&findings, "DB-DROP"), "Got: {findings:?}");
    assert!(!fires(&findings, "MSSQL-DEK-DROP"), "Got: {findings:?}");
}

#[test]
fn alter_database_not_hijacked_by_scoped_lookahead() {
    // Plain ALTER DATABASE must keep routing to the database parser.
    let sql = "ALTER DATABASE finance SET TRUSTWORTHY ON;";
    let findings = analyze(sql);
    assert!(!fires(&findings, "MSSQL-CRYPTO-CHG"), "Got: {:?}", findings);
    assert!(
        fires(&findings, "MSSQL-DB-TRUSTWORTHY-ON"),
        "Got: {:?}",
        findings
    );
}
