// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Firing tests for the MSSQL principal-creation, external-model, and
//! OPENROWSET inline-credential rules.

use lexega_core::analyzer::{AnalysisConfig, RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::mssql;

fn analyze(sql: &str) -> Vec<(String, RiskLevel)> {
    let config = AnalysisConfig {
        dialect: Some(mssql()),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .findings
        .iter()
        .map(|s| match s {
            RuleMatch::Analysis(g) => (g.matched_rule.clone(), g.risk_level),
        })
        .collect()
}

fn analyze_context(sql: &str) -> Vec<(String, RiskLevel)> {
    let config = AnalysisConfig {
        dialect: Some(mssql()),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .context
        .iter()
        .map(|s| match s {
            RuleMatch::Analysis(g) => (g.matched_rule.clone(), g.risk_level),
        })
        .collect()
}

/// Findings and context together.
fn analyze_entries(sql: &str) -> Vec<(String, RiskLevel)> {
    let mut entries = analyze(sql);
    entries.extend(analyze_context(sql));
    entries
}

fn fires(findings: &[(String, RiskLevel)], rule_id: &str) -> bool {
    findings.iter().any(|(id, _)| id == rule_id)
}

fn fires_with_level(findings: &[(String, RiskLevel)], rule_id: &str, level: RiskLevel) -> bool {
    findings.iter().any(|(id, l)| id == rule_id && *l == level)
}

// ── CREATE LOGIN / USER ─────────────────────────────────────────────────────

#[test]
fn create_login_with_password_fires_login_new_and_cred_leak() {
    let sql = "CREATE LOGIN app_login WITH PASSWORD = 'S3cret!';";
    let context = analyze_context(sql);
    assert!(
        fires_with_level(&context, "MSSQL-LOGIN-NEW", RiskLevel::Info),
        "Got: {:?}",
        context
    );
    let findings = analyze_entries(sql);
    assert!(fires(&findings, "CRED-PWD-LEAK"), "Got: {:?}", findings);
    assert!(!fires(&findings, "MSSQL-LOGIN-EXT"), "Got: {:?}", findings);
}

#[test]
fn create_login_from_windows_fires_login_new_only() {
    let sql = "CREATE LOGIN [corp\\bob] FROM WINDOWS;";
    let context = analyze_context(sql);
    assert!(fires(&context, "MSSQL-LOGIN-NEW"), "Got: {:?}", context);
    let findings = analyze_entries(sql);
    assert!(!fires(&findings, "MSSQL-LOGIN-EXT"), "Got: {:?}", findings);
    assert!(!fires(&findings, "CRED-PWD-LEAK"), "Got: {:?}", findings);
}

#[test]
fn create_login_from_external_provider_fires_ext() {
    let findings = analyze_context("CREATE LOGIN [app@contoso.com] FROM EXTERNAL PROVIDER;");
    assert!(
        fires_with_level(&findings, "MSSQL-LOGIN-EXT", RiskLevel::Info),
        "Got: {:?}",
        findings
    );
    assert!(fires(&findings, "MSSQL-LOGIN-NEW"), "Got: {:?}", findings);
}

#[test]
fn create_user_for_login_fires_user_new() {
    let sql = "CREATE USER app_user FOR LOGIN app_login;";
    let context = analyze_context(sql);
    assert!(
        fires_with_level(&context, "MSSQL-USER-NEW", RiskLevel::Info),
        "Got: {:?}",
        context
    );
    let findings = analyze_entries(sql);
    assert!(!fires(&findings, "MSSQL-USER-EXT"), "Got: {:?}", findings);
}

#[test]
fn create_user_from_external_provider_fires_ext() {
    let findings = analyze_context("CREATE USER [analyst@contoso.com] FROM EXTERNAL PROVIDER;");
    assert!(
        fires_with_level(&findings, "MSSQL-USER-EXT", RiskLevel::Info),
        "Got: {:?}",
        findings
    );
    assert!(fires(&findings, "MSSQL-USER-NEW"), "Got: {:?}", findings);
}

// ── EXTERNAL MODEL ──────────────────────────────────────────────────────────

#[test]
fn create_external_model_fires_extmdl_new_once() {
    let sql = "CREATE EXTERNAL MODEL embeddings_model WITH \
               (LOCATION = 'https://contoso.openai.azure.com/openai/deployments/te3', \
                API_FORMAT = 'Azure OpenAI', MODEL_TYPE = EMBEDDINGS, MODEL = 'te3');";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-EXTMDL-NEW", RiskLevel::Medium),
        "Got: {:?}",
        findings
    );
    assert_eq!(
        findings
            .iter()
            .filter(|(id, _)| id == "MSSQL-EXTMDL-NEW")
            .count(),
        1,
        "Got: {:?}",
        findings
    );
}

#[test]
fn alter_external_model_fires_extmdl_chg() {
    let sql = "ALTER EXTERNAL MODEL embeddings_model SET (MODEL = 'te3-large');";
    let findings = analyze_entries(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-EXTMDL-CHG", RiskLevel::Medium),
        "Got: {:?}",
        findings
    );
    assert!(!fires(&findings, "MSSQL-EXTMDL-NEW"), "Got: {:?}", findings);
}

// ── OPENROWSET inline credentials ───────────────────────────────────────────

#[test]
fn openrowset_inline_password_fires_critical() {
    let sql = "SELECT a.* FROM OPENROWSET('SQLNCLI', \
               'Server=finance-sql;UID=sa;PWD=Hunter2!', \
               'SELECT * FROM finance.dbo.payroll') AS a;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(
            &findings,
            "MSSQL-OPENROWSET-INLINE-CRED",
            RiskLevel::Critical
        ),
        "Got: {:?}",
        findings
    );
}

#[test]
fn openrowset_bulk_no_inline_cred() {
    // BULK file import carries no connection-string credentials.
    let sql = "SELECT * FROM OPENROWSET(BULK 'D:\\data\\export.csv', SINGLE_CLOB) AS t;";
    let findings = analyze(sql);
    assert!(
        !fires(&findings, "MSSQL-OPENROWSET-INLINE-CRED"),
        "Got: {:?}",
        findings
    );
}

// ── CHECK_POLICY / CHECK_EXPIRATION ─────────────────────────────────────────

#[test]
fn create_login_check_policy_off_fires_high() {
    let findings = analyze("CREATE LOGIN svc_app WITH PASSWORD = 'P@ss', CHECK_POLICY = OFF;");
    assert!(
        fires_with_level(&findings, "MSSQL-LOGIN-CHECK-POLICY-OFF", RiskLevel::High),
        "Got: {:?}",
        findings
    );
}

#[test]
fn alter_login_check_policy_off_fires() {
    let findings = analyze("ALTER LOGIN svc_app WITH CHECK_POLICY = OFF;");
    assert!(
        fires(&findings, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn check_policy_on_is_silent() {
    // The protective direction must not fire.
    let findings = analyze("CREATE LOGIN svc_app WITH PASSWORD = 'P@ss', CHECK_POLICY = ON;");
    assert!(
        !fires(&findings, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        findings
    );
    assert!(
        !fires(&findings, "MSSQL-LOGIN-CHECK-EXPIRATION-OFF"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn check_expiration_off_fires_low_not_policy() {
    // CHECK_EXPIRATION must not alias CHECK_POLICY.
    let findings = analyze("ALTER LOGIN svc_app WITH CHECK_EXPIRATION = OFF;");
    assert!(
        fires_with_level(
            &findings,
            "MSSQL-LOGIN-CHECK-EXPIRATION-OFF",
            RiskLevel::Low
        ),
        "Got: {:?}",
        findings
    );
    assert!(
        !fires(&findings, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn both_policy_options_off_fire_both() {
    let findings = analyze(
        "CREATE LOGIN svc_app WITH PASSWORD = 'P@ss', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;",
    );
    assert!(
        fires(&findings, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        findings
    );
    assert!(
        fires(&findings, "MSSQL-LOGIN-CHECK-EXPIRATION-OFF"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn login_without_policy_options_is_silent() {
    let findings = analyze("CREATE LOGIN svc_app WITH PASSWORD = 'P@ss';");
    assert!(
        !fires(&findings, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        findings
    );
    assert!(
        !fires(&findings, "MSSQL-LOGIN-CHECK-EXPIRATION-OFF"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn check_policy_off_after_other_options_still_fires() {
    // The option is read wherever it appears in the WITH list.
    let findings =
        analyze("ALTER LOGIN svc_app WITH PASSWORD = 'N3w!' MUST_CHANGE, CHECK_POLICY = OFF;");
    assert!(
        fires(&findings, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        findings
    );
}
