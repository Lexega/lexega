// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Firing tests for the MSSQL principal-creation, external-model, and
//! OPENROWSET inline-credential rules.

use lexega_core::analyzer::{AnalysisConfig, RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::mssql;

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

// ── CREATE LOGIN / USER ─────────────────────────────────────────────────────

#[test]
fn create_login_with_password_fires_login_new_and_cred_leak() {
    let signals = analyze("CREATE LOGIN app_login WITH PASSWORD = 'S3cret!';");
    assert!(
        fires_with_level(&signals, "MSSQL-LOGIN-NEW", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "CRED-PWD-LEAK"), "Got: {:?}", signals);
    assert!(!fires(&signals, "MSSQL-LOGIN-EXT"), "Got: {:?}", signals);
}

#[test]
fn create_login_from_windows_fires_login_new_only() {
    let signals = analyze("CREATE LOGIN [corp\\bob] FROM WINDOWS;");
    assert!(fires(&signals, "MSSQL-LOGIN-NEW"), "Got: {:?}", signals);
    assert!(!fires(&signals, "MSSQL-LOGIN-EXT"), "Got: {:?}", signals);
    assert!(!fires(&signals, "CRED-PWD-LEAK"), "Got: {:?}", signals);
}

#[test]
fn create_login_from_external_provider_fires_ext() {
    let signals = analyze("CREATE LOGIN [app@contoso.com] FROM EXTERNAL PROVIDER;");
    assert!(
        fires_with_level(&signals, "MSSQL-LOGIN-EXT", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-LOGIN-NEW"), "Got: {:?}", signals);
}

#[test]
fn create_user_for_login_fires_user_new() {
    let signals = analyze("CREATE USER app_user FOR LOGIN app_login;");
    assert!(
        fires_with_level(&signals, "MSSQL-USER-NEW", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(!fires(&signals, "MSSQL-USER-EXT"), "Got: {:?}", signals);
}

#[test]
fn create_user_from_external_provider_fires_ext() {
    let signals = analyze("CREATE USER [analyst@contoso.com] FROM EXTERNAL PROVIDER;");
    assert!(
        fires_with_level(&signals, "MSSQL-USER-EXT", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-USER-NEW"), "Got: {:?}", signals);
}

// ── EXTERNAL MODEL ──────────────────────────────────────────────────────────

#[test]
fn create_external_model_fires_extmdl_new_and_rmt() {
    let sql = "CREATE EXTERNAL MODEL embeddings_model WITH \
               (LOCATION = 'https://contoso.openai.azure.com/openai/deployments/te3', \
                API_FORMAT = 'Azure OpenAI', MODEL_TYPE = EMBEDDINGS, MODEL = 'te3');";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-EXTMDL-NEW", RiskLevel::High),
        "Got: {:?}",
        signals
    );
    assert!(fires(&signals, "MSSQL-EXTMDL-RMT"), "Got: {:?}", signals);
}

#[test]
fn alter_external_model_fires_extmdl_chg() {
    let sql = "ALTER EXTERNAL MODEL embeddings_model SET (MODEL = 'te3-large');";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-EXTMDL-CHG", RiskLevel::Medium),
        "Got: {:?}",
        signals
    );
    assert!(!fires(&signals, "MSSQL-EXTMDL-NEW"), "Got: {:?}", signals);
}

// ── OPENROWSET inline credentials ───────────────────────────────────────────

#[test]
fn openrowset_inline_password_fires_critical() {
    let sql = "SELECT a.* FROM OPENROWSET('SQLNCLI', \
               'Server=finance-sql;UID=sa;PWD=Hunter2!', \
               'SELECT * FROM finance.dbo.payroll') AS a;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(
            &signals,
            "MSSQL-OPENROWSET-INLINE-CRED",
            RiskLevel::Critical
        ),
        "Got: {:?}",
        signals
    );
}

#[test]
fn openrowset_bulk_no_inline_cred() {
    // BULK file import carries no connection-string credentials.
    let sql = "SELECT * FROM OPENROWSET(BULK 'D:\\data\\export.csv', SINGLE_CLOB) AS t;";
    let signals = analyze(sql);
    assert!(
        !fires(&signals, "MSSQL-OPENROWSET-INLINE-CRED"),
        "Got: {:?}",
        signals
    );
}

// ── CHECK_POLICY / CHECK_EXPIRATION ─────────────────────────────────────────

#[test]
fn create_login_check_policy_off_fires_high() {
    let signals = analyze("CREATE LOGIN svc_app WITH PASSWORD = 'P@ss', CHECK_POLICY = OFF;");
    assert!(
        fires_with_level(&signals, "MSSQL-LOGIN-CHECK-POLICY-OFF", RiskLevel::High),
        "Got: {:?}",
        signals
    );
}

#[test]
fn alter_login_check_policy_off_fires() {
    let signals = analyze("ALTER LOGIN svc_app WITH CHECK_POLICY = OFF;");
    assert!(
        fires(&signals, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn check_policy_on_is_silent() {
    // The protective direction must not fire.
    let signals = analyze("CREATE LOGIN svc_app WITH PASSWORD = 'P@ss', CHECK_POLICY = ON;");
    assert!(
        !fires(&signals, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-LOGIN-CHECK-EXPIRATION-OFF"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn check_expiration_off_fires_low_not_policy() {
    // CHECK_EXPIRATION must not alias CHECK_POLICY.
    let signals = analyze("ALTER LOGIN svc_app WITH CHECK_EXPIRATION = OFF;");
    assert!(
        fires_with_level(&signals, "MSSQL-LOGIN-CHECK-EXPIRATION-OFF", RiskLevel::Low),
        "Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn both_policy_options_off_fire_both() {
    let signals = analyze(
        "CREATE LOGIN svc_app WITH PASSWORD = 'P@ss', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;",
    );
    assert!(
        fires(&signals, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        signals
    );
    assert!(
        fires(&signals, "MSSQL-LOGIN-CHECK-EXPIRATION-OFF"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn login_without_policy_options_is_silent() {
    let signals = analyze("CREATE LOGIN svc_app WITH PASSWORD = 'P@ss';");
    assert!(
        !fires(&signals, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-LOGIN-CHECK-EXPIRATION-OFF"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn check_policy_off_after_other_options_still_fires() {
    // The option is read wherever it appears in the WITH list.
    let signals =
        analyze("ALTER LOGIN svc_app WITH PASSWORD = 'N3w!' MUST_CHANGE, CHECK_POLICY = OFF;");
    assert!(
        fires(&signals, "MSSQL-LOGIN-CHECK-POLICY-OFF"),
        "Got: {:?}",
        signals
    );
}
