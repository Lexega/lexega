// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL OPENDATASOURCE inline-credential detection. `OPENDATASOURCE`
//! is T-SQL ad-hoc remote access; its connection string carries inline
//! credentials in the same shapes as `OPENROWSET`. The recognition
//! reuses the remote-source call collector (generalized over the
//! function name), so this file also guards that OPENROWSET still fires.

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
        .filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some((g.matched_rule.clone(), g.risk_level)),
        })
        .collect()
}

fn fires(signals: &[(String, RiskLevel)], rule_id: &str) -> bool {
    signals.iter().any(|(id, _)| id == rule_id)
}

fn fires_with_level(signals: &[(String, RiskLevel)], rule_id: &str, level: RiskLevel) -> bool {
    signals.iter().any(|(id, l)| id == rule_id && *l == level)
}

#[test]
fn opendatasource_inline_password_fires_critical() {
    let sql = "SELECT * FROM OPENDATASOURCE('SQLNCLI', \
               'Data Source=h;User ID=u;Password=p').db.dbo.t;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(
            &signals,
            "MSSQL-OPENDATASOURCE-INLINE-CRED",
            RiskLevel::Critical
        ),
        "MSSQL-OPENDATASOURCE-INLINE-CRED should fire at Critical. Got: {:?}",
        signals
    );
}

#[test]
fn opendatasource_pwd_shorthand_fires() {
    let sql = "SELECT * FROM OPENDATASOURCE('SQLNCLI', \
               'Server=h;UID=sa;PWD=secret').db.dbo.t;";
    let signals = analyze(sql);
    assert!(
        fires(&signals, "MSSQL-OPENDATASOURCE-INLINE-CRED"),
        "PWD= shorthand should fire. Got: {:?}",
        signals
    );
}

#[test]
fn opendatasource_integrated_security_no_finding() {
    // No embedded credential — integrated security. Must stay silent.
    let sql = "SELECT * FROM OPENDATASOURCE('SQLNCLI', \
               'Data Source=h;Integrated Security=SSPI').db.dbo.t;";
    let signals = analyze(sql);
    assert!(
        !fires(&signals, "MSSQL-OPENDATASOURCE-INLINE-CRED"),
        "OPENDATASOURCE without inline creds must not fire. Got: {:?}",
        signals
    );
}

#[test]
fn openrowset_still_fires_after_collector_refactor() {
    // Regression guard: the remote-source collector was generalized over
    // the function name; OPENROWSET inline-cred must still fire.
    let sql = "SELECT * FROM OPENROWSET('SQLNCLI', \
               'Server=h;UID=sa;PWD=secret', 'SELECT 1') AS r;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(
            &signals,
            "MSSQL-OPENROWSET-INLINE-CRED",
            RiskLevel::Critical
        ),
        "MSSQL-OPENROWSET-INLINE-CRED should still fire. Got: {:?}",
        signals
    );
}
