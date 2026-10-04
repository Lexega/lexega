// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL role-membership procedures (sp_addrolemember / sp_addsrvrolemember /
//! sp_droprolemember / sp_dropsrvrolemember) and sp_configure surface-area
//! options beyond xp_cmdshell. All rules predicate on the existing
//! `mssql_exec.procedure_name` + typed `mssql_exec.args` facts — no new
//! substrate. Which role names and option names are dangerous is YAML policy.

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

// ── sp_addsrvrolemember ─────────────────────────────────────────────────────

#[test]
fn add_srv_role_member_fires_high() {
    let sql = "EXEC sp_addsrvrolemember N'corp\\bob', N'diskadmin';";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SRVROLE-MEMBER-ADD", RiskLevel::High),
        "MSSQL-SRVROLE-MEMBER-ADD should fire at High. Got: {:?}",
        signals
    );
    // Non-sysadmin role: escalation rule stays silent.
    assert!(
        !fires(&signals, "MSSQL-SRVROLE-SYSADMIN"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn add_srv_role_member_sysadmin_fires_critical() {
    let sql = "EXEC sp_addsrvrolemember @loginame = N'corp\\bob', @rolename = N'sysadmin';";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SRVROLE-SYSADMIN", RiskLevel::Critical),
        "MSSQL-SRVROLE-SYSADMIN should fire at Critical. Got: {:?}",
        signals
    );
    // The High base rule fires alongside the Critical escalation rule.
    assert!(
        fires(&signals, "MSSQL-SRVROLE-MEMBER-ADD"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn add_srv_role_member_securityadmin_mixed_case_fires_critical() {
    // value_literal is lowercased at extraction; SecurityAdmin must match.
    let sql = "EXEC master.dbo.sp_addsrvrolemember N'svc_app', N'SecurityAdmin';";
    let signals = analyze(sql);
    assert!(
        fires(&signals, "MSSQL-SRVROLE-SYSADMIN"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn add_srv_role_member_variable_role_no_escalation() {
    // Role passed as a variable — no literal to match; base rule still fires.
    let sql = "EXEC sp_addsrvrolemember @login, @role;";
    let signals = analyze(sql);
    assert!(
        !fires(&signals, "MSSQL-SRVROLE-SYSADMIN"),
        "Got: {:?}",
        signals
    );
    assert!(
        fires(&signals, "MSSQL-SRVROLE-MEMBER-ADD"),
        "Got: {:?}",
        signals
    );
}

// ── sp_addrolemember ────────────────────────────────────────────────────────

#[test]
fn add_role_member_fires_medium() {
    let sql = "EXEC sp_addrolemember N'db_datareader', N'reporting_user';";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-ROLE-MEMBER-ADD", RiskLevel::Medium),
        "MSSQL-ROLE-MEMBER-ADD should fire at Medium. Got: {:?}",
        signals
    );
    assert!(
        !fires(&signals, "MSSQL-DBROLE-ADMIN-ADD"),
        "Got: {:?}",
        signals
    );
}

#[test]
fn add_role_member_db_owner_fires_high() {
    let sql = "EXEC sp_addrolemember N'db_owner', N'app_user';";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-DBROLE-ADMIN-ADD", RiskLevel::High),
        "MSSQL-DBROLE-ADMIN-ADD should fire at High. Got: {:?}",
        signals
    );
    assert!(
        fires(&signals, "MSSQL-ROLE-MEMBER-ADD"),
        "Got: {:?}",
        signals
    );
}

// ── sp_droprolemember / sp_dropsrvrolemember ────────────────────────────────

#[test]
fn drop_role_member_fires_medium() {
    let sql = "EXEC sp_droprolemember N'db_datawriter', N'app_user';";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-ROLE-MEMBER-DROP", RiskLevel::Medium),
        "MSSQL-ROLE-MEMBER-DROP should fire at Medium. Got: {:?}",
        signals
    );
}

#[test]
fn drop_srv_role_member_fires() {
    let sql = "EXEC sp_dropsrvrolemember N'corp\\bob', N'sysadmin';";
    let signals = analyze(sql);
    assert!(
        fires(&signals, "MSSQL-ROLE-MEMBER-DROP"),
        "Got: {:?}",
        signals
    );
}

// ── sp_configure surface-area options ───────────────────────────────────────

#[test]
fn spconfig_ole_automation_fires_critical() {
    let sql = "EXEC sp_configure N'Ole Automation Procedures', 1;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(
            &signals,
            "MSSQL-SPCONFIG-OLE-AUTOMATION",
            RiskLevel::Critical
        ),
        "MSSQL-SPCONFIG-OLE-AUTOMATION should fire at Critical. Got: {:?}",
        signals
    );
}

#[test]
fn spconfig_clr_enabled_fires_high() {
    let sql = "EXEC sp_configure 'clr enabled', 1;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SPCONFIG-CLR", RiskLevel::High),
        "MSSQL-SPCONFIG-CLR should fire at High. Got: {:?}",
        signals
    );
}

#[test]
fn spconfig_clr_strict_security_fires() {
    let sql = "EXEC sp_configure 'clr strict security', 0;";
    let signals = analyze(sql);
    assert!(fires(&signals, "MSSQL-SPCONFIG-CLR"), "Got: {:?}", signals);
}

#[test]
fn spconfig_adhoc_distributed_queries_fires_high() {
    let sql = "EXEC sp_configure 'Ad Hoc Distributed Queries', 1;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SPCONFIG-ADHOC-QUERIES", RiskLevel::High),
        "MSSQL-SPCONFIG-ADHOC-QUERIES should fire at High. Got: {:?}",
        signals
    );
}

#[test]
fn spconfig_xdb_chaining_fires_high() {
    let sql = "EXEC sp_configure 'cross db ownership chaining', 1;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SPCONFIG-XDB-CHAINING", RiskLevel::High),
        "MSSQL-SPCONFIG-XDB-CHAINING should fire at High. Got: {:?}",
        signals
    );
}

#[test]
fn spconfig_remote_access_fires_medium() {
    let sql = "EXEC sp_configure 'remote access', 0;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SPCONFIG-REMOTE-ACCESS", RiskLevel::Medium),
        "MSSQL-SPCONFIG-REMOTE-ACCESS should fire at Medium. Got: {:?}",
        signals
    );
}

#[test]
fn spconfig_dac_fires_medium() {
    let sql = "EXEC sp_configure 'remote admin connections', 1;";
    let signals = analyze(sql);
    assert!(
        fires_with_level(&signals, "MSSQL-SPCONFIG-DAC", RiskLevel::Medium),
        "MSSQL-SPCONFIG-DAC should fire at Medium. Got: {:?}",
        signals
    );
}

#[test]
fn spconfig_benign_option_fires_none_of_new_rules() {
    let sql = "EXEC sp_configure 'max degree of parallelism', 8;";
    let signals = analyze(sql);
    for id in [
        "MSSQL-SPCONFIG-OLE-AUTOMATION",
        "MSSQL-SPCONFIG-CLR",
        "MSSQL-SPCONFIG-ADHOC-QUERIES",
        "MSSQL-SPCONFIG-XDB-CHAINING",
        "MSSQL-SPCONFIG-REMOTE-ACCESS",
        "MSSQL-SPCONFIG-DAC",
    ] {
        assert!(
            !fires(&signals, id),
            "{id} should not fire. Got: {:?}",
            signals
        );
    }
}

// ── Negative: an ordinary proc call fires none of these ─────────────────────

#[test]
fn ordinary_proc_fires_no_role_or_spconfig_rules() {
    let sql = "EXEC dbo.refresh_reporting_cache @full = 1;";
    let signals = analyze(sql);
    for id in [
        "MSSQL-SRVROLE-MEMBER-ADD",
        "MSSQL-SRVROLE-SYSADMIN",
        "MSSQL-ROLE-MEMBER-ADD",
        "MSSQL-DBROLE-ADMIN-ADD",
        "MSSQL-ROLE-MEMBER-DROP",
    ] {
        assert!(
            !fires(&signals, id),
            "{id} should not fire. Got: {:?}",
            signals
        );
    }
}
