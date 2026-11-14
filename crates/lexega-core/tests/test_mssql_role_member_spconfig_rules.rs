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

/// Findings, then context entries.
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

// ── sp_addsrvrolemember ─────────────────────────────────────────────────────

#[test]
fn add_srv_role_member_fires_high() {
    let sql = "EXEC sp_addsrvrolemember N'corp\\bob', N'diskadmin';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-SRVROLE-MEMBER-ADD", RiskLevel::High),
        "MSSQL-SRVROLE-MEMBER-ADD should fire at High. Got: {:?}",
        findings
    );
    // Non-sysadmin role: escalation rule stays silent.
    assert!(
        !fires(&findings, "MSSQL-SRVROLE-SYSADMIN"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn add_srv_role_member_sysadmin_fires_critical() {
    let sql = "EXEC sp_addsrvrolemember @loginame = N'corp\\bob', @rolename = N'sysadmin';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-SRVROLE-SYSADMIN", RiskLevel::Critical),
        "MSSQL-SRVROLE-SYSADMIN should fire at Critical. Got: {:?}",
        findings
    );
    // The High base rule fires alongside the Critical escalation rule.
    assert!(
        fires(&findings, "MSSQL-SRVROLE-MEMBER-ADD"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn add_srv_role_member_securityadmin_mixed_case_fires_critical() {
    // value_literal is lowercased at extraction; SecurityAdmin must match.
    let sql = "EXEC master.dbo.sp_addsrvrolemember N'svc_app', N'SecurityAdmin';";
    let findings = analyze(sql);
    assert!(
        fires(&findings, "MSSQL-SRVROLE-SYSADMIN"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn add_srv_role_member_variable_role_no_escalation() {
    // Role passed as a variable — no literal to match; base rule still fires.
    let sql = "EXEC sp_addsrvrolemember @login, @role;";
    let findings = analyze(sql);
    assert!(
        !fires(&findings, "MSSQL-SRVROLE-SYSADMIN"),
        "Got: {:?}",
        findings
    );
    assert!(
        fires(&findings, "MSSQL-SRVROLE-MEMBER-ADD"),
        "Got: {:?}",
        findings
    );
}

// ── sp_addrolemember ────────────────────────────────────────────────────────

#[test]
fn add_role_member_fires_info() {
    let sql = "EXEC sp_addrolemember N'db_datareader', N'reporting_user';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-ROLE-MEMBER-ADD", RiskLevel::Info),
        "MSSQL-ROLE-MEMBER-ADD should fire at Info. Got: {:?}",
        findings
    );
    assert!(
        !fires(&findings, "MSSQL-DBROLE-ADMIN-ADD"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn add_role_member_db_owner_fires_high() {
    let sql = "EXEC sp_addrolemember N'db_owner', N'app_user';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-DBROLE-ADMIN-ADD", RiskLevel::High),
        "MSSQL-DBROLE-ADMIN-ADD should fire at High. Got: {:?}",
        findings
    );
    assert!(
        fires_with_level(&findings, "MSSQL-ROLE-MEMBER-ADD", RiskLevel::Info),
        "Got: {:?}",
        findings
    );
}

// ── sp_droprolemember / sp_dropsrvrolemember ────────────────────────────────

#[test]
fn drop_role_member_fires_low() {
    let sql = "EXEC sp_droprolemember N'db_datawriter', N'app_user';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-ROLE-MEMBER-DROP", RiskLevel::Low),
        "MSSQL-ROLE-MEMBER-DROP should fire at Low. Got: {:?}",
        findings
    );
}

#[test]
fn drop_srv_role_member_fires() {
    let sql = "EXEC sp_dropsrvrolemember N'corp\\bob', N'sysadmin';";
    let findings = analyze(sql);
    assert!(
        fires(&findings, "MSSQL-ROLE-MEMBER-DROP"),
        "Got: {:?}",
        findings
    );
}

// ── sp_configure surface-area options ───────────────────────────────────────

#[test]
fn spconfig_ole_automation_fires_critical() {
    let sql = "EXEC sp_configure N'Ole Automation Procedures', 1;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(
            &findings,
            "MSSQL-SPCONFIG-OLE-AUTOMATION",
            RiskLevel::Critical
        ),
        "MSSQL-SPCONFIG-OLE-AUTOMATION should fire at Critical. Got: {:?}",
        findings
    );
}

#[test]
fn spconfig_clr_enabled_fires_high() {
    let sql = "EXEC sp_configure 'clr enabled', 1;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-SPCONFIG-CLR", RiskLevel::High),
        "MSSQL-SPCONFIG-CLR should fire at High. Got: {:?}",
        findings
    );
}

#[test]
fn spconfig_clr_strict_security_fires() {
    let sql = "EXEC sp_configure 'clr strict security', 0;";
    let findings = analyze(sql);
    assert!(
        fires(&findings, "MSSQL-SPCONFIG-CLR"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn spconfig_adhoc_distributed_queries_fires_high() {
    let sql = "EXEC sp_configure 'Ad Hoc Distributed Queries', 1;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-SPCONFIG-ADHOC-QUERIES", RiskLevel::High),
        "MSSQL-SPCONFIG-ADHOC-QUERIES should fire at High. Got: {:?}",
        findings
    );
}

#[test]
fn spconfig_xdb_chaining_fires_high() {
    let sql = "EXEC sp_configure 'cross db ownership chaining', 1;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-SPCONFIG-XDB-CHAINING", RiskLevel::High),
        "MSSQL-SPCONFIG-XDB-CHAINING should fire at High. Got: {:?}",
        findings
    );
}

#[test]
fn spconfig_remote_access_fires_medium() {
    let sql = "EXEC sp_configure 'remote access', 0;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-SPCONFIG-REMOTE-ACCESS", RiskLevel::Medium),
        "MSSQL-SPCONFIG-REMOTE-ACCESS should fire at Medium. Got: {:?}",
        findings
    );
}

#[test]
fn spconfig_dac_fires_medium() {
    let sql = "EXEC sp_configure 'remote admin connections', 1;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-SPCONFIG-DAC", RiskLevel::Medium),
        "MSSQL-SPCONFIG-DAC should fire at Medium. Got: {:?}",
        findings
    );
}

#[test]
fn spconfig_surface_options_fire_only_when_turned_on() {
    for (option, rule, level) in [
        (
            "xp_cmdshell",
            "MSSQL-SPCONFIG-XPCMDSHELL",
            RiskLevel::Critical,
        ),
        (
            "Ole Automation Procedures",
            "MSSQL-SPCONFIG-OLE-AUTOMATION",
            RiskLevel::Critical,
        ),
        ("clr enabled", "MSSQL-SPCONFIG-CLR", RiskLevel::High),
        (
            "Ad Hoc Distributed Queries",
            "MSSQL-SPCONFIG-ADHOC-QUERIES",
            RiskLevel::High,
        ),
        (
            "cross db ownership chaining",
            "MSSQL-SPCONFIG-XDB-CHAINING",
            RiskLevel::High,
        ),
    ] {
        for sql in [
            format!("EXEC sp_configure '{option}', 1;"),
            format!("EXEC sp_configure @configname = '{option}', @configvalue = 1;"),
            format!("EXEC sp_configure @configvalue = 1, @configname = N'{option}';"),
            format!("EXEC sp_configure '{option}', @value;"),
        ] {
            let findings = analyze(&sql);
            assert!(
                fires_with_level(&findings, rule, level),
                "{rule} should fire at {level:?} on `{sql}`. Got: {findings:?}"
            );
        }
        for sql in [
            format!("EXEC sp_configure '{option}', 0;"),
            format!("EXEC sp_configure '{option}', '0';"),
            format!("EXEC sp_configure @configname = '{option}', @configvalue = 0;"),
            format!("EXEC sp_configure '{option}';"),
            format!("EXEC sp_configure @configname = '{option}';"),
        ] {
            let findings = analyze(&sql);
            assert!(
                !fires(&findings, rule),
                "{rule} must not fire on `{sql}`. Got: {findings:?}"
            );
        }
    }
}

#[test]
fn spconfig_clr_strict_security_fires_only_when_turned_off() {
    for sql in [
        "EXEC sp_configure 'clr strict security', 0;",
        "EXEC sp_configure @configname = 'clr strict security', @configvalue = 0;",
    ] {
        let findings = analyze(sql);
        assert!(
            fires_with_level(&findings, "MSSQL-SPCONFIG-CLR", RiskLevel::High),
            "MSSQL-SPCONFIG-CLR should fire at High on `{sql}`. Got: {findings:?}"
        );
    }
    for sql in [
        "EXEC sp_configure 'clr strict security', 1;",
        "EXEC sp_configure 'clr strict security';",
        "EXEC sp_configure 'clr enabled', 0;",
    ] {
        let findings = analyze(sql);
        assert!(
            !fires(&findings, "MSSQL-SPCONFIG-CLR"),
            "MSSQL-SPCONFIG-CLR must not fire on `{sql}`. Got: {findings:?}"
        );
    }
}

#[test]
fn spconfig_benign_option_fires_none_of_new_rules() {
    let sql = "EXEC sp_configure 'max degree of parallelism', 8;";
    let findings = analyze(sql);
    for id in [
        "MSSQL-SPCONFIG-OLE-AUTOMATION",
        "MSSQL-SPCONFIG-CLR",
        "MSSQL-SPCONFIG-ADHOC-QUERIES",
        "MSSQL-SPCONFIG-XDB-CHAINING",
        "MSSQL-SPCONFIG-REMOTE-ACCESS",
        "MSSQL-SPCONFIG-DAC",
    ] {
        assert!(
            !fires(&findings, id),
            "{id} should not fire. Got: {:?}",
            findings
        );
    }
}

// ── Negative: an ordinary proc call fires none of these ─────────────────────

#[test]
fn ordinary_proc_fires_no_role_or_spconfig_rules() {
    let sql = "EXEC dbo.refresh_reporting_cache @full = 1;";
    let findings = analyze(sql);
    for id in [
        "MSSQL-SRVROLE-MEMBER-ADD",
        "MSSQL-SRVROLE-SYSADMIN",
        "MSSQL-ROLE-MEMBER-ADD",
        "MSSQL-DBROLE-ADMIN-ADD",
        "MSSQL-ROLE-MEMBER-DROP",
    ] {
        assert!(
            !fires(&findings, id),
            "{id} should not fire. Got: {:?}",
            findings
        );
    }
}
