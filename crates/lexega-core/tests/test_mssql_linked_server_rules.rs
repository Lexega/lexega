// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL linked-server and SQL Agent CmdExec detection rules. These
//! predicate on the `mssql_exec.procedure_name` (base name,
//! qualifier-stripped) and `mssql_exec.args_text` facts, and cover the
//! lateral-movement / OS-exec / plaintext-credential surfaces.

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

fn fires(findings: &[(String, RiskLevel)], rule_id: &str) -> bool {
    findings.iter().any(|(id, _)| id == rule_id)
}

fn fires_with_level(findings: &[(String, RiskLevel)], rule_id: &str, level: RiskLevel) -> bool {
    findings.iter().any(|(id, l)| id == rule_id && *l == level)
}

// ── sp_addlinkedserver ──────────────────────────────────────────────────────

#[test]
fn add_linked_server_fires_medium() {
    let sql = "EXEC sp_addlinkedserver @server=N'L', @provider=N'SQLNCLI', @datasrc=N'h';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-LINKEDSRV-ADD", RiskLevel::Medium),
        "MSSQL-LINKEDSRV-ADD should fire at Medium. Got: {:?}",
        findings
    );
}

#[test]
fn add_linked_server_qualified_name_fires() {
    // Conventional invocation is fully qualified; base-name normalization
    // (mssql_exec.procedure_name) must let it match.
    let sql = "EXEC master.dbo.sp_addlinkedserver @server=N'L';";
    let findings = analyze(sql);
    assert!(
        fires(&findings, "MSSQL-LINKEDSRV-ADD"),
        "Got: {:?}",
        findings
    );
}

// ── sp_addlinkedsrvlogin ────────────────────────────────────────────────────

#[test]
fn add_linked_srv_login_fires_medium() {
    let sql = "EXEC sp_addlinkedsrvlogin @rmtsrvname=N'L', @useself=N'True';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-LINKEDSRV-LOGIN", RiskLevel::Medium),
        "MSSQL-LINKEDSRV-LOGIN should fire at Medium. Got: {:?}",
        findings
    );
}

#[test]
fn add_linked_srv_login_inline_password_fires_critical() {
    let sql = "EXEC master.dbo.sp_addlinkedsrvlogin @rmtsrvname=N'L', @useself=N'False', \
               @rmtuser=N'u', @rmtpassword=N'P@ss!';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-LINKEDSRV-LOGIN-CRED", RiskLevel::Critical),
        "MSSQL-LINKEDSRV-LOGIN-CRED should fire at Critical. Got: {:?}",
        findings
    );
    // The High base rule also fires alongside the Critical credential rule.
    assert!(
        fires(&findings, "MSSQL-LINKEDSRV-LOGIN"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn add_linked_srv_login_variable_password_no_cred() {
    // `@rmtpassword = @p` passes a variable, not a literal — the typed
    // value_kind distinguishes this from a hard-coded password, which a
    // text glob over args could not. The credential rule must stay silent.
    let sql = "EXEC sp_addlinkedsrvlogin @rmtsrvname=N'L', @useself=N'False', \
               @rmtuser=N'u', @rmtpassword=@p;";
    let findings = analyze(sql);
    assert!(
        !fires(&findings, "MSSQL-LINKEDSRV-LOGIN-CRED"),
        "MSSQL-LINKEDSRV-LOGIN-CRED must not fire for a variable password. Got: {:?}",
        findings
    );
    // The base linked-server-login rule still fires.
    assert!(
        fires(&findings, "MSSQL-LINKEDSRV-LOGIN"),
        "Got: {:?}",
        findings
    );
}

#[test]
fn add_linked_srv_login_integrated_security_no_cred() {
    // @useself = 'True', no @rmtpassword literal — the credential rule
    // must stay silent (regression guard against over-firing).
    let sql = "EXEC sp_addlinkedsrvlogin @rmtsrvname=N'L', @useself=N'True';";
    let findings = analyze(sql);
    assert!(
        !fires(&findings, "MSSQL-LINKEDSRV-LOGIN-CRED"),
        "MSSQL-LINKEDSRV-LOGIN-CRED must not fire without an inline password. Got: {:?}",
        findings
    );
}

// ── sp_add_jobstep @subsystem = 'CmdExec' ───────────────────────────────────

#[test]
fn agent_job_cmdexec_fires_critical() {
    let sql = "EXEC msdb.dbo.sp_add_jobstep @job_name=N'j', @step_name=N's', \
               @subsystem=N'CmdExec', @command=N'whoami';";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-AGENTJOB-CMDEXEC", RiskLevel::Critical),
        "MSSQL-AGENTJOB-CMDEXEC should fire at Critical. Got: {:?}",
        findings
    );
}

#[test]
fn agent_job_tsql_subsystem_no_cmdexec() {
    // A non-CmdExec subsystem must not fire the OS-command rule.
    let sql = "EXEC msdb.dbo.sp_add_jobstep @job_name=N'j', @step_name=N's', \
               @subsystem=N'TSQL', @command=N'SELECT 1';";
    let findings = analyze(sql);
    assert!(
        !fires(&findings, "MSSQL-AGENTJOB-CMDEXEC"),
        "MSSQL-AGENTJOB-CMDEXEC must not fire on a TSQL step. Got: {:?}",
        findings
    );
}

// ── Negative: an ordinary proc call fires none of these ─────────────────────

#[test]
fn ordinary_proc_fires_no_linked_server_rules() {
    let sql = "EXEC dbo.my_business_proc @arg = 1;";
    let findings = analyze(sql);
    for id in [
        "MSSQL-LINKEDSRV-ADD",
        "MSSQL-LINKEDSRV-LOGIN",
        "MSSQL-LINKEDSRV-LOGIN-CRED",
        "MSSQL-AGENTJOB-CMDEXEC",
    ] {
        assert!(
            !fires(&findings, id),
            "{id} should not fire. Got: {:?}",
            findings
        );
    }
}
