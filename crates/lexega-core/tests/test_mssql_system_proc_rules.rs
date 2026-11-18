// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL Server system procedures that reach outside the database: the
//! file-system and registry extended procedures, startup procedures
//! (sp_procoption) and mail carrying query results or files
//! (sp_send_dbmail). The rules read `mssql_exec.procedure_name` and the
//! typed `mssql_exec.args`; which names and values matter is YAML policy.

use lexega_core::analyzer::{AnalysisConfig, RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::mssql;

const NEW_RULES: [&str; 5] = [
    "MSSQL-XP-FILESYSTEM",
    "MSSQL-XP-REGISTRY-READ",
    "MSSQL-XP-REGISTRY-WRITE",
    "MSSQL-STARTUP-PROC",
    "MSSQL-DBMAIL-EGRESS",
];

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

fn assert_fires_at(sql: &str, rule_id: &str, level: RiskLevel) {
    let findings = analyze(sql);
    assert!(
        findings.iter().any(|(id, l)| id == rule_id && *l == level),
        "{rule_id} should fire at {level:?} on: {sql}\nGot: {findings:?}"
    );
}

fn assert_silent(sql: &str, rule_id: &str) {
    let findings = analyze(sql);
    assert!(
        !findings.iter().any(|(id, _)| id == rule_id),
        "{rule_id} should not fire on: {sql}\nGot: {findings:?}"
    );
}

/// The one new rule a statement raises, and none of the others.
fn assert_only(sql: &str, rule_id: &str, level: RiskLevel) {
    assert_fires_at(sql, rule_id, level);
    for other in NEW_RULES.iter().filter(|id| **id != rule_id) {
        assert_silent(sql, other);
    }
}

// ── File system ─────────────────────────────────────────────────────────────

#[test]
fn file_system_procedures_fire_high() {
    for sql in [
        r"EXEC xp_dirtree '\\10.0.0.5\share';",
        r"EXEC xp_fileexist 'C:\backup\full.bak';",
        r"EXEC xp_subdirs 'C:\backup';",
    ] {
        assert_only(sql, "MSSQL-XP-FILESYSTEM", RiskLevel::High);
    }
}

#[test]
fn file_system_procedure_matches_qualified_quoted_and_any_case() {
    for sql in [
        r"EXEC master..xp_dirtree '\\10.0.0.5\share', 1, 1;",
        r"EXECUTE master.dbo.xp_fileexist 'C:\x.txt';",
        r"EXEC [master].[sys].[XP_DIRTREE] 'C:\';",
    ] {
        assert_fires_at(sql, "MSSQL-XP-FILESYSTEM", RiskLevel::High);
    }
}

#[test]
fn file_system_procedure_feeding_an_insert_fires() {
    assert_fires_at(
        r"INSERT INTO #files EXEC master..xp_dirtree 'C:\backup', 1, 1;",
        "MSSQL-XP-FILESYSTEM",
        RiskLevel::High,
    );
}

// ── Registry ────────────────────────────────────────────────────────────────

#[test]
fn registry_reads_fire_high() {
    for sql in [
        r"EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App', 'Key';",
        r"EXEC master..xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode';",
        r"EXEC xp_regenumkeys 'HKEY_LOCAL_MACHINE', 'SOFTWARE';",
        r"EXEC xp_instance_regenumkeys 'HKEY_LOCAL_MACHINE', 'SOFTWARE';",
        r"EXEC xp_regenumvalues 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App';",
        r"EXEC xp_instance_regenumvalues 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App';",
    ] {
        assert_only(sql, "MSSQL-XP-REGISTRY-READ", RiskLevel::High);
    }
}

#[test]
fn registry_writes_fire_critical() {
    for sql in [
        r"EXEC xp_regwrite @rootkey='HKEY_LOCAL_MACHINE', @key='SOFTWARE\App', @value_name='v', @type='REG_SZ', @value='x';",
        r"EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2;",
        r"EXEC xp_regdeletekey 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App';",
        r"EXEC xp_instance_regdeletekey 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App';",
        r"EXEC xp_regdeletevalue 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App', 'v';",
        r"EXEC xp_instance_regdeletevalue 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App', 'v';",
        r"EXEC xp_regaddmultistring 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App', 'v', 'x';",
        r"EXEC xp_instance_regaddmultistring 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App', 'v', 'x';",
        r"EXEC xp_regremovemultistring 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App', 'v', 'x';",
        r"EXEC xp_instance_regremovemultistring 'HKEY_LOCAL_MACHINE', 'SOFTWARE\App', 'v', 'x';",
    ] {
        assert_only(sql, "MSSQL-XP-REGISTRY-WRITE", RiskLevel::Critical);
    }
}

#[test]
fn registry_write_matches_qualified_quoted_and_any_case() {
    assert_fires_at(
        "EXEC [master].[dbo].[XP_REGWRITE] 'HKEY_LOCAL_MACHINE', 'k', 'v', 'REG_SZ', 'x';",
        "MSSQL-XP-REGISTRY-WRITE",
        RiskLevel::Critical,
    );
}

// ── Startup procedures ──────────────────────────────────────────────────────

#[test]
fn startup_procedure_turned_on_fires_high() {
    for sql in [
        "EXEC sp_procoption @ProcName = 'dbo.warm_cache', @OptionName = 'startup', @OptionValue = 'on';",
        "EXEC sp_procoption 'dbo.warm_cache', 'startup', 'true';",
        "EXEC master.dbo.sp_procoption N'dbo.warm_cache', N'startup', N'ON';",
    ] {
        assert_only(sql, "MSSQL-STARTUP-PROC", RiskLevel::High);
    }
}

#[test]
fn startup_procedure_with_a_value_not_written_fires() {
    // The value is a variable: not shown to be off.
    assert_fires_at(
        "EXEC sp_procoption 'dbo.warm_cache', 'startup', @value;",
        "MSSQL-STARTUP-PROC",
        RiskLevel::High,
    );
    assert_fires_at(
        "EXEC sp_procoption @ProcName = 'dbo.warm_cache', @OptionName = 'startup';",
        "MSSQL-STARTUP-PROC",
        RiskLevel::High,
    );
}

#[test]
fn startup_procedure_turned_off_is_silent() {
    for sql in [
        "EXEC sp_procoption 'dbo.warm_cache', 'startup', 'off';",
        "EXEC sp_procoption 'dbo.warm_cache', 'startup', 'false';",
        "EXEC sp_procoption @ProcName = 'dbo.warm_cache', @OptionName = 'startup', @OptionValue = 'OFF';",
        "EXEC sp_procoption @OptionValue = N'False', @ProcName = 'dbo.warm_cache', @OptionName = 'startup';",
    ] {
        assert_silent(sql, "MSSQL-STARTUP-PROC");
    }
}

#[test]
fn startup_procedure_named_off_is_not_the_option_value() {
    // 'off' in the procedure-name position does not clear the finding.
    assert_fires_at(
        "EXEC sp_procoption 'off', 'startup', 'on';",
        "MSSQL-STARTUP-PROC",
        RiskLevel::High,
    );
}

// ── Database Mail ───────────────────────────────────────────────────────────

#[test]
fn mail_with_query_results_fires_medium() {
    assert_only(
        "EXEC msdb.dbo.sp_send_dbmail @recipients = 'a@example.com', @query = 'SELECT * FROM dbo.cards';",
        "MSSQL-DBMAIL-EGRESS",
        RiskLevel::Medium,
    );
    // A query held in a variable is still a query sent.
    assert_fires_at(
        "EXEC msdb.dbo.sp_send_dbmail @recipients = 'a@example.com', @query = @q, @attach_query_result_as_file = 1;",
        "MSSQL-DBMAIL-EGRESS",
        RiskLevel::Medium,
    );
}

#[test]
fn mail_with_file_attachments_fires_medium() {
    assert_only(
        r"EXEC sp_send_dbmail @recipients = 'a@example.com', @subject = 'x', @file_attachments = 'C:\backup\full.bak';",
        "MSSQL-DBMAIL-EGRESS",
        RiskLevel::Medium,
    );
}

#[test]
fn mail_with_a_long_positional_list_fires() {
    // Twelve positional arguments reach @file_attachments.
    assert_fires_at(
        r"EXEC sp_send_dbmail 'ops', 'a@example.com', NULL, NULL, NULL, NULL, 'subject', 'body', 'TEXT', 'Normal', 'Normal', 'C:\backup\full.bak';",
        "MSSQL-DBMAIL-EGRESS",
        RiskLevel::Medium,
    );
}

#[test]
fn mail_with_text_only_is_silent() {
    for sql in [
        "EXEC msdb.dbo.sp_send_dbmail @profile_name = 'ops', @recipients = 'oncall@example.com', @subject = 'job failed', @body = 'see the log';",
        "EXEC sp_send_dbmail 'ops', 'oncall@example.com', NULL, NULL, NULL, NULL, 'job failed', 'see the log';",
    ] {
        assert_silent(sql, "MSSQL-DBMAIL-EGRESS");
    }
}

// ── Other procedures ────────────────────────────────────────────────────────

#[test]
fn other_procedures_fire_none_of_the_rules() {
    for sql in [
        "EXEC dbo.usp_report 1;",
        "EXEC xp_cmdshell 'dir';",
        "EXEC sp_configure 'show advanced options', 1;",
        // A name that only starts like a listed one.
        "EXEC dbo.xp_dirtree_report 'x';",
        // The name as an argument, not the procedure called.
        "EXEC dbo.audit_call 'xp_regwrite';",
    ] {
        for rule_id in NEW_RULES {
            assert_silent(sql, rule_id);
        }
    }
}
