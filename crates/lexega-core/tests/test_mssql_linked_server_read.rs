// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL four-part (linked-server) reference detection. A T-SQL
//! `server.database.schema.object` name is a distributed query against a
//! remote SQL Server over a linked server. The `server` component is
//! carried on the typed `TableRef` (reads_table / writes_table), and
//! `MSSQL-LINKEDSRV-READ` fires when it is present.

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

#[test]
fn four_part_read_fires_low() {
    let sql = "SELECT * FROM PAYROLL_LINK.payroll.dbo.EmployeeCompensation;";
    let findings = analyze(sql);
    assert!(
        fires_with_level(&findings, "MSSQL-LINKEDSRV-READ", RiskLevel::Low),
        "MSSQL-LINKEDSRV-READ should fire at Low on a four-part read. Got: {:?}",
        findings
    );
}

#[test]
fn four_part_write_fires() {
    let sql = "UPDATE PAYROLL_LINK.payroll.dbo.t SET x = 1;";
    let findings = analyze(sql);
    assert!(
        fires(&findings, "MSSQL-LINKEDSRV-READ"),
        "MSSQL-LINKEDSRV-READ should fire on a four-part write target. Got: {:?}",
        findings
    );
}

#[test]
fn three_part_read_does_not_fire() {
    // An ordinary three-part name has no linked-server component.
    let sql = "SELECT * FROM payroll.dbo.EmployeeCompensation;";
    let findings = analyze(sql);
    assert!(
        !fires(&findings, "MSSQL-LINKEDSRV-READ"),
        "MSSQL-LINKEDSRV-READ must not fire on a three-part name. Got: {:?}",
        findings
    );
}

#[test]
fn bracket_quoted_four_part_fires() {
    let sql = "SELECT * FROM [PAYROLL_LINK].[payroll].[dbo].[EmployeeCompensation];";
    let findings = analyze(sql);
    assert!(
        fires(&findings, "MSSQL-LINKEDSRV-READ"),
        "MSSQL-LINKEDSRV-READ should fire on a bracket-quoted four-part name. Got: {:?}",
        findings
    );
}
