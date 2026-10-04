// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL-GRT-* rule family: dangerous T-SQL permission grants.
//!
//! Rule IDs:
//!   MSSQL-GRT-CONTROL-SERVER        (Critical) — sysadmin-equivalent
//!   MSSQL-GRT-IMPERSONATE-ANY-LOGIN (Critical) — impersonate any login
//!   MSSQL-GRT-IMPERSONATE           (High)     — impersonate a principal
//!   MSSQL-GRT-SERVER-ADMIN          (High)     — ALTER ANY LOGIN / ... list
//!   MSSQL-GRT-UNSAFE-ASSEMBLY       (High)     — UNSAFE / EXTERNAL ACCESS ASSEMBLY
//!   MSSQL-GRT-TAKE-OWNERSHIP        (High)     — TAKE OWNERSHIP
//!   MSSQL-GRT-CONTROL-DATABASE      (High)     — CONTROL ON DATABASE::
//!   MSSQL-GRT-CONTROL-SCHEMA        (Medium)   — CONTROL ON SCHEMA::
//!   MSSQL-GRT-VIEW-DEFINITION-STATE (Medium)   — VIEW ANY DATABASE / ... list
//!   MSSQL-GRT-TRACE-BULK            (Medium)   — ALTER TRACE / ADMINISTER BULK OPERATIONS
//!   MSSQL-GRT-TO-GUEST              (Medium)   — grant to the guest user
//!
//! Plus the server-tier forms: generic GRT-* / DNY-* rules must reach
//! statements whose grammar omits the `ON` clause.

use lexega_core::analyzer::AnalysisReport;
use lexega_core::dialect::mssql;

fn analyze_mssql(sql: &str) -> AnalysisReport {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mssql());
    lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("analysis should succeed")
}

fn has_signal(report: &AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| s.rule_id() == Some(rule_id))
}

fn assert_fires(sql: &str, rule_id: &str) {
    let report = analyze_mssql(sql);
    assert!(
        has_signal(&report, rule_id),
        "{rule_id} should fire on: {sql}\nsignals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| s.rule_id())
            .collect::<Vec<_>>()
    );
}

fn assert_silent(sql: &str, rule_id: &str) {
    let report = analyze_mssql(sql);
    assert!(
        !has_signal(&report, rule_id),
        "{rule_id} should NOT fire on: {sql}"
    );
}

// ── Critical tier ────────────────────────────────────────────────────

#[test]
fn control_server_fires() {
    assert_fires(
        "GRANT CONTROL SERVER TO bad_login;",
        "MSSQL-GRT-CONTROL-SERVER",
    );
}

#[test]
fn impersonate_any_login_fires_and_is_disjoint_from_bare_impersonate() {
    let sql = "GRANT IMPERSONATE ANY LOGIN TO l;";
    assert_fires(sql, "MSSQL-GRT-IMPERSONATE-ANY-LOGIN");
    // Disjoint in: lists — the three-word permission must not also trip
    // the bare IMPERSONATE rule.
    assert_silent(sql, "MSSQL-GRT-IMPERSONATE");
}

// ── High tier ────────────────────────────────────────────────────────

#[test]
fn impersonate_on_login_fires() {
    assert_fires(
        "GRANT IMPERSONATE ON LOGIN::sa TO some_login;",
        "MSSQL-GRT-IMPERSONATE",
    );
}

#[test]
fn server_admin_permissions_fire() {
    assert_fires("GRANT ALTER ANY LOGIN TO l;", "MSSQL-GRT-SERVER-ADMIN");
    assert_fires(
        "GRANT ALTER ANY SERVER ROLE TO l;",
        "MSSQL-GRT-SERVER-ADMIN",
    );
    assert_fires("GRANT ALTER ANY CREDENTIAL TO l;", "MSSQL-GRT-SERVER-ADMIN");
    assert_fires("GRANT ALTER ANY DATABASE TO l;", "MSSQL-GRT-SERVER-ADMIN");
    assert_fires("GRANT ALTER SERVER STATE TO l;", "MSSQL-GRT-SERVER-ADMIN");
}

#[test]
fn assembly_permissions_fire() {
    assert_fires("GRANT UNSAFE ASSEMBLY TO l;", "MSSQL-GRT-UNSAFE-ASSEMBLY");
    assert_fires(
        "GRANT EXTERNAL ACCESS ASSEMBLY TO l;",
        "MSSQL-GRT-UNSAFE-ASSEMBLY",
    );
}

#[test]
fn take_ownership_fires() {
    assert_fires(
        "GRANT TAKE OWNERSHIP ON OBJECT::dbo.t TO u1;",
        "MSSQL-GRT-TAKE-OWNERSHIP",
    );
}

#[test]
fn control_on_database_fires_only_for_database_class() {
    assert_fires(
        "GRANT CONTROL ON DATABASE::proddb TO u2;",
        "MSSQL-GRT-CONTROL-DATABASE",
    );
    // Table-level CONTROL is not database-scope.
    assert_silent(
        "GRANT CONTROL ON OBJECT::dbo.t TO u2;",
        "MSSQL-GRT-CONTROL-DATABASE",
    );
    assert_silent(
        "GRANT CONTROL ON OBJECT::dbo.t TO u2;",
        "MSSQL-GRT-CONTROL-SCHEMA",
    );
}

// ── Medium tier ──────────────────────────────────────────────────────

#[test]
fn control_on_schema_fires() {
    assert_fires(
        "GRANT CONTROL ON SCHEMA::dbo TO u1;",
        "MSSQL-GRT-CONTROL-SCHEMA",
    );
}

#[test]
fn view_metadata_permissions_fire() {
    assert_fires(
        "GRANT VIEW ANY DATABASE TO l;",
        "MSSQL-GRT-VIEW-DEFINITION-STATE",
    );
    assert_fires(
        "GRANT VIEW SERVER STATE TO l;",
        "MSSQL-GRT-VIEW-DEFINITION-STATE",
    );
    assert_fires(
        "GRANT VIEW ANY DEFINITION TO l;",
        "MSSQL-GRT-VIEW-DEFINITION-STATE",
    );
}

#[test]
fn trace_and_bulk_permissions_fire() {
    assert_fires("GRANT ALTER TRACE TO l;", "MSSQL-GRT-TRACE-BULK");
    assert_fires(
        "GRANT ADMINISTER BULK OPERATIONS TO l;",
        "MSSQL-GRT-TRACE-BULK",
    );
}

#[test]
fn grant_to_guest_fires() {
    assert_fires("GRANT SELECT ON dbo.t TO guest;", "MSSQL-GRT-TO-GUEST");
}

// ── Negatives: benign grants stay silent ─────────────────────────────

#[test]
fn benign_object_grant_fires_no_mssql_grt_rule() {
    let report = analyze_mssql("GRANT SELECT ON OBJECT::dbo.t TO app_user;");
    let fired: Vec<&str> = report
        .signals
        .iter()
        .filter_map(|s| s.rule_id())
        .filter(|id| id.starts_with("MSSQL-GRT-"))
        .collect();
    assert!(
        fired.is_empty(),
        "unexpected MSSQL-GRT-* signals: {fired:?}"
    );
}

#[test]
fn deny_of_dangerous_permission_fires_no_mssql_grt_rule() {
    // DENY is a restriction, not an escalation — the MSSQL-GRT-* family
    // gates on kind: grant.
    let report = analyze_mssql("DENY CONTROL SERVER TO l;");
    assert!(!has_signal(&report, "MSSQL-GRT-CONTROL-SERVER"));
}

// ── Regressions: server-tier parse fix restores generic rules ────────

#[test]
fn grt_to_public_fires_on_server_tier_grant() {
    assert_fires("GRANT CONTROL SERVER TO public;", "GRT-TO-PUBLIC");
}

#[test]
fn dny_to_public_fires_on_server_tier_deny() {
    assert_fires("DENY CONTROL SERVER TO public;", "DNY-TO-PUBLIC");
}

#[test]
fn grt_with_opt_fires_on_class_qualified_grant() {
    assert_fires(
        "GRANT IMPERSONATE ON USER::etl_user TO r WITH GRANT OPTION;",
        "GRT-WITH-OPT",
    );
}
