// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Invariant: rule evaluation enumerates EVERY statement at EVERY nesting depth,
//! uniformly across rule families and across all body-bearing constructs.
//!
//! Three things have to hold: (A) the privilege and policy-attachment rule
//! families see a GRANT / REVOKE / DENY inside any body, not only top-level
//! `script.stmts`; (B) `CREATE TASK` and MSSQL `CREATE TRIGGER` bodies are
//! enumerated for every family; (C) the scripting-block statement dispatcher
//! parses every statement type (GRANT / REVOKE / DENY / …) inside a
//! `BEGIN … END` block.
//!
//! Each test puts a statement that DOES fire a rule inside a body and asserts
//! the rule fires — i.e. the inner statement was both parsed and rule-evaluated.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect;

fn rule_ids(sql: &str, d: lexega_core::DialectRef) -> Vec<String> {
    let cfg = AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn assert_fires(sql: &str, d: lexega_core::DialectRef, rule: &str) {
    let ids = rule_ids(sql, d);
    assert!(
        ids.contains(&rule.to_string()),
        "expected {rule} to fire (inner statement must be parsed + analyzed). Got: {ids:?}\nSQL: {sql}"
    );
}

// ── (A) Privilege family enumerates bodies ───────────────────────────────

#[test]
fn test_grant_in_mysql_procedure_body_fires() {
    assert_fires(
        "CREATE PROCEDURE p() BEGIN GRANT ALL ON db.* TO 'x'@'%'; END;",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_mysql_trigger_body_fires() {
    assert_fires(
        "CREATE TRIGGER t AFTER INSERT ON u FOR EACH ROW \
         BEGIN GRANT ALL ON db.* TO 'x'@'%'; END;",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_mysql_event_body_fires() {
    assert_fires(
        "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO GRANT ALL ON db.* TO 'x'@'%';",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_nested_control_flow_fires() {
    assert_fires(
        "CREATE PROCEDURE p() BEGIN IF 1 = 1 THEN GRANT ALL ON db.* TO 'x'@'%'; END IF; END;",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_snowflake_task_body_fires() {
    assert_fires(
        "CREATE TASK t WAREHOUSE = w SCHEDULE = '1 minute' AS GRANT ALL ON DATABASE d TO ROLE r;",
        dialect::snowflake(),
        "GRT-ALL-PRIV",
    );
}

// ── (B) Body-bearing statement types recurse for DDL too ─────────────────

#[test]
fn test_drop_in_snowflake_task_body_fires() {
    assert_fires(
        "CREATE TASK t WAREHOUSE = w SCHEDULE = '1 minute' AS DROP TABLE audit_log;",
        dialect::snowflake(),
        "TBL-DROP",
    );
}

#[test]
fn test_drop_in_mssql_trigger_body_fires() {
    assert_fires(
        "CREATE TRIGGER tr ON dbo.t AFTER INSERT AS BEGIN DROP TABLE shadow; END;",
        dialect::mssql(),
        "TBL-DROP",
    );
}

// ── (C) Block dispatcher recognizes every statement type (no opacity) ────

#[test]
fn test_block_body_statements_not_skipped() {
    // The privilege statement inside the block must be analyzed, not dropped as
    // opaque.
    let cfg = AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    };
    // A privilege statement and a DDL statement in the same block body — both
    // must be analyzed.
    let report = analyze_risk_with_policy_config(
        "CREATE PROCEDURE p() BEGIN GRANT ALL ON db.* TO 'x'@'%'; DROP TABLE staging; END;",
        &cfg,
    )
    .expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "no statement in the block body may be skipped as opaque"
    );
}

// ── MySQL REVOKE `user@host` grantee parity (grant/revoke) ───────────────
//
// GRANT routes to a MySQL-aware grantee reader that consumes the `@host`
// suffix; the generic REVOKE path did not, so `REVOKE … FROM 'u'@'h'` went
// opaque (at top level and inside bodies). Both forms must now parse.

fn assert_not_skipped(sql: &str, d: lexega_core::DialectRef) {
    let cfg = AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "statement must be parsed, not skipped: {sql}"
    );
}

#[test]
fn test_mysql_revoke_user_at_host_quoted() {
    assert_not_skipped("REVOKE SELECT ON db.t FROM 'y'@'%';", dialect::mysql());
}

#[test]
fn test_mysql_revoke_user_at_host_unquoted() {
    assert_not_skipped("REVOKE ALL ON db.* FROM y@localhost;", dialect::mysql());
}

#[test]
fn test_mysql_revoke_user_at_host_in_body() {
    assert_not_skipped(
        "CREATE PROCEDURE p() BEGIN REVOKE SELECT ON db.t FROM 'y'@'%'; END;",
        dialect::mysql(),
    );
}
