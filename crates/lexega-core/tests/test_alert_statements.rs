// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake ALERT lifecycle statements.
//!
//! Covers parsing/formatting round-trips for CREATE / ALTER / DROP ALERT
//! (including the `IF (EXISTS (…)) THEN <action>` body and the ALTER
//! action forms), the SNW-ALERT-* governance rules, and the key
//! correctness property: the embedded condition/action SQL is recognized
//! as part of the alert and NOT analyzed as standalone statements.

use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.signals)
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ───────────────────────── formatting ─────────────────────────

#[test]
fn test_alert_formatting_variants() {
    assert_formats_safe(
        "CREATE ALERT my_alert WAREHOUSE = compute_wh SCHEDULE = '1 MINUTE' COMMENT = 'c' IF (EXISTS (SELECT 1 FROM t WHERE x > 10)) THEN INSERT INTO log VALUES (1);\n\
         CREATE OR REPLACE ALERT IF NOT EXISTS db1.sch1.a2 WAREHOUSE = wh SCHEDULE = 'USING CRON 0 9 * * * UTC' IF (EXISTS (SELECT count(*) FROM events)) THEN CALL notify_proc();\n\
         ALTER ALERT my_alert RESUME;\n\
         ALTER ALERT my_alert SUSPEND;\n\
         ALTER ALERT IF EXISTS my_alert SET WAREHOUSE = wh2 SCHEDULE = '5 MINUTE';\n\
         ALTER ALERT my_alert UNSET COMMENT;\n\
         ALTER ALERT my_alert MODIFY CONDITION EXISTS (SELECT 1 FROM t2);\n\
         ALTER ALERT my_alert MODIFY ACTION DELETE FROM staging WHERE 1=1;\n\
         DROP ALERT my_alert;\n\
         DROP ALERT IF EXISTS db1.sch1.a2;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_alert_create_and_drop() {
    let rules = analyze_and_get_rules(
        "CREATE ALERT a WAREHOUSE = wh SCHEDULE = '1 MINUTE' IF (EXISTS (SELECT 1)) THEN INSERT INTO log VALUES (1);",
    );
    assert!(rules.contains("SNW-ALERT-NEW"), "got {rules:?}");

    let report = analyze_risk("DROP ALERT IF EXISTS a;").expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("SNW-ALERT-DROP"), "got {rules:?}");
    assert!(
        report.summary.high_count >= 1,
        "dropping an alert is high severity"
    );
}

#[test]
fn test_alert_resume_suspend() {
    let rules = analyze_and_get_rules("ALTER ALERT a RESUME;");
    assert!(rules.contains("SNW-ALERT-RESUME"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER ALERT a SUSPEND;");
    assert!(rules.contains("SNW-ALERT-SUSPEND"), "got {rules:?}");
}

#[test]
fn test_alert_modify_action_and_condition() {
    let rules = analyze_and_get_rules("ALTER ALERT a MODIFY ACTION DELETE FROM staging WHERE 1=1;");
    assert!(rules.contains("SNW-ALERT-ACTION-CHG"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER ALERT a MODIFY CONDITION EXISTS (SELECT 1 FROM t);");
    assert!(rules.contains("SNW-ALERT-COND-CHG"), "got {rules:?}");
}

#[test]
fn test_alert_unparseable_action_body() {
    let rules = analyze_and_get_rules(
        "CREATE ALERT a WAREHOUSE = wh SCHEDULE = '1 MINUTE' IF (EXISTS (SELECT 1)) THEN @#$ not valid;",
    );
    assert!(rules.contains("SNW-ALERT-PARSE-ERR"), "got {rules:?}");
}

// ───────────────────────── negative / correctness cases ─────────────────────────

#[test]
fn test_alert_set_unset_fire_no_action_rules() {
    let rules = analyze_and_get_rules("ALTER ALERT a SET WAREHOUSE = wh2 SCHEDULE = '5 MINUTE';");
    assert!(
        !rules.contains("SNW-ALERT-ACTION-CHG") && !rules.contains("SNW-ALERT-COND-CHG"),
        "SET must not fire MODIFY rules, got {rules:?}"
    );

    let rules = analyze_and_get_rules("ALTER ALERT a UNSET COMMENT;");
    assert!(
        !rules.contains("SNW-ALERT-ACTION-CHG"),
        "UNSET must not fire ACTION-CHG, got {rules:?}"
    );
}

#[test]
fn test_alert_action_body_not_analyzed_standalone() {
    // The action body is an unbounded DELETE. Before ALERT was parsed, the
    // body fragmented into a standalone DELETE that fired DML-WRITE-UNBOUNDED
    // out of context. Now it is recognized as the alert's action and must
    // NOT produce a standalone DML finding (mirrors the TASK body model).
    let rules = analyze_and_get_rules(
        "CREATE ALERT a WAREHOUSE = wh SCHEDULE = '1 MINUTE' IF (EXISTS (SELECT 1)) THEN DELETE FROM staging;",
    );
    assert!(rules.contains("SNW-ALERT-NEW"), "got {rules:?}");
    assert!(
        !rules.contains("DML-WRITE-UNBOUNDED"),
        "the alert action body must not be analyzed as a standalone statement, got {rules:?}"
    );
}

#[test]
fn test_alert_condition_query_not_analyzed_standalone() {
    // The condition query must likewise not surface standalone query
    // findings — it is consumed as part of the alert.
    let report = analyze_risk(
        "CREATE ALERT a WAREHOUSE = wh SCHEDULE = '1 MINUTE' IF (EXISTS (SELECT * FROM t WHERE 1=1)) THEN CALL p();",
    )
    .expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(
        rules.iter().all(|r| r.starts_with("SNW-ALERT-")),
        "only alert rules should fire, got {rules:?}"
    );
}
