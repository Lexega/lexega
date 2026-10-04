// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake RESOURCE MONITOR lifecycle statements.
//!
//! Covers parsing/formatting round-trips for CREATE / ALTER / DROP
//! RESOURCE MONITOR (including the `WITH` property bag and the
//! `TRIGGERS ON <pct> PERCENT DO <action>` clause) and the
//! SNW-RESMON-* governance rules.

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
fn test_resource_monitor_formatting_variants() {
    assert_formats_safe(
        "CREATE RESOURCE MONITOR my_rm WITH CREDIT_QUOTA = 1000 FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY NOTIFY_USERS = (alice, bob) TRIGGERS ON 75 PERCENT DO NOTIFY ON 100 PERCENT DO SUSPEND ON 110 PERCENT DO SUSPEND_IMMEDIATE;\n\
         CREATE OR REPLACE RESOURCE MONITOR IF NOT EXISTS rm2 WITH CREDIT_QUOTA = 500;\n\
         ALTER RESOURCE MONITOR my_rm SET CREDIT_QUOTA = 2000 TRIGGERS ON 80 PERCENT DO SUSPEND;\n\
         ALTER RESOURCE MONITOR IF EXISTS rm2 SET NOTIFY_USERS = (carol);\n\
         DROP RESOURCE MONITOR my_rm;\n\
         DROP RESOURCE MONITOR IF EXISTS rm2;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_resource_monitor_create_info() {
    let rules = analyze_and_get_rules(
        "CREATE RESOURCE MONITOR rm WITH CREDIT_QUOTA = 1000 TRIGGERS ON 100 PERCENT DO SUSPEND;",
    );
    assert!(rules.contains("INFO-SNW-RESMON-NEW"), "got {rules:?}");
    // A monitor that suspends at 100% enforces a hard cap — NO-SUSPEND
    // must stay silent.
    assert!(
        !rules.contains("SNW-RESMON-NO-SUSPEND"),
        "a SUSPEND trigger must suppress NO-SUSPEND, got {rules:?}"
    );
}

#[test]
fn test_resource_monitor_no_suspend_trigger() {
    // No triggers at all: nothing halts compute.
    let rules = analyze_and_get_rules("CREATE RESOURCE MONITOR rm WITH CREDIT_QUOTA = 1000;");
    assert!(rules.contains("SNW-RESMON-NO-SUSPEND"), "got {rules:?}");

    // Notify-only triggers: alerts but no automatic suspension.
    let rules = analyze_and_get_rules(
        "CREATE RESOURCE MONITOR rm WITH CREDIT_QUOTA = 1000 TRIGGERS ON 90 PERCENT DO NOTIFY;",
    );
    assert!(rules.contains("SNW-RESMON-NO-SUSPEND"), "got {rules:?}");
}

#[test]
fn test_resource_monitor_suspend_immediate_counts_as_enforcing() {
    let rules = analyze_and_get_rules(
        "CREATE RESOURCE MONITOR rm WITH CREDIT_QUOTA = 1000 TRIGGERS ON 100 PERCENT DO SUSPEND_IMMEDIATE;",
    );
    assert!(
        !rules.contains("SNW-RESMON-NO-SUSPEND"),
        "SUSPEND_IMMEDIATE enforces a cap, got {rules:?}"
    );
}

#[test]
fn test_resource_monitor_quota_changed() {
    let rules = analyze_and_get_rules("ALTER RESOURCE MONITOR rm SET CREDIT_QUOTA = 5000;");
    assert!(rules.contains("SNW-RESMON-QUOTA-CHG"), "got {rules:?}");
}

#[test]
fn test_resource_monitor_triggers_changed() {
    let rules =
        analyze_and_get_rules("ALTER RESOURCE MONITOR rm SET TRIGGERS ON 50 PERCENT DO SUSPEND;");
    assert!(rules.contains("SNW-RESMON-TRIGGERS-CHG"), "got {rules:?}");
}

#[test]
fn test_resource_monitor_drop_high() {
    let report = analyze_risk("DROP RESOURCE MONITOR IF EXISTS rm;").expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("SNW-RESMON-DROP"), "got {rules:?}");
    assert!(
        report.summary.high_count >= 1,
        "dropping a cost guardrail is high severity"
    );
}

// ───────────────────────── negative / routing cases ─────────────────────────

#[test]
fn test_warehouse_resmon_assignment_does_not_fire_resmon_rules() {
    // The warehouse-side `RESOURCE_MONITOR = x` property is a distinct
    // construct (INFO-SNW-WH-RESMON) and must not trip the RESOURCE
    // MONITOR object rules.
    let rules = analyze_and_get_rules(
        "CREATE WAREHOUSE wh WITH WAREHOUSE_SIZE = 'XSMALL' RESOURCE_MONITOR = my_rm;",
    );
    assert!(
        !rules.iter().any(|r| r.contains("RESMON-DROP")
            || r.contains("RESMON-NO-SUSPEND")
            || r.contains("RESMON-TRIGGERS")
            || r.contains("RESMON-QUOTA")),
        "warehouse monitor assignment must not fire RESOURCE MONITOR object rules, got {rules:?}"
    );
}

#[test]
fn test_repeated_triggers_keyword_tolerated() {
    // Some authors repeat the `TRIGGERS` keyword before each clause; the
    // whole statement must parse as one ALTER (not leave a dangling opaque
    // tail) and fire TRIGGERS-CHG.
    let sql = "ALTER RESOURCE MONITOR rm SET TRIGGERS ON 90 PERCENT DO NOTIFY TRIGGERS ON 100 PERCENT DO NOTIFY;";
    assert_formats_safe(sql);
    let rules = analyze_and_get_rules(sql);
    assert!(rules.contains("SNW-RESMON-TRIGGERS-CHG"), "got {rules:?}");
}

#[test]
fn test_alter_quota_only_does_not_fire_triggers_changed() {
    let rules = analyze_and_get_rules("ALTER RESOURCE MONITOR rm SET CREDIT_QUOTA = 5000;");
    assert!(
        !rules.contains("SNW-RESMON-TRIGGERS-CHG"),
        "a quota-only ALTER must not fire TRIGGERS-CHG, got {rules:?}"
    );
}
