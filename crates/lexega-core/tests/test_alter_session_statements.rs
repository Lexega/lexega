// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake `ALTER SESSION { SET | UNSET }` statements.
//!
//! Covers parsing/formatting round-trips and the INFO-SNW-SESSION-PARAM-* /
//! SNW-SESSION-* governance rules, plus the disambiguation from the
//! `ALTER SESSION POLICY` sibling (SESSION lexes as an identifier, so the
//! ALTER dispatcher peeks past it for SET/UNSET).

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
fn test_alter_session_set_basic() {
    assert_formats_safe("ALTER SESSION SET TIMEZONE = 'America/Los_Angeles';");
}

#[test]
fn test_alter_session_set_value_kinds() {
    assert_formats_safe(
        "ALTER SESSION SET QUERY_TAG = 'ETL_JOB_42';\n\
         ALTER SESSION SET AUTOCOMMIT = FALSE;\n\
         ALTER SESSION SET ERROR_ON_NONDETERMINISTIC_MERGE = TRUE;\n\
         ALTER SESSION SET STATEMENT_TIMEOUT_IN_SECONDS = 3600;",
    );
}

#[test]
fn test_alter_session_set_multiple_params() {
    assert_formats_safe("ALTER SESSION SET WEEK_START = 1, WEEK_OF_YEAR_POLICY = 1;");
}

#[test]
fn test_alter_session_unset_variants() {
    assert_formats_safe(
        "ALTER SESSION UNSET TIMEZONE;\n\
         ALTER SESSION UNSET QUERY_TAG, TIMEZONE;",
    );
}

#[test]
fn test_alter_session_multi_statement() {
    assert_formats_safe(
        "ALTER SESSION SET TIMEZONE = 'UTC';\n\
         ALTER SESSION SET QUERY_TAG = 'job1';\n\
         ALTER SESSION UNSET QUERY_TAG;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_alter_session_set_info_signal() {
    let rules = analyze_and_get_rules("ALTER SESSION SET TIMEZONE = 'UTC';");
    assert!(
        rules.contains("INFO-SNW-SESSION-PARAM-SET"),
        "ALTER SESSION SET should fire INFO-SNW-SESSION-PARAM-SET, got {rules:?}"
    );
}

#[test]
fn test_alter_session_unset_info_signal() {
    let rules = analyze_and_get_rules("ALTER SESSION UNSET QUERY_TAG, TIMEZONE;");
    assert!(
        rules.contains("INFO-SNW-SESSION-PARAM-UNSET"),
        "ALTER SESSION UNSET should fire INFO-SNW-SESSION-PARAM-UNSET, got {rules:?}"
    );
}

#[test]
fn test_alter_session_stmt_timeout_disabled() {
    // The dangerous param+value (STATEMENT_TIMEOUT_IN_SECONDS = 0) is matched
    // by YAML predicate over the typed `name`/`value` facts — recognition in
    // Rust, policy in YAML.
    let rules = analyze_and_get_rules("ALTER SESSION SET STATEMENT_TIMEOUT_IN_SECONDS = 0;");
    assert!(
        rules.contains("SNW-SESSION-STMT-TIMEOUT-OFF"),
        "STATEMENT_TIMEOUT_IN_SECONDS = 0 should fire SNW-SESSION-STMT-TIMEOUT-OFF, got {rules:?}"
    );
}

#[test]
fn test_alter_session_stmt_timeout_nonzero_negative() {
    let rules = analyze_and_get_rules("ALTER SESSION SET STATEMENT_TIMEOUT_IN_SECONDS = 3600;");
    assert!(
        !rules.contains("SNW-SESSION-STMT-TIMEOUT-OFF"),
        "non-zero timeout must NOT fire SNW-SESSION-STMT-TIMEOUT-OFF, got {rules:?}"
    );
    assert!(
        rules.contains("INFO-SNW-SESSION-PARAM-SET"),
        "non-zero timeout SET should still fire the info signal, got {rules:?}"
    );
}

#[test]
fn test_alter_session_keepalive_on() {
    let rules = analyze_and_get_rules("ALTER SESSION SET CLIENT_SESSION_KEEP_ALIVE = TRUE;");
    assert!(
        rules.contains("SNW-SESSION-KEEPALIVE-ON"),
        "CLIENT_SESSION_KEEP_ALIVE = TRUE should fire SNW-SESSION-KEEPALIVE-ON, got {rules:?}"
    );
}

#[test]
fn test_alter_session_keepalive_lowercase_boolean() {
    // Boolean values are canonicalized at lowering, so lowercase `true`
    // matches the same `value: TRUE` predicate.
    let rules = analyze_and_get_rules("ALTER SESSION SET client_session_keep_alive = true;");
    assert!(
        rules.contains("SNW-SESSION-KEEPALIVE-ON"),
        "lowercase keep-alive = true should still fire SNW-SESSION-KEEPALIVE-ON, got {rules:?}"
    );
}

#[test]
fn test_alter_session_keepalive_false_negative() {
    let rules = analyze_and_get_rules("ALTER SESSION SET CLIENT_SESSION_KEEP_ALIVE = FALSE;");
    assert!(
        !rules.contains("SNW-SESSION-KEEPALIVE-ON"),
        "keep-alive = FALSE must NOT fire SNW-SESSION-KEEPALIVE-ON, got {rules:?}"
    );
}

#[test]
fn test_alter_session_nondeterministic_merge_off() {
    let rules = analyze_and_get_rules("ALTER SESSION SET ERROR_ON_NONDETERMINISTIC_MERGE = FALSE;");
    assert!(
        rules.contains("SNW-SESSION-NONDETERMINISTIC-DML"),
        "disabling nondeterministic-MERGE error should fire SNW-SESSION-NONDETERMINISTIC-DML, got {rules:?}"
    );
}

#[test]
fn test_alter_session_nondeterministic_update_off_lowercase() {
    // Lowercase param name (normalized) and lowercase boolean value both resolve.
    let rules =
        analyze_and_get_rules("ALTER SESSION SET error_on_nondeterministic_update = false;");
    assert!(
        rules.contains("SNW-SESSION-NONDETERMINISTIC-DML"),
        "disabling nondeterministic-UPDATE error should fire SNW-SESSION-NONDETERMINISTIC-DML, got {rules:?}"
    );
}

#[test]
fn test_alter_session_nondeterministic_true_negative() {
    let rules = analyze_and_get_rules("ALTER SESSION SET ERROR_ON_NONDETERMINISTIC_MERGE = TRUE;");
    assert!(
        !rules.contains("SNW-SESSION-NONDETERMINISTIC-DML"),
        "leaving the nondeterministic guard ON (TRUE) must NOT fire, got {rules:?}"
    );
}

// ───────────────── disambiguation from ALTER SESSION POLICY ─────────────────

#[test]
fn test_alter_session_set_does_not_fire_session_policy_rules() {
    // A session PARAMETER SET — even one whose name resembles a policy
    // property — routes to the parameter parser, never the policy rules.
    let rules = analyze_and_get_rules("ALTER SESSION SET SESSION_IDLE_TIMEOUT_MINS = 30;");
    assert!(
        !rules.contains("SNW-SESSPOL-IDLE-CHG") && !rules.contains("SNW-SESSPOL-IDLE-UNSET"),
        "ALTER SESSION SET must not fire session-policy rules, got {rules:?}"
    );
    assert!(
        rules.contains("INFO-SNW-SESSION-PARAM-SET"),
        "ALTER SESSION SET should still fire its own info signal, got {rules:?}"
    );
}

#[test]
fn test_alter_session_policy_still_fires_after_collision_split() {
    // Regression: the ALTER SESSION POLICY sibling must keep parsing and
    // firing its own rules after ALTER SESSION SET/UNSET was added.
    let rules =
        analyze_and_get_rules("ALTER SESSION POLICY mypol SET SESSION_IDLE_TIMEOUT_MINS = 30;");
    assert!(
        rules.contains("SNW-SESSPOL-IDLE-CHG"),
        "ALTER SESSION POLICY must still fire SNW-SESSPOL-IDLE-CHG, got {rules:?}"
    );
    assert!(
        !rules.contains("INFO-SNW-SESSION-PARAM-SET"),
        "ALTER SESSION POLICY must not fire session-parameter rules, got {rules:?}"
    );
}

#[test]
fn test_alter_session_and_policy_format_safe_together() {
    assert_formats_safe(
        "ALTER SESSION SET TIMEZONE = 'UTC';\n\
         ALTER SESSION POLICY mypol SET SESSION_IDLE_TIMEOUT_MINS = 30;",
    );
}
