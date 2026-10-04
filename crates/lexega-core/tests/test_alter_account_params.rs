// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake generic `ALTER ACCOUNT SET/UNSET <param>` governance.
//!
//! The AUTHENTICATION POLICY attachment slice is covered elsewhere; this
//! covers the account-level parameter facts (ddl.account.*) and the
//! SNW-ACCT-* rules.

use lexega_core::analyzer::RuleMatch;

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

#[test]
fn test_unload_to_inline_url_is_critical() {
    let report = analyze_risk("ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = FALSE;")
        .expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("SNW-ACCT-UNLOAD-INLINE"), "got {rules:?}");
    assert!(rules.contains("INFO-SNW-ACCT-PARAM-CHG"), "got {rules:?}");
    assert!(
        report.summary.critical_count >= 1,
        "inline-URL unload is a critical exfil path"
    );
}

#[test]
fn test_unload_to_inline_url_true_is_safe() {
    // The protective direction (= TRUE) must NOT fire the critical rule.
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = TRUE;");
    assert!(
        !rules.contains("SNW-ACCT-UNLOAD-INLINE"),
        "= TRUE is the safe direction, got {rules:?}"
    );
    assert!(rules.contains("INFO-SNW-ACCT-PARAM-CHG"), "got {rules:?}");
}

#[test]
fn test_stage_integration_relaxed() {
    let rules = analyze_and_get_rules(
        "ALTER ACCOUNT SET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = FALSE;",
    );
    assert!(rules.contains("SNW-ACCT-STAGE-INTEG-OFF"), "got {rules:?}");
}

#[test]
fn test_network_policy_set_and_unset() {
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET NETWORK_POLICY = corp_pol;");
    assert!(rules.contains("SNW-ACCT-NETPOL-SET"), "got {rules:?}");
    assert!(!rules.contains("SNW-ACCT-NETPOL-UNSET"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER ACCOUNT UNSET NETWORK_POLICY;");
    assert!(rules.contains("SNW-ACCT-NETPOL-UNSET"), "got {rules:?}");
    assert!(rules.contains("INFO-SNW-ACCT-PARAM-CHG"), "got {rules:?}");
    assert!(!rules.contains("SNW-ACCT-NETPOL-SET"), "got {rules:?}");
}

#[test]
fn test_multi_param_set_extracts_each() {
    // A param followed by another (comma or whitespace separated) must still
    // match by exact value — the leading param's value scan must not absorb
    // the separator.
    let rules = analyze_and_get_rules(
        "ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = FALSE, NETWORK_POLICY = 'wide_open';",
    );
    assert!(rules.contains("SNW-ACCT-UNLOAD-INLINE"), "got {rules:?}");
    assert!(rules.contains("SNW-ACCT-NETPOL-SET"), "got {rules:?}");
}

#[test]
fn test_rekey_off_and_unredacted_errors() {
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET PERIODIC_DATA_REKEYING = FALSE;");
    assert!(rules.contains("SNW-ACCT-REKEY-OFF"), "got {rules:?}");

    let rules =
        analyze_and_get_rules("ALTER ACCOUNT SET ENABLE_UNREDACTED_QUERY_SYNTAX_ERROR = TRUE;");
    assert!(rules.contains("SNW-ACCT-UNREDACTED-ERR"), "got {rules:?}");
}

// ───────────────────────── negative cases ─────────────────────────

#[test]
fn test_benign_param_fires_only_baseline() {
    // A benign retention bump fires the info baseline but no specific danger.
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET DATA_RETENTION_TIME_IN_DAYS = 7;");
    assert!(rules.contains("INFO-SNW-ACCT-PARAM-CHG"), "got {rules:?}");
    assert!(
        !rules.iter().any(|r| r.starts_with("SNW-ACCT-")),
        "no specific danger rule should fire, got {rules:?}"
    );
}

#[test]
fn test_authentication_policy_attachment_not_param_facts() {
    // SET AUTHENTICATION POLICY is the attachment slice, not a generic param —
    // it must not fire the generic param baseline.
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET AUTHENTICATION POLICY = my_pol;");
    assert!(
        !rules.contains("INFO-SNW-ACCT-PARAM-CHG"),
        "authpol attachment is not a generic param, got {rules:?}"
    );
}

// ──────────────────── data-retention / Time Travel ────────────────────

#[test]
fn test_account_data_retention_zero_disables_time_travel() {
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET DATA_RETENTION_TIME_IN_DAYS = 0;");
    assert!(rules.contains("SNW-ACCT-RETENTION-ZERO"), "got {rules:?}");
}

#[test]
fn test_account_min_data_retention_zero_removes_floor() {
    let rules = analyze_and_get_rules("ALTER ACCOUNT SET MIN_DATA_RETENTION_TIME_IN_DAYS = 0;");
    assert!(
        rules.contains("SNW-ACCT-MIN-RETENTION-ZERO"),
        "got {rules:?}"
    );
    // MIN_DATA_RETENTION_TIME_IN_DAYS must not be read as the object-level
    // DATA_RETENTION_TIME_IN_DAYS rule.
    assert!(
        !rules.contains("SNW-ACCT-RETENTION-ZERO"),
        "MIN floor must not alias the account default, got {rules:?}"
    );
}
