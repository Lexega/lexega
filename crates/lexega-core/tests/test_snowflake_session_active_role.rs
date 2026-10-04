// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for session-context-aware analysis: the active session role
//! established by `USE ROLE` is folded into each statement's facts so
//! rules can compose it. Exercises `SNW-SESSION-GRANT-UNDER-ACCOUNTADMIN`
//! and the per-position correctness of the active-role fold (a statement
//! sees the role in effect when it runs, not the whole-script last role).

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const RULE: &str = "SNW-SESSION-GRANT-UNDER-ACCOUNTADMIN";

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
fn grant_under_accountadmin_fires() {
    let ids = analyze_and_get_rules("USE ROLE ACCOUNTADMIN;\nGRANT SELECT ON TABLE t TO ROLE r;");
    assert!(ids.contains(RULE), "ids={:?}", ids);
}

#[test]
fn grant_under_securityadmin_silent() {
    // Same grant, different active role: SECURITYADMIN is the recommended
    // role for grants, so the rule stays silent.
    let ids = analyze_and_get_rules("USE ROLE SECURITYADMIN;\nGRANT SELECT ON TABLE t TO ROLE r;");
    assert!(!ids.contains(RULE), "ids={:?}", ids);
}

#[test]
fn grant_without_use_role_silent() {
    // No session role established — nothing to flag.
    let ids = analyze_and_get_rules("GRANT SELECT ON TABLE t TO ROLE r;");
    assert!(!ids.contains(RULE), "ids={:?}", ids);
}

#[test]
fn grant_before_accountadmin_not_flagged_by_later_role() {
    // Per-position correctness: a grant that PRECEDES `USE ROLE
    // ACCOUNTADMIN` runs under the prior (here unset) role. A later
    // ACCOUNTADMIN must not retroactively flag it.
    let ids = analyze_and_get_rules(
        "GRANT SELECT ON TABLE a TO ROLE r1;\nUSE ROLE ACCOUNTADMIN;\nSELECT 1;",
    );
    assert!(!ids.contains(RULE), "ids={:?}", ids);
}

#[test]
fn role_transition_latest_wins() {
    // Active role at the grant is SECURITYADMIN (the most recent USE
    // ROLE), not the earlier ACCOUNTADMIN.
    let ids = analyze_and_get_rules(
        "USE ROLE ACCOUNTADMIN;\nUSE ROLE SECURITYADMIN;\nGRANT SELECT ON TABLE t TO ROLE r;",
    );
    assert!(!ids.contains(RULE), "ids={:?}", ids);
}

#[test]
fn active_role_normalized_case_insensitive() {
    // Lowercase role normalizes to ACCOUNTADMIN and fires (predicate
    // matches the normalized identifier, not the raw spelling).
    let ids = analyze_and_get_rules("use role accountadmin;\ngrant select on table t to role r;");
    assert!(ids.contains(RULE), "ids={:?}", ids);
}

#[test]
fn grant_after_accountadmin_fires_across_multiple_grants() {
    // Both grants run under ACCOUNTADMIN; the rule fires.
    let ids = analyze_and_get_rules(
        "USE ROLE ACCOUNTADMIN;\nGRANT SELECT ON TABLE a TO ROLE r1;\nGRANT INSERT ON TABLE b TO ROLE r2;",
    );
    assert!(ids.contains(RULE), "ids={:?}", ids);
}
