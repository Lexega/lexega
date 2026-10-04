// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Governance/security rules over `SHOW` reconnaissance facts.
//!
//! `SHOW` is read-only metadata enumeration, so these rules cap at low/info
//! and stay narrow — broad `SHOW` traffic (tooling, dashboards) must not fire.
//! Covers privilege-graph recon on admin roles, account-wide grant
//! enumeration, and security-surface enumeration. The privileged-role match
//! is case-insensitive (the grant name is normalized in the facts).

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

// ───────────────── privilege-graph recon on admin roles ─────────────────

#[test]
fn test_show_grants_to_privileged_role() {
    let rules = analyze_and_get_rules("SHOW GRANTS TO ROLE ACCOUNTADMIN;");
    assert!(
        rules.contains("SHOW-GRANTS-PRIV-ROLE-RECON"),
        "SHOW GRANTS TO ROLE ACCOUNTADMIN should fire SHOW-GRANTS-PRIV-ROLE-RECON, got {rules:?}"
    );
}

#[test]
fn test_show_grants_of_privileged_role_lowercase() {
    // The grant name is normalized in the facts, so lowercase matches the
    // upper-cased privileged-role list.
    let rules = analyze_and_get_rules("SHOW GRANTS OF ROLE securityadmin;");
    assert!(
        rules.contains("SHOW-GRANTS-PRIV-ROLE-RECON"),
        "lowercase OF ROLE securityadmin should still fire SHOW-GRANTS-PRIV-ROLE-RECON, got {rules:?}"
    );
}

#[test]
fn test_show_grants_nonprivileged_role_negative() {
    let rules = analyze_and_get_rules("SHOW GRANTS TO ROLE analyst;");
    assert!(
        !rules.contains("SHOW-GRANTS-PRIV-ROLE-RECON"),
        "SHOW GRANTS on a non-privileged role must NOT fire, got {rules:?}"
    );
}

#[test]
fn test_show_grants_to_user_named_like_role_negative() {
    // A USER (not a ROLE) named like an admin role must not trip the role rule.
    let rules = analyze_and_get_rules("SHOW GRANTS TO USER accountadmin;");
    assert!(
        !rules.contains("SHOW-GRANTS-PRIV-ROLE-RECON"),
        "SHOW GRANTS TO USER must not fire the role-recon rule, got {rules:?}"
    );
}

// ───────────────── account-wide grant enumeration ─────────────────

#[test]
fn test_show_grants_on_account() {
    let rules = analyze_and_get_rules("SHOW GRANTS ON ACCOUNT;");
    assert!(
        rules.contains("SHOW-GRANTS-ON-ACCOUNT-RECON"),
        "SHOW GRANTS ON ACCOUNT should fire SHOW-GRANTS-ON-ACCOUNT-RECON, got {rules:?}"
    );
}

// ───────────────── security-surface enumeration (info) ─────────────────

#[test]
fn test_show_security_surface_info() {
    for sql in [
        "SHOW MASKING POLICIES;",
        "SHOW ROW ACCESS POLICIES;",
        "SHOW NETWORK POLICIES;",
        "SHOW USERS;",
        "SHOW ROLES;",
        "SHOW SECRETS;",
        "SHOW INTEGRATIONS;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(
            rules.contains("INFO-SHOW-SECURITY-SURFACE"),
            "{sql:?} should fire INFO-SHOW-SECURITY-SURFACE, got {rules:?}"
        );
    }
}

// ───────────────── negative: benign SHOW must stay silent ─────────────────

#[test]
fn test_benign_show_fires_no_security_rules() {
    for sql in [
        "SHOW TABLES;",
        "SHOW VIEWS;",
        "SHOW GRANTS;", // current-user grants — benign
        "SHOW GRANTS TO ROLE analyst;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(
            !rules.contains("SHOW-GRANTS-PRIV-ROLE-RECON")
                && !rules.contains("SHOW-GRANTS-ON-ACCOUNT-RECON")
                && !rules.contains("INFO-SHOW-SECURITY-SURFACE"),
            "benign {sql:?} must not fire SHOW security rules, got {rules:?}"
        );
    }
}
