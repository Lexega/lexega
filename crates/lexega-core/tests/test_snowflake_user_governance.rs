// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake CREATE/ALTER USER governance object-property
//! recognition and the SNW-USER-* rule cluster. The properties are
//! recognized into `ddl.principal.snowflake_user.*`; the danger verdict
//! (privileged default role, MFA-bypass window, deprecated TYPE,
//! password without forced rotation) lives in YAML.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => report
            .signals
            .iter()
            .filter_map(|f| match f {
                RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
            })
            .collect(),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

// ── DEFAULT_ROLE = <privileged system role> ─────────────────────────

#[test]
fn default_role_accountadmin_flags() {
    let rules = analyze_and_get_rules("CREATE USER svc DEFAULT_ROLE = ACCOUNTADMIN;");
    assert!(rules.contains("SNW-USER-DEFAULT-ROLE-PRIV"));
}

#[test]
fn default_role_securityadmin_via_alter_flags() {
    let rules = analyze_and_get_rules("ALTER USER svc SET DEFAULT_ROLE = SECURITYADMIN;");
    assert!(rules.contains("SNW-USER-DEFAULT-ROLE-PRIV"));
}

#[test]
fn default_role_lowercase_normalizes_and_flags() {
    let rules = analyze_and_get_rules("create user svc default_role = sysadmin;");
    assert!(rules.contains("SNW-USER-DEFAULT-ROLE-PRIV"));
}

#[test]
fn default_role_non_privileged_does_not_flag() {
    let rules = analyze_and_get_rules("CREATE USER svc DEFAULT_ROLE = ANALYST;");
    assert!(!rules.contains("SNW-USER-DEFAULT-ROLE-PRIV"));
}

// ── MINS_TO_BYPASS_MFA > 0 ──────────────────────────────────────────

#[test]
fn mfa_bypass_window_flags() {
    let rules = analyze_and_get_rules("CREATE USER svc MINS_TO_BYPASS_MFA = 60;");
    assert!(rules.contains("SNW-USER-MFA-BYPASS"));
}

#[test]
fn mfa_bypass_zero_does_not_flag() {
    let rules = analyze_and_get_rules("CREATE USER svc MINS_TO_BYPASS_MFA = 0;");
    assert!(!rules.contains("SNW-USER-MFA-BYPASS"));
}

// ── TYPE = LEGACY_SERVICE ───────────────────────────────────────────

#[test]
fn type_legacy_service_flags() {
    let rules = analyze_and_get_rules("CREATE USER svc TYPE = LEGACY_SERVICE;");
    assert!(rules.contains("SNW-USER-TYPE-LEGACY"));
}

#[test]
fn type_service_does_not_flag() {
    let rules = analyze_and_get_rules("CREATE USER svc TYPE = SERVICE;");
    assert!(!rules.contains("SNW-USER-TYPE-LEGACY"));
}

// ── PASSWORD set without MUST_CHANGE_PASSWORD ───────────────────────

#[test]
fn password_without_must_change_flags() {
    let rules = analyze_and_get_rules(
        "CREATE USER bob PASSWORD = 'Secret123!' MUST_CHANGE_PASSWORD = FALSE;",
    );
    assert!(rules.contains("SNW-USER-PWD-NO-CHANGE"));
}

#[test]
fn password_with_must_change_true_does_not_flag() {
    let rules = analyze_and_get_rules(
        "CREATE USER bob PASSWORD = 'Secret123!' MUST_CHANGE_PASSWORD = TRUE;",
    );
    assert!(!rules.contains("SNW-USER-PWD-NO-CHANGE"));
}

#[test]
fn password_without_must_change_clause_does_not_flag() {
    // No explicit MUST_CHANGE_PASSWORD clause: the recognizer captures no
    // value, so `must_change_password: false` cannot match.
    let rules = analyze_and_get_rules("CREATE USER bob PASSWORD = 'Secret123!';");
    assert!(!rules.contains("SNW-USER-PWD-NO-CHANGE"));
}

// ── A benign user with none of the flagged properties stays quiet ───

#[test]
fn benign_user_emits_no_snw_user_rules() {
    let rules = analyze_and_get_rules(
        "CREATE USER svc TYPE = SERVICE DEFAULT_ROLE = ANALYST \
         MINS_TO_BYPASS_MFA = 0 RSA_PUBLIC_KEY = 'MIIB...';",
    );
    assert!(!rules.contains("SNW-USER-DEFAULT-ROLE-PRIV"));
    assert!(!rules.contains("SNW-USER-MFA-BYPASS"));
    assert!(!rules.contains("SNW-USER-TYPE-LEGACY"));
    assert!(!rules.contains("SNW-USER-PWD-NO-CHANGE"));
}
