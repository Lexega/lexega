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
            .findings
            .iter()
            .map(|f| match f {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
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

// ── ALTER USER: network policy removal, key credentials, re-enabling ─

#[test]
fn alter_user_unset_network_policy_flags() {
    for sql in [
        "ALTER USER bob UNSET NETWORK_POLICY;",
        "alter user bob unset network_policy;",
        "ALTER USER IF EXISTS bob UNSET MINS_TO_BYPASS_MFA, NETWORK_POLICY;",
        "ALTER USER bob UNSET NETWORK_POLICY, DEFAULT_ROLE;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(rules.contains("SNW-USER-NETPOL-UNSET"), "{sql}: {rules:?}");
    }
}

#[test]
fn alter_user_set_network_policy_does_not_flag_unset() {
    let rules = analyze_and_get_rules("ALTER USER bob SET NETWORK_POLICY = corp_only;");
    assert!(!rules.contains("SNW-USER-NETPOL-UNSET"));
}

#[test]
fn alter_user_unset_other_property_does_not_flag_unset() {
    let rules = analyze_and_get_rules("ALTER USER bob UNSET DEFAULT_ROLE;");
    assert!(!rules.contains("SNW-USER-NETPOL-UNSET"));
}

#[test]
fn alter_account_unset_network_policy_is_not_a_user_finding() {
    let rules = analyze_and_get_rules("ALTER ACCOUNT UNSET NETWORK_POLICY;");
    assert!(rules.contains("SNW-ACCT-NETPOL-UNSET"));
    assert!(!rules.contains("SNW-USER-NETPOL-UNSET"));
}

#[test]
fn alter_user_set_rsa_key_flags() {
    for sql in [
        "ALTER USER bob SET RSA_PUBLIC_KEY = 'MIIBIjAN';",
        "ALTER USER bob SET RSA_PUBLIC_KEY_2 = 'MIIBIjAN';",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(rules.contains("SNW-USER-KEY-SET"), "{sql}: {rules:?}");
    }
}

#[test]
fn create_user_with_key_does_not_flag_key_set() {
    let rules = analyze_and_get_rules("CREATE USER svc RSA_PUBLIC_KEY = 'MIIB...';");
    assert!(!rules.contains("SNW-USER-KEY-SET"));
}

#[test]
fn alter_user_unset_rsa_key_does_not_flag_key_set() {
    let rules = analyze_and_get_rules("ALTER USER bob UNSET RSA_PUBLIC_KEY;");
    assert!(!rules.contains("SNW-USER-KEY-SET"));
}

/// Rule ids raised on `sql` read under `dialect`.
fn rules_in(dialect: lexega_core::dialect::DialectRef, sql: &str) -> HashSet<String> {
    let config = lexega_core::analyzer::AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    match lexega_core::api::analyze_risk_with_policy_config(sql, &config) {
        Ok(report) => report
            .entries()
            .map(|f| match f {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect(),
        Err(e) => panic!("{sql}: {e:?}"),
    }
}

#[test]
fn password_set_on_a_user_or_role_flags_in_every_dialect() {
    use lexega_core::dialect::{mssql, postgres, redshift, snowflake};
    for (dialect, statements) in [
        (
            snowflake(),
            vec![
                "ALTER USER bob SET PASSWORD = 'Qw7Zx9Rl!pw';",
                "ALTER USER bob SET PASSWORD = '${BOB_PW}';",
                "ALTER USER bob SET PASSWORD = 'REPLACE_ME';",
                "alter user bob set password = 'x' must_change_password = true;",
            ],
        ),
        (
            mssql(),
            vec![
                "ALTER USER bob WITH PASSWORD = 'Qw7Zx9Rl!pw';",
                "ALTER USER bob WITH PASSWORD = '${BOB_PW}';",
                "ALTER USER bob WITH PASSWORD = 'REPLACE_ME';",
            ],
        ),
        (
            postgres(),
            vec![
                "ALTER USER bob WITH PASSWORD 'Qw7Zx9Rl!pw';",
                "ALTER USER bob PASSWORD 'Qw7Zx9Rl!pw';",
                "ALTER USER bob WITH ENCRYPTED PASSWORD 'Qw7Zx9Rl!pw';",
                "ALTER ROLE bob PASSWORD '${BOB_PW}';",
                "ALTER ROLE bob PASSWORD 'REPLACE_ME';",
            ],
        ),
        (
            redshift(),
            vec![
                "ALTER USER bob PASSWORD 'Qw7Zx9Rl!pw';",
                "ALTER USER bob WITH PASSWORD '${BOB_PW}';",
            ],
        ),
    ] {
        for sql in statements {
            let rules = rules_in(dialect.clone(), sql);
            assert!(rules.contains("USER-PWD-SET"), "{sql}: {rules:?}");
        }
    }
}

#[test]
fn password_set_keeps_the_value_findings() {
    use lexega_core::dialect::snowflake;
    let rules = rules_in(snowflake(), "ALTER USER bob SET PASSWORD = 'Qw7Zx9Rl!pw';");
    assert!(rules.contains("CRED-PWD-LEAK"), "{rules:?}");
    let rules = rules_in(snowflake(), "ALTER USER bob SET PASSWORD = 'REPLACE_ME';");
    assert!(rules.contains("CRED-DUMMY-VALUE"), "{rules:?}");
}

#[test]
fn password_set_is_not_raised_by_other_clauses() {
    use lexega_core::dialect::{mssql, postgres, snowflake};
    for (dialect, sql) in [
        (snowflake(), "CREATE USER bob PASSWORD = 'Qw7Zx9Rl!pw';"),
        (
            snowflake(),
            "ALTER USER bob SET MUST_CHANGE_PASSWORD = TRUE;",
        ),
        (snowflake(), "ALTER USER bob SET PASSWORD POLICY pp;"),
        (snowflake(), "ALTER USER bob UNSET PASSWORD;"),
        (mssql(), "CREATE USER bob WITH PASSWORD = 'Qw7Zx9Rl!pw';"),
        (postgres(), "CREATE ROLE bob PASSWORD 'Qw7Zx9Rl!pw';"),
        (postgres(), "ALTER ROLE bob PASSWORD NULL;"),
        (postgres(), "ALTER ROLE bob WITH LOGIN;"),
    ] {
        let rules = rules_in(dialect, sql);
        assert!(!rules.contains("USER-PWD-SET"), "{sql}: {rules:?}");
    }
}

#[test]
fn alter_user_disabled_false_flags() {
    let rules = analyze_and_get_rules("ALTER USER bob SET DISABLED = FALSE;");
    assert!(rules.contains("SNW-USER-ENABLE"));
}

#[test]
fn alter_user_disabled_true_does_not_flag_enable() {
    let rules = analyze_and_get_rules("ALTER USER bob SET DISABLED = TRUE;");
    assert!(!rules.contains("SNW-USER-ENABLE"));
}
