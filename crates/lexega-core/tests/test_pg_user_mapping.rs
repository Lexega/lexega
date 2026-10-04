// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL/MED `CREATE USER MAPPING` (PostgreSQL FDW).
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped), governance
//! — including that the critical `CRED-PWD-LEAK` detection and password
//! redaction apply, that `FOR PUBLIC` raises a broad-access finding, and that
//! no `ROLE-NEW` fires — and the dialect non-regression that `CREATE USER
//! MAPPING` with no `FOR` clause is an
//! ordinary `CREATE USER` whose user is named `MAPPING` (e.g. Snowflake).

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn cfg(d: lexega_core::dialect::DialectRef) -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    }
}

fn rule_ids_d(sql: &str, d: lexega_core::dialect::DialectRef) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &cfg(d)).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn rule_ids(sql: &str) -> Vec<String> {
    rule_ids_d(sql, dialect::postgres())
}

fn roundtrip_not_skipped(sql: &str, d: lexega_core::dialect::DialectRef) {
    let mut config = FormatterConfig::default();
    config.dialect = d.clone();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let report = analyze_risk_with_policy_config(sql, &cfg(d)).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "must be analyzed, not skipped: {sql}"
    );
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_for_targets_and_options_recognized() {
    let pg = dialect::postgres();
    roundtrip_not_skipped(
        "CREATE USER MAPPING FOR app SERVER s OPTIONS (user 'u', password 'p');",
        pg.clone(),
    );
    roundtrip_not_skipped(
        "CREATE USER MAPPING FOR PUBLIC SERVER s OPTIONS (user 'u');",
        pg.clone(),
    );
    roundtrip_not_skipped(
        "CREATE USER MAPPING IF NOT EXISTS FOR CURRENT_USER SERVER s;",
        pg.clone(),
    );
    // Quoted role name, no options.
    roundtrip_not_skipped("CREATE USER MAPPING FOR \"my role\" SERVER s;", pg);
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "CREATE USER MAPPING FOR a SERVER s1 OPTIONS (user 'u1', password 'p1');\n\
         CREATE USER MAPPING FOR PUBLIC SERVER s2 OPTIONS (user 'u2');\n\
         CREATE USER MAPPING IF NOT EXISTS FOR CURRENT_USER SERVER s3;",
        dialect::postgres(),
    );
}

// ── Governance: false-positive removed + correct classification ─────────

#[test]
fn test_no_spurious_role_creation_finding() {
    // The headline fix: a user mapping is not a role. ROLE-NEW must be gone.
    let ids = rule_ids("CREATE USER MAPPING FOR app SERVER s OPTIONS (user 'u', password 'p');");
    assert!(
        !ids.contains(&"ROLE-NEW".to_string()),
        "user mapping must NOT fire the role-creation finding. Got: {ids:?}"
    );
    assert!(
        ids.contains(&"INFO-PG-FDW-USER-MAPPING".to_string()),
        "user mapping should fire its own info signal. Got: {ids:?}"
    );
}

#[test]
fn test_password_leak_detection_survives_reroute() {
    // CRED-PWD-LEAK must still fire via the create_user_mapping branch — the
    // re-route away from CREATE USER must not lose critical secret detection.
    let ids =
        rule_ids("CREATE USER MAPPING FOR app SERVER s OPTIONS (user 'u', password 'secret');");
    assert!(
        ids.contains(&"CRED-PWD-LEAK".to_string()),
        "hardcoded password in a user mapping must fire CRED-PWD-LEAK. Got: {ids:?}"
    );
}

#[test]
fn test_no_password_no_cred_leak() {
    // Soundness: a mapping with no password option must not fire CRED-PWD-LEAK.
    let ids = rule_ids("CREATE USER MAPPING FOR app SERVER s OPTIONS (user 'u');");
    assert!(
        !ids.contains(&"CRED-PWD-LEAK".to_string()),
        "a mapping without a password must NOT fire CRED-PWD-LEAK. Got: {ids:?}"
    );
}

#[test]
fn test_for_public_fires_broad_rule() {
    let ids = rule_ids("CREATE USER MAPPING FOR PUBLIC SERVER s OPTIONS (user 'u');");
    assert!(
        ids.contains(&"PG-FDW-USER-MAPPING-PUBLIC".to_string()),
        "FOR PUBLIC should fire the broad-access rule. Got: {ids:?}"
    );
}

#[test]
fn test_specific_role_does_not_fire_public_rule() {
    // Soundness: the public rule keys on the typed is_public flag.
    let ids = rule_ids("CREATE USER MAPPING FOR app SERVER s OPTIONS (user 'u');");
    assert!(
        !ids.contains(&"PG-FDW-USER-MAPPING-PUBLIC".to_string()),
        "a mapping for a specific role must NOT fire the public rule. Got: {ids:?}"
    );
}

// ── ALTER USER MAPPING ──────────────────────────────────────────────────

#[test]
fn test_alter_recognized_and_roundtrips() {
    let pg = dialect::postgres();
    roundtrip_not_skipped(
        "ALTER USER MAPPING FOR app SERVER s OPTIONS (SET password 'new', ADD sslmode 'require');",
        pg.clone(),
    );
    roundtrip_not_skipped(
        "ALTER USER MAPPING FOR PUBLIC SERVER s OPTIONS (DROP password);",
        pg,
    );
}

#[test]
fn test_alter_no_spurious_role_change_finding() {
    // The fix: ALTER USER MAPPING is not ALTER USER. ROLE-CHG must be gone.
    let ids = rule_ids("ALTER USER MAPPING FOR app SERVER s OPTIONS (SET password 'new');");
    assert!(
        !ids.contains(&"ROLE-CHG".to_string()),
        "altering a user mapping must NOT fire the role-change finding. Got: {ids:?}"
    );
    assert!(
        ids.contains(&"INFO-PG-FDW-USER-MAPPING".to_string()),
        "altering a user mapping should fire its own signal. Got: {ids:?}"
    );
}

#[test]
fn test_alter_set_password_fires_cred_leak() {
    let ids = rule_ids("ALTER USER MAPPING FOR app SERVER s OPTIONS (SET password 'new');");
    assert!(
        ids.contains(&"CRED-PWD-LEAK".to_string()),
        "ALTER … SET password '<lit>' must fire CRED-PWD-LEAK. Got: {ids:?}"
    );
}

#[test]
fn test_alter_drop_password_no_cred_leak() {
    // Soundness: DROP password removes the option (no value literal) — not a leak.
    let ids = rule_ids("ALTER USER MAPPING FOR app SERVER s OPTIONS (DROP password);");
    assert!(
        !ids.contains(&"CRED-PWD-LEAK".to_string()),
        "ALTER … DROP password must NOT fire CRED-PWD-LEAK. Got: {ids:?}"
    );
}

#[test]
fn test_alter_for_public_fires_broad_rule() {
    let ids = rule_ids("ALTER USER MAPPING FOR PUBLIC SERVER s OPTIONS (SET user 'u');");
    assert!(
        ids.contains(&"PG-FDW-USER-MAPPING-PUBLIC".to_string()),
        "ALTER … FOR PUBLIC should fire the broad-access rule. Got: {ids:?}"
    );
}

// ── DROP USER MAPPING ───────────────────────────────────────────────────

#[test]
fn test_drop_recognized_and_roundtrips() {
    let pg = dialect::postgres();
    roundtrip_not_skipped("DROP USER MAPPING FOR app SERVER s;", pg.clone());
    roundtrip_not_skipped("DROP USER MAPPING IF EXISTS FOR CURRENT_USER SERVER s;", pg);
}

#[test]
fn test_drop_no_spurious_role_drop_and_not_truncated() {
    let report = analyze_risk_with_policy_config(
        "DROP USER MAPPING FOR app SERVER s;",
        &cfg(dialect::postgres()),
    )
    .expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "DROP USER MAPPING must not leave an orphaned opaque statement"
    );
    let ids = rule_ids("DROP USER MAPPING FOR app SERVER s;");
    assert!(
        !ids.contains(&"ROLE-DROP".to_string()),
        "dropping a user mapping must NOT fire the role-drop finding. Got: {ids:?}"
    );
    assert!(
        ids.contains(&"INFO-PG-FDW-USER-MAPPING-DROP".to_string()),
        "dropping a user mapping should fire its own signal. Got: {ids:?}"
    );
}

// ── Dialect non-regression: CREATE / ALTER / DROP USER named MAPPING ─────

#[test]
fn test_create_user_named_mapping_not_hijacked() {
    // No FOR clause → this is an ordinary CREATE USER whose user is named
    // MAPPING (e.g. on Snowflake, which has no FDW). The structural guard must
    // leave it on the principal parser, so it stays a role-creation statement.
    for (sql, d) in [
        ("CREATE USER MAPPING;", dialect::snowflake()),
        ("CREATE USER MAPPING PASSWORD = 'x';", dialect::snowflake()),
    ] {
        roundtrip_not_skipped(sql, d.clone());
        let ids = rule_ids_d(sql, d);
        assert!(
            !ids.iter().any(|id| id.starts_with("PG-FDW-USER-MAPPING")
                || id == "INFO-PG-FDW-USER-MAPPING"),
            "CREATE USER named MAPPING must not fire a user-mapping finding: {sql}. Got: {ids:?}"
        );
        assert!(
            ids.contains(&"ROLE-NEW".to_string()),
            "CREATE USER named MAPPING is still a principal creation: {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_alter_drop_user_named_mapping_not_hijacked() {
    // ALTER / DROP USER MAPPING with no FOR clause is an ordinary principal
    // statement on a user named MAPPING — the structural guard leaves it alone.
    let sf = dialect::snowflake();
    for (sql, expected) in [
        ("ALTER USER MAPPING SET PASSWORD = 'x';", "ROLE-CHG"),
        ("DROP USER MAPPING;", "ROLE-DROP"),
    ] {
        roundtrip_not_skipped(sql, sf.clone());
        let ids = rule_ids_d(sql, sf.clone());
        assert!(
            !ids.iter().any(|id| id.starts_with("PG-FDW-USER-MAPPING")
                || id == "INFO-PG-FDW-USER-MAPPING"
                || id == "INFO-PG-FDW-USER-MAPPING-DROP"),
            "principal stmt on user MAPPING must not fire a user-mapping finding: {sql}. Got: {ids:?}"
        );
        assert!(
            ids.contains(&expected.to_string()),
            "{sql} should remain a principal statement ({expected}). Got: {ids:?}"
        );
    }
}
