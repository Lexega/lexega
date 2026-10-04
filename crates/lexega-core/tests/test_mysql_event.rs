// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `CREATE EVENT` / `ALTER EVENT` — scheduled SQL jobs.
//!
//! An event runs its `DO` body on a schedule under the definer's privileges,
//! so the scheduled-execution surface includes a recurring `DROP`/`GRANT`.
//! Covers recognition (parse + byte-exact round-trip, not skipped), the
//! one-time-vs-recurring policy split, the `DO`-body analysis, ALTER
//! reconfiguration, and the non-regression of Snowflake `CREATE EVENT TABLE`.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mysql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    }
}

fn rule_ids_cfg(sql: &str, cfg: &AnalysisConfig) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, cfg).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn rule_ids(sql: &str) -> Vec<String> {
    rule_ids_cfg(sql, &mysql_cfg())
}

fn roundtrip_not_skipped(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mysql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");
    assert_eq!(out, sql, "byte-exact round-trip expected: {sql}");

    let report = analyze_risk_with_policy_config(sql, &mysql_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "the event must be analyzed, not skipped: {sql}"
    );
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_event_forms_recognized() {
    roundtrip_not_skipped("CREATE EVENT e1 ON SCHEDULE EVERY 1 HOUR DO DELETE FROM logs;");
    roundtrip_not_skipped("CREATE EVENT IF NOT EXISTS e2 ON SCHEDULE AT '2025-01-01' DO SELECT 1;");
    roundtrip_not_skipped(
        "CREATE DEFINER = 'root'@'localhost' EVENT e ON SCHEDULE EVERY 1 DAY \
         ON COMPLETION PRESERVE DISABLE ON SLAVE DO BEGIN SELECT 1; END;",
    );
    roundtrip_not_skipped("ALTER EVENT e1 ON SCHEDULE EVERY 2 HOUR RENAME TO e2 ENABLE;");
    roundtrip_not_skipped("ALTER EVENT e1 DISABLE;");
}

#[test]
fn test_definer_current_user_form() {
    roundtrip_not_skipped(
        "CREATE DEFINER = CURRENT_USER EVENT e ON SCHEDULE EVERY 5 MINUTE DO SELECT 1;",
    );
}

// ── Governance: DEFINER security context ─────────────────────────────────

#[test]
fn test_explicit_definer_fires_definer_rule() {
    let ids = rule_ids(
        "CREATE DEFINER = 'root'@'localhost' EVENT e ON SCHEDULE EVERY 1 DAY DO DELETE FROM logs;",
    );
    assert!(
        ids.contains(&"MYSQL-EVENT-DEFINER".to_string()),
        "an explicit DEFINER account should fire the definer rule. Got: {ids:?}"
    );
}

#[test]
fn test_current_user_definer_does_not_fire_definer_rule() {
    // Recognition vs policy: the verdict keys on an EXPLICIT account, not on
    // the mere presence of a DEFINER clause. CURRENT_USER is the invoker's own
    // identity — no privilege delegation — so it stays silent.
    let ids =
        rule_ids("CREATE DEFINER = CURRENT_USER EVENT e ON SCHEDULE EVERY 1 DAY DO SELECT 1;");
    assert!(
        !ids.contains(&"MYSQL-EVENT-DEFINER".to_string()),
        "a CURRENT_USER definer must NOT fire the definer rule. Got: {ids:?}"
    );
}

#[test]
fn test_no_definer_does_not_fire_definer_rule() {
    let ids = rule_ids("CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO SELECT 1;");
    assert!(
        !ids.contains(&"MYSQL-EVENT-DEFINER".to_string()),
        "an event with no DEFINER must NOT fire the definer rule. Got: {ids:?}"
    );
}

#[test]
fn test_alter_event_definer_fires_definer_rule() {
    let ids = rule_ids("ALTER DEFINER = reporting_admin EVENT e DISABLE;");
    assert!(
        ids.contains(&"MYSQL-EVENT-DEFINER".to_string()),
        "ALTER … DEFINER with an explicit account should fire the definer rule. Got: {ids:?}"
    );
}

// ── Governance: recurring vs one-time (recognition vs policy) ────────────

#[test]
fn test_recurring_event_fires_recurring_and_info() {
    let ids = rule_ids("CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO SELECT 1;");
    assert!(
        ids.contains(&"MYSQL-EVENT-RECURRING".to_string())
            && ids.contains(&"INFO-MYSQL-EVENT".to_string()),
        "a recurring (EVERY) event should fire both rules. Got: {ids:?}"
    );
}

#[test]
fn test_one_time_event_fires_info_only() {
    // The elevated verdict keys on the recurring schedule, not on the
    // statement being an event. A one-time AT event stays info-only.
    let ids = rule_ids("CREATE EVENT e ON SCHEDULE AT '2025-01-01 00:00:00' DO SELECT 1;");
    assert!(
        ids.contains(&"INFO-MYSQL-EVENT".to_string()),
        "a one-time event should fire the info rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MYSQL-EVENT-RECURRING".to_string()),
        "a one-time (AT) event must NOT fire the recurring rule. Got: {ids:?}"
    );
}

// ── Flagship: the DO body is analyzed through the full corpus ────────────

#[test]
fn test_scheduled_drop_in_body_fires_through_corpus() {
    let ids = rule_ids("CREATE EVENT nightly ON SCHEDULE EVERY 1 DAY DO DROP TABLE audit_log;");
    assert!(
        ids.contains(&"TBL-DROP".to_string()),
        "a scheduled DROP TABLE must fire TBL-DROP from inside the event body. Got: {ids:?}"
    );
}

#[test]
fn test_compound_body_statements_each_analyze() {
    let ids = rule_ids(
        "CREATE EVENT c ON SCHEDULE EVERY 1 DAY DO BEGIN DELETE FROM a; DROP TABLE b; END;",
    );
    assert!(
        ids.contains(&"TBL-DROP".to_string()),
        "DROP TABLE inside a BEGIN…END event body must fire TBL-DROP. Got: {ids:?}"
    );
}

// ── ALTER ────────────────────────────────────────────────────────────────

#[test]
fn test_alter_event_body_rebind_fires_body_changed() {
    let ids = rule_ids("ALTER EVENT e DO SELECT 2;");
    assert!(
        ids.contains(&"MYSQL-EVENT-BODY-CHANGED".to_string())
            && ids.contains(&"INFO-MYSQL-EVENT-ALTER".to_string()),
        "ALTER … DO should fire both the body-changed and the alter-info rules. Got: {ids:?}"
    );
}

#[test]
fn test_alter_event_no_body_fires_alter_info_only() {
    let ids = rule_ids("ALTER EVENT e DISABLE;");
    assert!(
        ids.contains(&"INFO-MYSQL-EVENT-ALTER".to_string()),
        "ALTER EVENT should fire the alter-info rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MYSQL-EVENT-BODY-CHANGED".to_string()),
        "an ALTER without DO must NOT fire the body-changed rule. Got: {ids:?}"
    );
}

// ── Non-regression: Snowflake CREATE EVENT TABLE ─────────────────────────

#[test]
fn test_snowflake_event_table_not_affected() {
    let sf_cfg = AnalysisConfig {
        dialect: Some(dialect::snowflake()),
        ..Default::default()
    };
    // `CREATE EVENT TABLE` is a Snowflake table variant, not a scheduled
    // event — it must not be hijacked by the MySQL event parser.
    let ids = rule_ids_cfg("CREATE EVENT TABLE my_events;", &sf_cfg);
    assert!(
        !ids.iter().any(|id| id.contains("MYSQL-EVENT")),
        "Snowflake EVENT TABLE must not fire the MySQL event rules. Got: {ids:?}"
    );
}
