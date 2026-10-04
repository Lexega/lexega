// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `CREATE TRIGGER` — an inline-body trigger that runs automatically on
//! a row event.
//!
//! A trigger runs arbitrary SQL on every matching write, under the definer's
//! privileges — a classic persistence/backdoor surface. Covers recognition
//! (parse + byte-exact round-trip, not skipped), the DEFINER security-context
//! split, the body analysis (the governance payoff), and the non-regression of
//! the PG / MSSQL trigger forms.

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
        "the trigger must be analyzed, not skipped: {sql}"
    );
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_trigger_forms_recognized() {
    roundtrip_not_skipped(
        "CREATE TRIGGER t1 BEFORE INSERT ON acct FOR EACH ROW SET NEW.created = NOW();",
    );
    roundtrip_not_skipped(
        "CREATE DEFINER = 'root'@'localhost' TRIGGER audit AFTER UPDATE ON users \
         FOR EACH ROW BEGIN INSERT INTO log VALUES (NEW.id); END;",
    );
    // Unquoted user@host definer (host lexes as a single @host token).
    roundtrip_not_skipped(
        "CREATE DEFINER = root@localhost TRIGGER d AFTER DELETE ON t FOR EACH ROW SET @x = 1;",
    );
    // Trigger ordering clause.
    roundtrip_not_skipped(
        "CREATE TRIGGER t2 BEFORE UPDATE ON acct FOR EACH ROW FOLLOWS t1 SET NEW.v = 2;",
    );
}

// ── Governance: DEFINER security context (recognition vs policy) ─────────

#[test]
fn test_explicit_definer_fires_definer_rule() {
    for sql in [
        "CREATE DEFINER = 'root'@'localhost' TRIGGER a AFTER INSERT ON u FOR EACH ROW SET NEW.x=1;",
        "CREATE DEFINER = root@localhost TRIGGER a AFTER INSERT ON u FOR EACH ROW SET NEW.x=1;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"MYSQL-TRIGGER-DEFINER".to_string()),
            "an explicit DEFINER should fire the trigger definer rule. Got: {ids:?} for {sql}"
        );
    }
}

#[test]
fn test_no_definer_fires_info_only() {
    let ids = rule_ids("CREATE TRIGGER t BEFORE INSERT ON acct FOR EACH ROW SET NEW.x = 1;");
    assert!(
        ids.contains(&"INFO-MYSQL-TRIGGER".to_string()),
        "a trigger should fire the info rule. Got: {ids:?}"
    );
    assert!(
        !ids.contains(&"MYSQL-TRIGGER-DEFINER".to_string()),
        "a trigger with no DEFINER must NOT fire the definer rule. Got: {ids:?}"
    );
}

#[test]
fn test_current_user_definer_does_not_fire_definer_rule() {
    let ids = rule_ids(
        "CREATE DEFINER = CURRENT_USER TRIGGER t AFTER INSERT ON u FOR EACH ROW SET NEW.x = 1;",
    );
    assert!(
        !ids.contains(&"MYSQL-TRIGGER-DEFINER".to_string()),
        "a CURRENT_USER definer must NOT fire the definer rule. Got: {ids:?}"
    );
}

// ── Flagship: the trigger body is analyzed through the corpus ────────────

#[test]
fn test_trigger_body_drop_fires_through_corpus() {
    let ids = rule_ids(
        "CREATE TRIGGER t AFTER UPDATE ON users FOR EACH ROW \
         BEGIN INSERT INTO log VALUES (1); DROP TABLE shadow; END;",
    );
    assert!(
        ids.contains(&"TBL-DROP".to_string()),
        "a DROP TABLE in the trigger body must fire TBL-DROP. Got: {ids:?}"
    );
}

// ── Non-regression: PostgreSQL / MSSQL triggers ──────────────────────────

#[test]
fn test_pg_trigger_not_affected() {
    let pg_cfg = AnalysisConfig {
        dialect: Some(dialect::postgres()),
        ..Default::default()
    };
    // PG triggers delegate to a function — they must not route to the MySQL
    // inline-body parser or fire the MySQL trigger rules.
    let ids = rule_ids_cfg(
        "CREATE TRIGGER t AFTER INSERT ON tbl FOR EACH ROW EXECUTE FUNCTION f();",
        &pg_cfg,
    );
    assert!(
        !ids.iter().any(|id| id.contains("MYSQL-TRIGGER")),
        "a PostgreSQL trigger must not fire the MySQL trigger rules. Got: {ids:?}"
    );
}

#[test]
fn test_mssql_trigger_not_affected() {
    let mssql_cfg = AnalysisConfig {
        dialect: Some(dialect::mssql()),
        ..Default::default()
    };
    let ids = rule_ids_cfg(
        "CREATE TRIGGER t ON dbo.tbl AFTER INSERT AS BEGIN SELECT 1; END;",
        &mssql_cfg,
    );
    assert!(
        !ids.iter().any(|id| id.contains("MYSQL-TRIGGER")),
        "an MSSQL trigger must not fire the MySQL trigger rules. Got: {ids:?}"
    );
}
