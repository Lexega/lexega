// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL governance signals: extension and view drops, rules,
//! triggers, session settings.
//!
//!   PG-EXT-DROP  – DROP EXTENSION              (High)
//!   PG-EXT-CASCADE-DROP  – DROP EXTENSION CASCADE      (Critical)
//!   VIEW-CHG     – ALTER VIEW                  (Medium)
//!   VIEW-DROP  – DROP VIEW                   (Medium)
//!   VIEW-CASCADE-DROP  – DROP VIEW CASCADE           (High)
//!   PG-RULE-CHG  – ALTER RULE                  (Medium)
//!   PG-RULE-DROP  – DROP RULE                   (High)
//!   PG-RULE-CASCADE-DROP  – DROP RULE CASCADE           (High)
//!   PG-TRIG-OFF  – ALTER TABLE DISABLE TRIGGER (Critical)
//!   INFO-PG-TRIG-ON  – ALTER TABLE ENABLE TRIGGER  (Info)
//!   PG-ROLE-SET  – SET ROLE / SESSION AUTH     (High)
//!   PG-SESSION-CHG  – SET search_path / RESET     (Medium)
//!   PG-SESSION-SET  – Generic SET parameter       (Low)
//!
//! Covers: formatting roundtrip, rule firing, classification,
//!         analyzed-not-skipped, multi-statement evidence counting.

use lexega_core::{
    analyzer::{AnalysisConfig, RuleMatch},
    dialect, format_sql_with_config, verify_formatting_safe, FormatterConfig, PostgresDialect,
};

use lexega_core::api::analyze_risk_with_policy_config;
use std::sync::Arc;

// ── Helpers ─────────────────────────────────────────────────────────────

fn pg_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(PostgresDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| match s {
        RuleMatch::Analysis(g) => g.matched_rule == rule_id,
    })
}

fn pg_format(sql: &str) -> String {
    let config = FormatterConfig {
        dialect: dialect::postgres(),
        ..Default::default()
    };
    format_sql_with_config(sql, &config).expect("should format")
}

fn rule_ids(report: &lexega_core::analyzer::AnalysisReport) -> Vec<&str> {
    report
        .signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(g.matched_rule.as_str()),
        })
        .collect()
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-EXT-DROP / PG-EXT-CASCADE-DROP : DROP EXTENSION
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_extension_format_roundtrip() {
    let sql = "DROP EXTENSION pgcrypto;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_extension_if_exists_format() {
    let sql = "DROP EXTENSION IF EXISTS hstore;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_extension_cascade_format() {
    let sql = "DROP EXTENSION pgcrypto CASCADE;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_extension_signal_fires() {
    let report = pg_analyze("DROP EXTENSION pgcrypto;");
    assert!(
        has_rule(&report, "PG-EXT-DROP"),
        "Should fire PG-EXT-DROP (extension dropped). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_extension_cascade_fires_both() {
    let report = pg_analyze("DROP EXTENSION pgcrypto CASCADE;");
    assert!(
        has_rule(&report, "PG-EXT-DROP"),
        "Should fire PG-EXT-DROP (extension dropped). Got: {:?}",
        rule_ids(&report)
    );
    assert!(
        has_rule(&report, "PG-EXT-CASCADE-DROP"),
        "Should fire PG-EXT-CASCADE-DROP (cascade). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_extension_analyzed_not_skipped() {
    let report = pg_analyze("DROP EXTENSION pg_trgm;");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

#[test]
fn test_drop_extension_multi_statement_evidence() {
    let sql = "DROP EXTENSION pgcrypto;\nDROP EXTENSION hstore;";
    let report = pg_analyze(sql);
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "PG-EXT-DROP"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Should have evidence for each DROP EXTENSION, got {}",
        total_evidence
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  C306 : ALTER VIEW (generic, cross-dialect)
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_view_format_roundtrip() {
    let sql = "ALTER VIEW my_view RENAME TO new_view;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_alter_view_owner_format() {
    let sql = "ALTER VIEW my_view OWNER TO new_owner;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_alter_view_signal_fires() {
    let report = pg_analyze("ALTER VIEW my_view RENAME TO new_view;");
    assert!(
        has_rule(&report, "VIEW-CHG"),
        "Should fire VIEW-CHG (view modified). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_alter_view_analyzed_not_skipped() {
    let report = pg_analyze("ALTER VIEW v1 SET (security_barrier = true);");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  VIEW-DROP / VIEW-CASCADE-DROP : DROP VIEW
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_view_format_roundtrip() {
    let sql = "DROP VIEW my_view;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_view_if_exists_format() {
    let sql = "DROP VIEW IF EXISTS my_view;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_view_cascade_format() {
    let sql = "DROP VIEW my_view CASCADE;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_view_signal_fires() {
    let report = pg_analyze("DROP VIEW my_view;");
    assert!(
        has_rule(&report, "VIEW-DROP"),
        "Should fire VIEW-DROP (view dropped). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_view_cascade_fires_both() {
    let report = pg_analyze("DROP VIEW my_view CASCADE;");
    assert!(
        has_rule(&report, "VIEW-DROP"),
        "Should fire VIEW-DROP (view dropped). Got: {:?}",
        rule_ids(&report)
    );
    assert!(
        has_rule(&report, "VIEW-CASCADE-DROP"),
        "Should fire VIEW-CASCADE-DROP (cascade). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_view_analyzed_not_skipped() {
    let report = pg_analyze("DROP VIEW old_view;");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-RULE-CHG : ALTER RULE
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_rule_format_roundtrip() {
    let sql = "ALTER RULE my_rule ON my_table RENAME TO new_rule;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_alter_rule_signal_fires() {
    let report = pg_analyze("ALTER RULE my_rule ON my_table RENAME TO new_rule;");
    assert!(
        has_rule(&report, "PG-RULE-CHG"),
        "Should fire PG-RULE-CHG (rule modified). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_alter_rule_analyzed_not_skipped() {
    let report = pg_analyze("ALTER RULE my_rule ON my_table RENAME TO new_rule;");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-RULE-DROP / PG-RULE-CASCADE-DROP : DROP RULE
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_rule_format_roundtrip() {
    let sql = "DROP RULE my_rule ON my_table;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_rule_if_exists_format() {
    let sql = "DROP RULE IF EXISTS my_rule ON my_table;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_rule_cascade_format() {
    let sql = "DROP RULE my_rule ON my_table CASCADE;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_drop_rule_signal_fires() {
    let report = pg_analyze("DROP RULE my_rule ON my_table;");
    assert!(
        has_rule(&report, "PG-RULE-DROP"),
        "Should fire PG-RULE-DROP (rule dropped). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_rule_cascade_fires_both() {
    let report = pg_analyze("DROP RULE my_rule ON my_table CASCADE;");
    assert!(
        has_rule(&report, "PG-RULE-DROP"),
        "Should fire PG-RULE-DROP (rule dropped). Got: {:?}",
        rule_ids(&report)
    );
    assert!(
        has_rule(&report, "PG-RULE-CASCADE-DROP"),
        "Should fire PG-RULE-CASCADE-DROP (cascade). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_rule_analyzed_not_skipped() {
    let report = pg_analyze("DROP RULE my_rule ON my_table;");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-TRIG-OFF / INFO-PG-TRIG-ON : ALTER TABLE ENABLE/DISABLE TRIGGER
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_disable_trigger_format_roundtrip() {
    let sql = "ALTER TABLE my_table DISABLE TRIGGER my_trigger;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_enable_trigger_format_roundtrip() {
    let sql = "ALTER TABLE my_table ENABLE TRIGGER my_trigger;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_disable_trigger_all_format() {
    let sql = "ALTER TABLE my_table DISABLE TRIGGER ALL;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_enable_always_trigger_format() {
    let sql = "ALTER TABLE my_table ENABLE ALWAYS TRIGGER my_trigger;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_enable_replica_trigger_format() {
    let sql = "ALTER TABLE my_table ENABLE REPLICA TRIGGER my_trigger;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_disable_trigger_signal_fires() {
    let report = pg_analyze("ALTER TABLE my_table DISABLE TRIGGER audit_trigger;");
    assert!(
        has_rule(&report, "PG-TRIG-OFF"),
        "Should fire PG-TRIG-OFF (trigger disabled). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_enable_trigger_signal_fires() {
    let report = pg_analyze("ALTER TABLE my_table ENABLE TRIGGER audit_trigger;");
    assert!(
        has_rule(&report, "INFO-PG-TRIG-ON"),
        "Should fire INFO-PG-TRIG-ON (trigger enabled). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_disable_trigger_all_signal() {
    let report = pg_analyze("ALTER TABLE my_table DISABLE TRIGGER ALL;");
    assert!(
        has_rule(&report, "PG-TRIG-OFF"),
        "Should fire PG-TRIG-OFF for DISABLE ALL. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_enable_always_trigger_signal() {
    let report = pg_analyze("ALTER TABLE my_table ENABLE ALWAYS TRIGGER my_trigger;");
    assert!(
        has_rule(&report, "INFO-PG-TRIG-ON"),
        "Should fire INFO-PG-TRIG-ON for ENABLE ALWAYS. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_disable_trigger_analyzed_not_skipped() {
    let report = pg_analyze("ALTER TABLE t1 DISABLE TRIGGER t;");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

#[test]
fn test_disable_trigger_multi_statement_evidence() {
    let sql = "ALTER TABLE t1 DISABLE TRIGGER tr1;\nALTER TABLE t2 DISABLE TRIGGER tr2;";
    let report = pg_analyze(sql);
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "PG-TRIG-OFF"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Should have evidence for each DISABLE TRIGGER, got {}",
        total_evidence
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-ROLE-SET : SET ROLE / SET SESSION AUTHORIZATION
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_set_role_format_roundtrip() {
    let sql = "SET ROLE admin;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_set_session_role_format() {
    let sql = "SET SESSION ROLE admin;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_set_local_role_format() {
    let sql = "SET LOCAL ROLE admin;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_set_session_authorization_format() {
    let sql = "SET SESSION AUTHORIZATION 'admin_user';";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_set_role_signal_fires() {
    let report = pg_analyze("SET ROLE admin;");
    assert!(
        has_rule(&report, "PG-ROLE-SET"),
        "Should fire PG-ROLE-SET (session role changed). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_set_session_authorization_signal_fires() {
    let report = pg_analyze("SET SESSION AUTHORIZATION 'admin_user';");
    assert!(
        has_rule(&report, "PG-ROLE-SET"),
        "Should fire PG-ROLE-SET (session auth changed). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_set_role_analyzed_not_skipped() {
    let report = pg_analyze("SET ROLE admin;");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-SESSION-CHG : SET search_path / RESET
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_set_search_path_format_roundtrip() {
    let sql = "SET search_path TO public, my_schema;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_reset_role_format_roundtrip() {
    let sql = "RESET ROLE;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_reset_all_format_roundtrip() {
    let sql = "RESET ALL;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_reset_search_path_format() {
    let sql = "RESET search_path;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_set_search_path_signal_fires() {
    let report = pg_analyze("SET search_path TO public, my_schema;");
    assert!(
        has_rule(&report, "PG-SESSION-CHG"),
        "Should fire PG-SESSION-CHG (session state changed). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_reset_fires_session_state_signal() {
    let report = pg_analyze("RESET ROLE;");
    assert!(
        has_rule(&report, "PG-SESSION-CHG"),
        "Should fire PG-SESSION-CHG for RESET. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_reset_analyzed_not_skipped() {
    let report = pg_analyze("RESET ALL;");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-SESSION-SET : Generic SET parameter
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_set_statement_timeout_format() {
    let sql = "SET statement_timeout TO '5s';";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_set_work_mem_format() {
    let sql = "SET work_mem TO '256MB';";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_set_generic_signal_fires() {
    let report = pg_analyze("SET statement_timeout TO '5s';");
    assert!(
        has_rule(&report, "PG-SESSION-SET"),
        "Should fire PG-SESSION-SET (generic SET). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_set_generic_analyzed_not_skipped() {
    let report = pg_analyze("SET work_mem TO '256MB';");
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should be analyzed, not skipped"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  Cross-cutting: Multi-statement with mixed MEDIUM constructs
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_mixed_medium_multi_statement_format() {
    let sql = "\
        DROP EXTENSION pgcrypto;\n\
        ALTER TABLE audit_log DISABLE TRIGGER audit_trigger;\n\
        SET ROLE admin;\n\
        DROP VIEW sensitive_data_view CASCADE;\n\
        DROP RULE audit_rule ON orders;\n\
        RESET ROLE;\n";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).unwrap();
}

#[test]
fn test_mixed_medium_multi_statement_signals() {
    let sql = "\
        DROP EXTENSION pgcrypto;\n\
        ALTER TABLE audit_log DISABLE TRIGGER audit_trigger;\n\
        SET ROLE admin;\n\
        DROP VIEW sensitive_data_view;\n\
        DROP RULE audit_rule ON orders;\n";
    let report = pg_analyze(sql);
    let ids = rule_ids(&report);
    assert!(
        has_rule(&report, "PG-EXT-DROP"),
        "DROP EXTENSION should fire PG-EXT-DROP. Got: {:?}",
        ids
    );
    assert!(
        has_rule(&report, "PG-TRIG-OFF"),
        "DISABLE TRIGGER should fire PG-TRIG-OFF. Got: {:?}",
        ids
    );
    assert!(
        has_rule(&report, "PG-ROLE-SET"),
        "SET ROLE should fire PG-ROLE-SET. Got: {:?}",
        ids
    );
    assert!(
        has_rule(&report, "VIEW-DROP"),
        "DROP VIEW should fire VIEW-DROP. Got: {:?}",
        ids
    );
    assert!(
        has_rule(&report, "PG-RULE-DROP"),
        "DROP RULE should fire PG-RULE-DROP. Got: {:?}",
        ids
    );
}

#[test]
fn test_mixed_medium_multi_all_analyzed() {
    let sql = "\
        DROP EXTENSION pgcrypto;\n\
        ALTER TABLE t1 DISABLE TRIGGER tr1;\n\
        SET ROLE admin;\n\
        DROP VIEW v1;\n\
        DROP RULE r1 ON t1;\n";
    let report = pg_analyze(sql);
    assert!(
        report.summary.statements_analyzed >= 5,
        "All 5 statements should be analyzed. Got analyzed={}, skipped={}",
        report.summary.statements_analyzed,
        report.summary.statements_skipped
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  Negative tests: normal ALTER TABLE should NOT trigger trigger signals
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_normal_alter_table_no_trigger_signal() {
    // Normal ALTER TABLE ADD COLUMN should NOT fire PG-TRIG-OFF or INFO-PG-TRIG-ON
    let report = pg_analyze("ALTER TABLE my_table ADD COLUMN new_col INT;");
    assert!(
        !has_rule(&report, "PG-TRIG-OFF"),
        "Normal ALTER TABLE should NOT fire PG-TRIG-OFF"
    );
    assert!(
        !has_rule(&report, "INFO-PG-TRIG-ON"),
        "Normal ALTER TABLE should NOT fire INFO-PG-TRIG-ON"
    );
}

#[test]
fn test_normal_drop_table_no_view_signal() {
    // DROP TABLE should NOT fire VIEW-DROP (view dropped)
    let report = pg_analyze("DROP TABLE my_table;");
    assert!(
        !has_rule(&report, "VIEW-DROP"),
        "DROP TABLE should NOT fire VIEW-DROP (view dropped)"
    );
}
