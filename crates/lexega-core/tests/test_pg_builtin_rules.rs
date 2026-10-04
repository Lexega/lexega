// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL built-in analysis rules (PG-RLS-NEW through PG-SUB-CHG).
//!
//! Validates that PG statements emit the correct governance/security signals
//! and that YAML rules match against those signals.

use lexega_core::{
    analyzer::{AnalysisConfig, RuleMatch},
    PostgresDialect,
};

use lexega_core::api::{analyze_risk, analyze_risk_with_policy_config};
use std::collections::HashSet;
use std::sync::Arc;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => extract_rule_ids(&report.signals),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

/// Helper for PG-dialect-gated statements (COPY, REFRESH MATVIEW, SUBSCRIPTION)
fn analyze_pg_dialect(sql: &str) -> HashSet<String> {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(PostgresDialect));
    match analyze_risk_with_policy_config(sql, &config) {
        Ok(report) => extract_rule_ids(&report.signals),
        Err(e) => {
            eprintln!("Parse error (PG dialect): {:?}", e);
            HashSet::new()
        }
    }
}

// ============================================================================
// PG RLS POLICY (PG-RLS-NEW through PG-RLS-PERMISSIVE)
// ============================================================================

#[test]
fn test_pg_rls_policy_created() {
    let sql = "CREATE POLICY user_policy ON users USING (user_id = current_user);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("INFO-PG-RLS-NEW"),
        "INFO-PG-RLS-NEW should fire for CREATE POLICY. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_policy_modified() {
    let sql = "ALTER POLICY user_policy ON users USING (user_id = current_user AND active = true);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-RLS-CHG"),
        "PG-RLS-CHG should fire for ALTER POLICY (modify). Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_policy_renamed() {
    let sql = "ALTER POLICY user_policy ON users RENAME TO new_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-RLS-NAME-CHG"),
        "PG-RLS-NAME-CHG should fire for ALTER POLICY RENAME. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_policy_dropped() {
    let sql = "DROP POLICY user_policy ON users;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-RLS-DROP"),
        "PG-RLS-DROP should fire for DROP POLICY. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_policy_dropped_cascade() {
    let sql = "DROP POLICY user_policy ON users CASCADE;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-RLS-CASCADE-DROP"),
        "PG-RLS-CASCADE-DROP should fire for DROP POLICY CASCADE. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_policy_permissive() {
    let sql = "CREATE POLICY user_policy ON users AS PERMISSIVE USING (user_id = current_user);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("INFO-PG-RLS-NEW"),
        "INFO-PG-RLS-NEW should fire for CREATE POLICY. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("PG-RLS-PERMISSIVE"),
        "PG-RLS-PERMISSIVE should fire for PERMISSIVE policy. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_policy_restrictive_no_c006() {
    let sql = "CREATE POLICY user_policy ON users AS RESTRICTIVE USING (user_id = current_user);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("INFO-PG-RLS-NEW"),
        "INFO-PG-RLS-NEW should fire for CREATE POLICY. Got: {:?}",
        rules
    );
    assert!(
        !rules.contains("PG-RLS-PERMISSIVE"),
        "PG-RLS-PERMISSIVE should NOT fire for RESTRICTIVE policy. Got: {:?}",
        rules
    );
}

// ----- ALTER TABLE ... ROW LEVEL SECURITY toggle (PG-RLS-TABLE-*) -----

#[test]
fn test_pg_rls_table_disable() {
    let rules = analyze_and_get_rules("ALTER TABLE t DISABLE ROW LEVEL SECURITY;");
    assert!(
        rules.contains("PG-RLS-TABLE-DISABLE"),
        "PG-RLS-TABLE-DISABLE should fire for DISABLE RLS. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_table_no_force() {
    let rules = analyze_and_get_rules("ALTER TABLE t NO FORCE ROW LEVEL SECURITY;");
    assert!(
        rules.contains("PG-RLS-TABLE-NO-FORCE"),
        "PG-RLS-TABLE-NO-FORCE should fire for NO FORCE RLS. Got: {:?}",
        rules
    );
    // The relaxing form must not be mistaken for the critical DISABLE.
    assert!(
        !rules.contains("PG-RLS-TABLE-DISABLE"),
        "DISABLE rule must not fire for NO FORCE. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_rls_table_enable_force_positive() {
    let enable = analyze_and_get_rules("ALTER TABLE t ENABLE ROW LEVEL SECURITY;");
    assert!(
        enable.contains("INFO-PG-RLS-TABLE-ENABLE"),
        "INFO-PG-RLS-TABLE-ENABLE should fire for ENABLE RLS. Got: {:?}",
        enable
    );
    let force = analyze_and_get_rules("ALTER TABLE t FORCE ROW LEVEL SECURITY;");
    assert!(
        force.contains("INFO-PG-RLS-TABLE-FORCE"),
        "INFO-PG-RLS-TABLE-FORCE should fire for FORCE RLS. Got: {:?}",
        force
    );
    // Strengthening forms must not trip the weakening rules.
    assert!(
        !enable.contains("PG-RLS-TABLE-DISABLE") && !force.contains("PG-RLS-TABLE-NO-FORCE"),
        "Positive RLS toggles must not fire weakening rules. enable={:?} force={:?}",
        enable,
        force
    );
}

#[test]
fn test_pg_enable_trigger_is_not_rls() {
    // Regression: ENABLE/DISABLE TRIGGER must route to the trigger-state
    // parser, never the RLS action.
    let rules = analyze_and_get_rules("ALTER TABLE t ENABLE TRIGGER trg;");
    assert!(
        !rules.iter().any(|r| r.contains("RLS-TABLE")),
        "ENABLE TRIGGER must not fire any RLS-TABLE rule. Got: {:?}",
        rules
    );
}

// ============================================================================
// PG TRIGGER (PG-TRIG-*)
// ============================================================================

#[test]
fn test_pg_trigger_created() {
    let sql = "CREATE TRIGGER audit_trigger AFTER INSERT ON orders FOR EACH ROW EXECUTE FUNCTION audit_fn();";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("TRIG-NEW"),
        "TRIG-NEW should fire for CREATE TRIGGER. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_trigger_renamed() {
    let sql = "ALTER TRIGGER old_trigger ON orders RENAME TO new_trigger;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-TRIG-NAME-CHG"),
        "PG-TRIG-NAME-CHG should fire for ALTER TRIGGER RENAME. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_trigger_depends_on_extension() {
    let sql = "ALTER TRIGGER audit_trigger ON orders DEPENDS ON EXTENSION pg_audit;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("TRIG-CHG"),
        "TRIG-CHG should fire for ALTER TRIGGER (modify). Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_trigger_dropped() {
    let sql = "DROP TRIGGER audit_trigger ON orders;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("TRIG-DROP"),
        "TRIG-DROP should fire for DROP TRIGGER. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_trigger_dropped_cascade() {
    let sql = "DROP TRIGGER audit_trigger ON orders CASCADE;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-TRIG-CASCADE-DROP"),
        "PG-TRIG-CASCADE-DROP should fire for DROP TRIGGER CASCADE. Got: {:?}",
        rules
    );
}

// ============================================================================
// PG COPY (PG-COPY-*)
// ============================================================================

#[test]
fn test_pg_copy_from() {
    let sql = "COPY users FROM '/tmp/users.csv' WITH (FORMAT csv);";
    let rules = analyze_pg_dialect(sql);
    assert!(
        rules.contains("PG-COPY-FROM"),
        "PG-COPY-FROM should fire for COPY FROM. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_copy_to() {
    let sql = "COPY users TO '/tmp/export.csv' WITH (FORMAT csv);";
    let rules = analyze_pg_dialect(sql);
    assert!(
        rules.contains("PG-COPY-TO"),
        "PG-COPY-TO should fire for COPY TO. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_copy_program() {
    let sql = "COPY users FROM PROGRAM 'cat /etc/passwd' WITH (FORMAT csv);";
    let rules = analyze_pg_dialect(sql);
    assert!(
        rules.contains("PG-COPY-PROGRAM"),
        "PG-COPY-PROGRAM should fire for COPY FROM PROGRAM. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_copy_to_program() {
    let sql = "COPY users TO PROGRAM 'gzip > /tmp/users.csv.gz' WITH (FORMAT csv);";
    let rules = analyze_pg_dialect(sql);
    assert!(
        rules.contains("PG-COPY-PROGRAM"),
        "PG-COPY-PROGRAM should fire for COPY TO PROGRAM. Got: {:?}",
        rules
    );
}

// ============================================================================
// PG DOMAIN (PG-DOMAIN-*)
// ============================================================================

#[test]
fn test_pg_domain_created() {
    let sql = "CREATE DOMAIN email_addr AS TEXT CHECK (VALUE ~ '^.+@.+$');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("INFO-PG-DOMAIN-NEW"),
        "INFO-PG-DOMAIN-NEW should fire for CREATE DOMAIN. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_not_null_dropped() {
    let sql = "ALTER DOMAIN email_addr DROP NOT NULL;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-DOMAIN-NOTNULL-DROP"),
        "PG-DOMAIN-NOTNULL-DROP should fire for ALTER DOMAIN DROP NOT NULL. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_constraint_dropped() {
    let sql = "ALTER DOMAIN email_addr DROP CONSTRAINT email_check;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-DOMAIN-CONSTR-DROP"),
        "PG-DOMAIN-CONSTR-DROP should fire for ALTER DOMAIN DROP CONSTRAINT. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_constraint_dropped_cascade() {
    let sql = "ALTER DOMAIN email_addr DROP CONSTRAINT email_check CASCADE;";
    let rules = analyze_and_get_rules(sql);
    assert!(rules.contains("PG-DOMAIN-CONSTR-CASCADE-DROP"), "PG-DOMAIN-CONSTR-CASCADE-DROP should fire for ALTER DOMAIN DROP CONSTRAINT CASCADE. Got: {:?}", rules);
}

#[test]
fn test_pg_domain_constraint_added() {
    let sql = "ALTER DOMAIN email_addr ADD CONSTRAINT email_check CHECK (VALUE ~ '^.+@.+$');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("INFO-PG-DOMAIN-CONSTR-ADD"),
        "INFO-PG-DOMAIN-CONSTR-ADD should fire for ALTER DOMAIN ADD CONSTRAINT. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_modified() {
    let sql = "ALTER DOMAIN email_addr SET DEFAULT 'user@example.com';";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-DOMAIN-CHG"),
        "PG-DOMAIN-CHG should fire for ALTER DOMAIN SET DEFAULT. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_renamed() {
    let sql = "ALTER DOMAIN email_addr RENAME TO email_address;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-DOMAIN-NAME-CHG"),
        "PG-DOMAIN-NAME-CHG should fire for ALTER DOMAIN RENAME. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_owner_changed() {
    let sql = "ALTER DOMAIN email_addr OWNER TO admin;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-DOMAIN-OWNER-CHG"),
        "PG-DOMAIN-OWNER-CHG should fire for ALTER DOMAIN OWNER TO. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_dropped() {
    let sql = "DROP DOMAIN email_addr;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-DOMAIN-DROP"),
        "PG-DOMAIN-DROP should fire for DROP DOMAIN. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_domain_dropped_cascade() {
    let sql = "DROP DOMAIN email_addr CASCADE;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-DOMAIN-CASCADE-DROP"),
        "PG-DOMAIN-CASCADE-DROP should fire for DROP DOMAIN CASCADE. Got: {:?}",
        rules
    );
}

// ============================================================================
// PG ALTER SYSTEM (PG-SYS-CFG-CHG)
// ============================================================================

#[test]
fn test_pg_alter_system() {
    let sql = "ALTER SYSTEM SET max_connections = 200;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-SYS-CFG-CHG"),
        "PG-SYS-CFG-CHG should fire for ALTER SYSTEM. Got: {:?}",
        rules
    );
}

// ============================================================================
// PG DROP/REASSIGN OWNED (PG-OWNED-DROP, PG-OWNED-REASSIGN)
// ============================================================================

#[test]
fn test_pg_drop_owned() {
    let sql = "DROP OWNED BY old_user;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-OWNED-DROP"),
        "PG-OWNED-DROP should fire for DROP OWNED. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_reassign_owned() {
    let sql = "REASSIGN OWNED BY old_user TO new_user;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-OWNED-REASSIGN"),
        "PG-OWNED-REASSIGN should fire for REASSIGN OWNED. Got: {:?}",
        rules
    );
}

// ============================================================================
// PG ALTER INDEX / REINDEX (PG-IDX-NAME-CHG through PG-IDX-REBUILD)
// ============================================================================

#[test]
fn test_pg_index_renamed() {
    let sql = "ALTER INDEX old_idx RENAME TO new_idx;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-IDX-NAME-CHG"),
        "PG-IDX-NAME-CHG should fire for ALTER INDEX RENAME. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_index_modified() {
    let sql = "ALTER INDEX my_idx SET TABLESPACE fast_ssd;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-IDX-CHG"),
        "PG-IDX-CHG should fire for ALTER INDEX (modify). Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_reindex() {
    let sql = "REINDEX TABLE users;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-IDX-REBUILD"),
        "PG-IDX-REBUILD should fire for REINDEX. Got: {:?}",
        rules
    );
}

// ============================================================================
// PG REFRESH MATERIALIZED VIEW (PG-MATVIEW-REFRESH)
// ============================================================================

#[test]
fn test_pg_refresh_matview() {
    let sql = "REFRESH MATERIALIZED VIEW CONCURRENTLY my_matview;";
    let rules = analyze_pg_dialect(sql);
    assert!(
        rules.contains("PG-MATVIEW-REFRESH"),
        "PG-MATVIEW-REFRESH should fire for REFRESH MATERIALIZED VIEW. Got: {:?}",
        rules
    );
}

// ============================================================================
// SIMPLE STATEMENTS (PG-TBL-LOCK through PG-SUB-CHG)
// ============================================================================

#[test]
fn test_pg_lock_table() {
    let sql = "LOCK TABLE users IN ACCESS EXCLUSIVE MODE;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-TBL-LOCK"),
        "PG-TBL-LOCK should fire for LOCK TABLE. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_discard() {
    let sql = "DISCARD ALL;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-SESSION-DISCARD"),
        "PG-SESSION-DISCARD should fire for DISCARD. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_create_rule() {
    let sql = "CREATE RULE notify_insert AS ON INSERT TO users DO ALSO NOTIFY user_changes;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-RULE-NEW"),
        "PG-RULE-NEW should fire for CREATE RULE. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_publication() {
    let sql = "CREATE PUBLICATION my_pub FOR TABLE users, orders;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-PUB-CHG"),
        "PG-PUB-CHG should fire for PUBLICATION statement. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_subscription() {
    let sql =
        "CREATE SUBSCRIPTION my_sub CONNECTION 'host=primary dbname=mydb' PUBLICATION my_pub;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("PG-SUB-CHG"),
        "PG-SUB-CHG should fire for SUBSCRIPTION statement. Got: {:?}",
        rules
    );
}

// ============================================================================
// MULTI-STATEMENT TESTS (ensure no NodeId collision / deduplication bugs)
// ============================================================================

#[test]
fn test_pg_multi_policy_statements() {
    let sql = r#"
        CREATE POLICY read_policy ON users USING (user_id = current_user);
        CREATE POLICY write_policy ON users AS PERMISSIVE FOR INSERT WITH CHECK (dept_id = 1);
        DROP POLICY old_policy ON orders CASCADE;
    "#;
    let report = analyze_risk(sql).expect("should analyze");
    let rules = extract_rule_ids(&report.signals);

    // All 3 statements should produce signals
    assert!(
        rules.contains("INFO-PG-RLS-NEW"),
        "Should detect CREATE POLICY. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("PG-RLS-CASCADE-DROP"),
        "Should detect DROP POLICY CASCADE. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("PG-RLS-PERMISSIVE"),
        "Should detect PERMISSIVE. Got: {:?}",
        rules
    );
    assert!(
        report.summary.total_reported_signals >= 3,
        "Should have at least 3 signals from 3 statements. Got: {}",
        report.summary.total_reported_signals
    );
}

#[test]
fn test_pg_multi_domain_statements() {
    let sql = r#"
        CREATE DOMAIN phone AS TEXT CHECK (VALUE ~ '^\+?[0-9]+$');
        ALTER DOMAIN phone DROP NOT NULL;
        DROP DOMAIN phone CASCADE;
    "#;
    let report = analyze_risk(sql).expect("should analyze");
    let rules = extract_rule_ids(&report.signals);

    assert!(
        rules.contains("INFO-PG-DOMAIN-NEW"),
        "Should detect CREATE DOMAIN. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("PG-DOMAIN-NOTNULL-DROP"),
        "Should detect DROP NOT NULL. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("PG-DOMAIN-CASCADE-DROP"),
        "Should detect DROP DOMAIN CASCADE. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_mixed_critical_signals() {
    let sql = r#"
        COPY users FROM PROGRAM 'malicious-cmd';
        ALTER SYSTEM SET log_connections = off;
        DROP OWNED BY hacked_user;
    "#;
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(PostgresDialect));
    let report = analyze_risk_with_policy_config(sql, &config).expect("should analyze");
    let rules = extract_rule_ids(&report.signals);

    assert!(
        rules.contains("PG-COPY-PROGRAM"),
        "Should detect COPY PROGRAM. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("PG-SYS-CFG-CHG"),
        "Should detect ALTER SYSTEM. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("PG-OWNED-DROP"),
        "Should detect DROP OWNED. Got: {:?}",
        rules
    );
    assert!(
        report.summary.critical_count >= 3,
        "Should have at least 3 critical signals. Got: {}",
        report.summary.critical_count
    );
}

// ============================================================================
// RISK LEVEL VALIDATION
// ============================================================================

#[test]
fn test_pg_critical_risk_levels() {
    // All of these should be Critical
    let critical_sqls = vec![
        ("PG-RLS-DROP", "DROP POLICY user_policy ON users;"),
        (
            "PG-RLS-CASCADE-DROP",
            "DROP POLICY user_policy ON users CASCADE;",
        ),
        (
            "PG-TRIG-CASCADE-DROP",
            "DROP TRIGGER audit_trigger ON orders CASCADE;",
        ),
        (
            "PG-COPY-PROGRAM",
            "COPY users FROM PROGRAM 'cat /etc/passwd';",
        ),
        (
            "PG-DOMAIN-CONSTR-CASCADE-DROP",
            "ALTER DOMAIN d DROP CONSTRAINT c CASCADE;",
        ),
        ("PG-DOMAIN-CASCADE-DROP", "DROP DOMAIN d CASCADE;"),
        ("PG-SYS-CFG-CHG", "ALTER SYSTEM SET shared_buffers = '1GB';"),
        ("PG-OWNED-DROP", "DROP OWNED BY old_user;"),
    ];

    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(PostgresDialect));

    for (expected_rule, sql) in critical_sqls {
        let report =
            analyze_risk_with_policy_config(sql, &config).expect(&format!("Should parse: {}", sql));
        let rules = extract_rule_ids(&report.signals);
        assert!(
            rules.contains(expected_rule),
            "{} should fire for: {}. Got: {:?}",
            expected_rule,
            sql,
            rules
        );
        assert!(
            report.summary.critical_count >= 1,
            "Critical count should be >= 1 for {}. Got: {}",
            expected_rule,
            report.summary.critical_count
        );
    }
}

#[test]
fn test_pg_info_risk_levels() {
    // These should be Info level (positive governance signals)
    let info_sqls = vec![
        ("INFO-PG-RLS-NEW", "CREATE POLICY p ON t USING (true);"),
        ("INFO-PG-DOMAIN-NEW", "CREATE DOMAIN d AS TEXT;"),
        (
            "INFO-PG-DOMAIN-CONSTR-ADD",
            "ALTER DOMAIN d ADD CONSTRAINT c CHECK (VALUE > 0);",
        ),
    ];

    for (expected_rule, sql) in info_sqls {
        let report = analyze_risk(sql).expect(&format!("Should parse: {}", sql));
        let rules = extract_rule_ids(&report.signals);
        assert!(
            rules.contains(expected_rule),
            "{} should fire for: {}. Got: {:?}",
            expected_rule,
            sql,
            rules
        );
        assert!(
            report.summary.info_count >= 1,
            "Info count should be >= 1 for {}. Got: {}",
            expected_rule,
            report.summary.info_count
        );
    }
}

// ============================================================================
// Anonymous DO block body decomposition
//
// `DO $$ … $$` bodies are sub-parsed (shared with CREATE PROCEDURE), so inner
// statements are flattened and rule-evaluated alongside the block's own
// PG-ANON-EXEC signal — parity with proc/func bodies.
// ============================================================================

#[test]
fn test_pg_do_block_inner_drop_fires() {
    let rules = analyze_pg_dialect("DO $$\nBEGIN\n  DROP TABLE important;\nEND;\n$$;\n");
    assert!(
        rules.contains("PG-ANON-EXEC"),
        "DO block itself should flag anonymous execution. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("TBL-DROP"),
        "Inner DROP TABLE in a DO body should be decomposed and fire TBL-DROP. Got: {:?}",
        rules
    );
}

#[test]
fn test_pg_do_block_tagged_inner_truncate_fires() {
    let rules = analyze_pg_dialect("DO $body$\nBEGIN\n  TRUNCATE TABLE t;\nEND;\n$body$;\n");
    assert!(
        rules.contains("PG-ANON-EXEC"),
        "Tagged DO block should flag anonymous execution. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("TBL-TRUNCATE"),
        "Inner TRUNCATE in a tagged DO body should be decomposed and fire TBL-TRUNCATE. Got: {:?}",
        rules
    );
}
