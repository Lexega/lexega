// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL governance signals: indexes, sequences, types,
//! comments, maintenance, notifications, tablespaces.
//!
//!   INFO-PG-IDX-NEW  – Index Created              (Info)
//!   PG-IDX-DROP  – Index Dropped              (Low)
//!   PG-IDX-CASCADE-DROP  – Index Dropped CASCADE      (Medium)
//!   INFO-SEQ-NEW  – Sequence Created           (Info)
//!   INFO-SEQ-CHG  – Sequence Modified          (Info)
//!   SEQ-DROP  – Sequence Dropped           (Low)
//!   SEQ-CASCADE-DROP  – Sequence Dropped CASCADE   (Medium)
//!   INFO-PG-TYPE-NEW  – Type Created               (Info)
//!   INFO-PG-TYPE-CHG  – Type Modified              (Info)
//!   PG-TYPE-DROP  – Type Dropped               (Low)
//!   PG-TYPE-CASCADE-DROP  – Type Dropped CASCADE       (Medium)
//!   INFO-COMMENT-CHG  – Comment Changed            (Info)
//!   INFO-PG-MAINT-VACUUM  – Maintenance (VACUUM)       (Info)
//!   INFO-PG-MAINT-ANALYZE  – Maintenance (ANALYZE)      (Info)
//!   INFO-PG-MAINT-CLUSTER  – Maintenance (CLUSTER)      (Info)
//!   INFO-PG-NOTIFY-SUB  – Notification LISTEN        (Info)
//!   INFO-PG-NOTIFY-SEND  – Notification NOTIFY        (Info)
//!   INFO-PG-NOTIFY-UNSUB  – Notification UNLISTEN      (Info)
//!   INFO-PG-AGG-NEW  – Aggregate Created          (Info)
//!   INFO-PG-OP-NEW  – Operator Created           (Info)
//!   PG-TBLSPC-NEW  – Tablespace Created         (Low)
//!   PG-TBLSPC-DROP  – Tablespace Dropped         (Medium)
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

// ═══════════════════════════════════════════════════════════════════════
//  CREATE INDEX — INFO-PG-IDX-NEW
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_create_index_format_roundtrip() {
    let sql = "CREATE INDEX idx_users_email ON users (email);";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_create_index_signal() {
    let sql = "CREATE INDEX idx_users_email ON users (email);";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-PG-IDX-NEW"), "rules: {:?}", rule_ids(&r));
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_create_unique_index_signal() {
    let sql = "CREATE UNIQUE INDEX idx_pk ON orders (id);";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-PG-IDX-NEW"), "rules: {:?}", rule_ids(&r));
}

#[test]
fn test_create_index_if_not_exists() {
    let sql = "CREATE INDEX IF NOT EXISTS idx_ts ON events (created_at);";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-PG-IDX-NEW"), "rules: {:?}", rule_ids(&r));
}

// ═══════════════════════════════════════════════════════════════════════
//  DROP INDEX — PG-IDX-DROP, PG-IDX-CASCADE-DROP
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_index_format_roundtrip() {
    let sql = "DROP INDEX idx_users_email;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_drop_index_signal() {
    let sql = "DROP INDEX idx_users_email;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-IDX-DROP"), "rules: {:?}", rule_ids(&r));
    assert!(!has_rule(&r, "PG-IDX-CASCADE-DROP"), "no cascade");
}

#[test]
fn test_drop_index_cascade_signal() {
    let sql = "DROP INDEX idx_users_email CASCADE;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-IDX-DROP"), "rules: {:?}", rule_ids(&r));
    assert!(
        has_rule(&r, "PG-IDX-CASCADE-DROP"),
        "cascade rule: {:?}",
        rule_ids(&r)
    );
}

#[test]
fn test_drop_index_if_exists() {
    let sql = "DROP INDEX IF EXISTS idx_old;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-IDX-DROP"), "rules: {:?}", rule_ids(&r));
}

// ═══════════════════════════════════════════════════════════════════════
//  CREATE SEQUENCE — INFO-SEQ-NEW
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_create_sequence_format_roundtrip() {
    let sql = "CREATE SEQUENCE user_id_seq START 1 INCREMENT 1;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_create_sequence_signal() {
    let sql = "CREATE SEQUENCE user_id_seq;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-SEQ-NEW"), "rules: {:?}", rule_ids(&r));
    assert!(r.summary.statements_analyzed >= 1);
}

// ═══════════════════════════════════════════════════════════════════════
//  ALTER SEQUENCE — INFO-SEQ-CHG
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_sequence_format_roundtrip() {
    let sql = "ALTER SEQUENCE user_id_seq RESTART WITH 100;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_alter_sequence_signal() {
    let sql = "ALTER SEQUENCE user_id_seq RESTART WITH 100;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-SEQ-CHG"), "rules: {:?}", rule_ids(&r));
}

#[test]
fn test_alter_sequence_owned_by() {
    let sql = "ALTER SEQUENCE user_id_seq OWNED BY users.id;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-SEQ-CHG"), "rules: {:?}", rule_ids(&r));
}

// ═══════════════════════════════════════════════════════════════════════
//  DROP SEQUENCE — SEQ-DROP, SEQ-CASCADE-DROP
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_sequence_format_roundtrip() {
    let sql = "DROP SEQUENCE user_id_seq;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_drop_sequence_signal() {
    let sql = "DROP SEQUENCE user_id_seq;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "SEQ-DROP"), "rules: {:?}", rule_ids(&r));
    assert!(!has_rule(&r, "SEQ-CASCADE-DROP"), "no cascade");
}

#[test]
fn test_drop_sequence_cascade_signal() {
    let sql = "DROP SEQUENCE user_id_seq CASCADE;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "SEQ-DROP"), "rules: {:?}", rule_ids(&r));
    assert!(
        has_rule(&r, "SEQ-CASCADE-DROP"),
        "cascade: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  CREATE TYPE — INFO-PG-TYPE-NEW
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_create_type_enum_format_roundtrip() {
    let sql = "CREATE TYPE mood AS ENUM ('happy', 'sad', 'neutral');";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_create_type_signal() {
    let sql = "CREATE TYPE mood AS ENUM ('happy', 'sad');";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-TYPE-NEW"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_create_type_composite() {
    let sql = "CREATE TYPE address AS (street TEXT, city TEXT, zip TEXT);";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-TYPE-NEW"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  ALTER TYPE — INFO-PG-TYPE-CHG
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_type_format_roundtrip() {
    let sql = "ALTER TYPE mood ADD VALUE 'anxious';";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_alter_type_signal() {
    let sql = "ALTER TYPE mood ADD VALUE 'anxious';";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-TYPE-CHG"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

#[test]
fn test_alter_type_rename() {
    let sql = "ALTER TYPE mood RENAME TO emotion;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-TYPE-CHG"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  DROP TYPE — PG-TYPE-DROP, PG-TYPE-CASCADE-DROP
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_type_format_roundtrip() {
    let sql = "DROP TYPE mood;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_drop_type_signal() {
    let sql = "DROP TYPE mood;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TYPE-DROP"), "rules: {:?}", rule_ids(&r));
    assert!(!has_rule(&r, "PG-TYPE-CASCADE-DROP"), "no cascade");
}

#[test]
fn test_drop_type_cascade_signal() {
    let sql = "DROP TYPE mood CASCADE;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TYPE-DROP"), "rules: {:?}", rule_ids(&r));
    assert!(
        has_rule(&r, "PG-TYPE-CASCADE-DROP"),
        "cascade: {:?}",
        rule_ids(&r)
    );
}

#[test]
fn test_drop_type_if_exists() {
    let sql = "DROP TYPE IF EXISTS old_status;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TYPE-DROP"), "rules: {:?}", rule_ids(&r));
}

// ═══════════════════════════════════════════════════════════════════════
//  COMMENT ON — INFO-COMMENT-CHG
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_comment_on_table_format_roundtrip() {
    let sql = "COMMENT ON TABLE users IS 'User accounts table';";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_comment_on_signal() {
    let sql = "COMMENT ON TABLE users IS 'Main users table';";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-COMMENT-CHG"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_comment_on_column() {
    let sql = "COMMENT ON COLUMN users.email IS 'Primary email address';";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-COMMENT-CHG"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

#[test]
fn test_comment_on_null_removes() {
    let sql = "COMMENT ON TABLE users IS NULL;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-COMMENT-CHG"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  VACUUM — INFO-PG-MAINT-VACUUM
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_vacuum_format_roundtrip() {
    let sql = "VACUUM users;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_vacuum_signal() {
    let sql = "VACUUM users;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-MAINT-VACUUM"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_vacuum_full() {
    let sql = "VACUUM FULL users;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-MAINT-VACUUM"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

#[test]
fn test_vacuum_analyze() {
    let sql = "VACUUM ANALYZE users;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-MAINT-VACUUM"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  ANALYZE — INFO-PG-MAINT-ANALYZE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_analyze_format_roundtrip() {
    let sql = "ANALYZE users;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_analyze_signal() {
    let sql = "ANALYZE users;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-MAINT-ANALYZE"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_analyze_verbose() {
    let sql = "ANALYZE VERBOSE users;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-MAINT-ANALYZE"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  CLUSTER — INFO-PG-MAINT-CLUSTER
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_cluster_format_roundtrip() {
    let sql = "CLUSTER users USING idx_users_email;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_cluster_signal() {
    let sql = "CLUSTER users USING idx_users_email;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-MAINT-CLUSTER"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_cluster_bare() {
    let sql = "CLUSTER;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-MAINT-CLUSTER"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  LISTEN — INFO-PG-NOTIFY-SUB
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_listen_format_roundtrip() {
    let sql = "LISTEN my_channel;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_listen_signal() {
    let sql = "LISTEN my_channel;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-NOTIFY-SUB"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

// ═══════════════════════════════════════════════════════════════════════
//  NOTIFY — INFO-PG-NOTIFY-SEND
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_notify_format_roundtrip() {
    let sql = "NOTIFY my_channel;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_notify_signal() {
    let sql = "NOTIFY my_channel;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-NOTIFY-SEND"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_notify_with_payload() {
    let sql = "NOTIFY my_channel, 'payload data';";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-NOTIFY-SEND"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  UNLISTEN — INFO-PG-NOTIFY-UNSUB
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_unlisten_format_roundtrip() {
    let sql = "UNLISTEN my_channel;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_unlisten_signal() {
    let sql = "UNLISTEN my_channel;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-NOTIFY-UNSUB"),
        "rules: {:?}",
        rule_ids(&r)
    );
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_unlisten_all() {
    let sql = "UNLISTEN *;";
    let r = pg_analyze(sql);
    assert!(
        has_rule(&r, "INFO-PG-NOTIFY-UNSUB"),
        "rules: {:?}",
        rule_ids(&r)
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  CREATE AGGREGATE — INFO-PG-AGG-NEW
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_create_aggregate_format_roundtrip() {
    let sql = "CREATE AGGREGATE my_avg (float8) (sfunc = float8_accum, stype = float8[]);";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_create_aggregate_signal() {
    let sql = "CREATE AGGREGATE my_avg (float8) (sfunc = float8_accum, stype = float8[]);";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-PG-AGG-NEW"), "rules: {:?}", rule_ids(&r));
    assert!(r.summary.statements_analyzed >= 1);
}

// ═══════════════════════════════════════════════════════════════════════
//  CREATE OPERATOR — INFO-PG-OP-NEW
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_create_operator_format_roundtrip() {
    let sql = "CREATE OPERATOR === (leftarg = text, rightarg = text, procedure = my_eq);";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_create_operator_signal() {
    let sql = "CREATE OPERATOR === (leftarg = text, rightarg = text, procedure = my_eq);";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "INFO-PG-OP-NEW"), "rules: {:?}", rule_ids(&r));
    assert!(r.summary.statements_analyzed >= 1);
}

// ═══════════════════════════════════════════════════════════════════════
//  CREATE TABLESPACE — PG-TBLSPC-NEW
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_create_tablespace_format_roundtrip() {
    let sql = "CREATE TABLESPACE fast_disk LOCATION '/ssd/pgdata';";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_create_tablespace_signal() {
    let sql = "CREATE TABLESPACE fast_disk LOCATION '/ssd/pgdata';";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TBLSPC-NEW"), "rules: {:?}", rule_ids(&r));
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_create_tablespace_with_owner() {
    let sql = "CREATE TABLESPACE fast_disk OWNER admin LOCATION '/ssd/pgdata';";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TBLSPC-NEW"), "rules: {:?}", rule_ids(&r));
}

// ═══════════════════════════════════════════════════════════════════════
//  DROP TABLESPACE — PG-TBLSPC-DROP
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_drop_tablespace_format_roundtrip() {
    let sql = "DROP TABLESPACE fast_disk;";
    let fmt = pg_format(sql);
    verify_formatting_safe(sql, &fmt).expect("safe roundtrip");
}

#[test]
fn test_drop_tablespace_signal() {
    let sql = "DROP TABLESPACE fast_disk;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TBLSPC-DROP"), "rules: {:?}", rule_ids(&r));
    assert!(r.summary.statements_analyzed >= 1);
}

#[test]
fn test_drop_tablespace_if_exists() {
    let sql = "DROP TABLESPACE IF EXISTS fast_disk;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TBLSPC-DROP"), "rules: {:?}", rule_ids(&r));
}

// ═══════════════════════════════════════════════════════════════════════
//  Multi-statement evidence counting
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_statement_low_tier() {
    let sql = r#"
        CREATE INDEX idx1 ON t1 (a);
        CREATE INDEX idx2 ON t2 (b);
        DROP INDEX idx3;
        CREATE SEQUENCE seq1;
        ALTER SEQUENCE seq2 RESTART;
        DROP SEQUENCE seq3;
        CREATE TYPE mood AS ENUM ('happy');
        ALTER TYPE mood ADD VALUE 'sad';
        DROP TYPE old_type;
        COMMENT ON TABLE t IS 'test';
        VACUUM t1;
        ANALYZE t2;
        CLUSTER t3 USING idx_t3;
        LISTEN ch;
        NOTIFY ch;
        UNLISTEN ch;
    "#;
    let r = pg_analyze(sql);

    assert!(
        r.summary.statements_analyzed >= 16,
        "all 16 stmts analyzed, got {}",
        r.summary.statements_analyzed
    );

    // Spot-check a few rules
    assert!(has_rule(&r, "INFO-PG-IDX-NEW"), "CREATE INDEX");
    assert!(has_rule(&r, "PG-IDX-DROP"), "DROP INDEX");
    assert!(has_rule(&r, "INFO-SEQ-NEW"), "CREATE SEQUENCE");
    assert!(has_rule(&r, "INFO-SEQ-CHG"), "ALTER SEQUENCE");
    assert!(has_rule(&r, "SEQ-DROP"), "DROP SEQUENCE");
    assert!(has_rule(&r, "INFO-PG-TYPE-NEW"), "CREATE TYPE");
    assert!(has_rule(&r, "INFO-PG-TYPE-CHG"), "ALTER TYPE");
    assert!(has_rule(&r, "PG-TYPE-DROP"), "DROP TYPE");
    assert!(has_rule(&r, "INFO-COMMENT-CHG"), "COMMENT ON");
    assert!(has_rule(&r, "INFO-PG-MAINT-VACUUM"), "VACUUM");
    assert!(has_rule(&r, "INFO-PG-MAINT-ANALYZE"), "ANALYZE");
    assert!(has_rule(&r, "INFO-PG-MAINT-CLUSTER"), "CLUSTER");
    assert!(has_rule(&r, "INFO-PG-NOTIFY-SUB"), "LISTEN");
    assert!(has_rule(&r, "INFO-PG-NOTIFY-SEND"), "NOTIFY");
    assert!(has_rule(&r, "INFO-PG-NOTIFY-UNSUB"), "UNLISTEN");
}

#[test]
fn test_multi_cascade_drops() {
    let sql = r#"
        DROP INDEX idx1 CASCADE;
        DROP SEQUENCE seq1 CASCADE;
        DROP TYPE mood CASCADE;
    "#;
    let r = pg_analyze(sql);

    assert!(has_rule(&r, "PG-IDX-CASCADE-DROP"), "DROP INDEX CASCADE");
    assert!(has_rule(&r, "SEQ-CASCADE-DROP"), "DROP SEQUENCE CASCADE");
    assert!(has_rule(&r, "PG-TYPE-CASCADE-DROP"), "DROP TYPE CASCADE");
}

// ═══════════════════════════════════════════════════════════════════════
//  Negative tests — safe patterns should NOT fire unrelated rules
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_create_index_no_drop_signal() {
    let sql = "CREATE INDEX idx_ok ON t (a);";
    let r = pg_analyze(sql);
    assert!(
        !has_rule(&r, "PG-IDX-DROP"),
        "CREATE INDEX should not fire DROP INDEX rule"
    );
    assert!(
        !has_rule(&r, "PG-IDX-CASCADE-DROP"),
        "CREATE INDEX should not fire CASCADE rule"
    );
}

#[test]
fn test_vacuum_no_type_signal() {
    let sql = "VACUUM users;";
    let r = pg_analyze(sql);
    assert!(
        !has_rule(&r, "INFO-PG-TYPE-NEW"),
        "VACUUM should not fire TYPE created"
    );
    assert!(
        !has_rule(&r, "INFO-SEQ-NEW"),
        "VACUUM should not fire SEQUENCE created"
    );
}

#[test]
fn test_drop_index_restrict_no_cascade() {
    let sql = "DROP INDEX idx_old RESTRICT;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-IDX-DROP"), "DROP INDEX fires");
    assert!(
        !has_rule(&r, "PG-IDX-CASCADE-DROP"),
        "RESTRICT should not fire CASCADE rule"
    );
}

#[test]
fn test_drop_sequence_restrict_no_cascade() {
    let sql = "DROP SEQUENCE seq_old RESTRICT;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "SEQ-DROP"), "DROP SEQUENCE fires");
    assert!(
        !has_rule(&r, "SEQ-CASCADE-DROP"),
        "RESTRICT should not fire CASCADE rule"
    );
}

#[test]
fn test_drop_type_restrict_no_cascade() {
    let sql = "DROP TYPE old_type RESTRICT;";
    let r = pg_analyze(sql);
    assert!(has_rule(&r, "PG-TYPE-DROP"), "DROP TYPE fires");
    assert!(
        !has_rule(&r, "PG-TYPE-CASCADE-DROP"),
        "RESTRICT should not fire CASCADE rule"
    );
}
