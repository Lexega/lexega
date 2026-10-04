// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL governance signals: anonymous code, extensions, roles.
//!
//!   PG-ANON-EXEC  – DO $$ anonymous code block  (High)
//!   PG-EXT-NEW  – CREATE EXTENSION            (High)
//!   PG-EXT-CASCADE-NEW  – CREATE EXTENSION CASCADE    (Critical)
//!   ROLE-NEW     – CREATE ROLE/USER            (Medium)
//!   ROLE-CHG     – ALTER  ROLE/USER            (High)
//!   ROLE-DROP     – DROP   ROLE/USER            (High)
//!
//! Covers: formatting roundtrip, rule firing, classification, analyzed-not-skipped,
//!         multi-statement evidence counting, USER alias parity.

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
//  PG-ANON-EXEC : DO $$ anonymous code block
// ═════════════════════════════════════════════════════════════════════════

// ── Formatting ──────────────────────────────────────────────────────────

#[test]
fn test_do_block_basic_formats() {
    let sql = "DO $$ BEGIN RAISE NOTICE 'hello'; END $$;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_do_block_with_language_formats() {
    let sql = "DO $$ BEGIN RAISE NOTICE 'hello'; END $$ LANGUAGE plpgsql;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_do_block_tagged_dollar_formats() {
    let sql = "DO $body$ BEGIN NULL; END $body$;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_do_block_multiline_formats() {
    let sql = r#"DO $$
DECLARE
    v INT := 0;
BEGIN
    v := v + 1;
END
$$;"#;
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

// ── Signal ──────────────────────────────────────────────────────────────

#[test]
fn test_do_block_fires_pg_c042() {
    let sql = "DO $$ BEGIN NULL; END $$;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "PG-ANON-EXEC"),
        "PG-ANON-EXEC should fire for DO block. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_do_block_with_language_fires_pg_c042() {
    let sql = "DO $$ BEGIN NULL; END $$ LANGUAGE plpgsql;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "PG-ANON-EXEC"),
        "PG-ANON-EXEC should fire even with LANGUAGE clause. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_do_block_analyzed_not_skipped() {
    let sql = "DO $$ BEGIN NULL; END $$;";
    let report = pg_analyze(sql);
    // Every statement node is counted all the way through: the DO block plus
    // its inner NULL statement (the BEGIN/END grouping itself is not counted).
    assert_eq!(
        report.summary.statements_analyzed, 2,
        "DO block and its inner statement should be analyzed"
    );
    assert_eq!(
        report.summary.statements_skipped, 0,
        "DO block should NOT be skipped"
    );
}

// ── Multi-statement ─────────────────────────────────────────────────────

#[test]
fn test_do_block_multi_statement() {
    let sql = r#"
        DO $$ BEGIN NULL; END $$;
        DO $$ BEGIN RAISE NOTICE 'two'; END $$;
    "#;
    let report = pg_analyze(sql);
    // Counted all the way through: DO #1 (block + NULL = 2) and DO #2
    // (block + RAISE NOTICE = 2). RAISE NOTICE parses cleanly, so there is
    // no opaque fragment.
    assert_eq!(
        report.summary.statements_analyzed, 4,
        "Both DO blocks and their inner statements should be analyzed"
    );
    assert_eq!(
        report.summary.statements_skipped, 0,
        "RAISE NOTICE parses fully — no skipped fragment"
    );

    let evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "PG-ANON-EXEC"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        evidence >= 2,
        "Should have evidence for both DO blocks, got {}",
        evidence
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  PostgreSQL RAISE grammar — RAISE [level] 'format' [, args] [USING ...]
//  Each form must parse fully (no opaque fragment -> statements_skipped == 0)
//  and round-trip byte-exact through the formatter.
// ═════════════════════════════════════════════════════════════════════════

fn pg_raise_parses_clean(sql: &str) {
    let report = pg_analyze(sql);
    assert_eq!(
        report.summary.statements_skipped, 0,
        "RAISE should parse fully with no opaque fragment: {sql}"
    );
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("RAISE should round-trip byte-exact");
}

#[test]
fn test_pg_raise_notice_format_string() {
    pg_raise_parses_clean("DO $$ BEGIN RAISE NOTICE 'two'; END $$;");
}

#[test]
fn test_pg_raise_notice_with_args() {
    pg_raise_parses_clean("DO $$ BEGIN RAISE NOTICE 'got % and %', x, y; END $$;");
}

#[test]
fn test_pg_raise_warning_using_options() {
    pg_raise_parses_clean("DO $$ BEGIN RAISE WARNING 'w' USING HINT = 'h', DETAIL = 'd'; END $$;");
}

#[test]
fn test_pg_raise_exception_format() {
    pg_raise_parses_clean("DO $$ BEGIN RAISE EXCEPTION 'boom %', code; END $$;");
}

#[test]
fn test_pg_raise_bare_reraise() {
    pg_raise_parses_clean("DO $$ BEGIN RAISE; END $$;");
}

#[test]
fn test_pg_raise_using_only() {
    pg_raise_parses_clean("DO $$ BEGIN RAISE EXCEPTION USING MESSAGE = 'm'; END $$;");
}

// ═════════════════════════════════════════════════════════════════════════
//  PG-EXT-NEW / PG-EXT-CASCADE-NEW : CREATE EXTENSION
// ═════════════════════════════════════════════════════════════════════════

// ── Formatting ──────────────────────────────────────────────────────────

#[test]
fn test_create_extension_basic_formats() {
    let sql = "CREATE EXTENSION hstore;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_extension_if_not_exists_formats() {
    let sql = "CREATE EXTENSION IF NOT EXISTS pgcrypto;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_extension_with_schema_formats() {
    let sql = "CREATE EXTENSION hstore SCHEMA public;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_extension_with_version_formats() {
    let sql = "CREATE EXTENSION hstore VERSION '1.4';";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_extension_cascade_formats() {
    let sql = "CREATE EXTENSION postgres_fdw CASCADE;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_extension_full_syntax_formats() {
    let sql = "CREATE EXTENSION IF NOT EXISTS dblink SCHEMA public VERSION '1.8' CASCADE;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

// ── Signals ─────────────────────────────────────────────────────────────

#[test]
fn test_create_extension_fires_pg_ext_new() {
    let sql = "CREATE EXTENSION hstore;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "PG-EXT-NEW"),
        "PG-EXT-NEW should fire for CREATE EXTENSION. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_create_extension_does_not_fire_pg_ext_cascade_new_without_cascade() {
    let sql = "CREATE EXTENSION hstore;";
    let report = pg_analyze(sql);
    assert!(
        !has_rule(&report, "PG-EXT-CASCADE-NEW"),
        "PG-EXT-CASCADE-NEW should NOT fire without CASCADE. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_create_extension_cascade_fires_both() {
    let sql = "CREATE EXTENSION postgres_fdw CASCADE;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "PG-EXT-NEW"),
        "PG-EXT-NEW should fire for CASCADE too. Got: {:?}",
        rule_ids(&report)
    );
    assert!(
        has_rule(&report, "PG-EXT-CASCADE-NEW"),
        "PG-EXT-CASCADE-NEW should fire for CASCADE. Got: {:?}",
        rule_ids(&report)
    );
}

// ── Classification ──────────────────────────────────────────────────────

#[test]
fn test_create_extension_classified_as_ddl() {
    let sql = "CREATE EXTENSION hstore;";
    let report = pg_analyze(sql);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "CREATE EXTENSION should be DDL"
    );
}

#[test]
fn test_create_extension_analyzed_not_skipped() {
    let sql = "CREATE EXTENSION hstore;";
    let report = pg_analyze(sql);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(report.summary.statements_skipped, 0);
}

// ── Multi-statement ─────────────────────────────────────────────────────

#[test]
fn test_create_extension_multi_statement() {
    let sql = r#"
        CREATE EXTENSION hstore;
        CREATE EXTENSION IF NOT EXISTS pgcrypto;
        CREATE EXTENSION dblink CASCADE;
    "#;
    let report = pg_analyze(sql);
    assert_eq!(
        report.summary.statements_analyzed, 3,
        "All 3 CREATE EXTENSION should be analyzed"
    );

    // PG-EXT-NEW should fire for all three
    let c043_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "PG-EXT-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        c043_evidence >= 3,
        "PG-EXT-NEW evidence should cover all 3, got {}",
        c043_evidence
    );

    // PG-EXT-CASCADE-NEW should only fire for the CASCADE one
    assert!(
        has_rule(&report, "PG-EXT-CASCADE-NEW"),
        "PG-EXT-CASCADE-NEW should fire for the CASCADE statement"
    );
}

// ═════════════════════════════════════════════════════════════════════════
//  C091 : CREATE ROLE / CREATE USER
// ═════════════════════════════════════════════════════════════════════════

// ── Formatting ──────────────────────────────────────────────────────────

#[test]
fn test_create_role_basic_formats() {
    let sql = "CREATE ROLE readonly;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_role_with_options_formats() {
    let sql = "CREATE ROLE app_user LOGIN PASSWORD 'secret123' VALID UNTIL '2025-12-31';";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_role_superuser_formats() {
    let sql = "CREATE ROLE admin_role SUPERUSER CREATEDB CREATEROLE LOGIN;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_role_in_role_formats() {
    let sql = "CREATE ROLE team_member IN ROLE dev_team;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_create_user_formats() {
    let sql = "CREATE USER deploy_user PASSWORD 'deploy123';";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

// ── Signals ─────────────────────────────────────────────────────────────

#[test]
fn test_create_role_fires_pg_role_new() {
    let sql = "CREATE ROLE readonly;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "ROLE-NEW"),
        "ROLE-NEW should fire for CREATE ROLE. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_create_user_fires_pg_role_new() {
    let sql = "CREATE USER deploy_user PASSWORD 'deploy123';";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "ROLE-NEW"),
        "ROLE-NEW should fire for CREATE USER (alias). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_create_role_analyzed_not_skipped() {
    let sql = "CREATE ROLE readonly;";
    let report = pg_analyze(sql);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(report.summary.statements_skipped, 0);
}

// ═════════════════════════════════════════════════════════════════════════
//  C092 : ALTER ROLE / ALTER USER
// ═════════════════════════════════════════════════════════════════════════

// ── Formatting ──────────────────────────────────────────────────────────

#[test]
fn test_alter_role_basic_formats() {
    let sql = "ALTER ROLE app_user NOLOGIN;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_alter_role_set_formats() {
    let sql = "ALTER ROLE app_user SET search_path TO public, app_schema;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_alter_role_rename_formats() {
    let sql = "ALTER ROLE old_name RENAME TO new_name;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_alter_role_password_formats() {
    let sql = "ALTER ROLE app_user PASSWORD 'new_password';";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_alter_role_superuser_formats() {
    let sql = "ALTER ROLE app_user SUPERUSER;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_alter_user_formats() {
    let sql = "ALTER USER deploy_user CREATEDB;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

// ── Signals ─────────────────────────────────────────────────────────────

#[test]
fn test_alter_role_fires_pg_role_chg() {
    let sql = "ALTER ROLE app_user NOLOGIN;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "ROLE-CHG"),
        "ROLE-CHG should fire for ALTER ROLE. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_alter_user_fires_pg_role_chg() {
    let sql = "ALTER USER deploy_user CREATEDB;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "ROLE-CHG"),
        "ROLE-CHG should fire for ALTER USER (alias). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_alter_role_analyzed_not_skipped() {
    let sql = "ALTER ROLE app_user NOLOGIN;";
    let report = pg_analyze(sql);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(report.summary.statements_skipped, 0);
}

// ═════════════════════════════════════════════════════════════════════════
//  C098 : DROP ROLE / DROP USER
// ═════════════════════════════════════════════════════════════════════════

// ── Formatting ──────────────────────────────────────────────────────────

#[test]
fn test_drop_role_basic_formats() {
    let sql = "DROP ROLE old_role;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_drop_role_if_exists_formats() {
    let sql = "DROP ROLE IF EXISTS old_role;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_drop_user_formats() {
    let sql = "DROP USER temp_user;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

#[test]
fn test_drop_user_if_exists_formats() {
    let sql = "DROP USER IF EXISTS temp_user;";
    let formatted = pg_format(sql);
    verify_formatting_safe(sql, &formatted).expect("safe");
}

// ── Signals ─────────────────────────────────────────────────────────────

#[test]
fn test_drop_role_fires_pg_role_drop() {
    let sql = "DROP ROLE old_role;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "ROLE-DROP"),
        "ROLE-DROP should fire for DROP ROLE. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_user_fires_pg_role_drop() {
    let sql = "DROP USER temp_user;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "ROLE-DROP"),
        "ROLE-DROP should fire for DROP USER (alias). Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_role_if_exists_fires_pg_role_drop() {
    let sql = "DROP ROLE IF EXISTS maybe_role;";
    let report = pg_analyze(sql);
    assert!(
        has_rule(&report, "ROLE-DROP"),
        "ROLE-DROP should fire even with IF EXISTS. Got: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn test_drop_role_analyzed_not_skipped() {
    let sql = "DROP ROLE old_role;";
    let report = pg_analyze(sql);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(report.summary.statements_skipped, 0);
}

// ═════════════════════════════════════════════════════════════════════════
//  Cross-cutting multi-statement & evidence tests
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_role_lifecycle_multi_statement() {
    let sql = r#"
        CREATE ROLE app_role LOGIN;
        ALTER ROLE app_role SET search_path TO public;
        DROP ROLE app_role;
    "#;
    let report = pg_analyze(sql);
    assert_eq!(
        report.summary.statements_analyzed, 3,
        "All 3 ROLE statements should be analyzed"
    );
    assert!(has_rule(&report, "ROLE-NEW"), "ROLE-NEW for CREATE");
    assert!(has_rule(&report, "ROLE-CHG"), "ROLE-CHG for ALTER");
    assert!(has_rule(&report, "ROLE-DROP"), "ROLE-DROP for DROP");
}

#[test]
fn test_user_lifecycle_multi_statement() {
    let sql = r#"
        CREATE USER app_user PASSWORD 'secret';
        ALTER USER app_user CREATEDB;
        DROP USER app_user;
    "#;
    let report = pg_analyze(sql);
    assert_eq!(
        report.summary.statements_analyzed, 3,
        "All 3 USER statements should be analyzed (USER is ROLE alias)"
    );
    assert!(has_rule(&report, "ROLE-NEW"), "ROLE-NEW for CREATE USER");
    assert!(has_rule(&report, "ROLE-CHG"), "ROLE-CHG for ALTER USER");
    assert!(has_rule(&report, "ROLE-DROP"), "ROLE-DROP for DROP USER");
}

#[test]
fn test_multiple_create_roles_evidence_count() {
    let sql = r#"
        CREATE ROLE reader;
        CREATE ROLE writer;
        CREATE ROLE admin SUPERUSER;
    "#;
    let report = pg_analyze(sql);
    assert_eq!(report.summary.statements_analyzed, 3);

    let evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "ROLE-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        evidence >= 3,
        "ROLE-NEW evidence should cover all 3 CREATE ROLE, got {}",
        evidence
    );
}

#[test]
fn test_mixed_governance_multi_statement() {
    let sql = r#"
        DO $$ BEGIN NULL; END $$;
        CREATE EXTENSION hstore;
        CREATE ROLE readonly;
        ALTER ROLE readonly SET search_path TO public;
        DROP ROLE readonly;
    "#;
    let report = pg_analyze(sql);
    // 6 statement nodes all the way through: the DO block plus its inner NULL
    // (= 2) and the four top-level governance statements.
    assert_eq!(
        report.summary.statements_analyzed, 6,
        "DO block (with its inner statement) and the four governance statements should be analyzed"
    );

    assert!(has_rule(&report, "PG-ANON-EXEC"), "DO block signal");
    assert!(has_rule(&report, "PG-EXT-NEW"), "CREATE EXTENSION signal");
    assert!(has_rule(&report, "ROLE-NEW"), "CREATE ROLE signal");
    assert!(has_rule(&report, "ROLE-CHG"), "ALTER ROLE signal");
    assert!(has_rule(&report, "ROLE-DROP"), "DROP ROLE signal");
}

// ═════════════════════════════════════════════════════════════════════════
//  Negative tests (should NOT fire wrong rules)
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_role_does_not_fire_alter_or_drop() {
    let sql = "CREATE ROLE test_role;";
    let report = pg_analyze(sql);
    assert!(
        !has_rule(&report, "ROLE-CHG"),
        "CREATE ROLE should NOT fire ROLE-CHG (ALTER)"
    );
    assert!(
        !has_rule(&report, "ROLE-DROP"),
        "CREATE ROLE should NOT fire ROLE-DROP (DROP)"
    );
}

#[test]
fn test_alter_role_does_not_fire_create_or_drop() {
    let sql = "ALTER ROLE test_role NOLOGIN;";
    let report = pg_analyze(sql);
    assert!(
        !has_rule(&report, "ROLE-NEW"),
        "ALTER ROLE should NOT fire ROLE-NEW (CREATE)"
    );
    assert!(
        !has_rule(&report, "ROLE-DROP"),
        "ALTER ROLE should NOT fire ROLE-DROP (DROP)"
    );
}

#[test]
fn test_drop_role_does_not_fire_create_or_alter() {
    let sql = "DROP ROLE test_role;";
    let report = pg_analyze(sql);
    assert!(
        !has_rule(&report, "ROLE-NEW"),
        "DROP ROLE should NOT fire ROLE-NEW (CREATE)"
    );
    assert!(
        !has_rule(&report, "ROLE-CHG"),
        "DROP ROLE should NOT fire ROLE-CHG (ALTER)"
    );
}

#[test]
fn test_do_block_does_not_fire_extension_or_role_rules() {
    let sql = "DO $$ BEGIN NULL; END $$;";
    let report = pg_analyze(sql);
    assert!(
        !has_rule(&report, "PG-EXT-NEW"),
        "DO should NOT fire extension rule"
    );
    assert!(
        !has_rule(&report, "ROLE-NEW"),
        "DO should NOT fire CREATE ROLE rule"
    );
}
