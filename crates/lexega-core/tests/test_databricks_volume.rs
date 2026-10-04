// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CREATE / ALTER / DROP VOLUME (Databricks Unity Catalog DDL).
//!
//! Covers:
//! - CREATE VOLUME with COMMENT, IF NOT EXISTS
//! - CREATE EXTERNAL VOLUME with LOCATION and COMMENT
//! - ALTER VOLUME actions (RENAME TO, OWNER TO, SET TAGS, UNSET TAGS)
//! - DROP VOLUME with IF EXISTS
//! - Formatting (semantic preservation via verify_formatting_safe)
//! - Risk analysis (signal generation and evidence counts)

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql_with_dialect,
    verify_formatting_safe, AstStmt, DatabricksDialect, FormatterConfig,
};
use std::sync::Arc;

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    }
}

fn dbx_format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &dbx_config())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn parses_as_create_volume(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::CreateVolume(_)))
}

fn parses_as_alter_volume(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::AlterVolume(_)))
}

fn parses_as_drop_volume(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::DropVolume(_)))
}

// ============================================================================
// CREATE VOLUME — Parsing
// ============================================================================

#[test]
fn parse_create_volume_basic() {
    assert!(parses_as_create_volume("CREATE VOLUME my_vol;"));
}

#[test]
fn parse_create_volume_if_not_exists() {
    assert!(parses_as_create_volume(
        "CREATE VOLUME IF NOT EXISTS my_vol;"
    ));
}

#[test]
fn parse_create_volume_with_comment() {
    assert!(parses_as_create_volume(
        "CREATE VOLUME my_vol COMMENT 'test volume';"
    ));
}

#[test]
fn parse_create_volume_qualified_name() {
    assert!(parses_as_create_volume(
        "CREATE VOLUME my_catalog.my_schema.my_vol;"
    ));
}

#[test]
fn parse_create_volume_qualified_name_if_not_exists() {
    assert!(parses_as_create_volume(
        "CREATE VOLUME IF NOT EXISTS catalog.schema.vol1 COMMENT 'hello';"
    ));
}

#[test]
fn parse_create_external_volume_basic() {
    assert!(parses_as_create_volume(
        "CREATE EXTERNAL VOLUME ext_vol LOCATION 's3://bucket/path';"
    ));
}

#[test]
fn parse_create_external_volume_with_comment() {
    assert!(parses_as_create_volume(
        "CREATE EXTERNAL VOLUME ext_vol LOCATION 'abfss://container@account.dfs/path' COMMENT 'Azure external';"
    ));
}

#[test]
fn parse_create_external_volume_if_not_exists() {
    assert!(parses_as_create_volume(
        "CREATE EXTERNAL VOLUME IF NOT EXISTS catalog.schema.ext_vol LOCATION 'gs://bucket/prefix';"
    ));
}

// ============================================================================
// ALTER VOLUME — Parsing
// ============================================================================

#[test]
fn parse_alter_volume_rename() {
    assert!(parses_as_alter_volume(
        "ALTER VOLUME my_vol RENAME TO new_name;"
    ));
}

#[test]
fn parse_alter_volume_owner_to() {
    assert!(parses_as_alter_volume(
        "ALTER VOLUME my_vol OWNER TO data_team;"
    ));
}

#[test]
fn parse_alter_volume_set_owner_to() {
    assert!(parses_as_alter_volume(
        "ALTER VOLUME my_vol SET OWNER TO admin_group;"
    ));
}

#[test]
fn parse_alter_volume_set_tags() {
    assert!(parses_as_alter_volume(
        "ALTER VOLUME my_vol SET TAGS ('env' = 'prod', 'team' = 'data');"
    ));
}

#[test]
fn parse_alter_volume_unset_tags() {
    assert!(parses_as_alter_volume(
        "ALTER VOLUME my_vol UNSET TAGS ('env', 'team');"
    ));
}

#[test]
fn parse_alter_volume_qualified_name() {
    assert!(parses_as_alter_volume(
        "ALTER VOLUME catalog.schema.vol RENAME TO catalog.schema.new_vol;"
    ));
}

// ============================================================================
// DROP VOLUME — Parsing
// ============================================================================

#[test]
fn parse_drop_volume_basic() {
    assert!(parses_as_drop_volume("DROP VOLUME my_vol;"));
}

#[test]
fn parse_drop_volume_if_exists() {
    assert!(parses_as_drop_volume("DROP VOLUME IF EXISTS my_vol;"));
}

#[test]
fn parse_drop_volume_qualified_name() {
    assert!(parses_as_drop_volume(
        "DROP VOLUME IF EXISTS catalog.schema.my_vol;"
    ));
}

// ============================================================================
// Formatting — Semantic Preservation
// ============================================================================

#[test]
fn format_create_volume() {
    dbx_format_and_verify("CREATE VOLUME my_vol;");
}

#[test]
fn format_create_volume_with_comment() {
    dbx_format_and_verify("CREATE VOLUME my_vol COMMENT 'production data';");
}

#[test]
fn format_create_external_volume() {
    dbx_format_and_verify(
        "CREATE EXTERNAL VOLUME ext_vol LOCATION 's3://bucket/path' COMMENT 'external';",
    );
}

#[test]
fn format_create_volume_if_not_exists() {
    dbx_format_and_verify("CREATE VOLUME IF NOT EXISTS catalog.schema.vol COMMENT 'test';");
}

#[test]
fn format_alter_volume_rename() {
    dbx_format_and_verify("ALTER VOLUME my_vol RENAME TO new_vol;");
}

#[test]
fn format_alter_volume_owner_to() {
    dbx_format_and_verify("ALTER VOLUME my_vol OWNER TO admin_group;");
}

#[test]
fn format_alter_volume_set_tags() {
    dbx_format_and_verify("ALTER VOLUME my_vol SET TAGS ('env' = 'prod', 'team' = 'data');");
}

#[test]
fn format_alter_volume_unset_tags() {
    dbx_format_and_verify("ALTER VOLUME my_vol UNSET TAGS ('env', 'team');");
}

#[test]
fn format_drop_volume() {
    dbx_format_and_verify("DROP VOLUME my_vol;");
}

#[test]
fn format_drop_volume_if_exists() {
    dbx_format_and_verify("DROP VOLUME IF EXISTS catalog.schema.my_vol;");
}

// ============================================================================
// Risk Analysis — Signal Detection
// ============================================================================

#[test]
fn signal_create_volume() {
    let report = dbx_analyze("CREATE VOLUME my_vol;");
    assert!(
        has_signal(&report, "DBX-VOL-NEW"),
        "Should detect DBX-VOL-NEW (Volume Created)"
    );
}

#[test]
fn signal_create_external_volume() {
    let report = dbx_analyze("CREATE EXTERNAL VOLUME ext_vol LOCATION 's3://bucket/path';");
    assert!(
        has_signal(&report, "DBX-VOL-NEW"),
        "Should detect DBX-VOL-NEW (Volume Created) for external volume"
    );
}

#[test]
fn signal_alter_volume_owner() {
    let report = dbx_analyze("ALTER VOLUME my_vol SET OWNER TO admin;");
    assert!(
        has_signal(&report, "DBX-VOL-OWNER-CHG"),
        "Should detect DBX-VOL-OWNER-CHG (Volume Ownership Transfer)"
    );
}

#[test]
fn signal_drop_volume() {
    let report = dbx_analyze("DROP VOLUME IF EXISTS old_vol;");
    assert!(
        has_signal(&report, "DBX-VOL-DROP"),
        "Should detect DBX-VOL-DROP (Volume Dropped)"
    );
}

#[test]
fn signal_alter_volume_rename() {
    let report = dbx_analyze("ALTER VOLUME my_vol RENAME TO new_name;");
    assert!(
        has_signal(&report, "DBX-VOL-NAME-CHG"),
        "Should detect DBX-VOL-NAME-CHG (Volume Renamed)"
    );
}

#[test]
fn signal_alter_volume_set_tags() {
    let report = dbx_analyze("ALTER VOLUME my_vol SET TAGS ('env' = 'prod');");
    assert!(
        has_signal(&report, "DBX-VOL-TAG-CHG"),
        "Should detect DBX-VOL-TAG-CHG (Volume Tags Modified)"
    );
}

#[test]
fn signal_alter_volume_unset_tags() {
    let report = dbx_analyze("ALTER VOLUME my_vol UNSET TAGS ('env');");
    assert!(
        has_signal(&report, "DBX-VOL-TAG-RMV"),
        "Should detect DBX-VOL-TAG-RMV (Volume Tags Removed)"
    );
}

// ============================================================================
// Multi-Statement — Evidence Count
// ============================================================================

#[test]
fn multi_statement_all_volume_ops() {
    let sql = r#"
        CREATE VOLUME vol1 COMMENT 'managed';
        CREATE EXTERNAL VOLUME ext_vol LOCATION 's3://bucket/data';
        ALTER VOLUME vol1 RENAME TO vol2;
        ALTER VOLUME vol1 SET OWNER TO admin_group;
        ALTER VOLUME vol1 SET TAGS ('env' = 'prod');
        ALTER VOLUME vol1 UNSET TAGS ('env');
        DROP VOLUME IF EXISTS old_vol;
    "#;

    let report = dbx_analyze(sql);

    // All 7 statements should be analyzed
    assert!(
        report.summary.total_reported_signals >= 6,
        "Expected at least 6 signals from 7 volume statements, got {}",
        report.summary.total_reported_signals
    );

    // Verify signals from all operation types
    assert!(
        has_signal(&report, "DBX-VOL-NEW"),
        "Should have Volume Created (DBX-VOL-NEW)"
    );
    assert!(
        has_signal(&report, "DBX-VOL-OWNER-CHG"),
        "Should have Volume Ownership Transfer (DBX-VOL-OWNER-CHG)"
    );
    assert!(
        has_signal(&report, "DBX-VOL-DROP"),
        "Should have Volume Dropped (DBX-VOL-DROP)"
    );
    assert!(
        has_signal(&report, "DBX-VOL-NAME-CHG"),
        "Should have Volume Renamed (DBX-VOL-NAME-CHG)"
    );
    assert!(
        has_signal(&report, "DBX-VOL-TAG-CHG"),
        "Should have Volume Tags Modified (DBX-VOL-TAG-CHG)"
    );
    assert!(
        has_signal(&report, "DBX-VOL-TAG-RMV"),
        "Should have Volume Tags Removed (DBX-VOL-TAG-RMV)"
    );
}

#[test]
fn multi_statement_evidence_count() {
    let sql = r#"
        DROP VOLUME vol1;
        DROP VOLUME vol2;
        DROP VOLUME vol3;
    "#;
    let report = dbx_analyze(sql);

    // Count evidence across all matching signals (may be deduplicated by rule)
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(g) if g.matched_rule == "DBX-VOL-DROP"))
        .map(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_evidence >= 3,
        "Should have evidence for each DROP VOLUME, got {}",
        total_evidence
    );
}

// ============================================================================
// Negative Tests — Should NOT parse as VOLUME
// ============================================================================

#[test]
fn not_a_volume_create_table() {
    // Ensure CREATE TABLE doesn't accidentally match as VOLUME
    let script = parse_sql_with_dialect("CREATE TABLE my_table (id INT);", &DatabricksDialect)
        .expect("should parse");
    assert!(
        !script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::CreateVolume(_))),
        "CREATE TABLE should not parse as CreateVolume"
    );
}

#[test]
fn not_a_volume_create_external_table() {
    // Ensure CREATE EXTERNAL TABLE doesn't match as VOLUME
    let script = parse_sql_with_dialect(
        "CREATE EXTERNAL TABLE ext_tbl (id INT) LOCATION 's3://bucket/path';",
        &DatabricksDialect,
    )
    .expect("should parse");
    assert!(
        !script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::CreateVolume(_))),
        "CREATE EXTERNAL TABLE should not parse as CreateVolume"
    );
}
