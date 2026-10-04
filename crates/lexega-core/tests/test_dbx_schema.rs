// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks CREATE/ALTER/DROP SCHEMA with MANAGED LOCATION and other Databricks-specific
//! clauses (LOCATION, DEFAULT COLLATION, WITH DBPROPERTIES, OWNER TO, PREDICTIVE OPTIMIZATION).
//!
//! Covers:
//! - CREATE SCHEMA with MANAGED LOCATION, LOCATION, DEFAULT COLLATION, WITH DBPROPERTIES
//! - ALTER SCHEMA SET DBPROPERTIES, OWNER TO, PREDICTIVE OPTIMIZATION, DEFAULT COLLATION
//! - ALTER SCHEMA SET/UNSET TAGS (Databricks-style with TAGS Identifier)
//! - DROP SCHEMA CASCADE/RESTRICT (already supported, sanity check)
//! - Signal emission and YAML rule matching (DBX-SCHEMA-*)
//! - Formatting round-trip (verify_formatting_safe)
//! - Multi-statement evidence counting

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, verify_formatting_safe, DatabricksDialect,
    FormatterConfig,
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

// ============================================================================
// CREATE SCHEMA - Basic formatting
// ============================================================================

#[test]
fn test_create_schema_basic() {
    dbx_format_and_verify("CREATE SCHEMA my_schema;");
}

#[test]
fn test_create_schema_if_not_exists() {
    dbx_format_and_verify("CREATE SCHEMA IF NOT EXISTS my_catalog.my_schema;");
}

#[test]
fn test_create_schema_comment() {
    dbx_format_and_verify("CREATE SCHEMA my_schema COMMENT 'test schema';");
}

// ============================================================================
// CREATE SCHEMA - MANAGED LOCATION (Databricks Unity Catalog)
// ============================================================================

#[test]
fn test_create_schema_managed_location() {
    dbx_format_and_verify("CREATE SCHEMA my_schema MANAGED LOCATION 's3://depts/finance';");
}

#[test]
fn test_create_schema_managed_location_with_if_not_exists() {
    dbx_format_and_verify(
        "CREATE SCHEMA IF NOT EXISTS my_schema MANAGED LOCATION 's3://bucket/path';",
    );
}

#[test]
fn test_create_schema_managed_location_signal() {
    let sql = "CREATE SCHEMA my_schema MANAGED LOCATION 's3://depts/finance';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "DBX-SCHEMA-MGLOC"),
        "Should detect DBX-SCHEMA-MGLOC (Schema Managed Location Set). Signals: {:?}",
        report.signals
    );
}

// ============================================================================
// CREATE SCHEMA - LOCATION (Databricks Hive metastore)
// ============================================================================

#[test]
fn test_create_schema_location() {
    dbx_format_and_verify("CREATE SCHEMA my_schema LOCATION '/samplepath';");
}

#[test]
fn test_create_schema_location_signal() {
    let sql = "CREATE SCHEMA my_schema LOCATION '/samplepath';";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "DBX-SCHEMA-LOC"),
        "Should detect DBX-SCHEMA-LOC (Schema Location Set). Signals: {:?}",
        report.signals
    );
}

// ============================================================================
// CREATE SCHEMA - DEFAULT COLLATION (Databricks)
// ============================================================================

#[test]
fn test_create_schema_default_collation() {
    dbx_format_and_verify("CREATE SCHEMA my_schema DEFAULT COLLATION UNICODE_CI;");
}

#[test]
fn test_create_schema_default_collation_ai() {
    dbx_format_and_verify("CREATE SCHEMA experimental DEFAULT COLLATION UNICODE_CI_AI;");
}

// ============================================================================
// CREATE SCHEMA - WITH DBPROPERTIES (Databricks)
// ============================================================================

#[test]
fn test_create_schema_with_dbproperties() {
    dbx_format_and_verify(
        "CREATE SCHEMA IF NOT EXISTS customer_sc COMMENT 'This is customer schema' LOCATION '/samplepath' WITH DBPROPERTIES (ID=001, Name='John');",
    );
}

#[test]
fn test_create_schema_managed_location_with_dbproperties() {
    dbx_format_and_verify(
        "CREATE SCHEMA my_schema MANAGED LOCATION 's3://bucket/path' WITH DBPROPERTIES (env='prod');",
    );
}

// ============================================================================
// ALTER SCHEMA - SET DBPROPERTIES (Databricks)
// ============================================================================

#[test]
fn test_alter_schema_set_dbproperties() {
    dbx_format_and_verify(
        "ALTER SCHEMA my_schema SET DBPROPERTIES ('Edited-by' = 'John', 'Edit-date' = '01/01/2001');",
    );
}

#[test]
fn test_alter_schema_set_dbproperties_signal() {
    let sql = "ALTER SCHEMA my_schema SET DBPROPERTIES ('Edited-by' = 'John');";
    let report = dbx_analyze(sql);
    // DBX-SCHEMA-DBPROPS-CHG matches condition: modified on AlterSchemaStatement
    // SCHEMA-PROPS-CHG also matches modified condition
    let has_schema_props =
        has_signal(&report, "SCHEMA-PROPS-CHG") || has_signal(&report, "DBX-SCHEMA-DBPROPS-CHG");
    assert!(
        has_schema_props,
        "Should detect schema modification signal. Signals: {:?}",
        report.signals
    );
}

// ============================================================================
// ALTER SCHEMA - OWNER TO (Databricks)
// ============================================================================

#[test]
fn test_alter_schema_set_owner_to() {
    dbx_format_and_verify("ALTER SCHEMA my_schema SET OWNER TO `alf@melmak.et`;");
}

#[test]
fn test_alter_schema_owner_to_without_set() {
    dbx_format_and_verify("ALTER SCHEMA my_schema OWNER TO `admin_user`;");
}

#[test]
fn test_alter_schema_owner_to_signal() {
    let sql = "ALTER SCHEMA my_schema OWNER TO `admin_user`;";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "DBX-SCHEMA-OWNER-CHG"),
        "Should detect DBX-SCHEMA-OWNER-CHG (Schema Ownership Transferred). Signals: {:?}",
        report.signals
    );
}

// ============================================================================
// ALTER SCHEMA - PREDICTIVE OPTIMIZATION (Databricks)
// ============================================================================

#[test]
fn test_alter_schema_enable_predictive_optimization() {
    dbx_format_and_verify("ALTER SCHEMA my_schema ENABLE PREDICTIVE OPTIMIZATION;");
}

#[test]
fn test_alter_schema_disable_predictive_optimization() {
    dbx_format_and_verify("ALTER SCHEMA my_schema DISABLE PREDICTIVE OPTIMIZATION;");
}

#[test]
fn test_alter_schema_inherit_predictive_optimization() {
    dbx_format_and_verify("ALTER SCHEMA my_schema INHERIT PREDICTIVE OPTIMIZATION;");
}

#[test]
fn test_alter_schema_predictive_optimization_signal() {
    let sql = "ALTER SCHEMA my_schema ENABLE PREDICTIVE OPTIMIZATION;";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "DBX-SCHEMA-PREDOPT-CHG"),
        "Should detect DBX-SCHEMA-PREDOPT-CHG (Schema Predictive Optimization Changed). Signals: {:?}",
        report.signals
    );
}

// ============================================================================
// ALTER SCHEMA - DEFAULT COLLATION (Databricks)
// ============================================================================

#[test]
fn test_alter_schema_default_collation() {
    dbx_format_and_verify("ALTER SCHEMA my_schema DEFAULT COLLATION UNICODE_CI_AI;");
}

#[test]
fn test_alter_schema_default_collation_signal() {
    let sql = "ALTER SCHEMA my_schema DEFAULT COLLATION UNICODE_CI_AI;";
    let report = dbx_analyze(sql);
    assert!(
        has_signal(&report, "DBX-SCHEMA-COLLAT-CHG"),
        "Should detect DBX-SCHEMA-COLLAT-CHG (Schema Default Collation Changed). Signals: {:?}",
        report.signals
    );
}

// ============================================================================
// ALTER SCHEMA - SET/UNSET TAGS (Databricks)
// ============================================================================

#[test]
fn test_alter_schema_set_tags_databricks() {
    dbx_format_and_verify(
        "ALTER SCHEMA test SET TAGS ('tag1' = 'val1', 'tag2' = 'val2', 'tag3' = 'val3');",
    );
}

#[test]
fn test_alter_schema_unset_tags_databricks() {
    dbx_format_and_verify("ALTER SCHEMA test UNSET TAGS ('tag1', 'tag2', 'tag3');");
}

// ============================================================================
// DROP SCHEMA - Sanity checks (already supported)
// ============================================================================

#[test]
fn test_drop_schema_cascade() {
    dbx_format_and_verify("DROP SCHEMA IF EXISTS my_schema CASCADE;");
}

#[test]
fn test_drop_schema_restrict() {
    dbx_format_and_verify("DROP SCHEMA IF EXISTS my_schema RESTRICT;");
}

// ============================================================================
// Multi-statement tests
// ============================================================================

#[test]
fn test_multi_statement_schema_operations() {
    let sql = r#"
CREATE SCHEMA my_schema MANAGED LOCATION 's3://depts/finance';
ALTER SCHEMA my_schema SET OWNER TO `admin`;
ALTER SCHEMA my_schema ENABLE PREDICTIVE OPTIMIZATION;
DROP SCHEMA IF EXISTS old_schema CASCADE;
"#;
    dbx_format_and_verify(sql);

    let report = dbx_analyze(sql);

    // Count total evidence across all signals
    let total_evidence: usize = report
        .signals
        .iter()
        .map(|f| match f {
            RuleMatch::Analysis(ref p) => p.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 4,
        "Should have evidence for each statement. Got {} evidence from {} signals. Signals: {:?}",
        total_evidence,
        report.signals.len(),
        report.signals
    );
}

#[test]
fn test_combined_create_schema_all_clauses() {
    // Test all clauses together
    dbx_format_and_verify(
        "CREATE SCHEMA IF NOT EXISTS my_schema COMMENT 'test' MANAGED LOCATION 's3://bucket/path' WITH DBPROPERTIES (env='prod');",
    );
}
