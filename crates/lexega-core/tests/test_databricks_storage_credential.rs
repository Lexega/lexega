// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CREATE / ALTER / DROP [STORAGE|SERVICE] CREDENTIAL (Databricks Unity Catalog).
//!
//! Covers:
//! - CREATE STORAGE CREDENTIAL with COMMENT, IF NOT EXISTS
//! - CREATE CREDENTIAL (bare form) and CREATE SERVICE CREDENTIAL
//! - ALTER STORAGE CREDENTIAL (RENAME TO, OWNER TO, SET OWNER TO)
//! - DROP STORAGE CREDENTIAL with IF EXISTS
//! - All three credential kinds: STORAGE, SERVICE, bare CREDENTIAL
//! - Formatting (semantic preservation via verify_formatting_safe)
//! - Risk analysis (signal generation via YAML rules DBX-CRED-NEW..DBX-CRED-NAME-CHG)

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

fn parses_as_create_storage_credential(sql: &str) -> bool {
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
        .any(|s| matches!(s, AstStmt::CreateStorageCredential(_)))
}

fn parses_as_alter_storage_credential(sql: &str) -> bool {
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
        .any(|s| matches!(s, AstStmt::AlterStorageCredential(_)))
}

fn parses_as_drop_storage_credential(sql: &str) -> bool {
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
        .any(|s| matches!(s, AstStmt::DropStorageCredential(_)))
}

// ============================================================================
// CREATE STORAGE CREDENTIAL — Parsing
// ============================================================================

#[test]
fn parse_create_storage_credential_basic() {
    assert!(parses_as_create_storage_credential(
        "CREATE STORAGE CREDENTIAL my_cred;"
    ));
}

#[test]
fn parse_create_storage_credential_if_not_exists() {
    assert!(parses_as_create_storage_credential(
        "CREATE STORAGE CREDENTIAL IF NOT EXISTS my_cred;"
    ));
}

#[test]
fn parse_create_storage_credential_with_comment() {
    assert!(parses_as_create_storage_credential(
        "CREATE STORAGE CREDENTIAL my_cred COMMENT 'S3 access for prod';"
    ));
}

#[test]
fn parse_create_storage_credential_if_not_exists_with_comment() {
    assert!(parses_as_create_storage_credential(
        "CREATE STORAGE CREDENTIAL IF NOT EXISTS my_cred COMMENT 'test credential';"
    ));
}

#[test]
fn parse_create_storage_credential_backtick_name() {
    assert!(parses_as_create_storage_credential(
        "CREATE STORAGE CREDENTIAL `my-special-cred`;"
    ));
}

// ============================================================================
// CREATE CREDENTIAL (bare) and SERVICE CREDENTIAL — Parsing
// ============================================================================

#[test]
fn parse_create_credential_bare() {
    assert!(parses_as_create_storage_credential(
        "CREATE CREDENTIAL bare_cred;"
    ));
}

#[test]
fn parse_create_credential_bare_with_comment() {
    assert!(parses_as_create_storage_credential(
        "CREATE CREDENTIAL bare_cred COMMENT 'no qualifier';"
    ));
}

#[test]
fn parse_create_service_credential_basic() {
    assert!(parses_as_create_storage_credential(
        "CREATE SERVICE CREDENTIAL svc_cred;"
    ));
}

#[test]
fn parse_create_service_credential_if_not_exists() {
    assert!(parses_as_create_storage_credential(
        "CREATE SERVICE CREDENTIAL IF NOT EXISTS svc_cred COMMENT 'service';"
    ));
}

// ============================================================================
// ALTER STORAGE CREDENTIAL — Parsing
// ============================================================================

#[test]
fn parse_alter_storage_credential_rename_to() {
    assert!(parses_as_alter_storage_credential(
        "ALTER STORAGE CREDENTIAL my_cred RENAME TO new_cred;"
    ));
}

#[test]
fn parse_alter_storage_credential_owner_to() {
    assert!(parses_as_alter_storage_credential(
        "ALTER STORAGE CREDENTIAL my_cred OWNER TO admin_group;"
    ));
}

#[test]
fn parse_alter_storage_credential_set_owner_to() {
    assert!(parses_as_alter_storage_credential(
        "ALTER STORAGE CREDENTIAL my_cred SET OWNER TO data_team;"
    ));
}

#[test]
fn parse_alter_credential_bare_rename() {
    assert!(parses_as_alter_storage_credential(
        "ALTER CREDENTIAL my_cred RENAME TO new_name;"
    ));
}

#[test]
fn parse_alter_service_credential_owner() {
    assert!(parses_as_alter_storage_credential(
        "ALTER SERVICE CREDENTIAL svc_cred OWNER TO ops_team;"
    ));
}

#[test]
fn parse_alter_storage_credential_backtick_names() {
    assert!(parses_as_alter_storage_credential(
        "ALTER STORAGE CREDENTIAL `my-cred` RENAME TO `new-cred`;"
    ));
}

// ============================================================================
// DROP STORAGE CREDENTIAL — Parsing
// ============================================================================

#[test]
fn parse_drop_storage_credential_basic() {
    assert!(parses_as_drop_storage_credential(
        "DROP STORAGE CREDENTIAL my_cred;"
    ));
}

#[test]
fn parse_drop_storage_credential_if_exists() {
    assert!(parses_as_drop_storage_credential(
        "DROP STORAGE CREDENTIAL IF EXISTS old_cred;"
    ));
}

#[test]
fn parse_drop_credential_bare() {
    assert!(parses_as_drop_storage_credential(
        "DROP CREDENTIAL bare_cred;"
    ));
}

#[test]
fn parse_drop_service_credential() {
    assert!(parses_as_drop_storage_credential(
        "DROP SERVICE CREDENTIAL svc_cred;"
    ));
}

#[test]
fn parse_drop_storage_credential_backtick_name() {
    assert!(parses_as_drop_storage_credential(
        "DROP STORAGE CREDENTIAL IF EXISTS `special-cred-123`;"
    ));
}

// ============================================================================
// Formatting — Semantic Preservation
// ============================================================================

#[test]
fn format_create_storage_credential() {
    dbx_format_and_verify("CREATE STORAGE CREDENTIAL my_cred;");
}

#[test]
fn format_create_storage_credential_if_not_exists_comment() {
    dbx_format_and_verify(
        "CREATE STORAGE CREDENTIAL IF NOT EXISTS my_cred COMMENT 'S3 access for prod';",
    );
}

#[test]
fn format_create_credential_bare() {
    dbx_format_and_verify("CREATE CREDENTIAL bare_cred;");
}

#[test]
fn format_create_service_credential() {
    dbx_format_and_verify("CREATE SERVICE CREDENTIAL svc_cred COMMENT 'service';");
}

#[test]
fn format_alter_storage_credential_rename() {
    dbx_format_and_verify("ALTER STORAGE CREDENTIAL my_cred RENAME TO new_cred;");
}

#[test]
fn format_alter_storage_credential_set_owner() {
    dbx_format_and_verify("ALTER STORAGE CREDENTIAL my_cred SET OWNER TO data_team;");
}

#[test]
fn format_alter_storage_credential_owner() {
    dbx_format_and_verify("ALTER STORAGE CREDENTIAL my_cred OWNER TO admin_group;");
}

#[test]
fn format_drop_storage_credential() {
    dbx_format_and_verify("DROP STORAGE CREDENTIAL my_cred;");
}

#[test]
fn format_drop_storage_credential_if_exists() {
    dbx_format_and_verify("DROP STORAGE CREDENTIAL IF EXISTS old_cred;");
}

#[test]
fn format_drop_service_credential() {
    dbx_format_and_verify("DROP SERVICE CREDENTIAL svc_cred;");
}

// ============================================================================
// Risk Analysis — Signal Generation
// ============================================================================

#[test]
fn signal_create_storage_credential() {
    let report = dbx_analyze("CREATE STORAGE CREDENTIAL my_cred;");
    assert!(
        has_signal(&report, "DBX-CRED-NEW"),
        "Should emit DBX-CRED-NEW (storage credential created)"
    );
    assert_eq!(report.summary.medium_count, 1);
}

#[test]
fn signal_create_credential_bare() {
    let report = dbx_analyze("CREATE CREDENTIAL bare_cred;");
    assert!(
        has_signal(&report, "DBX-CRED-NEW"),
        "Bare CREDENTIAL should also emit DBX-CRED-NEW"
    );
}

#[test]
fn signal_create_service_credential() {
    let report = dbx_analyze("CREATE SERVICE CREDENTIAL svc_cred;");
    assert!(
        has_signal(&report, "DBX-CRED-NEW"),
        "SERVICE CREDENTIAL should also emit DBX-CRED-NEW"
    );
}

#[test]
fn signal_drop_storage_credential() {
    let report = dbx_analyze("DROP STORAGE CREDENTIAL old_cred;");
    assert!(
        has_signal(&report, "DBX-CRED-DROP"),
        "Should emit DBX-CRED-DROP (storage credential dropped)"
    );
    assert!(report.summary.high_count >= 1);
}

#[test]
fn signal_alter_storage_credential_rename() {
    let report = dbx_analyze("ALTER STORAGE CREDENTIAL my_cred RENAME TO new_cred;");
    assert!(
        has_signal(&report, "DBX-CRED-NAME-CHG"),
        "Should emit DBX-CRED-NAME-CHG (storage credential renamed)"
    );
    assert_eq!(report.summary.medium_count, 1);
}

#[test]
fn signal_alter_storage_credential_owner() {
    let report = dbx_analyze("ALTER STORAGE CREDENTIAL my_cred SET OWNER TO data_team;");
    assert!(
        has_signal(&report, "DBX-CRED-OWNER-CHG"),
        "Should emit DBX-CRED-OWNER-CHG (storage credential ownership changed)"
    );
    assert!(report.summary.high_count >= 1);
}

#[test]
fn signal_alter_storage_credential_owner_no_set() {
    let report = dbx_analyze("ALTER STORAGE CREDENTIAL my_cred OWNER TO admin_group;");
    assert!(
        has_signal(&report, "DBX-CRED-OWNER-CHG"),
        "OWNER TO without SET should also emit DBX-CRED-OWNER-CHG"
    );
}

#[test]
fn signal_storage_credential_hardcoded_connection_string() {
    let sql = "CREATE STORAGE CREDENTIAL my_cred COMMENT 'postgres://admin:SuperSecret123@db.internal:5432/warehouse';";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "CRED-CONNSTR-LEAK"),
        "Hardcoded connection string in storage credential should trigger CRED-CONNSTR-LEAK"
    );
    assert!(
        has_signal(&report, "CRED-PWD-LEAK"),
        "Connection string with embedded password should also trigger CRED-PWD-LEAK"
    );
}

// ============================================================================
// Multi-Statement — Evidence Counts
// ============================================================================

#[test]
fn multi_statement_evidence_count() {
    let sql = r#"
        CREATE STORAGE CREDENTIAL cred1;
        CREATE STORAGE CREDENTIAL cred2;
        DROP STORAGE CREDENTIAL old_cred;
        ALTER STORAGE CREDENTIAL cred1 RENAME TO new_cred1;
    "#;
    let report = dbx_analyze(sql);

    // Should have 4 analyzed statements
    assert!(
        report.summary.total_reported_signals >= 3,
        "Should have at least 3 signals (2 create, 1 drop, 1 rename). Got: {}",
        report.summary.total_reported_signals
    );

    // Verify evidence count for deduplicated create signals
    let create_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-CRED-NEW"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        create_evidence >= 2,
        "Should have evidence for both CREATE statements. Got: {}",
        create_evidence
    );
}

// ============================================================================
// Non-Regression — Existing Features
// ============================================================================

#[test]
fn create_storage_integration_still_works() {
    // Ensure STORAGE INTEGRATION is not broken by STORAGE CREDENTIAL dispatch
    let sql = "CREATE STORAGE INTEGRATION my_int TYPE = EXTERNAL_STAGE STORAGE_PROVIDER = 'S3' ENABLED = TRUE STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::role/myrole' STORAGE_ALLOWED_LOCATIONS = ('s3://mybucket/mypath/');";
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("STORAGE INTEGRATION should still parse: {:?}", e));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("STORAGE INTEGRATION safety check failed: {}", e));
}

#[test]
fn drop_storage_integration_still_works() {
    let sql = "DROP STORAGE INTEGRATION my_int;";
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("DROP STORAGE INTEGRATION should still parse: {:?}", e));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("DROP STORAGE INTEGRATION safety check failed: {}", e));
}
