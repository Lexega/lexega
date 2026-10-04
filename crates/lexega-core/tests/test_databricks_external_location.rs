// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks CREATE EXTERNAL LOCATION statement.
//!
//! Covers: parsing, formatting, risk analysis, multi-statement handling.

use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

use lexega_core::api::analyze_risk;

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(
        |s| matches!(s, lexega_core::analyzer::RuleMatch::Analysis(g) if g.matched_rule == rule_id),
    )
}

// ───────────────────────────────────────────────────────────────────────
// Formatting + semantic preservation
// ───────────────────────────────────────────────────────────────────────

#[test]
fn test_create_external_location_basic() {
    let sql = "CREATE EXTERNAL LOCATION s3_remote URL 's3://us-east-1/location' WITH (STORAGE CREDENTIAL s3_remote_cred);";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
    // Should be reformatted with proper indentation
    assert!(
        formatted.contains("CREATE EXTERNAL LOCATION"),
        "header preserved"
    );
    assert!(formatted.contains("URL"), "URL keyword preserved");
    assert!(
        formatted.contains("'s3://us-east-1/location'"),
        "URL value preserved"
    );
    assert!(
        formatted.contains("STORAGE CREDENTIAL"),
        "STORAGE CREDENTIAL preserved"
    );
    assert!(
        formatted.contains("s3_remote_cred"),
        "credential name preserved"
    );
}

#[test]
fn test_create_external_location_if_not_exists() {
    let sql = "CREATE EXTERNAL LOCATION IF NOT EXISTS azure_loc URL 'abfss://container@account.dfs.core.windows.net/path' WITH (STORAGE CREDENTIAL azure_cred) COMMENT 'Azure storage location';";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
    assert!(
        formatted.contains("IF NOT EXISTS"),
        "IF NOT EXISTS preserved"
    );
    assert!(formatted.contains("COMMENT"), "COMMENT keyword preserved");
    assert!(
        formatted.contains("'Azure storage location'"),
        "comment value preserved"
    );
}

#[test]
fn test_create_external_location_backtick_quoted() {
    let sql = "CREATE EXTERNAL LOCATION `s3-remote` URL 's3://us-east-1/location' WITH (STORAGE CREDENTIAL `s3-remote-cred`) COMMENT 'Default source for AWS external data';";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
    assert!(
        formatted.contains("`s3-remote`"),
        "backtick-quoted location name preserved"
    );
    assert!(
        formatted.contains("`s3-remote-cred`"),
        "backtick-quoted credential preserved"
    );
}

#[test]
fn test_create_external_location_no_comment() {
    let sql =
        "CREATE EXTERNAL LOCATION my_loc URL 's3://bucket/path' WITH (STORAGE CREDENTIAL my_cred);";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
    assert!(
        !formatted.contains("COMMENT"),
        "no COMMENT when not specified"
    );
}

#[test]
fn test_create_external_location_formatting_structure() {
    // Verify proper indentation in formatted output
    let sql = "CREATE EXTERNAL LOCATION my_loc URL 's3://bucket/path' WITH (STORAGE CREDENTIAL my_cred) COMMENT 'test';";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    // Each clause should be on its own line
    let lines: Vec<&str> = formatted.lines().collect();
    assert!(
        lines.len() >= 3,
        "should have at least 3 lines: header, URL, WITH (got {} lines: {:?})",
        lines.len(),
        lines
    );
}

// ───────────────────────────────────────────────────────────────────────
// Risk analysis
// ───────────────────────────────────────────────────────────────────────

#[test]
fn test_create_external_location_risk_signal() {
    let sql = "CREATE EXTERNAL LOCATION s3_remote URL 's3://us-east-1/location' WITH (STORAGE CREDENTIAL s3_remote_cred);";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        report.summary.total_reported_signals > 0,
        "Should generate signals for CREATE EXTERNAL LOCATION (got 0 — parser may have fallen back to OpaqueContent)"
    );
}

#[test]
fn test_create_external_location_risk_rule_id() {
    let sql = "CREATE EXTERNAL LOCATION s3_remote URL 's3://us-east-1/location' WITH (STORAGE CREDENTIAL s3_remote_cred);";
    let report = analyze_risk(sql).expect("should analyze");

    let has_extloc_new = report.signals.iter().any(|s| {
        let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
        g.matched_rule == "DBX-EXTLOC-NEW"
    });
    assert!(
        has_extloc_new,
        "Should find DBX-EXTLOC-NEW (External Location Created) signal. Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| {
                match s {
                    lexega_core::analyzer::RuleMatch::Analysis(g) => format!("{}", g.matched_rule),
                }
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_alter_external_location_owner_risk_rule_id() {
    let sql = "ALTER EXTERNAL LOCATION s3_remote OWNER TO data_admin;";
    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        has_signal(&report, "DBX-EXTLOC-OWNER-CHG"),
        "Should find DBX-EXTLOC-OWNER-CHG (External Location Ownership Changed). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                lexega_core::analyzer::RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_alter_external_location_set_credential_risk_rule_id() {
    let sql = "ALTER EXTERNAL LOCATION s3_remote SET STORAGE CREDENTIAL s3_remote_cred_v2;";
    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        has_signal(&report, "DBX-EXTLOC-CRED-CHG"),
        "Should find DBX-EXTLOC-CRED-CHG (External Location Credential Modified). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                lexega_core::analyzer::RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_alter_external_location_set_url_force_risk_rule_id() {
    let sql = "ALTER EXTERNAL LOCATION s3_remote SET URL 's3://us-east-1/new-location' FORCE;";
    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        has_signal(&report, "DBX-EXTLOC-URL-CHG"),
        "Should find DBX-EXTLOC-URL-CHG (External Location URL Modified / weak config). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                lexega_core::analyzer::RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_alter_external_location_set_url_risk_rule_id() {
    let sql = "ALTER EXTERNAL LOCATION s3_remote SET URL 's3://us-east-1/new-location';";
    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        has_signal(&report, "DBX-EXTLOC-URL-CHG"),
        "Should find DBX-EXTLOC-URL-CHG (External Location URL Modified). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                lexega_core::analyzer::RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_drop_external_location_risk_rule_id() {
    let sql = "DROP EXTERNAL LOCATION s3_remote;";
    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        has_signal(&report, "DBX-EXTLOC-DROP"),
        "Should find DBX-EXTLOC-DROP (External Location Dropped). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                lexega_core::analyzer::RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

// ───────────────────────────────────────────────────────────────────────
// Multi-statement (test NodeId collision / evidence count)
// ───────────────────────────────────────────────────────────────────────

#[test]
fn test_create_external_location_multi_statement() {
    let sql = r#"
        CREATE EXTERNAL LOCATION loc1 URL 's3://bucket1/path' WITH (STORAGE CREDENTIAL cred1);
        CREATE EXTERNAL LOCATION loc2 URL 's3://bucket2/path' WITH (STORAGE CREDENTIAL cred2);
    "#;
    let report = analyze_risk(sql).expect("should analyze");

    // Count total evidence across all signals
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| {
            let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
            g.matched_rule == "DBX-EXTLOC-NEW"
        })
        .map(|s| {
            let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
            g.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Should have evidence for each CREATE EXTERNAL LOCATION (got {})",
        total_evidence
    );
}

// ───────────────────────────────────────────────────────────────────────
// Formatting idempotency
// ───────────────────────────────────────────────────────────────────────

#[test]
fn test_create_external_location_idempotent() {
    let sql = "CREATE EXTERNAL LOCATION my_loc URL 's3://bucket/path' WITH (STORAGE CREDENTIAL my_cred) COMMENT 'test';";
    let formatted1 =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("first format");
    let formatted2 =
        format_sql_with_config(&formatted1, &FormatterConfig::default()).expect("second format");
    assert_eq!(formatted1, formatted2, "Formatting should be idempotent");
}

// ────────────────────────────────────────────────────────────────────────
// Mixed with other statements
// ────────────────────────────────────────────────────────────────────────

#[test]
fn test_create_external_location_mixed_script() {
    let sql = r#"
CREATE EXTERNAL LOCATION my_loc
  URL 's3://bucket/path'
  WITH (STORAGE CREDENTIAL my_cred);

SELECT 1;
    "#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format mixed script");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
