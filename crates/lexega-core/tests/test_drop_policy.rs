// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for DROP MASKING POLICY and DROP ROW ACCESS POLICY parsing, formatting, and risk analysis

use lexega_core::analyzer::{RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

// =============================================================================
// DROP MASKING POLICY - PARSING AND FORMATTING
// =============================================================================

#[test]
fn test_drop_masking_policy_simple() {
    let sql = "DROP MASKING POLICY email_mask;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse simple DROP MASKING POLICY");

    verify_formatting_safe(sql, &formatted).expect("DROP MASKING POLICY should be safe");
}

#[test]
fn test_drop_masking_policy_qualified_name() {
    let sql = "DROP MASKING POLICY my_db.my_schema.email_mask;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP MASKING POLICY with qualified name");

    verify_formatting_safe(sql, &formatted).expect("qualified DROP MASKING POLICY should be safe");
}

#[test]
fn test_drop_masking_policy_quoted_identifier() {
    let sql = r#"DROP MASKING POLICY "My Special Policy";"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP MASKING POLICY with quoted identifier");

    verify_formatting_safe(sql, &formatted).expect("quoted DROP MASKING POLICY should be safe");
}

#[test]
fn test_drop_masking_policy_if_exists() {
    let sql = "DROP MASKING POLICY IF EXISTS email_mask;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP MASKING POLICY IF EXISTS");

    verify_formatting_safe(sql, &formatted).expect("DROP MASKING POLICY IF EXISTS should be safe");
}

#[test]
fn test_drop_aggregation_policy_if_exists() {
    let sql = "DROP AGGREGATION POLICY IF EXISTS db.s.agg_pol;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP AGGREGATION POLICY IF EXISTS");

    verify_formatting_safe(sql, &formatted)
        .expect("DROP AGGREGATION POLICY IF EXISTS should be safe");
}

#[test]
fn test_drop_projection_policy_if_exists() {
    let sql = "DROP PROJECTION POLICY IF EXISTS proj_pol;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP PROJECTION POLICY IF EXISTS");

    verify_formatting_safe(sql, &formatted)
        .expect("DROP PROJECTION POLICY IF EXISTS should be safe");
}

// =============================================================================
// DROP ROW ACCESS POLICY - PARSING AND FORMATTING
// =============================================================================

#[test]
fn test_drop_row_access_policy_simple() {
    let sql = "DROP ROW ACCESS POLICY secure_rows;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse simple DROP ROW ACCESS POLICY");

    verify_formatting_safe(sql, &formatted).expect("DROP ROW ACCESS POLICY should be safe");
}

#[test]
fn test_drop_row_access_policy_if_exists() {
    let sql = "DROP ROW ACCESS POLICY IF EXISTS secure_rows;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP ROW ACCESS POLICY IF EXISTS");

    verify_formatting_safe(sql, &formatted)
        .expect("DROP ROW ACCESS POLICY IF EXISTS should be safe");
}

#[test]
fn test_drop_row_access_policy_qualified_name() {
    let sql = "DROP ROW ACCESS POLICY my_db.my_schema.secure_rows;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP ROW ACCESS POLICY with qualified name");

    verify_formatting_safe(sql, &formatted)
        .expect("qualified DROP ROW ACCESS POLICY should be safe");
}

#[test]
fn test_drop_row_access_policy_if_exists_qualified() {
    let sql = "DROP ROW ACCESS POLICY IF EXISTS my_db.my_schema.secure_rows;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP ROW ACCESS POLICY IF EXISTS with qualified name");

    verify_formatting_safe(sql, &formatted)
        .expect("DROP ROW ACCESS POLICY IF EXISTS qualified should be safe");
}

#[test]
fn test_drop_row_access_policy_quoted_identifier() {
    let sql = r#"DROP ROW ACCESS POLICY IF EXISTS "My Row Policy";"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse DROP ROW ACCESS POLICY with quoted identifier");

    verify_formatting_safe(sql, &formatted).expect("quoted DROP ROW ACCESS POLICY should be safe");
}

// =============================================================================
// DROP MASKING POLICY - RISK ANALYSIS
// =============================================================================

#[test]
fn test_drop_masking_policy_medium_risk() {
    let sql = "DROP MASKING POLICY email_mask;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have medium finding for dropping masking policy
    assert!(
        report.summary.medium_count >= 1,
        "Should have medium finding for dropping masking policy"
    );

    // Should find MASK-DROP violation
    assert!(
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "MASK-DROP"
        }),
        "Should find MASK-DROP (masking policy dropped)"
    );
}

#[test]
fn test_drop_masking_policy_if_exists_medium_risk() {
    // IF EXISTS must not be consumed as the policy name: that would split
    // the statement and leave a phantom unparsed `EXISTS <name>` tail.
    let sql = "DROP MASKING POLICY IF EXISTS email_mask;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    assert_eq!(
        report.summary.statements_skipped, 0,
        "IF EXISTS must not split the statement"
    );

    assert!(
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "MASK-DROP"
        }),
        "Should find MASK-DROP with IF EXISTS"
    );
}

#[test]
fn test_drop_masking_policy_qualified_name_medium() {
    let sql = "DROP MASKING POLICY prod_db.security.email_mask;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have medium finding
    assert!(
        report.summary.medium_count >= 1,
        "Qualified DROP MASKING POLICY should be medium"
    );
}

// =============================================================================
// DROP ROW ACCESS POLICY - RISK ANALYSIS
// =============================================================================

#[test]
fn test_drop_row_access_policy_medium_risk() {
    let sql = "DROP ROW ACCESS POLICY secure_rows;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have medium finding for dropping row access policy
    assert!(
        report.summary.medium_count >= 1,
        "Should have medium finding for dropping row access policy"
    );

    // Should find RAP-DROP violation
    assert!(
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "RAP-DROP"
        }),
        "Should find RAP-DROP (row access policy dropped)"
    );
}

#[test]
fn test_drop_row_access_policy_if_exists_medium() {
    let sql = "DROP ROW ACCESS POLICY IF EXISTS secure_rows;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should still be medium even with IF EXISTS
    assert!(
        report.summary.medium_count >= 1,
        "DROP ROW ACCESS POLICY IF EXISTS should still be medium"
    );
}

#[test]
fn test_drop_row_access_policy_qualified_name_medium() {
    let sql = "DROP ROW ACCESS POLICY IF EXISTS prod_db.security.secure_rows;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have medium finding
    assert!(
        report.summary.medium_count >= 1,
        "Qualified DROP ROW ACCESS POLICY should be medium"
    );
}

// =============================================================================
// MULTI-STATEMENT TESTS
// =============================================================================

#[test]
fn test_drop_multiple_policies_multi_statement() {
    let sql = r#"
        DROP MASKING POLICY email_mask;
        DROP ROW ACCESS POLICY secure_rows;
        DROP MASKING POLICY ssn_mask;
    "#;

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Count total evidence across all medium findings (deduplication groups by rule, but tracks each occurrence)
    let total_medium_evidence: usize = report
        .findings
        .iter()
        .filter(|f| matches!(f.risk_level(), RiskLevel::Medium))
        .map(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.evidence_count.unwrap_or(1)
        })
        .sum();

    // Should have at least 3 evidence entries (one for each DROP)
    assert!(
        total_medium_evidence >= 3,
        "Should have evidence for each dropped policy, got {}",
        total_medium_evidence
    );
}

#[test]
fn test_mixed_policy_operations() {
    let sql = r#"
        CREATE MASKING POLICY new_mask AS (val STRING) RETURNS STRING -> '***';
        DROP MASKING POLICY old_mask;
        ALTER ROW ACCESS POLICY existing_policy RENAME TO renamed_policy;
        DROP ROW ACCESS POLICY defunct_policy;
    "#;

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have findings for both DROP statements (medium)
    // DROP MASKING POLICY (MASK-DROP) + DROP ROW ACCESS POLICY (RAP-DROP)
    let drop_masking_findings = report
        .findings
        .iter()
        .filter(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "MASK-DROP"
        })
        .count();

    let drop_row_access_findings = report
        .findings
        .iter()
        .filter(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "RAP-DROP"
        })
        .count();

    assert!(
        drop_masking_findings >= 1,
        "Should find at least one MASK-DROP (masking policy dropped)"
    );
    assert!(
        drop_row_access_findings >= 1,
        "Should find at least one RAP-DROP (row access policy dropped)"
    );
}
