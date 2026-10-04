// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::{
    analyzer::RiskLevel, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| {
        let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
        g.matched_rule == rule_id
    })
}

// =============================================================================
// BASIC PARSING AND FORMATTING
// =============================================================================

#[test]
fn test_undrop_table_basic() {
    let sql = "UNDROP TABLE my_table;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_undrop_table_qualified_name() {
    let sql = "UNDROP TABLE my_db.my_schema.my_table;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_undrop_table_two_part_name() {
    let sql = "UNDROP TABLE my_schema.my_table;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_undrop_table_quoted_name() {
    let sql = r#"UNDROP TABLE "My Table";"#;
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_undrop_table_no_semicolon() {
    let sql = "UNDROP TABLE my_table";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// =============================================================================
// RISK ANALYSIS SIGNALS
// =============================================================================

#[test]
fn test_undrop_table_signal() {
    let sql = "UNDROP TABLE deleted_audit_logs;";
    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        has_signal(&report, "INFO-TBL-UNDROP"),
        "Should find INFO-TBL-UNDROP (Table Recovered). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| {
                let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
                g.matched_rule.clone()
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_undrop_table_risk_level() {
    let sql = "UNDROP TABLE deleted_audit_logs;";
    let report = analyze_risk(sql).expect("should analyze");

    // SNW-TBL-UNDROP Table Recovered should be Info level
    let signal = report.signals.iter().find(|s| {
        let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
        g.matched_rule == "INFO-TBL-UNDROP"
    });

    assert!(signal.is_some(), "Should have INFO-TBL-UNDROP signal");
    if let Some(lexega_core::analyzer::RuleMatch::Analysis(ref g)) = signal {
        assert_eq!(
            g.risk_level,
            RiskLevel::Info,
            "Table Recovered should be Info risk level"
        );
    }
}

#[test]
fn test_undrop_table_qualified_signal() {
    let sql = "UNDROP TABLE prod_db.analytics.deleted_metrics;";
    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        has_signal(&report, "INFO-TBL-UNDROP"),
        "Should find INFO-TBL-UNDROP for qualified table name"
    );
}

// =============================================================================
// MULTI-STATEMENT TESTS
// =============================================================================

#[test]
fn test_undrop_table_multi_statement() {
    let sql = r#"
        UNDROP TABLE table1;
        UNDROP TABLE table2;
        UNDROP TABLE schema1.table3;
    "#;
    let report = analyze_risk(sql).expect("should analyze");

    // All 3 statements should parse
    assert_eq!(
        report.summary.statements_parsed, 3,
        "All 3 UNDROP TABLE statements should be parsed"
    );

    // Count evidence for SNW-TBL-UNDROP (Table Recovered) rule across all signals
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| {
            let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
            g.matched_rule == "INFO-TBL-UNDROP"
        })
        .map(|s| {
            let lexega_core::analyzer::RuleMatch::Analysis(ref g) = s;
            g.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_evidence >= 3,
        "Should have evidence for each UNDROP TABLE. Got: {}",
        total_evidence
    );
}

#[test]
fn test_undrop_table_mixed_with_other_statements() {
    let sql = r#"
        DROP TABLE old_data;
        UNDROP TABLE old_data;
        SELECT * FROM old_data;
    "#;
    let report = analyze_risk(sql).expect("should analyze");

    assert_eq!(
        report.summary.statements_parsed, 3,
        "All 3 statements should be parsed"
    );

    // Should have both Table Dropped (TBL-DROP) and Table Recovered (C314)
    assert!(
        has_signal(&report, "TBL-DROP"),
        "Should find TBL-DROP (Table Dropped)"
    );
    assert!(
        has_signal(&report, "INFO-TBL-UNDROP"),
        "Should find INFO-TBL-UNDROP (Table Recovered)"
    );
}

// =============================================================================
// FORMATTING PRESERVATION
// =============================================================================

#[test]
fn test_undrop_table_formatting_multi() {
    let sql = r#"
UNDROP TABLE my_table;

UNDROP TABLE my_db.my_schema.my_table;
    "#;
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
