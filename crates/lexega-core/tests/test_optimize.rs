// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

// ============================================================================
// Formatting tests — verify OPTIMIZE parses and formats correctly
// ============================================================================

#[test]
fn test_optimize_basic() {
    let sql = "OPTIMIZE my_table;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_optimize_qualified_name() {
    let sql = "OPTIMIZE catalog.schema.my_table;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_optimize_full() {
    let sql = "OPTIMIZE my_table FULL;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_optimize_where() {
    let sql = "OPTIMIZE my_table WHERE date = '2024-01-01';";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_optimize_zorder_by() {
    let sql = "OPTIMIZE my_table ZORDER BY (col1, col2, col3);";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_optimize_full_where_zorder() {
    let sql = "OPTIMIZE my_db.my_table FULL WHERE region = 'US' ZORDER BY (user_id, event_date);";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_optimize_where_complex_predicate() {
    let sql = "OPTIMIZE events WHERE date >= '2024-01-01' AND date < '2024-02-01';";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_optimize_zorder_single_column() {
    let sql = "OPTIMIZE my_table ZORDER BY (user_id);";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ============================================================================
// Risk analysis tests — verify signals are generated correctly
// ============================================================================

#[test]
fn test_optimize_risk_analysis_basic() {
    let sql = "OPTIMIZE my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Signals are deduplicated by rule — check evidence count
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-TBL-OPT"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 1,
        "OPTIMIZE should generate a signal. Got {} evidence.",
        total_evidence
    );
}

#[test]
fn test_optimize_risk_analysis_with_zorder() {
    let sql = "OPTIMIZE events ZORDER BY (user_id, event_date);";
    let report = analyze_risk(sql).expect("analysis should succeed");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-TBL-OPT"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 1,
        "OPTIMIZE with ZORDER should generate a signal. Got {} evidence.",
        total_evidence
    );
}

#[test]
fn test_optimize_multi_statement() {
    let sql = r#"
        OPTIMIZE table1;
        OPTIMIZE table2 ZORDER BY (col1);
        OPTIMIZE table3 FULL WHERE id > 100 ZORDER BY (col2, col3);
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Signals are deduplicated by rule — test evidence_count, not signal count
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-TBL-OPT"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 3,
        "Should have evidence for all 3 OPTIMIZE statements. Got {} evidence.",
        total_evidence
    );
}

#[test]
fn test_optimize_formatting_roundtrip() {
    // Format once, then format again — should be stable
    let sql = "OPTIMIZE catalog.schema.my_table FULL WHERE region = 'US' ZORDER BY (user_id, event_date);";
    let formatted1 = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("first format should succeed");
    let formatted2 = format_sql_with_config(&formatted1, &FormatterConfig::default())
        .expect("second format should succeed");
    assert_eq!(formatted1, formatted2, "Formatting should be idempotent");
}
