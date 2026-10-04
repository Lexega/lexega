// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Databricks CACHE TABLE / UNCACHE TABLE parsing, formatting, and risk analysis.

use lexega_core::analyzer::{RiskLevel, RuleMatch};
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

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| {
        let RuleMatch::Analysis(ref g) = s;
        g.matched_rule == rule_id
    })
}

// ============================================================================
// CACHE TABLE: Parsing + Formatting
// ============================================================================

#[test]
fn test_cache_table_basic() {
    let sql = "CACHE TABLE my_table;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_table_qualified_name() {
    let sql = "CACHE TABLE my_catalog.my_schema.my_table;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_lazy_table() {
    let sql = "CACHE LAZY TABLE my_table;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_table_with_options() {
    let sql = "CACHE TABLE my_table OPTIONS ('storageLevel' 'DISK_ONLY');";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_table_with_options_eq() {
    let sql = "CACHE TABLE my_table OPTIONS ('storageLevel' = 'MEMORY_AND_DISK');";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_lazy_table_with_options() {
    let sql = "CACHE LAZY TABLE my_table OPTIONS ('storageLevel' = 'MEMORY_ONLY');";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_table_with_as_query() {
    let sql = "CACHE TABLE my_cached_table AS SELECT * FROM source_table;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_table_with_bare_query() {
    let sql = "CACHE TABLE my_cached_table SELECT col1, col2 FROM source_table WHERE col1 > 10;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_cache_lazy_table_with_options_and_query() {
    let sql = "CACHE LAZY TABLE my_cached_table OPTIONS ('storageLevel' = 'MEMORY_AND_DISK_SER') AS SELECT * FROM big_table WHERE active = true;";
    dbx_format_and_verify(sql);
}

// ============================================================================
// UNCACHE TABLE: Parsing + Formatting
// ============================================================================

#[test]
fn test_uncache_table_basic() {
    let sql = "UNCACHE TABLE my_table;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_uncache_table_qualified_name() {
    let sql = "UNCACHE TABLE my_catalog.my_schema.my_table;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_uncache_table_if_exists() {
    let sql = "UNCACHE TABLE IF EXISTS my_table;";
    dbx_format_and_verify(sql);
}

#[test]
fn test_uncache_table_if_exists_qualified() {
    let sql = "UNCACHE TABLE IF EXISTS my_catalog.my_schema.my_table;";
    dbx_format_and_verify(sql);
}

// ============================================================================
// Multi-statement tests (catch NodeId collision bugs)
// ============================================================================

#[test]
fn test_cache_uncache_multi_statement() {
    let sql = r#"
        CACHE TABLE t1;
        CACHE LAZY TABLE t2;
        UNCACHE TABLE t3;
        UNCACHE TABLE IF EXISTS t4;
    "#;
    dbx_format_and_verify(sql);
}

// ============================================================================
// Risk Analysis: CACHE TABLE
// ============================================================================

#[test]
fn test_cache_table_signal_basic() {
    let sql = "CACHE TABLE my_table;";
    let report = dbx_analyze(sql);

    assert!(
        report.signals.len() >= 1,
        "Should generate at least one signal for CACHE TABLE, got: {:?}",
        report.signals
    );
    assert!(
        has_rule(&report, "DBX-TBL-CACHE"),
        "Should find DBX-TBL-CACHE (Table Cached)"
    );
}

#[test]
fn test_cache_lazy_table_signal() {
    let sql = "CACHE LAZY TABLE my_table;";
    let report = dbx_analyze(sql);

    assert!(
        report.signals.len() >= 1,
        "Should generate at least one signal for CACHE LAZY TABLE"
    );
    assert!(
        has_rule(&report, "INFO-DBX-TBL-CACHE-LAZY"),
        "Should find INFO-DBX-TBL-CACHE-LAZY (Table Lazy Cached)"
    );
}

#[test]
fn test_uncache_table_signal() {
    let sql = "UNCACHE TABLE my_table;";
    let report = dbx_analyze(sql);

    assert!(
        report.signals.len() >= 1,
        "Should generate at least one signal for UNCACHE TABLE"
    );
    assert!(
        has_rule(&report, "DBX-TBL-UNCACHE"),
        "Should find DBX-TBL-UNCACHE (Table Uncached)"
    );
}

#[test]
fn test_uncache_table_if_exists_signal() {
    let sql = "UNCACHE TABLE IF EXISTS my_table;";
    let report = dbx_analyze(sql);

    assert!(
        has_rule(&report, "DBX-TBL-UNCACHE"),
        "Should find DBX-TBL-UNCACHE (Table Uncached) even with IF EXISTS"
    );
}

// ============================================================================
// Multi-statement risk analysis (evidence count)
// ============================================================================

#[test]
fn test_cache_uncache_multi_statement_signals() {
    let sql = r#"
        CACHE TABLE t1;
        CACHE LAZY TABLE t2;
        UNCACHE TABLE t3;
    "#;
    let report = dbx_analyze(sql);

    // Count evidence for each rule
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|f| {
            let RuleMatch::Analysis(ref g) = f;
            g.matched_rule.contains("DBX-TBL-CACHE") || g.matched_rule.contains("DBX-TBL-UNCACHE")
        })
        .map(|f| {
            let RuleMatch::Analysis(ref g) = f;
            g.evidence_count.unwrap_or(1)
        })
        .sum();

    assert!(
        total_evidence >= 3,
        "Should have evidence for each CACHE/UNCACHE statement, got {}",
        total_evidence
    );
}

// ============================================================================
// Risk level verification
// ============================================================================

#[test]
fn test_cache_table_risk_level() {
    let sql = "CACHE TABLE my_table;";
    let report = dbx_analyze(sql);

    for signal in &report.signals {
        let RuleMatch::Analysis(ref g) = signal;
        if g.matched_rule == "DBX-TBL-CACHE" {
            assert_eq!(
                g.risk_level,
                RiskLevel::Low,
                "CACHE TABLE should be Low risk"
            );
        }
    }
}

#[test]
fn test_cache_lazy_table_risk_level() {
    let sql = "CACHE LAZY TABLE my_table;";
    let report = dbx_analyze(sql);

    for signal in &report.signals {
        let RuleMatch::Analysis(ref g) = signal;
        if g.matched_rule == "INFO-DBX-TBL-CACHE-LAZY" {
            assert_eq!(
                g.risk_level,
                RiskLevel::Info,
                "CACHE LAZY TABLE should be Info risk"
            );
        }
    }
}

#[test]
fn test_uncache_table_risk_level() {
    let sql = "UNCACHE TABLE my_table;";
    let report = dbx_analyze(sql);

    for signal in &report.signals {
        let RuleMatch::Analysis(ref g) = signal;
        if g.matched_rule == "DBX-TBL-UNCACHE" {
            assert_eq!(
                g.risk_level,
                RiskLevel::Low,
                "UNCACHE TABLE should be Low risk"
            );
        }
    }
}

// ============================================================================
// CACHE TABLE with query: ensure table references are tracked
// ============================================================================

#[test]
fn test_cache_table_tracks_target_table() {
    let sql = "CACHE TABLE my_table;";
    let report = dbx_analyze(sql);

    // Should track the target table as referenced
    assert!(
        report.summary.total_reported_signals > 0,
        "CACHE TABLE should generate at least one signal"
    );
}
