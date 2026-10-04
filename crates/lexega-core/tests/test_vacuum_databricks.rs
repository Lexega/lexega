// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt,
    DatabricksDialect, FormatterConfig,
};
use std::sync::Arc;

// ─── helpers ────────────────────────────────────────────────────────────────

fn dbx_format_and_verify(sql: &str) -> String {
    let config = FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config)
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

fn parses_as_vacuum(sql: &str) -> bool {
    let script = parse_sql(sql).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script.stmts.iter().any(|s| matches!(s, AstStmt::Vacuum(_)))
}

// ============================================================================
// Parsing tests — verify VACUUM parses as AstVacuum, not OpaqueContent
// ============================================================================

#[test]
fn test_vacuum_basic_parses() {
    assert!(parses_as_vacuum("VACUUM my_table;"));
}

#[test]
fn test_vacuum_qualified_name_parses() {
    assert!(parses_as_vacuum("VACUUM my_catalog.my_schema.my_table;"));
}

#[test]
fn test_vacuum_retain_parses() {
    assert!(parses_as_vacuum("VACUUM my_table RETAIN 168 HOURS;"));
}

#[test]
fn test_vacuum_dry_run_parses() {
    assert!(parses_as_vacuum("VACUUM my_table DRY RUN;"));
}

#[test]
fn test_vacuum_retain_and_dry_run_parses() {
    assert!(parses_as_vacuum("VACUUM my_table RETAIN 24 HOURS DRY RUN;"));
}

#[test]
fn test_vacuum_lite_parses() {
    assert!(parses_as_vacuum("VACUUM my_table LITE;"));
}

#[test]
fn test_vacuum_full_after_table_parses() {
    assert!(parses_as_vacuum("VACUUM my_table FULL;"));
}

#[test]
fn test_vacuum_lite_dry_run_parses() {
    assert!(parses_as_vacuum("VACUUM my_table LITE DRY RUN;"));
}

#[test]
fn test_vacuum_full_dry_run_parses() {
    assert!(parses_as_vacuum("VACUUM my_table FULL DRY RUN;"));
}

// ============================================================================
// Formatting tests — verify VACUUM formats and round-trips correctly
// ============================================================================

#[test]
fn test_vacuum_format_basic() {
    dbx_format_and_verify("VACUUM my_table;");
}

#[test]
fn test_vacuum_format_qualified_name() {
    dbx_format_and_verify("VACUUM my_catalog.my_schema.my_table;");
}

#[test]
fn test_vacuum_format_retain() {
    dbx_format_and_verify("VACUUM my_table RETAIN 168 HOURS;");
}

#[test]
fn test_vacuum_format_dry_run() {
    dbx_format_and_verify("VACUUM my_table DRY RUN;");
}

#[test]
fn test_vacuum_format_retain_dry_run() {
    dbx_format_and_verify("VACUUM my_table RETAIN 24 HOURS DRY RUN;");
}

#[test]
fn test_vacuum_format_lite() {
    dbx_format_and_verify("VACUUM my_table LITE;");
}

#[test]
fn test_vacuum_format_full_after_table() {
    dbx_format_and_verify("VACUUM my_table FULL;");
}

#[test]
fn test_vacuum_format_lite_dry_run() {
    dbx_format_and_verify("VACUUM my_table LITE DRY RUN;");
}

#[test]
fn test_vacuum_format_full_dry_run() {
    dbx_format_and_verify("VACUUM my_table FULL DRY RUN;");
}

#[test]
fn test_vacuum_format_idempotent() {
    let sql = "VACUUM my_catalog.my_schema.my_table RETAIN 168 HOURS DRY RUN;";
    let config = FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    };
    let formatted1 = format_sql_with_config(sql, &config).expect("first format");
    let formatted2 = format_sql_with_config(&formatted1, &config).expect("second format");
    assert_eq!(formatted1, formatted2, "Formatting should be idempotent");
}

// ============================================================================
// Risk analysis tests — VACUUM signals
// ============================================================================

#[test]
fn test_vacuum_risk_basic() {
    let report = dbx_analyze("VACUUM my_table;");

    // Should have at least one signal (INFO-PG-MAINT-VACUUM: maintenance executed)
    let vacuum_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "INFO-PG-MAINT-VACUUM"))
        .collect();
    assert!(
        !vacuum_signals.is_empty(),
        "VACUUM should generate INFO-PG-MAINT-VACUUM (maintenance executed). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_vacuum_risk_low_retention() {
    let report = dbx_analyze("VACUUM my_table RETAIN 24 HOURS;");

    // Should trigger DBX-VACUUM-LOWRET: VACUUM with low retention
    let low_retention_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-VACUUM-LOWRET"))
        .collect();
    assert!(
        !low_retention_signals.is_empty(),
        "VACUUM RETAIN 24 HOURS should generate DBX-VACUUM-LOWRET (low retention). Signals: {:?}",
        report
            .signals
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_vacuum_risk_safe_retention() {
    let report = dbx_analyze("VACUUM my_table RETAIN 168 HOURS;");

    // Should NOT trigger DBX-VACUUM-LOWRET (168 hours = 7 days, meets minimum)
    let low_retention_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-VACUUM-LOWRET"))
        .collect();
    assert!(
        low_retention_signals.is_empty(),
        "VACUUM RETAIN 168 HOURS should not generate DBX-VACUUM-LOWRET. Got: {:?}",
        low_retention_signals
    );
}

#[test]
fn test_vacuum_risk_dry_run_still_signals() {
    // DRY RUN is safe but still generates maintenance signal
    let report = dbx_analyze("VACUUM my_table DRY RUN;");

    let maintenance_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "INFO-PG-MAINT-VACUUM"))
        .collect();
    assert!(
        !maintenance_signals.is_empty(),
        "VACUUM DRY RUN should still generate INFO-PG-MAINT-VACUUM (maintenance executed)."
    );
}

#[test]
fn test_vacuum_risk_low_retention_with_dry_run() {
    let report = dbx_analyze("VACUUM my_table RETAIN 12 HOURS DRY RUN;");

    // Should still trigger low retention warning even with DRY RUN
    let low_retention_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-VACUUM-LOWRET"))
        .collect();
    assert!(
        !low_retention_signals.is_empty(),
        "VACUUM RETAIN 12 HOURS DRY RUN should generate DBX-VACUUM-LOWRET."
    );
}

#[test]
fn test_vacuum_multi_statement_evidence() {
    let sql = r#"
        VACUUM table1;
        VACUUM table2 RETAIN 24 HOURS;
        VACUUM table3 RETAIN 168 HOURS;
    "#;
    let report = dbx_analyze(sql);

    // Count maintenance evidence (all 3 should generate INFO-PG-MAINT-VACUUM)
    let maintenance_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "INFO-PG-MAINT-VACUUM"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        maintenance_evidence >= 3,
        "Should have evidence for all 3 VACUUM statements. Got {} evidence.",
        maintenance_evidence
    );

    // Only table2 (24 hours) should trigger low retention
    let low_retention_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-VACUUM-LOWRET"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        low_retention_evidence >= 1,
        "Should have at least 1 low retention evidence. Got {} evidence.",
        low_retention_evidence
    );
}

// ============================================================================
// PostgreSQL compatibility — ensure existing PG VACUUM still works
// ============================================================================

#[test]
fn test_vacuum_risk_zero_retention_critical() {
    let report = dbx_analyze("VACUUM my_table RETAIN 0 HOURS;");

    // Should trigger DBX-VACUUM-ZERO: VACUUM with zero retention (Critical)
    let zero_retention_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-VACUUM-ZERO"))
        .collect();
    assert!(
        !zero_retention_signals.is_empty(),
        "VACUUM RETAIN 0 HOURS should generate DBX-VACUUM-ZERO (zero retention, Critical). Signals: {:?}",
        report.signals.iter().map(|s| match s {
            RuleMatch::Analysis(g) => format!("{} ({:?})", g.matched_rule, g.risk_level),
        }).collect::<Vec<_>>()
    );

    // Should be Critical severity
    assert!(
        report.summary.critical_count >= 1,
        "VACUUM RETAIN 0 should have at least one Critical signal. Got: critical={}",
        report.summary.critical_count
    );

    // Should ALSO trigger DBX-VACUUM-LOWRET (low retention, High) since 0 < 168
    let low_retention_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-VACUUM-LOWRET"))
        .collect();
    assert!(
        !low_retention_signals.is_empty(),
        "VACUUM RETAIN 0 HOURS should also generate DBX-VACUUM-LOWRET (low retention)."
    );
}

#[test]
fn test_pg_vacuum_still_works() {
    // PG form: modifiers before table
    let sql = "VACUUM FULL VERBOSE ANALYZE users;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
}

#[test]
fn test_pg_vacuum_parenthesized_options() {
    let sql = "VACUUM (VERBOSE, ANALYZE) users;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
}

#[test]
fn test_pg_vacuum_bare() {
    let sql = "VACUUM;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
}
