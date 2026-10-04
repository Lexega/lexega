// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for SCRIPT-SILENT-HANDLER analysis rule.
//!
//! Detects DECLARE CONTINUE HANDLER FOR SQLEXCEPTION without RESIGNAL —
//! the SQL equivalent of `except: pass`.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};

use lexega_core::api::analyze_risk_with_policy_config;
use std::collections::HashSet;

fn databricks_config() -> AnalysisConfig {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(lexega_core::dialect::databricks());
    config
}

fn extract_rule_ids(sql: &str) -> HashSet<String> {
    let report = analyze_risk_with_policy_config(sql, &databricks_config())
        .expect("analysis should succeed");
    report
        .signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

// ============================================================================
// Positive: should trigger SCRIPT-SILENT-HANDLER
// ============================================================================

#[test]
fn test_silent_continue_handler_sqlexception() {
    let sql = r#"
        CREATE PROCEDURE test_proc()
        BEGIN
            DECLARE CONTINUE HANDLER FOR SQLEXCEPTION
            BEGIN
                SET err_count = err_count + 1;
            END;
            SELECT 1;
        END;
    "#;
    let report = analyze_risk_with_policy_config(sql, &databricks_config())
        .expect("analysis should succeed");

    // Debug: show all statement previews
    for sig in &report.statement_signals {
        eprintln!("Stmt line {}: {:?}", sig.line_number, sig.statement_preview);
    }
    eprintln!(
        "Summary: parsed={}, analyzed={}, bodies_analyzed={}, stmts_in_bodies={}",
        report.summary.statements_parsed,
        report.summary.statements_analyzed,
        report.summary.procedure_bodies_analyzed,
        report.summary.statements_in_bodies
    );
    eprintln!("Matched rules:");
    for signal in &report.signals {
        let RuleMatch::Analysis(g) = signal;
        eprintln!(
            "  Rule: {} (parent: {:?}) - {}",
            g.matched_rule, g.parent_context, g.message
        );
    }

    let rules = extract_rule_ids(sql);
    assert!(
        rules.contains("SCRIPT-SILENT-HANDLER"),
        "CONTINUE HANDLER FOR SQLEXCEPTION without RESIGNAL should trigger. Got: {:?}",
        rules
    );
}

#[test]
fn test_silent_handler_single_statement_body() {
    // Handler body is a single SET, not a BEGIN...END block
    let sql = "DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SET x = 1;";
    let rules = extract_rule_ids(sql);
    assert!(
        rules.contains("SCRIPT-SILENT-HANDLER"),
        "Single-statement silent handler should trigger. Got: {:?}",
        rules
    );
}

#[test]
fn test_silent_handler_multi_statement() {
    // Two silent handlers — both should produce evidence
    let sql = r#"
        DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SET x = 1;
        DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SET y = 2;
    "#;
    let report = analyze_risk_with_policy_config(sql, &databricks_config())
        .expect("analysis should succeed");

    let evidence: usize = report
        .signals
        .iter()
        .filter(
            |s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "SCRIPT-SILENT-HANDLER"),
        )
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        evidence >= 2,
        "Two silent handlers should produce evidence >= 2. Got: {}",
        evidence
    );
}

// ============================================================================
// Negative: should NOT trigger SCRIPT-SILENT-HANDLER
// ============================================================================

#[test]
fn test_handler_with_resignal_no_trigger() {
    let sql = r#"
        CREATE PROCEDURE test_proc()
        BEGIN
            DECLARE CONTINUE HANDLER FOR SQLEXCEPTION
            BEGIN
                SET err_count = err_count + 1;
                RESIGNAL;
            END;
            SELECT 1;
        END;
    "#;
    let rules = extract_rule_ids(sql);
    assert!(
        !rules.contains("SCRIPT-SILENT-HANDLER"),
        "Handler with RESIGNAL should NOT trigger. Got: {:?}",
        rules
    );
}

#[test]
fn test_handler_with_nested_resignal_no_trigger() {
    // RESIGNAL inside an IF inside the handler body
    let sql = r#"
        CREATE PROCEDURE test_proc()
        BEGIN
            DECLARE CONTINUE HANDLER FOR SQLEXCEPTION
            BEGIN
                SET err_count = err_count + 1;
                IF (err_count > 3) THEN
                    RESIGNAL;
                END IF;
            END;
            SELECT 1;
        END;
    "#;
    let rules = extract_rule_ids(sql);
    assert!(
        !rules.contains("SCRIPT-SILENT-HANDLER"),
        "Handler with nested RESIGNAL should NOT trigger. Got: {:?}",
        rules
    );
}

#[test]
fn test_exit_handler_no_trigger() {
    // EXIT handlers terminate the block, which is visible behaviour
    let sql = "DECLARE EXIT HANDLER FOR SQLEXCEPTION SET x = 1;";
    let rules = extract_rule_ids(sql);
    assert!(
        !rules.contains("SCRIPT-SILENT-HANDLER"),
        "EXIT HANDLER should NOT trigger. Got: {:?}",
        rules
    );
}

#[test]
fn test_continue_handler_not_found_no_trigger() {
    // NOT FOUND is a narrower condition — not the catch-all anti-pattern
    let sql = "DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = 1;";
    let rules = extract_rule_ids(sql);
    assert!(
        !rules.contains("SCRIPT-SILENT-HANDLER"),
        "CONTINUE HANDLER FOR NOT FOUND should NOT trigger. Got: {:?}",
        rules
    );
}

#[test]
fn test_continue_handler_sqlstate_no_trigger() {
    // Specific SQLSTATE is targeted, not a blanket catch-all
    let sql = "DECLARE CONTINUE HANDLER FOR SQLSTATE '42000' SET x = 1;";
    let rules = extract_rule_ids(sql);
    assert!(
        !rules.contains("SCRIPT-SILENT-HANDLER"),
        "Specific SQLSTATE handler should NOT trigger. Got: {:?}",
        rules
    );
}

#[test]
fn test_continue_handler_named_condition_no_trigger() {
    // Named condition is targeted, not a blanket catch-all
    let sql = "DECLARE CONTINUE HANDLER FOR my_custom_condition SET x = 1;";
    let rules = extract_rule_ids(sql);
    assert!(
        !rules.contains("SCRIPT-SILENT-HANDLER"),
        "Named condition handler should NOT trigger. Got: {:?}",
        rules
    );
}
