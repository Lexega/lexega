// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.findings.iter().any(
        |s| matches!(s, lexega_core::analyzer::RuleMatch::Analysis(g) if g.matched_rule == rule_id),
    )
}

fn has_context(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.context.iter().any(
        |s| matches!(s, lexega_core::analyzer::RuleMatch::Analysis(g) if g.matched_rule == rule_id),
    )
}

#[test]
fn test_create_stream_emits_info_c250() {
    let sql = "CREATE STREAM test_stream ON TABLE my_table;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    println!(
        "Total reported findings: {}",
        report.summary.total_reported_findings
    );
    println!(
        "Statement findings count: {}",
        report.statement_traces.len()
    );

    // Show per-statement previews
    for sig in &report.statement_traces {
        println!(
            "Statement at line {}: {:?}",
            sig.line_number, sig.statement_preview
        );
    }

    // Check matched rules
    println!("\nMatched rules:");
    for finding in &report.context {
        match finding {
            lexega_core::analyzer::RuleMatch::Analysis(g) => {
                println!("  Rule: {} - {}", g.matched_rule, g.message);
            }
        }
    }

    // The actual assertion
    assert!(
        has_context(&report, "SNW-STREAM-NEW"),
        "Should find SNW-STREAM-NEW (Stream Created) rule match. Got {} context entries total.",
        report.context.len()
    );
}

#[test]
fn test_drop_stream_emits_snw_stream_drop() {
    let sql = "DROP STREAM test_stream;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    println!(
        "Total reported findings: {}",
        report.summary.total_reported_findings
    );

    // Check matched rules
    for finding in &report.findings {
        match finding {
            lexega_core::analyzer::RuleMatch::Analysis(g) => {
                println!("  Rule: {} - {}", g.matched_rule, g.message);
            }
        }
    }

    assert!(
        has_rule(&report, "SNW-STREAM-DROP"),
        "Should find SNW-STREAM-DROP (Stream Dropped) rule match"
    );
}

// ============================================================================
// Task findings
// ============================================================================

#[test]
fn test_create_task_emits_info_c230() {
    let sql = "CREATE TASK my_task WAREHOUSE = compute_wh AS INSERT INTO t SELECT 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    println!(
        "Total reported findings: {}",
        report.summary.total_reported_findings
    );
    for finding in &report.context {
        match finding {
            lexega_core::analyzer::RuleMatch::Analysis(g) => {
                println!("  Rule: {} - {}", g.matched_rule, g.message);
            }
        }
    }

    assert!(
        has_context(&report, "SNW-TASK-NEW"),
        "Expected SNW-TASK-NEW finding for CREATE TASK"
    );
}

#[test]
fn test_drop_task_emits_snw_task_drop() {
    let sql = "DROP TASK my_task;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    println!(
        "Total reported findings: {}",
        report.summary.total_reported_findings
    );
    for finding in &report.findings {
        match finding {
            lexega_core::analyzer::RuleMatch::Analysis(g) => {
                println!("  Rule: {} - {}", g.matched_rule, g.message);
            }
        }
    }

    assert!(
        has_rule(&report, "SNW-TASK-DROP"),
        "Expected SNW-TASK-DROP finding for DROP TASK"
    );
}

// ============================================================================
// Dynamic Table findings
// ============================================================================

#[test]
fn test_create_dynamic_table_emits_info_c220() {
    let sql = "CREATE DYNAMIC TABLE my_dt TARGET_LAG = '1 hour' WAREHOUSE = compute_wh AS SELECT * FROM source;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    println!(
        "Total reported findings: {}",
        report.summary.total_reported_findings
    );
    for finding in &report.context {
        match finding {
            lexega_core::analyzer::RuleMatch::Analysis(g) => {
                println!("  Rule: {} - {}", g.matched_rule, g.message);
            }
        }
    }

    assert!(
        has_context(&report, "SNW-DYNTBL-NEW"),
        "Expected SNW-DYNTBL-NEW finding for CREATE DYNAMIC TABLE"
    );
}

#[test]
fn test_drop_dynamic_table_emits_finding() {
    let sql = "DROP DYNAMIC TABLE my_dt;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    println!(
        "Total reported findings: {}",
        report.summary.total_reported_findings
    );
    for finding in &report.findings {
        match finding {
            lexega_core::analyzer::RuleMatch::Analysis(g) => {
                println!("  Rule: {} - {}", g.matched_rule, g.message);
            }
        }
    }

    assert!(
        has_rule(&report, "SNW-DYNTBL-DROP"),
        "Expected SNW-DYNTBL-DROP finding for DROP DYNAMIC TABLE"
    );
}
