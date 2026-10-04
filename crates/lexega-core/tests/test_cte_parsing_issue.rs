// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;
/// Test to isolate CTE parsing issue in risk analyzer
///
/// The problem: CTEs parse fine in the formatter but show as "skipped" in risk analyzer
/// with high statement counts. This test isolates each step to find the issue.
use lexega_core::try_parse_script_from_str;

const CTE_SQL: &str = r#"WITH my_data AS (
  SELECT 1 as x
),
other_cte AS (
  SELECT 2 as y  
)
SELECT * FROM my_data JOIN other_cte;"#;

#[test]
fn test_cte_direct_parser() {
    println!("\n=== TEST 1: Direct Parser (try_parse_script_from_str) ===");

    let result = try_parse_script_from_str(CTE_SQL);
    assert!(result.is_ok(), "Parser should handle CTEs");

    let script = result.unwrap();
    println!(
        "Number of statements in script.stmts: {}",
        script.stmts.len()
    );

    for (i, stmt) in script.stmts.iter().enumerate() {
        println!("Statement {}: {:?}", i, std::mem::discriminant(stmt));
    }

    // A CTE query should be ONE statement
    assert_eq!(
        script.stmts.len(),
        1,
        "CTE query should be 1 statement, not {}",
        script.stmts.len()
    );
}

#[test]
fn test_cte_with_prepare_sql() {
    println!("\n=== TEST 2: Using prepare_sql_for_analysis ===");

    // Call the prepare function (this does Jinja rendering)
    let (sql_to_analyze, was_rendered) = lexega_core::api::prepare_sql_for_analysis_test(CTE_SQL)
        .expect("prepare_sql_for_analysis should succeed");

    println!("Was Jinja rendered: {}", was_rendered);
    println!("SQL to analyze length: {}", sql_to_analyze.len());
    println!("SQL to analyze:\n{}", sql_to_analyze);

    // Now parse it
    let result = try_parse_script_from_str(&sql_to_analyze);
    assert!(result.is_ok(), "Parser should handle prepared SQL");

    let script = result.unwrap();
    println!("Number of statements after prepare: {}", script.stmts.len());

    for (i, stmt) in script.stmts.iter().enumerate() {
        println!("Statement {}: {:?}", i, std::mem::discriminant(stmt));
    }

    assert_eq!(
        script.stmts.len(),
        1,
        "Prepared CTE query should be 1 statement, not {}",
        script.stmts.len()
    );
}

#[test]
fn test_cte_full_risk_analyzer() {
    println!("\n=== TEST 3: Full Risk Analyzer (analyze_risk) ===");

    let report = analyze_risk(CTE_SQL).expect("Risk analyzer should succeed");

    println!("Statements Parsed: {}", report.summary.statements_parsed);
    println!(
        "Statements Analyzed: {}",
        report.summary.statements_analyzed
    );
    println!("Statements Skipped: {}", report.summary.statements_skipped);

    // Should be 1 statement parsed and 1 analyzed (not skipped)
    assert_eq!(
        report.summary.statements_parsed, 1,
        "Should parse as 1 statement, got {}",
        report.summary.statements_parsed
    );
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "Should analyze 1 statement, got {}",
        report.summary.statements_analyzed
    );
    assert_eq!(
        report.summary.statements_skipped, 0,
        "Should not skip any statements, got {}",
        report.summary.statements_skipped
    );
}

const CTE_WITH_CONFIG: &str = r#"{{ config(materialized='view') }}

WITH my_data AS (
  SELECT 1 as x
),
other_cte AS (
  SELECT 2 as y  
)
SELECT * FROM my_data JOIN other_cte;"#;

#[test]
fn test_cte_with_jinja_config() {
    println!("\n=== TEST 4: CTE with dbt config block ===");

    let report = analyze_risk(CTE_WITH_CONFIG).expect("Risk analyzer should succeed");

    println!("Statements Parsed: {}", report.summary.statements_parsed);
    println!(
        "Statements Analyzed: {}",
        report.summary.statements_analyzed
    );
    println!("Statements Skipped: {}", report.summary.statements_skipped);

    // Config block should be rendered away or ignored, leaving 1 SQL statement
    assert!(
        report.summary.statements_parsed <= 2,
        "Should be 1-2 statements max (config + query), got {}",
        report.summary.statements_parsed
    );
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "Should analyze 1 SQL statement, got {}",
        report.summary.statements_analyzed
    );
}
