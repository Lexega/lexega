// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Unterminated delimiters must not swallow the rest of the input.
//!
//! An unterminated string, dollar-quote, or block comment, and an unclosed
//! `(`, must surface the affected region as unparsed content (an
//! `UnparsedConstruct` skip) instead of silently consuming the rest of the
//! input. Silent consumption would let a file report zero findings — and
//! pass strict mode — while a `GRANT ALL … TO PUBLIC` sat unanalyzed after
//! the broken delimiter.

use lexega_core::{
    analyzer::{AnalysisConfig, AnalysisReport, RuleMatch, SkipReason},
    PostgresDialect,
};

use lexega_core::api::analyze_risk_with_policy_config;
use std::collections::HashSet;
use std::sync::Arc;

fn analyze(sql: &str) -> AnalysisReport {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(PostgresDialect));
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn rule_ids(report: &AnalysisReport) -> HashSet<String> {
    report
        .signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn has_unparsed(report: &AnalysisReport) -> bool {
    report
        .skipped_details
        .iter()
        .any(|s| matches!(s.reason, SkipReason::UnparsedConstruct))
}

/// The dangerous trailing statement each case tries to smuggle past the gate.
const TRAILING_GRANT: &str = "\nGRANT ALL ON DATABASE prod TO ROLE PUBLIC;\n";

fn assert_surfaced(prefix: &str, label: &str) {
    let sql = format!("{prefix}{TRAILING_GRANT}");
    let report = analyze(&sql);
    assert!(
        has_unparsed(&report),
        "{label}: unterminated/unclosed region must surface as unparsed content \
         (so --strict fails closed), but skipped_details = {:?}",
        report.skipped_details
    );
}

#[test]
fn unterminated_string_is_surfaced() {
    assert_surfaced("SELECT 'unclosed string", "unterminated string");
}

#[test]
fn unterminated_block_comment_is_surfaced() {
    assert_surfaced("/* unclosed comment", "unterminated block comment");
}

#[test]
fn unterminated_trailing_block_comment_is_surfaced() {
    assert_surfaced(
        "SELECT 1 /* unclosed trailing",
        "unterminated trailing comment",
    );
}

#[test]
fn unterminated_dollar_quote_is_surfaced() {
    assert_surfaced("SELECT $tag$ unclosed dollar", "unterminated dollar-quote");
}

#[test]
fn unclosed_create_table_paren_is_surfaced() {
    assert_surfaced(
        "CREATE TABLE t (id INT, name",
        "unclosed CREATE TABLE column list",
    );
}

#[test]
fn unclosed_nested_check_paren_is_surfaced() {
    assert_surfaced(
        "CREATE TABLE t (a INT CHECK (a > 0",
        "unclosed nested CHECK paren",
    );
}

#[test]
fn unclosed_function_call_paren_is_surfaced() {
    assert_surfaced("SELECT foo(a, b", "unclosed function-call arg list");
}

#[test]
fn unclosed_projection_paren_is_surfaced() {
    // An unclosed `(` in a projection / scalar-expression position must not
    // parse as a benign error node that swallows the trailing statement and
    // passes strict mode with zero findings.
    assert_surfaced("SELECT a, (b + c", "unclosed projection paren");
}

#[test]
fn clean_delimited_trailing_grant_still_fires() {
    // Guard against the recovery-boundary fix over- or under-consuming: with
    // clean semicolons the garbage middle statement is skipped, but the
    // well-formed trailing GRANT is still parsed and flagged.
    let sql = "SELECT 1;\n@#$ garbage @#$ ;\nGRANT ALL ON DATABASE prod TO ROLE PUBLIC;\n";
    let report = analyze(sql);
    assert!(
        rule_ids(&report).contains("GRT-TO-PUBLIC"),
        "a cleanly-delimited trailing GRANT TO PUBLIC must still fire; rules = {:?}",
        rule_ids(&report)
    );
}

#[test]
fn well_formed_closed_delimiters_are_not_flagged() {
    // No false opaque: correct, closed delimiters (parens, function calls,
    // nested CHECK) analyze cleanly with no unparsed regions.
    let sql = "CREATE TABLE t (id INT, name VARCHAR(50), CHECK (id > 0));\n\
               SELECT coalesce(a, b), foo(x, y) FROM t WHERE id IN (1, 2, 3);\n";
    let report = analyze(sql);
    assert!(
        !has_unparsed(&report),
        "well-formed SQL must not surface unparsed content, got {:?}",
        report.skipped_details
    );
}

#[test]
fn unterminated_begin_block_does_not_abort_the_run() {
    // A structurally broken scripting block (BEGIN without END) must not
    // abort the run with no report. It degrades like any other unparsed
    // construct while the salvageable statements are still analyzed.
    let report = analyze("BEGIN\nSELECT 1;\nDELETE FROM orders;");
    assert!(
        has_unparsed(&report),
        "broken block should surface as unparsed content, got {:?}",
        report.skipped_details
    );
    assert!(
        rule_ids(&report).contains("DML-WRITE-UNBOUNDED"),
        "unbounded DELETE after the broken block must still be flagged; rules = {:?}",
        rule_ids(&report)
    );
}
