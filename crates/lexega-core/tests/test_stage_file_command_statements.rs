// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake client file commands PUT / GET / REMOVE / LIST.
//! These are top-level statements (not CREATE/ALTER/DROP). The operation kind
//! is the governance surface (GET = data-egress-to-client). Also covers
//! unquoted `file://` URIs, which `//` line-comment lexing must not swallow.

use lexega_core::api::analyze_risk;
use lexega_core::ast::types::AstStageFileCommandKind;
use lexega_core::ast::AstStmt;
use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig,
};
use std::collections::HashSet;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.signals)
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

fn first_kind(sql: &str) -> AstStageFileCommandKind {
    let script = parse_sql(sql).expect("should parse");
    match script.stmts.first().expect("one statement") {
        AstStmt::StageFileCommand(s) => s.kind,
        other => panic!("expected StageFileCommand, got {other:?}"),
    }
}

#[test]
fn test_get_fires_exfil() {
    let rules = analyze_and_get_rules("GET @my_stage/path file:///tmp/out/;");
    assert!(rules.contains("SNW-STAGE-GET"), "got {rules:?}");
}

#[test]
fn test_put_fires_info() {
    let rules = analyze_and_get_rules("PUT file:///tmp/data.csv @my_stage/path;");
    assert!(rules.contains("INFO-SNW-STAGE-PUT"), "got {rules:?}");
}

#[test]
fn test_remove_fires() {
    let rules = analyze_and_get_rules("REMOVE @my_stage/path PATTERN='.*.tmp';");
    assert!(rules.contains("SNW-STAGE-REMOVE"), "got {rules:?}");
}

#[test]
fn test_list_fires() {
    let rules = analyze_and_get_rules("LIST @my_stage/path;");
    assert!(rules.contains("INFO-SNW-STAGE-LIST"), "got {rules:?}");
}

#[test]
fn test_operation_kinds() {
    assert_eq!(
        first_kind("PUT file:///tmp/d.csv @s;"),
        AstStageFileCommandKind::Put
    );
    assert_eq!(
        first_kind("GET @s file:///tmp/o/;"),
        AstStageFileCommandKind::Get
    );
    assert_eq!(first_kind("REMOVE @s;"), AstStageFileCommandKind::Remove);
    assert_eq!(first_kind("LIST @s;"), AstStageFileCommandKind::List);
}

#[test]
fn test_aliases() {
    // RM is REMOVE, LS is LIST.
    assert_eq!(first_kind("RM @s;"), AstStageFileCommandKind::Remove);
    assert_eq!(first_kind("LS @s;"), AstStageFileCommandKind::List);
}

#[test]
fn test_file_uri_not_fragmented() {
    // The lexer must not treat the `//` in an unquoted `file:///` URI as a
    // line comment: that would swallow the rest of the line and merge
    // statements.
    let sql =
        "PUT file:///tmp/data.csv @my_stage/path PARALLEL=4;\nGET @my_stage/path file:///tmp/out/;";
    let script = parse_sql(sql).expect("should parse");
    assert_eq!(
        script.stmts.len(),
        2,
        "file:// URI must not comment-swallow the rest of the statement"
    );
    assert!(matches!(
        script.stmts.first(),
        Some(AstStmt::StageFileCommand(_))
    ));
}

#[test]
fn test_real_line_comment_still_works() {
    // The lexer change must not break genuine `//` line comments (preceded by
    // whitespace, not `:`/`/`).
    assert_formats_safe("SELECT 1; // a real comment\nSELECT 2;");
}

#[test]
fn test_forms_format_safe() {
    assert_formats_safe("PUT file:///tmp/data.csv @my_stage/path PARALLEL=4 AUTO_COMPRESS=TRUE;");
    assert_formats_safe("GET @my_stage/path file:///tmp/out/ PATTERN='.*.csv';");
    assert_formats_safe("REMOVE @my_stage/path PATTERN='.*.tmp';");
    assert_formats_safe("LIST @my_stage/path;");
    assert_formats_safe("RM @s;");
    assert_formats_safe("LS @s;");
}
