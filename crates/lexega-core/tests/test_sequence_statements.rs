// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake CREATE/ALTER/DROP SEQUENCE recognition + the
//! dialect-neutralized SEQ-* governance rules. The PG-shaped sequence parser
//! is shared across dialects; these cover the Snowflake-specific forms
//! (notably `CREATE OR REPLACE SEQUENCE`) and the SEQ-REPLACE counter-reset
//! signal. PG DROP/CASCADE coverage lives in test_pg_low_governance.rs.

use lexega_core::api::analyze_risk;
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

fn first_create_seq_or_replace(sql: &str) -> bool {
    let script = parse_sql(sql).expect("should parse");
    match script.stmts.first().expect("one statement") {
        AstStmt::CreateSequence(s) => s.or_replace,
        other => panic!("expected CreateSequence, got {other:?}"),
    }
}

#[test]
fn test_create_or_replace_sequence_parses_not_opaque() {
    // The sequence parser must consume OR REPLACE, or the statement goes
    // opaque (UnimplementedStatementType).
    let sql = "CREATE OR REPLACE SEQUENCE s1 START 1 INCREMENT 2 ORDER COMMENT='x';";
    let script = parse_sql(sql).expect("should parse");
    assert_eq!(script.stmts.len(), 1, "should be one statement");
    assert!(
        matches!(script.stmts.first(), Some(AstStmt::CreateSequence(_))),
        "should parse as CreateSequence, not opaque"
    );
    assert!(
        first_create_seq_or_replace(sql),
        "or_replace should be true"
    );
}

#[test]
fn test_or_replace_fires_seq_replace() {
    let rules = analyze_and_get_rules("CREATE OR REPLACE SEQUENCE s START 1 INCREMENT 2;");
    assert!(rules.contains("SEQ-REPLACE"), "got {rules:?}");
    assert!(rules.contains("INFO-SEQ-NEW"), "got {rules:?}");
}

#[test]
fn test_plain_create_does_not_fire_replace() {
    let rules = analyze_and_get_rules("CREATE SEQUENCE s START 1 INCREMENT 1 ORDER;");
    assert!(rules.contains("INFO-SEQ-NEW"), "got {rules:?}");
    assert!(
        !rules.contains("SEQ-REPLACE"),
        "SEQ-REPLACE must not fire without OR REPLACE: {rules:?}"
    );
    assert!(!first_create_seq_or_replace("CREATE SEQUENCE s START 1;"));
}

#[test]
fn test_snowflake_create_forms_parse() {
    // NOORDER, IF NOT EXISTS, START WITH, INCREMENT BY — all consumed.
    for sql in [
        "CREATE SEQUENCE IF NOT EXISTS s START WITH 1 INCREMENT BY 1 NOORDER;",
        "CREATE SEQUENCE s WITH START = 1 INCREMENT = 2 COMMENT = 'c';",
        "CREATE OR REPLACE SEQUENCE db.sch.s START 100;",
    ] {
        let script = parse_sql(sql).expect("should parse");
        assert!(
            matches!(script.stmts.first(), Some(AstStmt::CreateSequence(_))),
            "should parse as CreateSequence (not opaque): {sql}"
        );
    }
}

#[test]
fn test_alter_sequence_fires_chg() {
    let rules = analyze_and_get_rules("ALTER SEQUENCE s SET INCREMENT 5;");
    assert!(rules.contains("INFO-SEQ-CHG"), "got {rules:?}");
}

#[test]
fn test_drop_sequence_fires_drop() {
    let rules = analyze_and_get_rules("DROP SEQUENCE IF EXISTS s;");
    assert!(rules.contains("SEQ-DROP"), "got {rules:?}");
}

#[test]
fn test_forms_format_safe() {
    // OR REPLACE must round-trip byte-exact through the Pattern-B formatter.
    assert_formats_safe("CREATE OR REPLACE SEQUENCE s START 1 INCREMENT 2 ORDER COMMENT='x';");
    assert_formats_safe("CREATE SEQUENCE IF NOT EXISTS s START WITH 1 INCREMENT BY 1 NOORDER;");
    assert_formats_safe("ALTER SEQUENCE s SET INCREMENT 5;");
    assert_formats_safe("DROP SEQUENCE IF EXISTS s;");
}
