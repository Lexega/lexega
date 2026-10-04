// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP CORTEX SEARCH SERVICE`
//! statement family. A Cortex search service builds an AI search index over a
//! source query's rows. Covers the SNW-CORTEX-SEARCH-* rules, the
//! EMBEDDING_MODEL recognition primitive, that the `AS <query>` body is
//! consumed (not fragmented into a standalone SELECT), and byte-exact
//! formatting.

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

fn slice(sql: &str, start: u32, end: u32) -> &str {
    &sql[start as usize..end as usize]
}

const CREATE_FULL: &str = "CREATE CORTEX SEARCH SERVICE css ON body ATTRIBUTES title, lang WAREHOUSE = wh TARGET_LAG = '1 hour' EMBEDDING_MODEL = 'snowflake-arctic-embed-m' COMMENT = 'idx' AS SELECT body, title, lang FROM docs;";

#[test]
fn test_create_fires_new() {
    let rules = analyze_and_get_rules(CREATE_FULL);
    assert!(
        rules.contains("INFO-SNW-CORTEX-SEARCH-NEW"),
        "got {rules:?}"
    );
}

#[test]
fn test_plain_create_is_not_replace() {
    let rules =
        analyze_and_get_rules("CREATE CORTEX SEARCH SERVICE css ON c WAREHOUSE = wh TARGET_LAG = '1 h' AS SELECT c FROM t;");
    assert!(
        rules.contains("INFO-SNW-CORTEX-SEARCH-NEW"),
        "got {rules:?}"
    );
    assert!(
        !rules.contains("SNW-CORTEX-SEARCH-REPLACE"),
        "got {rules:?}"
    );
}

#[test]
fn test_or_replace_fires_replace() {
    let rules = analyze_and_get_rules(
        "CREATE OR REPLACE CORTEX SEARCH SERVICE db.sc.css ON c WAREHOUSE = wh TARGET_LAG = '1 day' AS SELECT c FROM t;",
    );
    assert!(
        rules.contains("INFO-SNW-CORTEX-SEARCH-NEW"),
        "got {rules:?}"
    );
    assert!(rules.contains("SNW-CORTEX-SEARCH-REPLACE"), "got {rules:?}");
}

#[test]
fn test_alter_actions_fire_nothing() {
    for sql in [
        "ALTER CORTEX SEARCH SERVICE css SET TARGET_LAG = '2 hours';",
        "ALTER CORTEX SEARCH SERVICE IF EXISTS css UNSET COMMENT;",
        "ALTER CORTEX SEARCH SERVICE css RESUME;",
        "ALTER CORTEX SEARCH SERVICE css SUSPEND;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(
            !rules.iter().any(|r| r.contains("CORTEX")),
            "{sql} should fire no CORTEX rules, got {rules:?}"
        );
    }
}

#[test]
fn test_drop_analyzes() {
    // Three-word object: must parse + analyze without OpaqueContent fallout.
    let report = analyze_risk("DROP CORTEX SEARCH SERVICE css;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_embedding_model_extracted() {
    let script = parse_sql(CREATE_FULL).expect("should parse");
    let stmt = script.stmts.first().expect("one statement");
    let AstStmt::CreateCortexSearchService(cs) = stmt else {
        panic!("expected CreateCortexSearchService");
    };
    let span = cs.embedding_model_span.expect("embedding model captured");
    let raw = slice(CREATE_FULL, span.start, span.end);
    assert_eq!(raw.trim().trim_matches('\''), "snowflake-arctic-embed-m");
    // The AS <query> body is captured (recognized, not analyzed).
    assert!(cs.source_query_span.is_some(), "source query span captured");
}

#[test]
fn test_as_body_not_fragmented() {
    // The inner SELECT must be consumed by the family parser, not parsed as a
    // second standalone statement.
    let script = parse_sql(CREATE_FULL).expect("should parse");
    assert_eq!(
        script.stmts.len(),
        1,
        "AS-query body must not fragment into a standalone SELECT"
    );
    assert!(matches!(
        script.stmts.first(),
        Some(AstStmt::CreateCortexSearchService(_))
    ));
}

#[test]
fn test_no_embedding_model_is_none() {
    let sql = "CREATE CORTEX SEARCH SERVICE css ON c WAREHOUSE = wh TARGET_LAG = '1 h' AS SELECT c FROM t;";
    let script = parse_sql(sql).expect("should parse");
    let AstStmt::CreateCortexSearchService(cs) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateCortexSearchService");
    };
    assert!(
        cs.embedding_model_span.is_none(),
        "no embedding model declared"
    );
}

#[test]
fn test_forms_format_safe() {
    assert_formats_safe(CREATE_FULL);
    assert_formats_safe(
        "CREATE OR REPLACE CORTEX SEARCH SERVICE db.sc.css ON c WAREHOUSE = wh TARGET_LAG = '1 day' AS SELECT c FROM t;",
    );
    assert_formats_safe("ALTER CORTEX SEARCH SERVICE css SET TARGET_LAG = '2 hours';");
    assert_formats_safe("ALTER CORTEX SEARCH SERVICE css RESUME;");
    assert_formats_safe("ALTER CORTEX SEARCH SERVICE IF EXISTS css SUSPEND;");
    assert_formats_safe("DROP CORTEX SEARCH SERVICE css;");
}
