// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP SEMANTIC VIEW` statement
//! family. A semantic view is a named model over base tables. Covers the
//! SNW-SEMVIEW-* rules, the base-table access-surface extraction from the
//! TABLES block, and byte-exact formatting of the multi-block grammar.

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

/// Slice a byte range out of the source.
fn slice(sql: &str, start: u32, end: u32) -> &str {
    &sql[start as usize..end as usize]
}

#[test]
fn test_create_semantic_view_fires_new() {
    let rules = analyze_and_get_rules(
        "CREATE SEMANTIC VIEW sv TABLES (orders AS db.sc.orders) METRICS (sv.r AS SUM(orders.x));",
    );
    assert!(rules.contains("INFO-SNW-SEMVIEW-NEW"), "got {rules:?}");
}

#[test]
fn test_plain_create_is_not_replace() {
    let rules = analyze_and_get_rules("CREATE SEMANTIC VIEW sv TABLES (t1);");
    assert!(rules.contains("INFO-SNW-SEMVIEW-NEW"), "got {rules:?}");
    assert!(!rules.contains("SNW-SEMVIEW-REPLACE"), "got {rules:?}");
}

#[test]
fn test_create_or_replace_fires_replace() {
    let rules = analyze_and_get_rules("CREATE OR REPLACE SEMANTIC VIEW db.sc.sv TABLES (t1, t2);");
    assert!(rules.contains("INFO-SNW-SEMVIEW-NEW"), "got {rules:?}");
    assert!(rules.contains("SNW-SEMVIEW-REPLACE"), "got {rules:?}");
}

#[test]
fn test_alter_actions_fire_nothing() {
    for sql in [
        "ALTER SEMANTIC VIEW sv SET COMMENT = 'x';",
        "ALTER SEMANTIC VIEW IF EXISTS sv UNSET COMMENT;",
        "ALTER SEMANTIC VIEW sv RENAME TO sv2;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(
            !rules.iter().any(|r| r.contains("SEMVIEW")),
            "{sql} should fire no SEMVIEW rules, got {rules:?}"
        );
    }
}

#[test]
fn test_drop_semantic_view_analyzes() {
    // Two-word object: must parse + analyze without OpaqueContent fallout.
    let report = analyze_risk("DROP SEMANTIC VIEW sv;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_base_tables_extracted_from_tables_block() {
    // The physical (referenced) table after `AS` is the access surface; the
    // per-entry trailing clauses (PRIMARY KEY, WITH SYNONYMS, COMMENT) must be
    // skipped without disturbing the entry split.
    let sql = "CREATE SEMANTIC VIEW sv TABLES (orders AS sales.public.orders PRIMARY KEY (o_orderkey) WITH SYNONYMS ('o'), customer AS sales.public.customer);";
    let script = parse_sql(sql).expect("should parse");
    let stmt = script.stmts.first().expect("one statement");
    let AstStmt::CreateSemanticView(cv) = stmt else {
        panic!("expected CreateSemanticView");
    };
    let physical: Vec<&str> = cv
        .tables
        .iter()
        .map(|t| slice(sql, t.physical_span.start, t.physical_span.end))
        .collect();
    assert_eq!(
        physical,
        vec!["sales.public.orders", "sales.public.customer"],
        "base-table access surface"
    );
    // Alias is distinct from the physical ref when `AS` is present.
    assert_eq!(
        slice(
            sql,
            cv.tables[0].alias_span.start,
            cv.tables[0].alias_span.end
        ),
        "orders"
    );
}

#[test]
fn test_bare_table_list_alias_equals_physical() {
    // `TABLES (t1, db.sc.t2)` — no `AS`, so each entry's physical ref is the
    // bare (possibly qualified) name itself.
    let sql = "CREATE SEMANTIC VIEW sv TABLES (t1, db.sc.t2);";
    let script = parse_sql(sql).expect("should parse");
    let AstStmt::CreateSemanticView(cv) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateSemanticView");
    };
    let physical: Vec<&str> = cv
        .tables
        .iter()
        .map(|t| slice(sql, t.physical_span.start, t.physical_span.end))
        .collect();
    assert_eq!(physical, vec!["t1", "db.sc.t2"]);
    // With no AS, the alias span equals the physical span.
    assert_eq!(
        slice(
            sql,
            cv.tables[0].alias_span.start,
            cv.tables[0].alias_span.end
        ),
        slice(
            sql,
            cv.tables[0].physical_span.start,
            cv.tables[0].physical_span.end
        )
    );
}

#[test]
fn test_optional_blocks_recognized() {
    // Presence of each optional model block is captured.
    let sql = "CREATE SEMANTIC VIEW sv TABLES (t1) RELATIONSHIPS (r AS t1 (a) REFERENCES t1 (b)) FACTS (t1.f AS t1.x) DIMENSIONS (t1.d AS t1.y) METRICS (t1.m AS SUM(t1.z));";
    let script = parse_sql(sql).expect("should parse");
    let AstStmt::CreateSemanticView(cv) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateSemanticView");
    };
    assert!(cv.relationships_span.is_some(), "relationships");
    assert!(cv.facts_span.is_some(), "facts");
    assert!(cv.dimensions_span.is_some(), "dimensions");
    assert!(cv.metrics_span.is_some(), "metrics");
}

#[test]
fn test_semantic_view_forms_format_safe() {
    // Every form must round-trip byte-exactly through the formatter.
    assert_formats_safe(
        "CREATE SEMANTIC VIEW rev_analysis\n  TABLES (\n    orders AS sales.public.orders PRIMARY KEY (o_orderkey) WITH SYNONYMS ('sales orders') COMMENT = 'orders',\n    customer AS sales.public.customer PRIMARY KEY (c_custkey)\n  )\n  RELATIONSHIPS (\n    orders_to_customer AS orders (o_custkey) REFERENCES customer (c_custkey)\n  )\n  FACTS (orders.order_value AS orders.o_totalprice)\n  DIMENSIONS (customer.customer_name AS customer.c_name)\n  METRICS (orders.total_revenue AS SUM(orders.order_value))\n  COMMENT = 'revenue model';",
    );
    assert_formats_safe("CREATE OR REPLACE SEMANTIC VIEW db.sc.sv TABLES (t1, t2);");
    assert_formats_safe("ALTER SEMANTIC VIEW sv SET COMMENT = 'x';");
    assert_formats_safe("ALTER SEMANTIC VIEW IF EXISTS sv RENAME TO sv2;");
    assert_formats_safe("DROP SEMANTIC VIEW sv;");
}
