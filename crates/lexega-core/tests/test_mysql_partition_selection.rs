// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL table-ref partition selection coverage:
//! `tbl PARTITION (p0, p1)` between the table name and the alias.
//!
//! Stored as a typed `AstPartitionSelection` on `AstTableRef` (the
//! `AstIndexHint` precedent), so it composes everywhere table factors
//! parse: joins, derived tables, INSERT...SELECT sources, multi-table DML.
//!
//! Covers:
//!   1. Round-trip safety (bare + alias + qualified + composition)
//!   2. AST structure (field set, name spans counted, table name clean)
//!   3. Statement span (clause-final PARTITION must extend the SELECT span)
//!   4. Dialect gating + query-bearing (analyzed, not opaque)

use lexega_core::ast::{AstStmt, FromItemKind};
use lexega_core::dialect::{mysql, snowflake};
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

fn mysql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mysql();
    config
}

fn format_and_verify(sql: &str) {
    let config = mysql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("MySQL formatting verification failed: {}", e));
}

fn single(sql: &str) -> AstStmt {
    let mut script = parse_sql_with_dialect(sql, mysql().as_ref())
        .unwrap_or_else(|e| panic!("MySQL parse failed for {:?}: {:?}", sql, e));
    assert_eq!(
        script.stmts.len(),
        1,
        "expected one statement for {:?}, got {}",
        sql,
        script.stmts.len()
    );
    script.stmts.remove(0)
}

fn first_table_ref(stmt: &AstStmt) -> &lexega_core::ast::AstTableRef {
    match stmt {
        AstStmt::Select(s) => match &s.from.first().expect("FROM present").kind {
            FromItemKind::TableRef(t) => t,
            other => panic!("expected TableRef, got {:?}", other),
        },
        other => panic!("expected Select, got {:?}", other),
    }
}

// ============================================================================
// 1. Round-trip safety
// ============================================================================

#[test]
fn test_roundtrip_partition_bare() {
    format_and_verify("SELECT * FROM orders PARTITION (p2024, pmax) WHERE total > 50;");
}

#[test]
fn test_roundtrip_partition_clause_final() {
    // Nothing after the clause — exercises both span extensions.
    format_and_verify("SELECT * FROM db1.orders PARTITION (p0);");
}

#[test]
fn test_roundtrip_partition_as_alias() {
    format_and_verify(
        "SELECT o.id FROM orders PARTITION (p2024) AS o JOIN customers c ON o.customer_id = c.id;",
    );
}

#[test]
fn test_roundtrip_partition_bare_alias() {
    format_and_verify("SELECT o.id FROM orders PARTITION (p2024) o WHERE o.total > 1;");
}

#[test]
fn test_roundtrip_partition_with_index_hint() {
    // MySQL grammar order: name PARTITION (...) [AS] alias index_hints.
    format_and_verify("SELECT * FROM orders PARTITION (p2024) AS o USE INDEX (idx_total);");
}

#[test]
fn test_roundtrip_partition_in_join_chain() {
    format_and_verify(
        "SELECT * FROM orders PARTITION (p2023) a JOIN orders PARTITION (p2024) b ON a.id = b.id;",
    );
}

#[test]
fn test_roundtrip_partition_in_derived_table() {
    format_and_verify("SELECT * FROM (SELECT id FROM orders PARTITION (p2024)) AS x;");
}

#[test]
fn test_roundtrip_partition_insert_select_source() {
    format_and_verify("INSERT INTO archive SELECT * FROM orders PARTITION (p2023, p2024);");
}

#[test]
fn test_roundtrip_partition_group_by_tail() {
    format_and_verify("SELECT COUNT(*) FROM orders PARTITION (p2023) GROUP BY status;");
}

#[test]
fn test_roundtrip_window_partition_by_unaffected() {
    // OVER (PARTITION BY ...) must not be hijacked by the table-ref clause.
    format_and_verify(
        "SELECT id, SUM(total) OVER (PARTITION BY customer_id ORDER BY placed_at) FROM orders;",
    );
}

// ============================================================================
// 2. AST structure
// ============================================================================

#[test]
fn test_partition_selection_field_populated() {
    let stmt = single("SELECT * FROM orders PARTITION (p2024, pmax) WHERE total > 50;");
    let tbl = first_table_ref(&stmt);
    let ps = tbl
        .partition_selection
        .as_ref()
        .expect("partition_selection must be set");
    assert_eq!(ps.partition_name_spans.len(), 2, "two partition names");
    assert!(ps.span.start < ps.lparen_span.start);
    assert_eq!(ps.span.end, ps.rparen_span.end, "clause span ends at ')'");
    // The table name stays a clean decomposable identifier.
    assert!(
        tbl.name.parts.is_some(),
        "table name parts must survive partition selection"
    );
}

#[test]
fn test_partition_selection_with_alias_both_captured() {
    let stmt = single("SELECT o.id FROM orders PARTITION (p2024) AS o;");
    let tbl = first_table_ref(&stmt);
    assert!(tbl.partition_selection.is_some(), "partition captured");
    assert!(tbl.alias.is_some(), "alias after the clause captured");
}

#[test]
fn test_plain_table_has_no_partition_selection() {
    let stmt = single("SELECT * FROM orders;");
    assert!(first_table_ref(&stmt).partition_selection.is_none());
}

// ============================================================================
// 3. Statement span
// ============================================================================

#[test]
fn test_clause_final_partition_extends_select_span() {
    let sql = "SELECT * FROM db1.orders PARTITION (p0);";
    let stmt = single(sql);
    match &stmt {
        AstStmt::Select(s) => {
            // Span must reach the clause's ')' (index of ')' in source).
            let rparen_pos = sql.rfind(')').expect("rparen present") as u32;
            assert!(
                s.span.end > rparen_pos,
                "SELECT span {:?} must cover clause-final PARTITION (rparen at {})",
                s.span,
                rparen_pos
            );
        }
        other => panic!("expected Select, got {:?}", other),
    }
}

// ============================================================================
// 4. Dialect gating + query-bearing
// ============================================================================

#[test]
fn test_snowflake_does_not_recognize_partition_selection() {
    let script = parse_sql_with_dialect(
        "SELECT * FROM orders PARTITION (p2024) WHERE total > 50;",
        snowflake().as_ref(),
    )
    .unwrap_or_else(|e| panic!("script-level parse should not hard-fail: {:?}", e));
    // Snowflake keeps pre-batch behavior: the tail shears to opaque.
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "Snowflake must not adopt MySQL partition selection"
    );
}

#[test]
fn test_partition_select_is_analyzed_not_opaque() {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mysql());
    let report = lexega_core::api::analyze_risk_with_policy_config(
        "SELECT * FROM orders PARTITION (p2024, pmax) WHERE total > 50;",
        &config,
    )
    .expect("analysis should succeed");
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "partition-selected scan must lower and analyze"
    );
}
