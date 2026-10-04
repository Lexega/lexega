// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for dbt node parsing: ref(), source(), var(), config(), this
//! Verifies that the parser creates first-class AST nodes for dbt functions.

use lexega_syntax::ast::{AstExpr, AstProjectionKind, AstStmt, ProjectionItemKind};
use lexega_syntax::parse_sql;

/// Helper to extract the first expression from a SELECT statement
fn parse_expr(sql: &str) -> Option<AstExpr> {
    let result = parse_sql(sql).ok()?;
    let stmt = result.stmts.first()?;

    if let AstStmt::Select(select) = stmt {
        if let AstProjectionKind::Columns(items) = &select.projection.kind {
            if let Some(item) = items.first() {
                if let ProjectionItemKind::SelectItem(select_item) = &item.kind {
                    return Some(select_item.expr.clone());
                }
            }
        }
    }
    None
}

#[test]
fn test_parse_dbt_ref_single_arg() {
    let sql = "SELECT ref('orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtRef {
            model_name,
            package_name,
            ..
        } => {
            assert_eq!(model_name, "orders");
            assert!(package_name.is_none());
        }
        other => panic!("Expected DbtRef, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_ref_two_args() {
    let sql = "SELECT ref('my_package', 'orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtRef {
            model_name,
            package_name,
            ..
        } => {
            assert_eq!(model_name, "orders");
            assert_eq!(package_name.as_deref(), Some("my_package"));
        }
        other => panic!("Expected DbtRef, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_source() {
    let sql = "SELECT source('raw_data', 'customers')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtSource {
            source_name,
            table_name,
            ..
        } => {
            assert_eq!(source_name, "raw_data");
            assert_eq!(table_name, "customers");
        }
        other => panic!("Expected DbtSource, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_var_single_arg() {
    let sql = "SELECT var('my_var')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtVar {
            var_name,
            default_value,
            ..
        } => {
            assert_eq!(var_name, "my_var");
            assert!(default_value.is_none());
        }
        other => panic!("Expected DbtVar, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_this_bare() {
    let sql = "SELECT this";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtThis { parens, .. } => {
            assert!(parens.is_none(), "Bare 'this' should have no parens");
        }
        other => panic!("Expected DbtThis, got {:?}", other),
    }
}

#[test]
fn test_parse_dbt_this_with_parens() {
    let sql = "SELECT this()";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtThis { parens, .. } => {
            assert!(parens.is_some(), "this() should have parens");
        }
        other => panic!("Expected DbtThis, got {:?}", other),
    }
}

#[test]
fn test_dbt_ref_inner_spans() {
    let sql = "SELECT ref('orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtRef {
            func_name_span,
            lparen_span,
            model_name_span,
            rparen_span,
            span,
            ..
        } => {
            // Verify spans are captured and in correct order
            assert!(func_name_span.start < lparen_span.start);
            assert!(lparen_span.start < model_name_span.start);
            assert!(model_name_span.end < rparen_span.end);
            assert!(span.start == func_name_span.start);
            assert!(span.end == rparen_span.end);
        }
        other => panic!("Expected DbtRef, got {:?}", other),
    }
}

#[test]
fn test_dbt_source_inner_spans() {
    let sql = "SELECT source('raw', 'orders')";
    let expr = parse_expr(sql).expect("Should parse expression");

    match expr {
        AstExpr::DbtSource {
            source_name_span,
            table_name_span,
            ..
        } => {
            // source_name comes before table_name
            assert!(source_name_span.end < table_name_span.start);
        }
        other => panic!("Expected DbtSource, got {:?}", other),
    }
}

#[test]
fn test_dbt_in_from_clause() {
    // dbt functions in FROM clause should be wrapped in Jinja braces
    let sql = "SELECT * FROM {{ ref('orders') }}";
    let result = parse_sql(sql);

    // Verify it parses without error
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
}
