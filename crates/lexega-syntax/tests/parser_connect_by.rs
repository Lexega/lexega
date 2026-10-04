// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CONNECT BY hierarchical queries

use lexega_syntax::{ast, parse_stmt_from_str};

/// Helper function to parse and extract SELECT statement
fn parse_select(sql: &str) -> ast::AstSelect {
    match parse_stmt_from_str(sql) {
        Some(ast::AstStmt::Select(select)) => select.as_ref().clone(),
        _ => panic!("Failed to parse as SELECT: {}", sql),
    }
}

#[test]
fn test_connect_by_basic() {
    let input =
        "SELECT employee_id, manager_id FROM employees CONNECT BY manager_id = PRIOR employee_id";
    let sel = parse_select(input);

    assert!(sel.connect_by.is_some());
    let cb = sel.connect_by.as_ref().unwrap();

    // No START WITH clause
    assert!(cb.start_with_span.is_none());
    assert!(cb.start_with_condition.is_none());

    // Has CONNECT BY conditions
    assert_eq!(cb.conditions.len(), 1);
}

#[test]
fn test_connect_by_with_start_with() {
    let input = "SELECT employee_id, manager_id FROM employees START WITH manager_id IS NULL CONNECT BY manager_id = PRIOR employee_id";
    let sel = parse_select(input);

    assert!(sel.connect_by.is_some());
    let cb = sel.connect_by.as_ref().unwrap();

    // Has START WITH clause
    assert!(cb.start_with_span.is_some());
    assert!(cb.start_with_condition.is_some());

    // Has CONNECT BY conditions
    assert_eq!(cb.conditions.len(), 1);
}

#[test]
fn test_connect_by_prior_left() {
    let input = "SELECT * FROM emp CONNECT BY PRIOR emp_id = mgr_id";
    let sel = parse_select(input);

    assert!(sel.connect_by.is_some());
    let cb = sel.connect_by.as_ref().unwrap();
    assert_eq!(cb.conditions.len(), 1);

    // Check that condition has PRIOR expression
    let cond = &cb.conditions[0];
    match cond {
        ast::AstExpr::BinaryOp { left, .. } => {
            match left.as_ref() {
                ast::AstExpr::Prior { .. } => {
                    // Success - PRIOR is on left side
                }
                _ => panic!("Expected PRIOR expression on left side"),
            }
        }
        _ => panic!("Expected binary operator in condition"),
    }
}

#[test]
fn test_connect_by_prior_right() {
    let input = "SELECT * FROM emp CONNECT BY mgr_id = PRIOR emp_id";
    let sel = parse_select(input);

    assert!(sel.connect_by.is_some());
    let cb = sel.connect_by.as_ref().unwrap();
    assert_eq!(cb.conditions.len(), 1);

    // Check that condition has PRIOR expression
    let cond = &cb.conditions[0];
    match cond {
        ast::AstExpr::BinaryOp { right, .. } => {
            match right.as_ref() {
                ast::AstExpr::Prior { .. } => {
                    // Success - PRIOR is on right side
                }
                _ => panic!("Expected PRIOR expression on right side"),
            }
        }
        _ => panic!("Expected binary operator in condition"),
    }
}

#[test]
fn test_connect_by_multiple_conditions() {
    let input = "SELECT * FROM emp CONNECT BY manager_id = PRIOR employee_id AND department_id = PRIOR department_id";
    let sel = parse_select(input);

    assert!(sel.connect_by.is_some());
    let cb = sel.connect_by.as_ref().unwrap();

    // One condition which is an AND expression combining two comparisons
    assert_eq!(cb.conditions.len(), 1);

    // Verify it's a binary operation (AND of two equality conditions)
    match &cb.conditions[0] {
        ast::AstExpr::BinaryOp { left, right, .. } => {
            // Both sides should be binary ops (the = comparisons)
            assert!(matches!(left.as_ref(), ast::AstExpr::BinaryOp { .. }));
            assert!(matches!(right.as_ref(), ast::AstExpr::BinaryOp { .. }));
        }
        _ => panic!("Expected AND expression"),
    }
}

#[test]
fn test_connect_by_with_where() {
    let input =
        "SELECT * FROM employees WHERE salary > 50000 CONNECT BY manager_id = PRIOR employee_id";
    let sel = parse_select(input);

    // Should have both WHERE and CONNECT BY
    assert!(sel.where_clause.is_some());
    assert!(sel.connect_by.is_some());
}

#[test]
fn test_connect_by_with_order_by() {
    let input = "SELECT * FROM emp CONNECT BY mgr_id = PRIOR emp_id ORDER BY emp_name";
    let sel = parse_select(input);

    // Should have both CONNECT BY and ORDER BY
    assert!(sel.connect_by.is_some());
    assert!(sel.order_by.is_some());
}

#[test]
fn test_connect_by_complex_hierarchy() {
    let input = r#"
        SELECT 
            employee_id,
            manager_id,
            first_name,
            last_name
        FROM employees
        START WITH manager_id IS NULL
        CONNECT BY PRIOR employee_id = manager_id
        ORDER BY employee_id
    "#;
    let sel = parse_select(input);

    // Should have projection with 4 items
    match &sel.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 4);
        }
        _ => panic!("Expected column projection"),
    }

    // Should have START WITH
    assert!(sel.connect_by.is_some());
    let cb = sel.connect_by.as_ref().unwrap();
    assert!(cb.start_with_span.is_some());
    assert!(cb.start_with_condition.is_some());

    // Should have CONNECT BY
    assert_eq!(cb.conditions.len(), 1);

    // Should have ORDER BY
    assert!(sel.order_by.is_some());
}

#[test]
fn test_connect_by_with_group_by() {
    let input =
        "SELECT dept_id, COUNT(*) FROM emp GROUP BY dept_id CONNECT BY mgr_id = PRIOR emp_id";
    let sel = parse_select(input);

    // Should have both GROUP BY and CONNECT BY
    assert!(sel.group_by.is_some());
    assert!(sel.connect_by.is_some());
}

#[test]
fn test_prior_expression_structure() {
    let input = "SELECT * FROM t CONNECT BY c1 = PRIOR c2";
    let sel = parse_select(input);

    let cb = sel.connect_by.as_ref().unwrap();
    let cond = &cb.conditions[0];

    match cond {
        ast::AstExpr::BinaryOp { right, .. } => {
            match right.as_ref() {
                ast::AstExpr::Prior {
                    node_id: _,
                    prior_span,
                    expr,
                    span,
                } => {
                    // Verify PRIOR expression structure
                    assert!(prior_span.start < prior_span.end);
                    assert!(span.start == prior_span.start);

                    // Inner expression should be an identifier
                    match expr.as_ref() {
                        ast::AstExpr::Ident {
                            column_ref: lexega_syntax::ast::AstColumnRef { .. },
                            ..
                        } => {
                            // Success
                        }
                        _ => panic!("Expected identifier in PRIOR expression"),
                    }
                }
                _ => panic!("Expected PRIOR expression"),
            }
        }
        _ => panic!("Expected binary operator"),
    }
}
