// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{ast, parse_stmt_from_str};

// Helper to unwrap ProjectionItem to SelectItem for tests
fn as_select_item(item: &ast::ProjectionItem) -> &ast::AstSelectItem {
    match &item.kind {
        ast::ProjectionItemKind::SelectItem(s) => s,
        _ => panic!("Expected SelectItem in projection"),
    }
}

/// Helper function to parse and extract SELECT statement
fn parse_select(sql: &str) -> ast::AstSelect {
    match parse_stmt_from_str(sql) {
        Some(ast::AstStmt::Select(select)) => select.as_ref().clone(),
        _ => panic!("Failed to parse as SELECT: {}", sql),
    }
}

/// Helper to check if an expression is a QualifiedStar
fn is_qualified_star(expr: &ast::AstExpr) -> bool {
    matches!(expr, ast::AstExpr::QualifiedStar { .. })
}

// ============================================================================
// Basic Qualified Star Tests
// ============================================================================

#[test]
fn test_qualified_star_simple() {
    let sql = "SELECT t.* FROM table1 t;";
    let select = parse_select(sql);

    // When qualified star appears alone, it's parsed as AstProjection::Star
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(
                star.qualifier.is_some(),
                "Expected qualifier on star projection"
            );
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 1, "Expected one select item");
            assert!(
                is_qualified_star(&as_select_item(&cols[0]).expr),
                "Expected qualified star expression"
            );
        }
    }
}

#[test]
fn test_qualified_star_full_table_name() {
    let sql = "SELECT employees.* FROM employees;";
    let select = parse_select(sql);

    // When qualified star appears alone, it's parsed as AstProjection::Star
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 1);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
        }
    }
}

// ============================================================================
// Qualified Star Mixed with Columns
// ============================================================================

#[test]
fn test_qualified_star_with_column_before() {
    let sql = "SELECT employee_id, emp.* FROM employees emp;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 2, "Expected two select items");
            // First should be a regular column
            assert!(
                matches!(as_select_item(&cols[0]).expr, ast::AstExpr::Ident { .. }),
                "Expected Ident for employee_id"
            );
            // Second should be qualified star
            assert!(
                is_qualified_star(&as_select_item(&cols[1]).expr),
                "Expected qualified star for emp.*"
            );
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_qualified_star_with_column_after() {
    let sql = "SELECT emp.*, department_id FROM employees emp;";
    let select = parse_select(sql);

    // When qualified star appears first, parse_star_projection handles it as Star
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 2);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
            assert!(matches!(
                as_select_item(&cols[1]).expr,
                ast::AstExpr::Ident { .. }
            ));
        }
    }
}

#[test]
fn test_qualified_star_between_columns() {
    let sql = "SELECT employee_id, emp.*, department_id FROM employees emp;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 3);
            assert!(matches!(
                as_select_item(&cols[0]).expr,
                ast::AstExpr::Ident { .. }
            ));
            assert!(is_qualified_star(&as_select_item(&cols[1]).expr));
            assert!(matches!(
                as_select_item(&cols[2]).expr,
                ast::AstExpr::Ident { .. }
            ));
        }
        _ => panic!("Expected Columns projection"),
    }
}

// ============================================================================
// Multiple Qualified Stars
// ============================================================================

#[test]
fn test_two_qualified_stars() {
    let sql =
        "SELECT emp.*, dept.* FROM employees emp JOIN departments dept ON emp.dept_id = dept.id;";
    let select = parse_select(sql);

    // Two qualified stars - first triggers Star projection mode
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 2);
            assert!(
                is_qualified_star(&as_select_item(&cols[0]).expr),
                "Expected qualified star for emp.*"
            );
            assert!(
                is_qualified_star(&as_select_item(&cols[1]).expr),
                "Expected qualified star for dept.*"
            );
        }
    }
}

#[test]
fn test_three_qualified_stars_with_columns() {
    let sql = "SELECT 'summary' AS type, t1.*, t2.*, extra_col, t3.* 
               FROM table1 t1 
               JOIN table2 t2 ON t1.id = t2.id
               JOIN table3 t3 ON t2.id = t3.id;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 5);
            // 'summary' AS type
            assert!(matches!(
                as_select_item(&cols[0]).expr,
                ast::AstExpr::Literal { .. }
            ));
            // t1.*
            assert!(is_qualified_star(&as_select_item(&cols[1]).expr));
            // t2.*
            assert!(is_qualified_star(&as_select_item(&cols[2]).expr));
            // extra_col
            assert!(matches!(
                as_select_item(&cols[3]).expr,
                ast::AstExpr::Ident { .. }
            ));
            // t3.*
            assert!(is_qualified_star(&as_select_item(&cols[4]).expr));
        }
        _ => panic!("Expected Columns projection"),
    }
}

// ============================================================================
// Qualified Star with WHERE and Other Clauses
// ============================================================================

#[test]
fn test_qualified_star_with_where() {
    let sql = "SELECT emp.* FROM employees emp WHERE emp.active = TRUE;";
    let select = parse_select(sql);

    // Single qualified star - parsed as Star projection
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 1);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
        }
    }
    assert!(select.where_clause.is_some(), "Expected WHERE clause");
}

#[test]
fn test_qualified_star_with_order_by() {
    let sql = "SELECT emp.* FROM employees emp ORDER BY emp.name;";
    let select = parse_select(sql);

    // Single qualified star - parsed as Star projection
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 1);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
        }
    }
    assert!(select.order_by.is_some(), "Expected ORDER BY clause");
}

#[test]
fn test_qualified_star_with_limit() {
    let sql = "SELECT emp.* FROM employees emp LIMIT 10;";
    let select = parse_select(sql);

    // Single qualified star - parsed as Star projection
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 1);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
        }
    }
    assert!(select.limit.is_some(), "Expected LIMIT clause");
}

// ============================================================================
// Qualified Star in Complex Queries
// ============================================================================

#[test]
fn test_qualified_star_in_subquery() {
    let sql = "SELECT * FROM (SELECT emp.* FROM employees emp) sub;";
    let select = parse_select(sql);

    // Outer query has unqualified *
    assert!(matches!(
        select.projection.kind,
        ast::AstProjectionKind::Star(_)
    ));

    // Check the subquery has qualified star
    if let Some(table_ref) = select.from.first() {
        if let Some(ref subquery) = table_ref.subquery {
            // Pattern-match to extract AstSelect from the AstStmt enum
            if let ast::AstStmt::Select(subquery_select) = subquery.as_ref() {
                // In subquery, single qualified star is parsed as Star projection
                match &subquery_select.projection.kind {
                    ast::AstProjectionKind::Star(star) => {
                        assert!(star.qualifier.is_some(), "Expected qualifier in subquery");
                    }
                    ast::AstProjectionKind::Columns(cols) => {
                        assert_eq!(cols.len(), 1);
                        assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
                    }
                }
            } else {
                panic!("Expected SELECT statement in subquery");
            }
        } else {
            panic!("Expected subquery in FROM clause");
        }
    }
}

#[test]
fn test_qualified_star_with_join() {
    let sql = "SELECT e.*, d.name AS dept_name 
               FROM employees e 
               INNER JOIN departments d ON e.dept_id = d.id;";
    let select = parse_select(sql);

    // Qualified star followed by column
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 2);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
            assert!(matches!(
                as_select_item(&cols[1]).expr,
                ast::AstExpr::Ident { .. }
            ));
            assert!(as_select_item(&cols[1]).alias.is_some());
        }
    }
}

#[test]
fn test_qualified_star_with_cte() {
    let sql = "WITH active_emp AS (
                   SELECT * FROM employees WHERE active = TRUE
               )
               SELECT ae.* FROM active_emp ae;";
    let select = parse_select(sql);

    assert!(select.with_clause.is_some(), "Expected WITH clause");
    // Single qualified star - parsed as Star projection
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 1);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
        }
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_qualified_star_with_string_literal() {
    // This is the original failing case - should now work
    let sql = "SELECT 'Average' AS aggregate, t.* FROM table1 t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 2);
            // First is string literal
            assert!(matches!(
                as_select_item(&cols[0]).expr,
                ast::AstExpr::Literal {
                    literal: ast::AstLiteral::String { .. },
                    ..
                }
            ));
            // Second is qualified star
            assert!(is_qualified_star(&as_select_item(&cols[1]).expr));
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_qualified_star_with_function_calls() {
    let sql = "SELECT COUNT(*), emp.*, MAX(salary) FROM employees emp GROUP BY emp.id;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 3);
            // COUNT(*)
            assert!(matches!(
                as_select_item(&cols[0]).expr,
                ast::AstExpr::FunctionCall { .. }
            ));
            // emp.*
            assert!(is_qualified_star(&as_select_item(&cols[1]).expr));
            // MAX(salary)
            assert!(matches!(
                as_select_item(&cols[2]).expr,
                ast::AstExpr::FunctionCall { .. }
            ));
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_qualified_star_with_case_expression() {
    let sql = "SELECT CASE WHEN active THEN 'Y' ELSE 'N' END AS status, emp.* FROM employees emp;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 2);
            // CASE expression
            assert!(matches!(
                as_select_item(&cols[0]).expr,
                ast::AstExpr::Case { .. }
            ));
            // emp.*
            assert!(is_qualified_star(&as_select_item(&cols[1]).expr));
        }
        _ => panic!("Expected Columns projection"),
    }
}

// ============================================================================
// Snowflake Documentation Examples
// ============================================================================

#[test]
fn test_qualified_star_docs_example() {
    // Based on Snowflake docs pattern for selecting from multiple tables
    let sql = "SELECT employee_table.* EXCLUDE department_id,
                      department_table.* RENAME department_name AS department
               FROM employee_table 
               INNER JOIN department_table
                   ON employee_table.department_id = department_table.department_id
               ORDER BY department, last_name, first_name;";
    let select = parse_select(sql);

    // Two qualified stars with modifiers
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_some());
        }
        ast::AstProjectionKind::Columns(cols) => {
            assert_eq!(cols.len(), 2);
            assert!(is_qualified_star(&as_select_item(&cols[0]).expr));
            assert!(is_qualified_star(&as_select_item(&cols[1]).expr));
        }
    }
}
