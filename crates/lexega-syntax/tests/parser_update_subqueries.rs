// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{ast, parse_sql};

#[test]
fn test_update_with_subquery_in_set_clause() {
    // Test that FROM/WHERE inside subqueries in SET clause don't confuse the parser
    let src = r#"UPDATE orders 
        SET discount = (SELECT MAX(discount) FROM promotions WHERE active = TRUE)
        WHERE order_id = 100;"#;

    let script = parse_sql(src).expect("Failed to parse");

    if let Some(ast::AstStmt::Update(update)) = script.stmts.first().map(|s| s) {
        // Should have exactly 1 assignment
        assert_eq!(update.set_assignments.len(), 1, "Expected 1 SET assignment");

        // The assignment value should be a parsed expression (subquery)
        let assignment = &update.set_assignments[0];
        match assignment.value.as_ref() {
            ast::AstExpr::ScalarSubquery { .. } => {
                // Good - it's a subquery expression
            }
            _ => panic!(
                "Expected subquery expression in SET value, got: {:?}",
                assignment.value
            ),
        }

        // Should NOT capture the subquery's FROM as the UPDATE's FROM clause
        assert!(
            update.from.is_empty(),
            "UPDATE should not have a FROM clause"
        );

        // Should capture the actual WHERE clause for the UPDATE
        assert!(
            update.where_clause.is_some(),
            "UPDATE should have a WHERE clause"
        );
    } else {
        panic!("Expected UPDATE statement");
    }
}

#[test]
fn test_update_with_multiple_subqueries() {
    // Test with multiple subqueries containing FROM/WHERE
    let src = r#"UPDATE products
        SET price = (SELECT AVG(price) FROM products WHERE category = 'electronics'),
            stock = (SELECT SUM(stock) FROM inventory WHERE product_id = products.id),
            last_updated = CURRENT_TIMESTAMP()
        WHERE active = true;"#;

    let script = parse_sql(src).expect("Failed to parse");

    if let Some(ast::AstStmt::Update(update)) = script.stmts.first().map(|s| s) {
        // Should have exactly 3 assignments
        assert_eq!(
            update.set_assignments.len(),
            3,
            "Expected 3 SET assignments"
        );

        // No FROM clause from the UPDATE itself
        assert!(
            update.from.is_empty(),
            "UPDATE should not have a FROM clause"
        );

        // Should have the actual WHERE clause
        assert!(
            update.where_clause.is_some(),
            "UPDATE should have a WHERE clause"
        );
    } else {
        panic!("Expected UPDATE statement");
    }
}

#[test]
fn test_update_with_real_from_and_subquery() {
    // Test UPDATE with both a real FROM clause AND subqueries in SET
    let src = r#"UPDATE target
        SET value = (SELECT MAX(value) FROM source WHERE type = 'special'),
            count = source.count
        FROM source
        WHERE target.id = source.target_id;"#;

    let script = parse_sql(src).expect("Failed to parse");

    if let Some(ast::AstStmt::Update(update)) = script.stmts.first().map(|s| s) {
        // Should have exactly 2 assignments
        assert_eq!(
            update.set_assignments.len(),
            2,
            "Expected 2 SET assignments"
        );

        // First assignment should contain a subquery
        match &*update.set_assignments[0].value {
            ast::AstExpr::ScalarSubquery { .. } => {
                // Good - it's a subquery expression
            }
            _ => panic!(
                "Expected subquery expression in first SET value, got: {:?}",
                update.set_assignments[0].value
            ),
        }

        // Should capture the real FROM clause (not the one in the subquery)
        assert!(!update.from.is_empty(), "UPDATE should have a FROM clause");
        assert_eq!(update.from.len(), 1, "UPDATE should have 1 FROM table");

        // Should have the WHERE clause
        assert!(
            update.where_clause.is_some(),
            "UPDATE should have a WHERE clause"
        );
    } else {
        panic!("Expected UPDATE statement");
    }
}
