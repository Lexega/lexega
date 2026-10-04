// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! PARSER TESTS: DML statement AST structure validation.
//!
//! NOTE: These tests validate detailed AST structure for DML statements.
//! For basic parse/format/roundtrip testing of DML fixtures, see test_fixtures_dml.rs
//!
//! Tests for INSERT, UPDATE, DELETE, MERGE, and RETURNING INTO clause

use lexega_syntax::ast;
use lexega_syntax::dialect::mssql;
use lexega_syntax::parse_sql;
use lexega_syntax::parse_sql_with_dialect;
use lexega_syntax::parse_stmt_from_str;
// MERGE statement tests

#[test]
fn test_merge_statement_basic() {
    let src = r#"
BEGIN
    MERGE INTO target t
    USING source s
    ON t.id = s.id
    WHEN MATCHED THEN
        UPDATE SET t.value = s.value
    WHEN NOT MATCHED THEN
        INSERT (id, value) VALUES (s.id, s.value);
    RETURN 'merged';
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse MERGE statement");

    // Verify enhanced AST structure captures details
    let script = script.unwrap();
    if let Some(ast::AstStmt::Block(b)) = script.stmts.first().map(|s| s) {
        let body = &b.body;
        if let Some(ast::AstStmt::Merge(merge)) = body.first() {
            // Should have 2 clauses
            assert_eq!(merge.clauses.len(), 2, "Expected 2 WHEN clauses");

            // First clause: UPDATE SET
            if let ast::AstMergeActionKind::UpdateSet { assignments, .. } = &merge.clauses[0].action
            {
                assert_eq!(assignments.len(), 1, "Expected 1 SET assignment");
                // Verify assignment structure exists
                let assignment = &assignments[0];
                assert!(
                    matches!(assignment.column.as_ref(), ast::AstExpr::Ident { .. }),
                    "Expected identifier column"
                );
                assert!(
                    assignment.value.span().end > assignment.value.span().start,
                    "Expected non-empty value expression"
                );
            } else {
                panic!("Expected UpdateSet action in first clause");
            }

            // Second clause: INSERT VALUES
            if let ast::AstMergeActionKind::InsertValues {
                columns, values, ..
            } = &merge.clauses[1].action
            {
                assert_eq!(columns.len(), 2, "Expected 2 columns");
                assert_eq!(values.len(), 2, "Expected 2 values");
            } else {
                panic!("Expected InsertValues action in second clause");
            }
        } else {
            panic!("Expected MERGE statement in block");
        }
    }
}

// RETURNING INTO clause tests

#[test]
fn test_insert_returning_into_single_column() {
    let src = r#"
CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    log_id INTEGER;
BEGIN
    INSERT INTO log_table (status) 
    VALUES ('RUNNING')
    RETURNING id INTO log_id;
    
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse INSERT with RETURNING...INTO"
    );
}

#[test]
fn test_select_into_multiple_columns() {
    let src = r#"
CREATE OR REPLACE FUNCTION test_func()
RETURNS NUMBER
LANGUAGE SQL
AS
DECLARE
    years INTEGER;
    rating NUMBER;
BEGIN
    SELECT DATEDIFF(year, hire_date, CURRENT_DATE()), last_rating
    INTO years, rating
    FROM employees
    WHERE id = 1;
    
    RETURN years;
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse SELECT...INTO with multiple columns"
    );
}

// SELECT INTO in basic block

#[test]
fn test_select_into_in_block() {
    let src = r#"
BEGIN
    SELECT col1, col2
    INTO var1, var2
    FROM table1
    WHERE id = 1;
    RETURN var1;
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse SELECT...INTO in block");
}

// UPDATE statement with enhanced AST tests

#[test]
fn test_update_single_assignment() {
    let src = "UPDATE employees SET salary = 50000 WHERE id = 1;";
    let stmt = parse_stmt_from_str(src).expect("Failed to parse");

    if let ast::AstStmt::Update(update) = stmt {
        assert!(update.set_span.is_some(), "SET span should be present");
        assert_eq!(update.set_assignments.len(), 1, "Expected 1 SET assignment");

        // Verify assignment structure exists
        let assignment = &update.set_assignments[0];
        assert!(
            matches!(*assignment.column, ast::AstExpr::Ident { .. }),
            "Expected identifier column"
        );
        assert!(
            assignment.value.span().end > assignment.value.span().start,
            "Expected non-empty value"
        );
        assert!(
            update.where_clause.is_some(),
            "WHERE clause should be present"
        );
    } else {
        panic!("Expected UPDATE statement");
    }
}

#[test]
fn test_update_multiple_assignments() {
    let src = "UPDATE products SET price = price * 1.1, stock = stock - 1, updated_at = CURRENT_TIMESTAMP() WHERE id = 100;";
    let stmt = parse_stmt_from_str(src).expect("Failed to parse");

    if let ast::AstStmt::Update(update) = stmt {
        assert_eq!(
            update.set_assignments.len(),
            3,
            "Expected 3 SET assignments"
        );

        // Verify each assignment structure
        for assignment in &update.set_assignments {
            assert!(
                matches!(*assignment.column, ast::AstExpr::Ident { .. }),
                "Column should be an identifier"
            );
            assert!(
                assignment.value.span().end > assignment.value.span().start,
                "Value should be non-empty"
            );
        }

        assert!(
            update.where_clause.is_some(),
            "WHERE clause should be present"
        );
    } else {
        panic!("Expected UPDATE statement");
    }
}

#[test]
fn test_update_with_from_clause() {
    let src = "UPDATE target SET value = source.new_value FROM source WHERE target.id = source.id;";
    let stmt = parse_stmt_from_str(src).expect("Failed to parse");

    if let ast::AstStmt::Update(update) = stmt {
        assert!(!update.from.is_empty(), "FROM clause should be present");
        assert!(
            update.where_clause.is_some(),
            "WHERE clause should be present"
        );
        assert_eq!(update.set_assignments.len(), 1, "Expected 1 SET assignment");
    } else {
        panic!("Expected UPDATE statement");
    }
}

#[test]
fn test_insert_with_output_clause() {
    let src = "INSERT INTO dbo.t (id, col) OUTPUT INSERTED.id, INSERTED.col VALUES (1, 'x');";
    let script = parse_sql_with_dialect(src, &*mssql()).expect("Failed to parse");
    let stmt = script.stmts.first().expect("Expected one statement");

    if let ast::AstStmt::Insert(insert) = stmt {
        assert!(insert.output.is_some(), "OUTPUT clause should be present");
    } else {
        panic!("Expected INSERT statement");
    }
}

#[test]
fn test_update_with_output_clause() {
    let src = "UPDATE dbo.t SET col = col + 1 OUTPUT INSERTED.col, DELETED.col WHERE id = 10;";
    let script = parse_sql_with_dialect(src, &*mssql()).expect("Failed to parse");
    let stmt = script.stmts.first().expect("Expected one statement");

    if let ast::AstStmt::Update(update) = stmt {
        assert!(update.output.is_some(), "OUTPUT clause should be present");
        assert!(update.where_clause.is_some(), "WHERE should be parsed");
    } else {
        panic!("Expected UPDATE statement");
    }
}

#[test]
fn test_delete_with_output_into_clause() {
    let src = "DELETE FROM dbo.t OUTPUT DELETED.id INTO #deleted_rows (id) WHERE id = 12;";
    let script = parse_sql_with_dialect(src, &*mssql()).expect("Failed to parse");
    let stmt = script.stmts.first().expect("Expected one statement");

    if let ast::AstStmt::Delete(delete) = stmt {
        assert!(delete.output.is_some(), "OUTPUT clause should be present");
        assert!(delete.where_clause.is_some(), "WHERE should be parsed");
    } else {
        panic!("Expected DELETE statement");
    }
}

#[test]
fn test_merge_with_output_clause() {
    let src = "MERGE INTO dbo.t AS target USING (SELECT 1 AS id, 'z' AS col) AS source ON target.id = source.id WHEN MATCHED THEN UPDATE SET target.col = source.col WHEN NOT MATCHED THEN INSERT (id, col) VALUES (source.id, source.col) OUTPUT $action, INSERTED.id, DELETED.id;";
    let script = parse_sql_with_dialect(src, &*mssql()).expect("Failed to parse");
    let stmt = script.stmts.first().expect("Expected one statement");

    if let ast::AstStmt::Merge(merge) = stmt {
        assert!(merge.output.is_some(), "OUTPUT clause should be present");
        assert_eq!(merge.clauses.len(), 2, "Expected 2 WHEN clauses");
    } else {
        panic!("Expected MERGE statement");
    }
}

// MERGE statement with enhanced AST tests

#[test]
fn test_merge_update_all_by_name() {
    let src = r#"
        MERGE INTO target
        USING source
        ON target.id = source.id
        WHEN MATCHED THEN UPDATE ALL BY NAME;
    "#;
    let script = parse_sql(src).expect("Failed to parse");

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first().map(|s| s) {
        assert_eq!(merge.clauses.len(), 1);
        assert!(matches!(
            merge.clauses[0].action,
            ast::AstMergeActionKind::UpdateAllByName { .. }
        ));
    } else {
        panic!("Expected MERGE statement");
    }
}

#[test]
fn test_merge_insert_all_by_name() {
    let src = r#"
        MERGE INTO target
        USING source
        ON target.id = source.id
        WHEN NOT MATCHED THEN INSERT ALL BY NAME;
    "#;
    let script = parse_sql(src).expect("Failed to parse");

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first().map(|s| s) {
        assert_eq!(merge.clauses.len(), 1);
        assert!(matches!(
            merge.clauses[0].action,
            ast::AstMergeActionKind::InsertAllByName { .. }
        ));
    } else {
        panic!("Expected MERGE statement");
    }
}

#[test]
fn test_merge_delete_action() {
    let src = r#"
        MERGE INTO target
        USING source
        ON target.id = source.id
        WHEN MATCHED AND source.deleted = TRUE THEN DELETE;
    "#;
    let script = parse_sql(src).expect("Failed to parse");

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first().map(|s| s) {
        assert_eq!(merge.clauses.len(), 1);
        assert!(matches!(
            merge.clauses[0].action,
            ast::AstMergeActionKind::Delete { .. }
        ));
        assert!(
            merge.clauses[0].and_condition_span.is_some(),
            "AND condition should be present"
        );
    } else {
        panic!("Expected MERGE statement");
    }
}

#[test]
fn test_merge_complex_multi_clause() {
    let src = r#"
        MERGE INTO inventory
        USING updates
        ON inventory.item_id = updates.item_id
        WHEN MATCHED AND updates.quantity = 0 THEN DELETE
        WHEN MATCHED THEN UPDATE SET 
            inventory.quantity = updates.quantity,
            inventory.price = updates.price,
            inventory.last_updated = CURRENT_TIMESTAMP()
        WHEN NOT MATCHED THEN INSERT (item_id, quantity, price, last_updated)
            VALUES (updates.item_id, updates.quantity, updates.price, CURRENT_TIMESTAMP());
    "#;
    let script = parse_sql(src).expect("Failed to parse");

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first().map(|s| s) {
        assert_eq!(merge.clauses.len(), 3, "Expected 3 WHEN clauses");

        // First clause: DELETE with condition
        assert!(matches!(
            merge.clauses[0].action,
            ast::AstMergeActionKind::Delete { .. }
        ));
        assert!(merge.clauses[0].and_condition_span.is_some());

        // Second clause: UPDATE SET with multiple assignments
        if let ast::AstMergeActionKind::UpdateSet { assignments, .. } = &merge.clauses[1].action {
            assert_eq!(assignments.len(), 3, "Expected 3 SET assignments");

            // Verify all assignments have proper structure
            for assignment in assignments {
                assert!(
                    matches!(*assignment.column, ast::AstExpr::Ident { .. }),
                    "Column should be an identifier"
                );
                assert!(
                    assignment.value.span().end > assignment.value.span().start,
                    "Value should be non-empty"
                );
            }
        } else {
            panic!("Expected UpdateSet action in second clause");
        }

        // Third clause: INSERT VALUES with 4 columns
        if let ast::AstMergeActionKind::InsertValues {
            columns, values, ..
        } = &merge.clauses[2].action
        {
            assert_eq!(columns.len(), 4, "Expected 4 columns");
            assert_eq!(values.len(), 4, "Expected 4 values");
        } else {
            panic!("Expected InsertValues action in third clause");
        }
    } else {
        panic!("Expected MERGE statement");
    }
}

#[test]
fn test_update_with_complex_expressions() {
    let src = r#"UPDATE orders 
        SET status = CASE 
                WHEN total > 1000 THEN 'VIP'
                WHEN total > 100 THEN 'STANDARD'
                ELSE 'BASIC'
            END,
            discount = (SELECT MAX(discount) FROM promotions WHERE active = TRUE),
            shipping_cost = GREATEST(5.00, total * 0.05)
        WHERE order_date > DATEADD(day, -30, CURRENT_DATE());"#;
    let stmt = parse_stmt_from_str(src).expect("Failed to parse");

    if let ast::AstStmt::Update(update) = stmt {
        assert_eq!(
            update.set_assignments.len(),
            3,
            "Expected 3 SET assignments"
        );

        // Verify all assignments have proper structure
        for (i, assignment) in update.set_assignments.iter().enumerate() {
            assert!(
                matches!(*assignment.column, ast::AstExpr::Ident { .. }),
                "Column {} should be an identifier",
                i
            );
            assert!(
                assignment.value.span().end > assignment.value.span().start,
                "Value {} should be non-empty",
                i
            );

            // Check expression types for complex values
            match i {
                0 => {
                    assert!(
                        matches!(*assignment.value, ast::AstExpr::Case { .. }),
                        "First value should be a CASE expression"
                    );
                }
                1 => {
                    // Subquery wrapped in parentheses is parsed as an expression
                    assert!(
                        assignment.value.span().end > assignment.value.span().start,
                        "Second value should contain subquery"
                    );
                }
                2 => {
                    assert!(
                        matches!(*assignment.value, ast::AstExpr::FunctionCall { .. }),
                        "Third value should be a function call (GREATEST)"
                    );
                }
                _ => {}
            }
        }

        assert!(
            update.where_clause.is_some(),
            "WHERE clause should be present"
        );
    } else {
        panic!("Expected UPDATE statement");
    }
}
