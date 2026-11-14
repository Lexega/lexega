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
    if let Some(ast::AstStmt::Block(b)) = script.stmts.first() {
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

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first() {
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

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first() {
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

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first() {
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

    if let Some(ast::AstStmt::Merge(merge)) = script.stmts.first() {
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

// DML target identity tests

/// How many nodes of `stmt` carry `id` (`NodeId(n)` in the debug dump).
fn node_id_occurrences(stmt: &ast::AstStmt, id: ast::NodeId) -> usize {
    format!("{stmt:?}").matches(&format!("{id:?}")).count()
}

fn span_text(src: &str, span: Option<lexega_syntax::lexer::Span>) -> Option<&str> {
    span.map(|s| &src[s.start as usize..s.end as usize])
}

#[test]
fn dml_targets_have_their_own_node_ids() {
    let src = "INSERT INTO t (a) SELECT a FROM s";
    let stmt = parse_stmt_from_str(src).expect("INSERT parses");
    let ast::AstStmt::Insert(insert) = &stmt else {
        panic!("expected INSERT, got {stmt:?}");
    };
    assert_ne!(insert.target_node_id, insert.node_id);
    assert_eq!(node_id_occurrences(&stmt, insert.target_node_id), 1);
    assert_eq!(span_text(src, insert.target_alias_span), None);

    let src = "REPLACE INTO t SELECT a FROM s";
    let stmt = parse_stmt_from_str(src).expect("REPLACE parses");
    let ast::AstStmt::ReplaceInto(replace) = &stmt else {
        panic!("expected REPLACE, got {stmt:?}");
    };
    assert_ne!(replace.target_node_id, replace.node_id);
    assert_eq!(node_id_occurrences(&stmt, replace.target_node_id), 1);
    assert_eq!(span_text(src, replace.target_alias_span), None);

    let src = "MERGE INTO t x USING s ON x.id = s.id WHEN MATCHED THEN UPDATE SET a = 1";
    let stmt = parse_stmt_from_str(src).expect("MERGE parses");
    let ast::AstStmt::Merge(merge) = &stmt else {
        panic!("expected MERGE, got {stmt:?}");
    };
    assert_ne!(merge.target_node_id, merge.node_id);
    assert_eq!(node_id_occurrences(&stmt, merge.target_node_id), 1);
    assert_eq!(span_text(src, merge.target_alias_span), Some("x"));
}

#[test]
fn an_insert_column_list_is_read_entry_by_entry() {
    use lexega_syntax::dialect::{mysql, snowflake, Dialect};

    fn parse_one(src: &str, dialect: &dyn Dialect) -> ast::AstStmt {
        let script = parse_sql_with_dialect(src, dialect).expect("statement parses");
        script.stmts.into_iter().next().expect("one statement")
    }
    /// Each entry's qualifier, where it has one, and name, as written.
    fn texts(src: &str, entries: &[ast::AstExpr]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| match entry {
                ast::AstExpr::Ident { column_ref, .. } => {
                    let name = span_text(src, Some(column_ref.name.span)).unwrap_or("");
                    match &column_ref.qualifier {
                        Some(q) => format!("{}.{name}", span_text(src, Some(q.span)).unwrap_or("")),
                        None => name.to_string(),
                    }
                }
                other => panic!("expected a column reference, got {other:?}"),
            })
            .collect()
    }

    // A comment between entries is no part of one.
    let src = "INSERT INTO t (a, -- note\n t.b, \"C\" /* c */) VALUES (1, 2, 3)";
    let ast::AstStmt::Insert(insert) = parse_one(src, &*snowflake()) else {
        panic!("expected INSERT");
    };
    assert_eq!(texts(src, &insert.columns), ["a", "t.b", "\"C\""]);

    let src = "REPLACE INTO t (`a`, b) VALUES (1, 2)";
    let ast::AstStmt::ReplaceInto(replace) = parse_one(src, &*mysql()) else {
        panic!("expected REPLACE");
    };
    assert_eq!(texts(src, &replace.columns), ["`a`", "b"]);

    let src = "INSERT ALL INTO t (a, b) VALUES (x, y) SELECT x, y FROM s";
    let ast::AstStmt::MultiInsert(multi) = parse_one(src, &*snowflake()) else {
        panic!("expected INSERT ALL");
    };
    let into = multi.into_clauses.first().expect("one INTO");
    assert_eq!(texts(src, &into.columns), ["a", "b"]);

    // No list, and a list whose entries are not each one expression.
    for src in ["INSERT INTO t VALUES (1)", "INSERT INTO t (a b) VALUES (1)"] {
        let ast::AstStmt::Insert(insert) = parse_one(src, &*snowflake()) else {
            panic!("expected INSERT: {src}");
        };
        assert!(insert.columns.is_empty(), "{src}: {:?}", insert.columns);
    }
}

#[test]
fn dml_row_sources_have_their_own_node_ids() {
    use lexega_syntax::dialect::{mysql, Dialect};

    fn parse_one(src: &str, dialect: &dyn Dialect) -> ast::AstStmt {
        let script = parse_sql_with_dialect(src, dialect).expect("statement parses");
        script.stmts.into_iter().next().expect("one statement")
    }

    let stmt =
        parse_stmt_from_str("INSERT INTO t (a, b) VALUES (1, 2), (3, 4)").expect("INSERT parses");
    let ast::AstStmt::Insert(insert) = &stmt else {
        panic!("expected INSERT, got {stmt:?}");
    };
    assert_ne!(insert.values_node_id, insert.node_id);
    assert_ne!(insert.values_node_id, insert.target_node_id);
    assert_eq!(node_id_occurrences(&stmt, insert.values_node_id), 1);

    let stmt = parse_one("REPLACE INTO t SET a = 1, b = 2", &*mysql());
    let ast::AstStmt::ReplaceInto(replace) = &stmt else {
        panic!("expected REPLACE, got {stmt:?}");
    };
    assert_ne!(replace.values_node_id, replace.node_id);
    assert_ne!(replace.values_node_id, replace.target_node_id);
    assert_eq!(node_id_occurrences(&stmt, replace.values_node_id), 1);

    let stmt = parse_stmt_from_str(
        "MERGE INTO t USING (SELECT id FROM s) src ON t.id = src.id WHEN MATCHED THEN DELETE",
    )
    .expect("MERGE parses");
    let ast::AstStmt::Merge(merge) = &stmt else {
        panic!("expected MERGE, got {stmt:?}");
    };
    assert_ne!(merge.using_node_id, merge.node_id);
    assert_ne!(merge.using_node_id, merge.target_node_id);
    assert_eq!(node_id_occurrences(&stmt, merge.using_node_id), 1);

    let stmt = parse_one(
        "DELETE d FROM orders d JOIN customers c ON c.id = d.customer_id WHERE c.closed = 1",
        &*mssql(),
    );
    let ast::AstStmt::Delete(delete) = &stmt else {
        panic!("expected DELETE, got {stmt:?}");
    };
    let alias_id = delete
        .targets
        .first()
        .expect("T-SQL target is kept")
        .node_id;
    assert_ne!(alias_id, delete.node_id);
    assert_eq!(node_id_occurrences(&stmt, alias_id), 1);

    let stmt = parse_stmt_from_str("DELETE FROM t WHERE a = 1").expect("DELETE parses");
    let ast::AstStmt::Delete(delete) = &stmt else {
        panic!("expected DELETE, got {stmt:?}");
    };
    assert!(delete.targets.is_empty());
}

#[test]
fn dml_target_alias_spans() {
    use lexega_syntax::dialect::{postgres, snowflake, Dialect};

    fn merge_alias<'a>(src: &'a str, dialect: &dyn Dialect) -> Option<&'a str> {
        let script = parse_sql_with_dialect(src, dialect).expect("MERGE parses");
        match script.stmts.first() {
            Some(ast::AstStmt::Merge(merge)) => span_text(src, merge.target_alias_span),
            other => panic!("expected MERGE, got {other:?}"),
        }
    }
    fn insert_alias<'a>(src: &'a str, dialect: &dyn Dialect) -> Option<&'a str> {
        let script = parse_sql_with_dialect(src, dialect).expect("INSERT parses");
        match script.stmts.first() {
            Some(ast::AstStmt::Insert(insert)) => span_text(src, insert.target_alias_span),
            other => panic!("expected INSERT, got {other:?}"),
        }
    }

    let snowflake = snowflake();
    assert_eq!(
        merge_alias(
            "MERGE INTO db.sch.t AS x USING s ON x.id = s.id WHEN MATCHED THEN DELETE",
            &*snowflake
        ),
        Some("x")
    );
    assert_eq!(
        merge_alias(
            "MERGE t x USING s ON x.id = s.id WHEN MATCHED THEN DELETE",
            &*snowflake
        ),
        Some("x")
    );
    assert_eq!(
        merge_alias(
            "MERGE INTO {{ this }} AS x USING s ON x.id = s.id WHEN MATCHED THEN DELETE",
            &*snowflake
        ),
        Some("x")
    );
    assert_eq!(
        merge_alias(
            "MERGE INTO dbo.t WITH (HOLDLOCK) AS x USING s ON x.id = s.id WHEN MATCHED THEN DELETE;",
            &*mssql()
        ),
        Some("x")
    );
    assert_eq!(
        merge_alias(
            "MERGE INTO dbo.t AS target USING s AS source ON target.id = source.id WHEN MATCHED THEN DELETE;",
            &*mssql()
        ),
        Some("target")
    );
    assert_eq!(
        merge_alias(
            r#"MERGE INTO t AS "x" USING s ON "x".id = s.id WHEN MATCHED THEN DELETE"#,
            &*snowflake
        ),
        Some(r#""x""#)
    );
    assert_eq!(
        merge_alias(
            "MERGE INTO dbo.t AS [x] USING s ON [x].id = s.id WHEN MATCHED THEN DELETE;",
            &*mssql()
        ),
        Some("[x]")
    );
    assert_eq!(
        merge_alias(
            "MERGE INTO db.t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
            &*snowflake
        ),
        None
    );
    assert_eq!(
        insert_alias("INSERT INTO t AS x (a) VALUES (1)", &*postgres()),
        Some("x")
    );
    assert_eq!(
        insert_alias("INSERT INTO db.t SELECT a FROM s", &*snowflake),
        None
    );
}

#[test]
fn a_named_target_formats_as_written() {
    use lexega_syntax::dialect::{databricks, mysql, postgres, snowflake};
    let cases: [(&str, lexega_syntax::dialect::DialectRef); 14] = [
        ("INSERT INTO #t SELECT a FROM s", mssql()),
        ("INSERT INTO tempdb..#t (a) VALUES (1)", mssql()),
        ("INSERT INTO [dbo].[t] AS x (a) VALUES (1)", mssql()),
        (
            "MERGE INTO #t WITH (HOLDLOCK) AS x USING s ON x.id = s.id WHEN MATCHED THEN DELETE;",
            mssql(),
        ),
        (
            "MERGE INTO #t WITH (HOLDLOCK) USING s ON #t.id = s.id WHEN MATCHED THEN DELETE;",
            mssql(),
        ),
        (
            "MERGE [dbo].[t] WITH (HOLDLOCK, ROWLOCK) USING (SELECT 1 AS id) AS s ON t.id = s.id \
             WHEN MATCHED THEN DELETE;",
            mssql(),
        ),
        ("INSERT INTO t@dblink (a) VALUES (1)", snowflake()),
        (
            "INSERT ALL INTO a (id) VALUES (id) INTO b (id) VALUES (id) SELECT id FROM s",
            snowflake(),
        ),
        ("COPY INTO t (a, b) FROM @stage", snowflake()),
        (
            "CREATE TABLE IF NOT EXISTS /* c */ s.zz_g (id INT)",
            snowflake(),
        ),
        ("CREATE TABLE \"my.new\" AS SELECT 1 AS id", snowflake()),
        ("CREATE UNLOGGED TABLE zz_g (id INT)", postgres()),
        ("CREATE TABLE IF NOT EXISTS zz_g (id INT)", databricks()),
        ("REPLACE INTO zz_r (id) VALUES (1)", mysql()),
    ];
    for (src, dialect) in cases {
        let config = lexega_syntax::FormatterConfig {
            dialect: dialect.clone(),
            ..Default::default()
        };
        let stmts = parse_sql_with_dialect(src, &*dialect)
            .expect("parses")
            .stmts;
        assert!(
            !stmts
                .iter()
                .any(|s| matches!(s, ast::AstStmt::OpaqueContent { .. })),
            "{src}: {stmts:?}"
        );
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    }
}

#[test]
fn a_multi_table_insert_reads_the_rows_each_into_writes() {
    let sql = "INSERT ALL WHEN id > 1 THEN INTO t (id, k) VALUES (id, UPPER(k)), (2, 'b') \
               INTO u VALUES (id) ELSE INTO w (id) SELECT id, k FROM s";
    let script = parse_sql(sql).expect("parses");
    let [ast::AstStmt::MultiInsert(mi)] = script.stmts.as_slice() else {
        panic!("{:?}", script.stmts);
    };
    let text = |span: lexega_syntax::lexer::Span| &sql[span.start as usize..span.end as usize];
    let [when] = mi.when_clauses.as_slice() else {
        panic!("{:?}", mi.when_clauses);
    };
    let [t, u] = when.into_clauses.as_slice() else {
        panic!("{:?}", when.into_clauses);
    };
    let rows: Vec<Vec<&str>> = t
        .values_rows
        .iter()
        .map(|row| row.iter().map(|value| text(value.span())).collect())
        .collect();
    assert_eq!(rows, [vec!["id", "UPPER(k)"], vec!["2", "'b'"]]);
    let row_texts: Vec<&str> = t.values_rows_spans.iter().map(|s| text(*s)).collect();
    assert_eq!(row_texts, ["(id, UPPER(k))", "(2, 'b')"]);
    assert_eq!(t.values_keyword_span.map(text), Some("VALUES"));
    assert_eq!(u.values_rows.len(), 1);
    let [w] = mi.else_into_clauses.as_slice() else {
        panic!("{:?}", mi.else_into_clauses);
    };
    assert!(w.values_keyword_span.is_none() && w.values_rows.is_empty());
    let formatted =
        lexega_syntax::format_sql_with_config(sql, &lexega_syntax::FormatterConfig::default())
            .expect("formats");
    lexega_syntax::verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("{e}\n{formatted}"));
}

/// The parts and kind of the name a statement's object reference holds.
fn name_of(src: &str, name: &ast::AstObjectRef) -> (Vec<Option<String>>, ast::AstTableNameKind) {
    let parts = name
        .parts
        .as_ref()
        .expect("a dotted name")
        .iter()
        .map(|part| {
            part.as_ref().map(|part| {
                let s = part.span();
                src[s.start as usize..s.end as usize].to_string()
            })
        })
        .collect();
    (parts, name.name_kind)
}

fn first_stmt(src: &str, dialect: &dyn lexega_syntax::dialect::Dialect) -> ast::AstStmt {
    parse_sql_with_dialect(src, dialect)
        .expect("parses")
        .stmts
        .into_iter()
        .next()
        .expect("one statement")
}

#[test]
fn a_write_target_is_the_name_its_tokens_spell() {
    use ast::AstTableNameKind as K;
    let target =
        |src: &str, dialect: &dyn lexega_syntax::dialect::Dialect| match first_stmt(src, dialect) {
            ast::AstStmt::Insert(i) => name_of(src, i.target_table.as_ref().expect("target")),
            ast::AstStmt::Merge(m) => name_of(src, m.target_table.as_ref().expect("target")),
            ast::AstStmt::ReplaceInto(r) => name_of(src, r.target_table.as_ref().expect("target")),
            ast::AstStmt::CopyIntoTable { table_name, .. } => name_of(src, &table_name),
            other => panic!("{src}: {other:?}"),
        };
    let some = |parts: &[&str]| {
        parts
            .iter()
            .map(|p| Some(p.to_string()))
            .collect::<Vec<_>>()
    };
    let mssql = mssql();
    assert_eq!(
        target("INSERT INTO #t SELECT a FROM s", &*mssql),
        (some(&["#t"]), K::LocalTemp)
    );
    assert_eq!(
        target("INSERT INTO ##g (a) VALUES (1)", &*mssql),
        (some(&["##g"]), K::GlobalTemp)
    );
    assert_eq!(
        target("INSERT INTO @tv (a) VALUES (1)", &*mssql),
        (some(&["@tv"]), K::TableVariable)
    );
    assert_eq!(
        target("INSERT INTO tempdb..#t (a) VALUES (1)", &*mssql),
        (
            vec![Some("tempdb".to_string()), None, Some("#t".to_string())],
            K::LocalTemp
        )
    );
    assert_eq!(
        target("INSERT INTO [dbo].[t] (a) VALUES (1)", &*mssql),
        (some(&["[dbo]", "[t]"]), K::Catalog)
    );
    assert_eq!(
        target(
            "MERGE INTO #t WITH (HOLDLOCK) AS x USING s ON x.id = s.id WHEN MATCHED THEN DELETE;",
            &*mssql
        ),
        (some(&["#t"]), K::LocalTemp)
    );
    // Table hints with no alias after them.
    assert_eq!(
        target(
            "MERGE INTO #t WITH (HOLDLOCK) USING s ON #t.id = s.id WHEN MATCHED THEN DELETE;",
            &*mssql
        ),
        (some(&["#t"]), K::LocalTemp)
    );
    assert_eq!(
        target(
            "MERGE [dbo].[t] WITH (HOLDLOCK) USING s ON t.id = s.id WHEN MATCHED THEN DELETE;",
            &*mssql
        ),
        (some(&["[dbo]", "[t]"]), K::Catalog)
    );
    let snowflake = lexega_syntax::dialect::snowflake();
    assert_eq!(
        target("COPY INTO db.s.t (a, b) FROM @stage", &*snowflake),
        (some(&["db", "s", "t"]), K::Catalog)
    );
    assert_eq!(
        target("INSERT INTO \"a.b\" AS x (a) VALUES (1)", &*snowflake),
        (some(&["\"a.b\""]), K::Catalog)
    );
    assert_eq!(
        target(
            "REPLACE INTO db.t (a) VALUES (1)",
            &*lexega_syntax::dialect::mysql()
        ),
        (some(&["db", "t"]), K::Catalog)
    );
}

#[test]
fn a_table_reference_says_what_kind_of_name_it_is() {
    use ast::AstTableNameKind as K;
    let read = |src: &str, dialect: &dyn lexega_syntax::dialect::Dialect| {
        let ast::AstStmt::Select(select) = first_stmt(src, dialect) else {
            panic!("{src}: not a SELECT");
        };
        let ast::FromItemKind::TableRef(table) = &select.from[0].kind else {
            panic!("{src}: not a table");
        };
        (
            src[table.name.span.start as usize..table.name.span.end as usize].to_string(),
            table.name.name_kind,
        )
    };
    let mssql = mssql();
    let snowflake = lexega_syntax::dialect::snowflake();
    assert_eq!(
        read("SELECT a FROM #t", &*mssql),
        ("#t".to_string(), K::LocalTemp)
    );
    assert_eq!(
        read("SELECT a FROM ##g", &*mssql),
        ("##g".to_string(), K::GlobalTemp)
    );
    assert_eq!(
        read("SELECT a FROM @tv", &*mssql),
        ("@tv".to_string(), K::TableVariable)
    );
    assert_eq!(
        read("SELECT a FROM dbo.t", &*mssql),
        ("dbo.t".to_string(), K::Catalog)
    );
    assert_eq!(
        read("SELECT $1 FROM @db.s.stage/path t", &*snowflake),
        ("@db.s.stage/path".to_string(), K::Stage)
    );
}

#[test]
fn a_dollar_string_given_as_words_is_a_string_only_where_the_dialect_writes_one() {
    use lexega_syntax::dialect::{bigquery, databricks, mysql, snowflake};
    let first_item = |src: &str, dialect: &dyn lexega_syntax::dialect::Dialect| {
        let ast::AstStmt::Select(select) = first_stmt(src, dialect) else {
            panic!("{src}: not a SELECT");
        };
        let ast::AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("{src}: no columns");
        };
        let ast::ProjectionItemKind::SelectItem(first) = &items[0].kind else {
            panic!("{src}: not a select item");
        };
        first.expr.clone()
    };
    for src in ["SELECT $$a$$ FROM t", "SELECT $$a b$$ FROM t"] {
        let expr = first_item(src, &*snowflake());
        assert!(
            matches!(
                expr,
                ast::AstExpr::Literal {
                    literal: ast::AstLiteral::String { .. },
                    ..
                }
            ),
            "[snowflake] {src}: {expr:?}"
        );
    }
    for dialect in [mysql(), mssql(), bigquery(), databricks()] {
        for src in ["SELECT $$a$$ FROM t", "SELECT $$abc FROM t"] {
            let script = parse_sql_with_dialect(src, &*dialect).expect("parses");
            assert_eq!(script.stmts.len(), 1, "{src}: {:?}", script.stmts);
            let expr = first_item(src, &*dialect);
            assert!(
                matches!(expr, ast::AstExpr::Ident { .. }),
                "[{}] {src}: {expr:?}",
                dialect.name()
            );
        }
    }
}

#[test]
fn a_prefixed_or_introduced_literal_is_one_value_in_an_expression() {
    use lexega_syntax::dialect::{bigquery, mysql, postgres, Dialect};
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };

    fn parse_one(src: &str, dialect: &dyn Dialect) -> ast::AstStmt {
        let script = parse_sql_with_dialect(src, dialect).expect("statement parses");
        assert_eq!(script.stmts.len(), 1, "{src}: {:?}", script.stmts);
        script.stmts.into_iter().next().expect("one statement")
    }
    fn literal_text<'s>(src: &'s str, expr: &ast::AstExpr) -> Option<&'s str> {
        let ast::AstExpr::Literal {
            literal: ast::AstLiteral::String { span },
            ..
        } = expr
        else {
            return None;
        };
        src.get(span.start as usize..span.end as usize)
    }
    fn round_trips(src: &str, dialect: lexega_syntax::DialectRef) {
        let config = FormatterConfig {
            dialect,
            ..Default::default()
        };
        let formatted = format_sql_with_config(src, &config).expect("formats");
        verify_formatting_safe_with_dialect(src, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    }

    // mysqldump's binary and charset-introduced values, and MySQL's other
    // prefixed literals, each one value of the row.
    let values = [
        "_binary 'ab\\'c'",
        "_binary 0x4142",
        "_binary X'4142'",
        "_utf8mb4'x'",
        "_latin1 /* c */ 'x'",
        "X'41'",
        "x'41'",
        "N'x'",
        "b'0101'",
        "B'01'",
    ];
    let src = format!("INSERT INTO t VALUES ({})", values.join(", "));
    let ast::AstStmt::Insert(insert) = parse_one(&src, &*mysql()) else {
        panic!("expected INSERT");
    };
    let read: Vec<Option<&str>> = insert.values_rows[0]
        .iter()
        .map(|e| literal_text(&src, e))
        .collect();
    let expected: Vec<Option<&str>> = values.iter().map(|v| Some(*v)).collect();
    assert_eq!(read, expected);
    round_trips(&src, mysql());

    for (src, dialect, literal) in [
        ("SELECT X'41' FROM t", mysql(), "X'41'"),
        ("SELECT _utf8mb4'x' AS a FROM t", mysql(), "_utf8mb4'x'"),
        ("SELECT X'1F', B'101', N'x' FROM t", postgres(), "X'1F'"),
        ("SELECT rb'\\x01', r\"a\" FROM t", bigquery(), "rb'\\x01'"),
    ] {
        let ast::AstStmt::Select(select) = parse_one(src, &*dialect) else {
            panic!("expected SELECT: {src}");
        };
        let ast::AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("expected columns: {src}");
        };
        let ast::ProjectionItemKind::SelectItem(first) = &items[0].kind else {
            panic!("expected a select item: {src}");
        };
        assert_eq!(
            literal_text(src, &first.expr),
            Some(literal),
            "{src}: {:?}",
            first.expr
        );
        round_trips(src, dialect);
    }
}

#[test]
fn a_dashed_project_name_is_one_part_of_a_table_name() {
    use lexega_syntax::dialect::{bigquery, snowflake, Dialect};
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };

    fn parts(src: &str, table: &ast::AstTableRef) -> Vec<String> {
        table
            .name
            .parts
            .as_ref()
            .expect("a dotted name has parts")
            .iter()
            .map(|part| {
                let span = part.as_ref().expect("no omitted part").span();
                src[span.start as usize..span.end as usize].to_string()
            })
            .collect()
    }
    fn parse_one(src: &str, dialect: &dyn Dialect) -> ast::AstStmt {
        let script = parse_sql_with_dialect(src, dialect).expect("statement parses");
        assert!(script.cut_statements.is_empty(), "{src}");
        assert_eq!(script.stmts.len(), 1, "{src}: {:?}", script.stmts);
        script.stmts.into_iter().next().expect("one statement")
    }

    for dialect in [bigquery(), snowflake()] {
        let src = "DELETE FROM my-project.ds.t WHERE TRUE";
        let ast::AstStmt::Delete(delete) = parse_one(src, &*dialect) else {
            panic!("expected DELETE: {src}");
        };
        let target = delete.target_table.as_ref().expect("target table");
        assert_eq!(parts(src, target), ["my-project", "ds", "t"]);

        let src = "SELECT * FROM my-proj-x.ds.t AS x JOIN my-other.ds.u ON x.id = u.id";
        let ast::AstStmt::Select(select) = parse_one(src, &*dialect) else {
            panic!("expected SELECT: {src}");
        };
        assert_eq!(parts(src, &select.from[0]), ["my-proj-x", "ds", "t"]);
        assert_eq!(
            parts(src, &select.from[0].joins[0].right),
            ["my-other", "ds", "u"]
        );

        for src in [
            "DELETE FROM my-project.ds.t WHERE TRUE",
            "INSERT INTO my-project.ds.t SELECT 1",
            "UPDATE my-project.ds.t SET a = 1 WHERE b = 2",
            "SELECT * FROM my-project.ds.t",
        ] {
            let config = FormatterConfig {
                dialect: dialect.clone(),
                ..FormatterConfig::default()
            };
            let formatted = format_sql_with_config(src, &config).expect("formats");
            assert_eq!(
                formatted.split_whitespace().collect::<Vec<_>>().join(" "),
                src
            );
            verify_formatting_safe_with_dialect(src, &formatted, config.dialect.as_ref())
                .expect("round-trips");
        }

        // In an expression the dash stays a subtraction.
        let ast::AstStmt::Select(select) = parse_one("SELECT a-b FROM t", &*dialect) else {
            panic!("expected SELECT");
        };
        let ast::AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("expected columns");
        };
        let ast::ProjectionItemKind::SelectItem(item) = &items[0].kind else {
            panic!("expected a select item");
        };
        assert!(matches!(
            item.expr,
            ast::AstExpr::BinaryOp {
                operator: ast::BinaryOperator::Minus,
                ..
            }
        ));
    }
}

#[test]
fn a_dashed_name_takes_number_and_keyword_segments() {
    use lexega_syntax::dialect::{bigquery, snowflake, Dialect};
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };

    fn parts(src: &str, name: &ast::AstObjectRef) -> Vec<String> {
        name.parts
            .as_ref()
            .expect("a dotted name has parts")
            .iter()
            .map(|part| {
                let span = part.as_ref().expect("no omitted part").span();
                src[span.start as usize..span.end as usize].to_string()
            })
            .collect()
    }
    fn parse_one(src: &str, dialect: &dyn Dialect) -> ast::AstStmt {
        let script = parse_sql_with_dialect(src, dialect).expect("statement parses");
        assert!(script.cut_statements.is_empty(), "{src}");
        assert_eq!(script.stmts.len(), 1, "{src}: {:?}", script.stmts);
        script.stmts.into_iter().next().expect("one statement")
    }
    fn first_item(stmt: ast::AstStmt) -> ast::AstExpr {
        let ast::AstStmt::Select(select) = stmt else {
            panic!("expected SELECT");
        };
        let ast::AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("expected columns");
        };
        let ast::ProjectionItemKind::SelectItem(item) = &items[0].kind else {
            panic!("expected a select item");
        };
        item.expr.clone()
    }

    for dialect in [bigquery(), snowflake()] {
        // `123.` is one number token: its `.` separates the first part.
        let src = "DELETE FROM proj-123.ds.t WHERE TRUE";
        let ast::AstStmt::Delete(delete) = parse_one(src, &*dialect) else {
            panic!("expected DELETE: {src}");
        };
        let target = delete.target_table.as_ref().expect("target table");
        assert_eq!(parts(src, &target.name), ["proj-123", "ds", "t"]);
        assert!(delete.where_clause.is_some(), "{src}");

        for (src, first) in [
            ("SELECT * FROM my-order-project.ds.t", "my-order-project"),
            ("SELECT * FROM p-1-2.ds.t", "p-1-2"),
            ("SELECT * FROM p-1-x.ds.t", "p-1-x"),
        ] {
            let ast::AstStmt::Select(select) = parse_one(src, &*dialect) else {
                panic!("expected SELECT: {src}");
            };
            assert_eq!(parts(src, &select.from[0].name), [first, "ds", "t"]);
        }

        let src = "INSERT INTO proj-123.ds.t SELECT 1";
        let ast::AstStmt::Insert(insert) = parse_one(src, &*dialect) else {
            panic!("expected INSERT: {src}");
        };
        let target = insert.target_table.as_ref().expect("target table");
        assert_eq!(parts(src, target), ["proj-123", "ds", "t"]);

        for src in [
            "DELETE FROM proj-123.ds.t WHERE TRUE",
            "INSERT INTO proj-123.ds.t SELECT 1",
            "UPDATE proj-123.ds.t SET a = 1 WHERE b = 2",
            "SELECT * FROM my-order-project.ds.t AS x JOIN p-1-2.ds.u ON x.id = u.id",
        ] {
            let config = FormatterConfig {
                dialect: dialect.clone(),
                ..Default::default()
            };
            let formatted = format_sql_with_config(src, &config).expect("formats");
            assert_eq!(
                formatted.split_whitespace().collect::<Vec<_>>().join(" "),
                src
            );
            verify_formatting_safe_with_dialect(src, &formatted, config.dialect.as_ref())
                .expect("round-trips");
        }

        // Digits then letters: the lexer's number and word are one segment.
        for (src, first) in [
            ("DELETE FROM proj-1a.ds.t WHERE TRUE", "proj-1a"),
            ("DELETE FROM team-1a2b.ds.t WHERE TRUE", "team-1a2b"),
            ("DELETE FROM p-1a-2b.ds.t WHERE TRUE", "p-1a-2b"),
        ] {
            let ast::AstStmt::Delete(delete) = parse_one(src, &*dialect) else {
                panic!("expected DELETE: {src}");
            };
            let target = delete.target_table.as_ref().expect("target table");
            assert_eq!(parts(src, &target.name), [first, "ds", "t"], "{src}");
            assert!(delete.where_clause.is_some(), "{src}");
            let config = FormatterConfig {
                dialect: dialect.clone(),
                ..Default::default()
            };
            let formatted = format_sql_with_config(src, &config).expect("formats");
            verify_formatting_safe_with_dialect(src, &formatted, config.dialect.as_ref())
                .expect("round-trips");
        }

        // In an expression the dash stays a subtraction.
        for src in ["SELECT a-1.5 FROM t", "SELECT a - 123. FROM t"] {
            assert!(
                matches!(
                    first_item(parse_one(src, &*dialect)),
                    ast::AstExpr::BinaryOp {
                        operator: ast::BinaryOperator::Minus,
                        ..
                    }
                ),
                "{src}"
            );
        }
    }
}

#[test]
fn a_tsql_delete_keeps_its_target_and_a_merge_reads_a_joined_source() {
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };
    fn parse_one(src: &str, dialect: &dyn lexega_syntax::dialect::Dialect) -> ast::AstStmt {
        let script = parse_sql_with_dialect(src, dialect).expect("statement parses");
        script.stmts.into_iter().next().expect("one statement")
    }
    let dialect = mssql();
    let src = "DELETE analytics.public.users FROM users u JOIN t ON t.id = u.id WHERE email = 'y'";
    let ast::AstStmt::Delete(delete) = parse_one(src, &*dialect) else {
        panic!("expected DELETE");
    };
    let [target] = delete.targets.as_slice() else {
        panic!("one target: {:?}", delete.targets);
    };
    assert_eq!(
        span_text(src, Some(target.span)),
        Some("analytics.public.users")
    );

    let src = "MERGE INTO e u USING a x JOIN b y ON x.id = y.id ON u.id = x.id \
               WHEN MATCHED THEN UPDATE SET name = 1";
    let ast::AstStmt::Merge(merge) = parse_one(src, &*dialect) else {
        panic!("expected MERGE");
    };
    let source = merge.using_table_ref.as_deref().expect("a table source");
    assert_eq!(source.joins.len(), 1);
    assert_eq!(
        span_text(src, merge.on_span),
        Some("ON u.id = x.id"),
        "the MERGE's own ON follows the source's joins"
    );

    let config = FormatterConfig {
        dialect: mssql(),
        ..FormatterConfig::default()
    };
    for src in [
        "DELETE d FROM orders d JOIN customers c ON c.id = d.customer_id WHERE c.closed = 1",
        "DELETE analytics.public.users FROM users u JOIN t ON t.id = u.id WHERE email = 'y'",
        "MERGE INTO e u USING a x JOIN b y ON x.id = y.id ON u.id = x.id WHEN MATCHED THEN UPDATE SET name = 1",
    ] {
        let formatted = format_sql_with_config(src, &config).expect("formats");
        verify_formatting_safe_with_dialect(src, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{src}: {e}\n{formatted}"));
    }
}

#[test]
fn a_mysql_multi_table_delete_reads_its_comma_from_list() {
    use lexega_syntax::dialect::mysql;
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };
    let src = "DELETE o FROM orders o, users u WHERE u.id = o.user_id AND email = 'q'";
    let script = parse_sql_with_dialect(src, &*mysql()).expect("parses");
    let Some(ast::AstStmt::Delete(delete)) = script.stmts.first() else {
        panic!("expected DELETE: {:?}", script.stmts);
    };
    let [rest] = delete.from_rest.as_slice() else {
        panic!("one more FROM item: {:?}", delete.from_rest);
    };
    assert_eq!(span_text(src, Some(rest.span)), Some("users u"));
    assert!(delete.using.is_empty() && delete.using_keyword_span.is_none());

    let config = FormatterConfig {
        dialect: mysql(),
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(src, &config).expect("formats");
    verify_formatting_safe_with_dialect(src, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("{e}\n{formatted}"));
    assert!(
        !formatted.to_ascii_uppercase().contains("USING"),
        "{formatted}"
    );
}

#[test]
fn a_mysql_delete_from_a_target_list_using_a_from_list_reads_each_target() {
    use lexega_syntax::dialect::mysql;
    use lexega_syntax::{
        format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
    };
    let config = FormatterConfig {
        dialect: mysql(),
        ..FormatterConfig::default()
    };
    for (src, targets, first, rest) in [
        (
            "DELETE FROM b, a USING b RIGHT JOIN a ON a.id = b.id WHERE a.x = 1",
            &["b", "a"][..],
            "b RIGHT JOIN a ON a.id = b.id",
            &[][..],
        ),
        (
            "DELETE QUICK FROM a.*, b.* USING a, b AS bb WHERE a.id = bb.id",
            &["a.*", "b.*"][..],
            "a",
            &["b AS bb"][..],
        ),
    ] {
        let script = parse_sql_with_dialect(src, &*mysql()).expect("parses");
        let [ast::AstStmt::Delete(delete)] = script.stmts.as_slice() else {
            panic!("one DELETE: {:?}", script.stmts);
        };
        let written: Vec<_> = delete
            .targets
            .iter()
            .map(|target| span_text(src, Some(target.span)))
            .collect();
        assert_eq!(
            written,
            targets.iter().map(|t| Some(*t)).collect::<Vec<_>>()
        );
        let target_table = delete.target_table.as_deref().expect("a FROM list");
        assert_eq!(span_text(src, Some(target_table.span)), Some(first));
        let listed: Vec<_> = delete
            .from_rest
            .iter()
            .map(|item| span_text(src, Some(item.span)))
            .collect();
        assert_eq!(listed, rest.iter().map(|t| Some(*t)).collect::<Vec<_>>());
        assert!(delete.using.is_empty());
        assert!(delete.where_clause.is_some(), "{src}");

        let formatted = format_sql_with_config(src, &config).expect("formats");
        verify_formatting_safe_with_dialect(src, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{src}: {e}\n{formatted}"));
        let upper = formatted.to_ascii_uppercase();
        let (from, using) = (upper.find("FROM"), upper.find("USING"));
        assert!(
            from.is_some() && using.is_some() && from < using,
            "{formatted}"
        );
    }
}

#[test]
fn a_merge_branch_may_do_nothing() {
    use lexega_syntax::ast::{AstMergeActionKind, AstStmt};
    let sql = "MERGE INTO a USING s ON a.id = s.id WHEN MATCHED THEN DO NOTHING \
               WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)";
    let script = parse_sql(sql).expect("parses");
    let [AstStmt::Merge(m)] = script.stmts.as_slice() else {
        panic!("{:?}", script.stmts);
    };
    let AstMergeActionKind::DoNothing { span } = &m.clauses[0].action else {
        panic!("{:?}", m.clauses[0].action);
    };
    assert_eq!(&sql[span.start as usize..span.end as usize], "DO NOTHING");
    let formatted =
        lexega_syntax::format_sql_with_config(sql, &lexega_syntax::FormatterConfig::default())
            .expect("formats");
    lexega_syntax::verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("{e}\n{formatted}"));
}

/// Databricks `INSERT OVERWRITE [TABLE] t [PARTITION (…)]` and `INSERT INTO
/// TABLE t`, and BigQuery `MERGE … INSERT ROW`, parse as the writes they
/// are, naming their target, and format keeping every token.
#[test]
fn an_overwrite_naming_its_table_and_an_insert_of_the_source_row_parse() {
    use lexega_syntax::dialect::{bigquery, databricks};
    let inserts = [
        (
            "INSERT OVERWRITE main.core.stage SELECT id, status FROM main.core.orders",
            "main.core.stage",
            false,
        ),
        (
            "INSERT OVERWRITE TABLE main.core.stage SELECT id, status FROM main.core.orders",
            "main.core.stage",
            true,
        ),
        (
            "INSERT OVERWRITE stage (id, status) SELECT id, status FROM orders",
            "stage",
            false,
        ),
        (
            "INSERT OVERWRITE TABLE stage PARTITION (status = 'US') SELECT id FROM orders",
            "stage",
            true,
        ),
        (
            "INSERT OVERWRITE TABLE stage PARTITION (status) SELECT id, status FROM orders",
            "stage",
            true,
        ),
        (
            "INSERT INTO TABLE stage PARTITION (dt = '2026-01-01') (id) VALUES (1)",
            "stage",
            true,
        ),
        (
            "INSERT OVERWRITE INTO stage SELECT id FROM orders",
            "stage",
            false,
        ),
    ];
    let dialect = databricks();
    let config = lexega_syntax::FormatterConfig {
        dialect: dialect.clone(),
        ..Default::default()
    };
    for (src, target, table_keyword) in inserts {
        let ast::AstStmt::Insert(insert) = first_stmt(src, &*dialect) else {
            panic!("{src}: not an INSERT");
        };
        let written = insert
            .target_table
            .as_ref()
            .map(|t| &src[t.span.start as usize..t.span.end as usize]);
        assert_eq!(written, Some(target), "{src}");
        assert!(insert.overwrite || src.starts_with("INSERT INTO"), "{src}");
        assert_eq!(insert.table_keyword_span.is_some(), table_keyword, "{src}");
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    }

    // A write of files names no table.
    for src in [
        "INSERT OVERWRITE DIRECTORY '/p' USING parquet SELECT 1",
        "INSERT OVERWRITE LOCAL DIRECTORY '/p' STORED AS parquet SELECT 1",
    ] {
        let script = parse_sql_with_dialect(src, &*dialect).expect("parses");
        let named = script.stmts.iter().any(
            |stmt| matches!(stmt, ast::AstStmt::Insert(insert) if insert.target_table.is_some()),
        );
        assert!(!named, "{src}: {:?}", script.stmts);
    }

    let dialect = bigquery();
    let config = lexega_syntax::FormatterConfig {
        dialect: dialect.clone(),
        ..Default::default()
    };
    for src in [
        "MERGE ds.stage T USING ds.orders S ON T.id = S.id WHEN NOT MATCHED THEN INSERT ROW",
        "MERGE ds.stage T USING ds.orders S ON T.id = S.id WHEN MATCHED THEN DELETE WHEN NOT MATCHED BY TARGET THEN INSERT ROW;",
    ] {
        let ast::AstStmt::Merge(merge) = first_stmt(src, &*dialect) else {
            panic!("{src}: not a MERGE");
        };
        let row = merge.clauses.iter().find_map(|clause| match &clause.action {
            ast::AstMergeActionKind::InsertRow { insert_span } => Some(*insert_span),
            ast::AstMergeActionKind::DoNothing { .. }
            | ast::AstMergeActionKind::UpdateAllByName { .. }
            | ast::AstMergeActionKind::UpdateSetStar { .. }
            | ast::AstMergeActionKind::UpdateSet { .. }
            | ast::AstMergeActionKind::Delete { .. }
            | ast::AstMergeActionKind::InsertAllByName { .. }
            | ast::AstMergeActionKind::InsertStar { .. }
            | ast::AstMergeActionKind::InsertValues { .. } => None,
        });
        let row = row.map(|s| &src[s.start as usize..s.end as usize]);
        assert_eq!(row, Some("INSERT ROW"), "{src}");
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
        assert!(formatted.contains("INSERT ROW"), "{formatted}");
    }
}

/// A T-SQL rowset function written as an INSERT's target, with or without
/// `INTO`, is the call as written, not a table, and formats keeping every
/// token.
#[test]
fn a_rowset_function_written_as_the_target_is_its_call() {
    let dialect = mssql();
    let config = lexega_syntax::FormatterConfig {
        dialect: dialect.clone(),
        ..Default::default()
    };
    for (src, target) in [
        (
            "INSERT OPENQUERY(LinkedSrv, 'SELECT Id, V FROM remote.t') VALUES (1, 'a')",
            "OPENQUERY(LinkedSrv, 'SELECT Id, V FROM remote.t')",
        ),
        (
            "INSERT INTO OPENQUERY(LinkedSrv, 'SELECT Id FROM remote.t') SELECT Id FROM dbo.t",
            "OPENQUERY(LinkedSrv, 'SELECT Id FROM remote.t')",
        ),
        (
            "INSERT OPENROWSET('SQLNCLI', 'Server=s;Trusted_Connection=yes;', 'SELECT Id FROM db.dbo.t') SELECT Id FROM dbo.t",
            "OPENROWSET('SQLNCLI', 'Server=s;Trusted_Connection=yes;', 'SELECT Id FROM db.dbo.t')",
        ),
        (
            "INSERT INTO OPENDATASOURCE('SQLNCLI', 'Data Source=s;Integrated Security=SSPI').db.dbo.t (Id) VALUES (1)",
            "OPENDATASOURCE('SQLNCLI', 'Data Source=s;Integrated Security=SSPI').db.dbo.t",
        ),
    ] {
        let ast::AstStmt::Insert(insert) = first_stmt(src, &*dialect) else {
            panic!("{src}: not an INSERT");
        };
        let name = insert.target_table.as_ref().expect("a target");
        assert_eq!(
            &src[name.span.start as usize..name.span.end as usize],
            target,
            "{src}"
        );
        assert_eq!(name.name_kind, ast::AstTableNameKind::Rowset, "{src}");
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    }
    // A table named like one, with its schema, is a table.
    let ast::AstStmt::Insert(insert) =
        first_stmt("INSERT INTO dbo.openquery (a) VALUES (1)", &*dialect)
    else {
        panic!("not an INSERT");
    };
    assert_eq!(
        insert.target_table.map(|t| t.name_kind),
        Some(ast::AstTableNameKind::Catalog)
    );
}

// DELETE leaves out FROM only where the dialect allows it, and a target with
// an alias there is followed by WHERE: prose that starts with "delete" is no
// statement.
#[test]
fn delete_without_from_is_read_only_where_the_dialect_allows_it() {
    use lexega_syntax::dialect::{bigquery, postgres};
    let is_delete = |src: &str, d: &dyn lexega_syntax::dialect::Dialect| {
        parse_sql_with_dialect(src, d)
            .map(|script| matches!(script.stmts.first(), Some(ast::AstStmt::Delete(_))))
            .unwrap_or(false)
    };
    for d in [postgres(), bigquery(), mssql()] {
        assert!(!is_delete("Delete old files", &*d), "{}", d.name());
        assert!(is_delete("DELETE FROM t WHERE a = 1", &*d), "{}", d.name());
    }
    assert!(!is_delete("DELETE t WHERE a = 1", &*postgres()));
    assert!(is_delete("DELETE ds.t x WHERE x.a = 1", &*bigquery()));
    assert!(is_delete("DELETE t WHERE a = 1", &*mssql()));
}
