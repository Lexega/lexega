// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for CHANGES clause for change tracking metadata
/// Based on Snowflake documentation: https://docs.snowflake.com/en/sql-reference/constructs/changes
use lexega_syntax::{ast, parse_stmt_from_str};

/// Basic CHANGES with DEFAULT information type
#[test]
fn test_changes_default_timestamp() {
    let sql =
        "SELECT * FROM t1 CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01 00:00:00');";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES DEFAULT");

    match stmt {
        ast::AstStmt::Select(select) => {
            assert_eq!(select.from.len(), 1, "Expected one table reference");
            let table_ref = &select.from[0];

            assert!(table_ref.changes.is_some(), "Expected CHANGES clause");
            let changes = table_ref.changes.as_ref().unwrap();

            assert_eq!(changes.information, ast::AstChangesInformation::Default);
            assert!(!changes.at_before.is_before, "Expected AT not BEFORE");
            assert!(matches!(
                changes.at_before.kind,
                ast::AstTimeTravelKind::Timestamp(_)
            ));
            assert!(changes.end.is_none(), "Expected no END clause");
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with APPEND_ONLY information type
#[test]
fn test_changes_append_only_offset() {
    let sql = "SELECT * FROM t1 CHANGES(INFORMATION => APPEND_ONLY) AT(OFFSET => -3600);";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES APPEND_ONLY");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");

            assert_eq!(changes.information, ast::AstChangesInformation::AppendOnly);
            assert!(matches!(
                changes.at_before.kind,
                ast::AstTimeTravelKind::Offset(_)
            ));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with STATEMENT parameter
#[test]
fn test_changes_statement() {
    let sql = "SELECT * FROM t1 CHANGES(INFORMATION => DEFAULT) AT(STATEMENT => '01a3f4e5-8b6c-7d9e-0f1a-2b3c4d5e6f7a');";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with STATEMENT");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");

            assert!(matches!(
                changes.at_before.kind,
                ast::AstTimeTravelKind::Statement(_)
            ));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with STREAM parameter
#[test]
fn test_changes_stream() {
    let sql = "SELECT * FROM t1 CHANGES(INFORMATION => DEFAULT) AT(STREAM => 'my_stream');";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with STREAM");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");

            assert!(matches!(
                changes.at_before.kind,
                ast::AstTimeTravelKind::Stream(_)
            ));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with BEFORE clause
#[test]
fn test_changes_before() {
    let sql = "SELECT * FROM t1 CHANGES(INFORMATION => DEFAULT) BEFORE(STATEMENT => 'abc123');";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with BEFORE");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");

            assert!(changes.at_before.is_before, "Expected BEFORE not AT");
            assert!(matches!(
                changes.at_before.kind,
                ast::AstTimeTravelKind::Statement(_)
            ));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with END clause using TIMESTAMP
#[test]
fn test_changes_with_end_timestamp() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => APPEND_ONLY) 
        AT(TIMESTAMP => '2024-01-01 00:00:00')
        END(TIMESTAMP => '2024-01-02 00:00:00');";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with END TIMESTAMP");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");

            assert!(changes.end.is_some(), "Expected END clause");
            let end = changes.end.as_ref().unwrap();
            assert!(matches!(end.kind, ast::AstTimeTravelKind::Timestamp(_)));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with END clause using OFFSET
#[test]
fn test_changes_with_end_offset() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => DEFAULT) 
        AT(TIMESTAMP => '2024-01-01 00:00:00')
        END(OFFSET => -7200);";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with END OFFSET");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");

            let end = changes.end.as_ref().expect("Expected END clause");
            assert!(matches!(end.kind, ast::AstTimeTravelKind::Offset(_)));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with END clause using STATEMENT
#[test]
fn test_changes_with_end_statement() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => DEFAULT) 
        AT(TIMESTAMP => '2024-01-01 00:00:00')
        END(STATEMENT => 'query-id-123');";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with END STATEMENT");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");

            let end = changes.end.as_ref().expect("Expected END clause");
            assert!(matches!(end.kind, ast::AstTimeTravelKind::Statement(_)));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES combined with table alias
#[test]
fn test_changes_with_alias() {
    let sql = "SELECT * FROM t1 CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01') AS changes_data;";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with alias");

    match stmt {
        ast::AstStmt::Select(select) => {
            let table_ref = &select.from[0];

            assert!(table_ref.changes.is_some(), "Expected CHANGES clause");
            assert!(table_ref.alias.is_some(), "Expected table alias");
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES combined with WHERE clause
#[test]
fn test_changes_with_where() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => APPEND_ONLY) 
        AT(TIMESTAMP => '2024-01-01')
        WHERE METADATA$ACTION = 'INSERT';";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with WHERE");

    match stmt {
        ast::AstStmt::Select(select) => {
            assert!(select.from[0].changes.is_some(), "Expected CHANGES clause");
            assert!(select.where_clause.is_some(), "Expected WHERE clause");
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with complex timestamp expression
#[test]
fn test_changes_timestamp_expression() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => DEFAULT) 
        AT(TIMESTAMP => DATEADD(hour, -1, CURRENT_TIMESTAMP()));";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with timestamp expression");

    match stmt {
        ast::AstStmt::Select(select) => {
            assert!(select.from[0].changes.is_some(), "Expected CHANGES clause");
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// Test JOIN with CHANGES on first table
#[test]
fn test_changes_with_join() {
    let sql = "SELECT * FROM 
        t1 CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01')
        JOIN t2 ON t1.id = t2.id;";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with JOIN");

    match stmt {
        ast::AstStmt::Select(select) => {
            assert_eq!(select.from.len(), 1, "Expected one base table in FROM");
            let table_ref = &select.from[0];

            // Verify CHANGES clause
            assert!(
                table_ref.changes.is_some(),
                "Expected CHANGES on first table"
            );
            let changes = table_ref.changes.as_ref().unwrap();
            assert!(matches!(
                changes.information,
                ast::AstChangesInformation::Default
            ));

            // Verify JOIN is attached to the base table
            assert_eq!(table_ref.joins.len(), 1, "Expected one JOIN on base table");
            let join = &table_ref.joins[0];
            assert!(matches!(join.kind, ast::AstJoinKind::Inner));
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// Verify CHANGES and time travel are mutually exclusive
#[test]
fn test_changes_not_with_time_travel() {
    let sql = "SELECT * FROM t1 CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01');";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse");

    match stmt {
        ast::AstStmt::Select(select) => {
            let table_ref = &select.from[0];

            // Should have CHANGES but not standalone time_travel
            assert!(table_ref.changes.is_some(), "Expected CHANGES clause");
            assert!(
                table_ref.time_travel.is_none(),
                "Should not have separate time_travel when CHANGES present"
            );
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES in CTE
#[test]
fn test_changes_in_cte() {
    let sql = "WITH changes_cte AS (
        SELECT * FROM t1 
        CHANGES(INFORMATION => DEFAULT) 
        AT(TIMESTAMP => '2024-01-01')
    )
    SELECT * FROM changes_cte;";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES in CTE");

    match stmt {
        ast::AstStmt::Select(select) => {
            let with_clause = select.with_clause.as_ref().expect("Expected WITH clause");
            assert!(!with_clause.ctes.is_empty(), "Expected CTEs");
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with session variable for timestamp
#[test]
fn test_changes_with_variable() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => DEFAULT) 
        AT(TIMESTAMP => $start_time)
        END(TIMESTAMP => $end_time);";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES with variables");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");
            assert!(changes.end.is_some(), "Expected END clause");
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES from Snowflake docs example - delta changes
#[test]
fn test_changes_docs_example_delta() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => DEFAULT) 
        AT(TIMESTAMP => $ts1);";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse docs example");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");
            assert_eq!(changes.information, ast::AstChangesInformation::Default);
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES from Snowflake docs example - append only
#[test]
fn test_changes_docs_example_append_only() {
    let sql = "SELECT * FROM t1 
        CHANGES(INFORMATION => APPEND_ONLY) 
        AT(TIMESTAMP => $ts1);";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse docs example");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");
            assert_eq!(changes.information, ast::AstChangesInformation::AppendOnly);
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES with END and specific interval
#[test]
fn test_changes_docs_example_with_end() {
    let sql = "SELECT C1 FROM t1 
        CHANGES(INFORMATION => APPEND_ONLY) 
        AT(TIMESTAMP => $ts1) 
        END(TIMESTAMP => $ts2);";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse docs example with END");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");
            assert!(changes.end.is_some(), "Expected END clause");
        }
        _ => panic!("Expected SELECT statement"),
    }
}

/// CHANGES using STREAM as the AT parameter
#[test]
fn test_changes_at_stream() {
    let sql = "SELECT C1 FROM t1 
        CHANGES(INFORMATION => APPEND_ONLY) 
        AT(STREAM => 's1') 
        END(TIMESTAMP => $ts2);";
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse CHANGES AT STREAM");

    match stmt {
        ast::AstStmt::Select(select) => {
            let changes = select.from[0]
                .changes
                .as_ref()
                .expect("Expected CHANGES clause");
            assert!(matches!(
                changes.at_before.kind,
                ast::AstTimeTravelKind::Stream(_)
            ));
            assert!(changes.end.is_some(), "Expected END clause");
        }
        _ => panic!("Expected SELECT statement"),
    }
}
