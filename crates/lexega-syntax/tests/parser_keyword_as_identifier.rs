// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test that reserved keywords can be used as identifiers when double-quoted
//! Based on Snowflake documentation on identifiers

use lexega_syntax::{ast::*, parse_stmt_from_str};

// Helper to unwrap ProjectionItem to SelectItem for tests
fn as_select_item(item: &ProjectionItem) -> &AstSelectItem {
    match &item.kind {
        ProjectionItemKind::SelectItem(s) => s,
        _ => panic!("Expected SelectItem in projection"),
    }
}

fn parse_select(sql: &str) -> AstSelect {
    let stmt = parse_stmt_from_str(sql).expect("Failed to parse");
    match stmt {
        AstStmt::Select(select) => select.as_ref().clone(),
        _ => panic!("Expected SELECT statement"),
    }
}

#[test]
fn test_double_quoted_keyword_as_column_alias() {
    // Column alias using a reserved keyword with double quotes
    let sql = r#"SELECT id AS "first", name AS "last" FROM users"#;
    let select = parse_select(sql);

    // Should parse successfully
    match &select.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            assert!(
                as_select_item(&items[0]).alias.is_some(),
                "Expected alias on first column"
            );
            assert!(
                as_select_item(&items[1]).alias.is_some(),
                "Expected alias on second column"
            );
        }
        _ => panic!("Expected column projection"),
    }
}

#[test]
fn test_unquoted_keyword_as_alias_lenient_parser() {
    // Our parser is lenient and accepts unquoted keywords as aliases
    // This is more permissive than strictly necessary but user-friendly
    let sql = "SELECT id AS first, name AS last FROM users";
    let select = parse_select(sql);

    match &select.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
        }
        _ => panic!("Expected column projection"),
    }
}

#[test]
fn test_double_quoted_keyword_as_table_name() {
    // Table name using a reserved keyword with double quotes
    let sql = r#"SELECT * FROM "select""#;
    let select = parse_select(sql);

    assert_eq!(select.from.len(), 1);
}

#[test]
fn test_pivot_with_quoted_keyword_aliases() {
    // PIVOT with double-quoted keyword aliases
    let sql = r#"SELECT * FROM sales PIVOT(SUM(amount) FOR quarter IN ('Q1' AS "first", 'Q2' AS "second"))"#;
    let select = parse_select(sql);

    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].pivot.is_some());

    let pivot = select.from[0].pivot.as_ref().unwrap();
    match &pivot.in_values {
        AstPivotInValues::ValueList(values) => {
            assert_eq!(values.len(), 2);
            assert!(values[0].alias.is_some(), "Expected alias for first value");
            assert!(values[1].alias.is_some(), "Expected alias for second value");
        }
        _ => panic!("Expected value list"),
    }
}

#[test]
fn test_pivot_with_unquoted_keyword_aliases_lenient() {
    // Our lenient parser accepts unquoted keywords as aliases
    let sql =
        "SELECT * FROM sales PIVOT(SUM(amount) FOR quarter IN ('Q1' AS first, 'Q2' AS second))";
    let select = parse_select(sql);

    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].pivot.is_some());

    let pivot = select.from[0].pivot.as_ref().unwrap();
    match &pivot.in_values {
        AstPivotInValues::ValueList(values) => {
            assert_eq!(values.len(), 2);
            assert!(values[0].alias.is_some(), "Expected alias for first value");
            assert!(values[1].alias.is_some(), "Expected alias for second value");
        }
        _ => panic!("Expected value list"),
    }
}

#[test]
fn test_unpivot_with_quoted_keyword_aliases() {
    // UNPIVOT with double-quoted keyword aliases
    let sql = r#"SELECT * FROM data UNPIVOT(value FOR name IN (jan AS "first", feb AS "last"))"#;
    let select = parse_select(sql);

    assert_eq!(select.from.len(), 1);
    assert!(select.from[0].unpivot.is_some());

    let unpivot = select.from[0].unpivot.as_ref().unwrap();
    assert_eq!(unpivot.columns.len(), 2);
    assert!(unpivot.columns[0].alias.is_some());
    assert!(unpivot.columns[1].alias.is_some());
}

#[test]
fn test_non_keyword_identifiers_work_normally() {
    // Non-keyword identifiers should work without quotes
    let sql = "SELECT id AS q1, name AS q2 FROM users";
    let select = parse_select(sql);

    match &select.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
        }
        _ => panic!("Expected column projection"),
    }
}

#[test]
fn test_real_snowflake_query_keyword_as_table_alias() {
    // Real Snowflake query using 'directed' (a keyword) as a table alias
    // This is the actual query that motivated the keyword-as-identifier work
    let sql = r#"
        SELECT 
            directed.menu_item_name
        FROM menu AS directed,
        LATERAL FLATTEN(input => directed.options) obj
    "#;
    let select = parse_select(sql);

    // The key achievement: this parses successfully without errors
    // 'directed' is a keyword (DIRECTED JOIN) but works as a table alias

    // Should parse the FROM clause
    assert!(
        select.from.len() > 0,
        "Expected at least one table in FROM clause"
    );

    // First table should have an alias ('directed')
    assert!(
        select.from[0].alias.is_some(),
        "Expected alias on first table"
    );

    // Projection should have one column (directed.menu_item_name)
    match &select.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1, "Expected one column in projection");
        }
        _ => panic!("Expected column projection"),
    }
}
