// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{ast, parse_stmt_from_str};

/// Helper function to parse and extract SELECT statement
fn parse_select(sql: &str) -> ast::AstSelect {
    match parse_stmt_from_str(sql) {
        Some(ast::AstStmt::Select(select)) => select.as_ref().clone(),
        _ => panic!("Failed to parse as SELECT: {}", sql),
    }
}

// ============================================================================
// PIVOT Tests
// ============================================================================

/// Test basic PIVOT with explicit value list
#[test]
fn test_pivot_explicit_values() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN ('2023_Q1', '2023_Q2', '2023_Q3'))
        ORDER BY empid;";
    let select = parse_select(sql);

    assert_eq!(select.from.len(), 1, "Expected one table in FROM");
    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some(), "Expected PIVOT clause");

    let pivot = table_ref.pivot.as_ref().unwrap();
    match &pivot.in_values {
        ast::AstPivotInValues::ValueList(values) => {
            assert_eq!(values.len(), 3, "Expected 3 pivot values");
        }
        _ => panic!("Expected ValueList in PIVOT IN clause"),
    }
}

/// Test PIVOT with aliases for values
#[test]
fn test_pivot_values_with_aliases() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN (
            '2023_Q1' AS q1,
            '2023_Q2' AS q2,
            '2023_Q3' AS q3,
            '2023_Q4' AS q4))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());

    let pivot = table_ref.pivot.as_ref().unwrap();
    match &pivot.in_values {
        ast::AstPivotInValues::ValueList(values) => {
            assert_eq!(values.len(), 4);
            assert!(values[0].alias.is_some(), "Expected alias for first value");
        }
        _ => panic!("Expected ValueList"),
    }
}

/// Test dynamic PIVOT with ANY
#[test]
fn test_pivot_any() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN (ANY))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());

    let pivot = table_ref.pivot.as_ref().unwrap();
    match &pivot.in_values {
        ast::AstPivotInValues::Any(order_by) => {
            assert!(order_by.is_none(), "Expected no ORDER BY");
        }
        _ => panic!("Expected ANY in PIVOT IN clause"),
    }
}

/// Test dynamic PIVOT with ANY and ORDER BY
#[test]
fn test_pivot_any_with_order_by() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN (ANY ORDER BY quarter))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());

    let pivot = table_ref.pivot.as_ref().unwrap();
    match &pivot.in_values {
        ast::AstPivotInValues::Any(order_by) => {
            assert!(order_by.is_some(), "Expected ORDER BY clause");
            assert!(
                order_by.as_ref().unwrap().len() > 0,
                "Expected ORDER BY items"
            );
        }
        _ => panic!("Expected ANY in PIVOT IN clause"),
    }
}

/// Test PIVOT with subquery
#[test]
fn test_pivot_subquery() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN (
            SELECT DISTINCT quarter
            FROM ad_campaign_types_by_quarter
            WHERE television = TRUE
            ORDER BY quarter))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());

    let pivot = table_ref.pivot.as_ref().unwrap();
    match &pivot.in_values {
        ast::AstPivotInValues::Subquery(_) => {
            // Successfully parsed subquery
        }
        _ => panic!("Expected Subquery in PIVOT IN clause"),
    }
}

/// Test PIVOT with aggregate alias
#[test]
fn test_pivot_aggregate_alias() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) AS total FOR quarter IN (ANY ORDER BY quarter))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());

    let pivot = table_ref.pivot.as_ref().unwrap();
    assert!(
        !pivot.aggregates.is_empty(),
        "Expected at least one aggregate"
    );
    assert!(
        pivot.aggregates[0].alias.is_some(),
        "Expected aggregate alias"
    );
}

/// Test PIVOT with DEFAULT ON NULL
#[test]
fn test_pivot_default_on_null() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN (ANY ORDER BY quarter)
            DEFAULT ON NULL (0))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());

    let pivot = table_ref.pivot.as_ref().unwrap();
    assert!(
        pivot.default_on_null.is_some(),
        "Expected DEFAULT ON NULL clause"
    );
}

/// Test PIVOT with DEFAULT ON NULL and explicit values
#[test]
fn test_pivot_default_on_null_explicit_values() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount)
            FOR quarter IN ('2023_Q1', '2023_Q2')
            DEFAULT ON NULL (0))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());

    let pivot = table_ref.pivot.as_ref().unwrap();
    assert!(pivot.default_on_null.is_some());
    match &pivot.in_values {
        ast::AstPivotInValues::ValueList(values) => {
            assert_eq!(values.len(), 2);
        }
        _ => panic!("Expected ValueList"),
    }
}

/// Test PIVOT with table alias
#[test]
fn test_pivot_with_alias() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN ('2023_Q1', '2023_Q2')) AS pivoted
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());
    assert!(table_ref.result_alias.is_some(), "Expected table alias");
}

/// Test PIVOT on subquery
#[test]
fn test_pivot_on_subquery() {
    let sql = "SELECT * FROM (SELECT * FROM quarterly_sales)
        PIVOT(SUM(amount) FOR quarter IN (ANY ORDER BY quarter))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.subquery.is_some(), "Expected subquery");
    assert!(table_ref.pivot.is_some(), "Expected PIVOT after subquery");
}

/// Test PIVOT in CTE
#[test]
fn test_pivot_in_cte() {
    let sql = "WITH pivoted AS (
        SELECT * FROM quarterly_sales
            PIVOT(SUM(amount) FOR quarter IN (ANY ORDER BY quarter))
    )
    SELECT * FROM pivoted ORDER BY empid;";
    let select = parse_select(sql);

    assert!(select.with_clause.is_some(), "Expected WITH clause");
}

/// Test Snowflake doc example: Dynamic pivot
#[test]
fn test_pivot_docs_example_dynamic() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN (ANY ORDER BY quarter))
        ORDER BY empid;";
    let select = parse_select(sql);
    assert!(select.from[0].pivot.is_some());
}

/// Test Snowflake doc example: Pivot with specific columns
#[test]
fn test_pivot_docs_example_specific_columns() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN (
            '2023_Q1',
            '2023_Q2',
            '2023_Q3',
            '2023_Q4'))
        ORDER BY empid;";
    let select = parse_select(sql);
    assert!(select.from[0].pivot.is_some());
}

// ============================================================================
// UNPIVOT Tests
// ============================================================================

/// Test basic UNPIVOT
#[test]
fn test_unpivot_basic() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT (sales FOR month IN (jan, feb, mar, apr))
        ORDER BY empid;";
    let select = parse_select(sql);

    assert_eq!(select.from.len(), 1);
    let table_ref = &select.from[0];
    assert!(table_ref.unpivot.is_some(), "Expected UNPIVOT clause");

    let unpivot = table_ref.unpivot.as_ref().unwrap();
    assert_eq!(unpivot.columns.len(), 4, "Expected 4 columns to unpivot");
    assert!(!unpivot.include_nulls, "Expected EXCLUDE NULLS (default)");
}

/// Test UNPIVOT with aliases
#[test]
fn test_unpivot_with_aliases() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT (sales FOR month IN (
            jan AS january,
            feb AS february,
            mar AS march,
            apr AS april)
        )
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.unpivot.is_some());

    let unpivot = table_ref.unpivot.as_ref().unwrap();
    assert_eq!(unpivot.columns.len(), 4);
    assert!(
        unpivot.columns[0].alias.is_some(),
        "Expected alias for first column"
    );
    assert!(
        unpivot.columns[1].alias.is_some(),
        "Expected alias for second column"
    );
}

/// Test UNPIVOT with INCLUDE NULLS
#[test]
fn test_unpivot_include_nulls() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT INCLUDE NULLS (sales FOR month IN (jan, feb, mar, apr))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.unpivot.is_some());

    let unpivot = table_ref.unpivot.as_ref().unwrap();
    assert!(unpivot.include_nulls, "Expected INCLUDE NULLS");
}

/// Test UNPIVOT with EXCLUDE NULLS (explicit)
#[test]
fn test_unpivot_exclude_nulls() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT EXCLUDE NULLS (sales FOR month IN (jan, feb, mar, apr))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.unpivot.is_some());

    let unpivot = table_ref.unpivot.as_ref().unwrap();
    assert!(!unpivot.include_nulls, "Expected EXCLUDE NULLS");
}

/// Test UNPIVOT with specific columns in SELECT
#[test]
fn test_unpivot_specific_columns_in_select() {
    let sql = "SELECT dept, month, sales FROM monthly_sales
        UNPIVOT INCLUDE NULLS (sales FOR month IN (jan, feb, mar, apr))
        ORDER BY dept;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.unpivot.is_some());
}

/// Test UNPIVOT with table alias
#[test]
fn test_unpivot_with_alias() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT (sales FOR month IN (jan, feb, mar, apr)) AS unpivoted
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.unpivot.is_some());
    assert!(table_ref.result_alias.is_some(), "Expected table alias");
}

/// Test UNPIVOT on subquery
#[test]
fn test_unpivot_on_subquery() {
    let sql = "SELECT * FROM (SELECT * FROM monthly_sales)
        UNPIVOT (sales FOR month IN (jan, feb, mar, apr))
        ORDER BY empid;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.subquery.is_some(), "Expected subquery");
    assert!(
        table_ref.unpivot.is_some(),
        "Expected UNPIVOT after subquery"
    );
}

/// Test Snowflake doc example: Basic UNPIVOT
#[test]
fn test_unpivot_docs_example_basic() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT (sales FOR month IN (jan, feb, mar, apr))
        ORDER BY empid;";
    let select = parse_select(sql);
    assert!(select.from[0].unpivot.is_some());
}

/// Test Snowflake doc example: UNPIVOT with INCLUDE NULLS
#[test]
fn test_unpivot_docs_example_include_nulls() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT INCLUDE NULLS (sales FOR month IN (jan, feb, mar, apr))
        ORDER BY empid;";
    let select = parse_select(sql);
    assert!(select.from[0].unpivot.as_ref().unwrap().include_nulls);
}

// ============================================================================
// Integration Tests - PIVOT and UNPIVOT together
// ============================================================================

/// Test that PIVOT and UNPIVOT are mutually exclusive
#[test]
fn test_pivot_not_with_unpivot() {
    // Can have PIVOT
    let sql1 = "SELECT * FROM t PIVOT(SUM(amount) FOR quarter IN (ANY));";
    let select1 = parse_select(sql1);
    assert!(select1.from[0].pivot.is_some());
    assert!(select1.from[0].unpivot.is_none());

    // Can have UNPIVOT
    let sql2 = "SELECT * FROM t UNPIVOT (sales FOR month IN (jan, feb));";
    let select2 = parse_select(sql2);
    assert!(select2.from[0].pivot.is_none());
    assert!(select2.from[0].unpivot.is_some());
}

/// Test PIVOT with WHERE clause
#[test]
fn test_pivot_with_where() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN ('2023_Q1', '2023_Q2'))
        WHERE empid > 1
        ORDER BY empid;";
    let select = parse_select(sql);

    assert!(select.from[0].pivot.is_some());
    assert!(select.where_clause.is_some(), "Expected WHERE clause");
}

/// Test UNPIVOT with WHERE clause
#[test]
fn test_unpivot_with_where() {
    let sql = "SELECT * FROM monthly_sales
        UNPIVOT (sales FOR month IN (jan, feb, mar, apr))
        WHERE empid > 1
        ORDER BY empid;";
    let select = parse_select(sql);

    assert!(select.from[0].unpivot.is_some());
    assert!(select.where_clause.is_some());
}

/// Test PIVOT with JOIN
#[test]
fn test_pivot_with_join() {
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(SUM(amount) FOR quarter IN ('2023_Q1', '2023_Q2'))
        JOIN employees ON quarterly_sales.empid = employees.id;";
    let select = parse_select(sql);

    let table_ref = &select.from[0];
    assert!(table_ref.pivot.is_some());
    assert_eq!(table_ref.joins.len(), 1, "Expected one JOIN");
}

/// Test PIVOT with multiple aggregations using different tables (simulated)
#[test]
fn test_pivot_multiple_aggregations_pattern() {
    // Test that PIVOT works in a query pattern that would be used for multiple aggregations
    let sql = "SELECT * FROM quarterly_sales
        PIVOT(AVG(amount) FOR quarter IN (ANY ORDER BY quarter));";
    let select = parse_select(sql);
    assert!(select.from[0].pivot.is_some());
}
