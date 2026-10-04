// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::{
    ast::{AstExpr, AstSelectItem, AstStmt, ProjectionItemKind},
    parse_sql,
};

// Helper to unwrap ProjectionItem to SelectItem for tests
fn as_select_item(item: &lexega_core::ast::ProjectionItem) -> &AstSelectItem {
    match &item.kind {
        ProjectionItemKind::SelectItem(s) => s,
        _ => panic!("Expected SelectItem in projection"),
    }
}

#[test]
fn test_row_number_basic() {
    let src = "SELECT ROW_NUMBER() OVER (ORDER BY id) AS row_num FROM users";
    let script = parse_sql(src).expect("failed to parse ROW_NUMBER() OVER");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => {
            match &sel.projection.kind {
                lexega_core::ast::AstProjectionKind::Columns(cols) => {
                    assert_eq!(cols.len(), 1);
                    match &as_select_item(&cols[0]).expr {
                        AstExpr::WindowFn { .. } => {
                            // Successfully parsed as window function
                        }
                        _ => panic!("expected WindowFn for ROW_NUMBER() OVER"),
                    }
                }
                _ => panic!("expected column projection"),
            }
        }
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_partition_by_single_column() {
    let src =
        "SELECT RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS rank FROM employees";
    let script =
        parse_sql(src).expect("failed to parse window function with PARTITION BY and DESC");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => {
            match &sel.projection.kind {
                lexega_core::ast::AstProjectionKind::Columns(cols) => {
                    assert_eq!(cols.len(), 1);
                    match &as_select_item(&cols[0]).expr {
                        AstExpr::WindowFn { window, .. } => {
                            assert_eq!(window.partition_by.len(), 1);
                            assert_eq!(window.order_by.len(), 1);
                            // Verify DESC was parsed correctly
                            assert_eq!(
                                window.order_by[0].asc,
                                Some(false),
                                "Expected DESC to set asc=false"
                            );
                        }
                        _ => panic!("expected WindowFn"),
                    }
                }
                _ => panic!("expected column projection"),
            }
        }
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_partition_by_multiple_columns() {
    let src =
        "SELECT RANK() OVER (PARTITION BY department, location ORDER BY salary) FROM employees";

    let script = parse_sql(src).expect("failed to parse PARTITION BY multiple columns");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                assert_eq!(cols.len(), 1);
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { window, .. } => {
                        assert_eq!(window.partition_by.len(), 2);
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected column projection"),
        },
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_sum_over_window() {
    let src = "SELECT SUM(amount) OVER (PARTITION BY customer_id ORDER BY order_date) AS running_total FROM orders";

    let script = parse_sql(src).expect("failed to parse SUM OVER");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                assert_eq!(cols.len(), 1);
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1);
                    }
                    _ => panic!("expected WindowFn for SUM OVER"),
                }
            }
            _ => panic!("expected column projection"),
        },
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_avg_over_window() {
    let src = "SELECT AVG(salary) OVER (PARTITION BY department) AS dept_avg FROM employees";

    let script = parse_sql(src).expect("failed to parse AVG OVER");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_count_over_window() {
    let src = "SELECT COUNT(*) OVER (PARTITION BY category) AS category_count FROM products";

    let script = parse_sql(src).expect("failed to parse COUNT(*) OVER");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_dense_rank() {
    let src = "SELECT DENSE_RANK() OVER (ORDER BY score DESC) AS rank FROM scores";

    let script = parse_sql(src).expect("failed to parse DENSE_RANK");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_lag_function() {
    let src = "SELECT LAG(price, 1) OVER (ORDER BY date) AS prev_price FROM stock_prices";

    let script = parse_sql(src).expect("failed to parse LAG");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => {
            match &sel.projection.kind {
                lexega_core::ast::AstProjectionKind::Columns(cols) => {
                    assert_eq!(cols.len(), 1);
                    match &as_select_item(&cols[0]).expr {
                        AstExpr::WindowFn { args, .. } => {
                            assert_eq!(args.len(), 2); // LAG(price, 1)
                        }
                        _ => panic!("expected WindowFn for LAG"),
                    }
                }
                _ => panic!("expected column projection"),
            }
        }
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_lead_function() {
    let src = "SELECT LEAD(price, 1, 0) OVER (ORDER BY date) AS next_price FROM stock_prices";

    let script = parse_sql(src).expect("failed to parse LEAD");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_first_value() {
    let src = "SELECT FIRST_VALUE(price) OVER (PARTITION BY product_id ORDER BY date) FROM prices";

    let script = parse_sql(src).expect("failed to parse FIRST_VALUE");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_last_value() {
    let src = "SELECT LAST_VALUE(price) OVER (PARTITION BY product_id ORDER BY date) FROM prices";

    let script = parse_sql(src).expect("failed to parse LAST_VALUE");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_window_frame_rows() {
    let src = "SELECT SUM(amount) OVER (ORDER BY date ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM transactions";

    let script = parse_sql(src).expect("failed to parse ROWS frame");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                assert_eq!(cols.len(), 1);
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { window, .. } => {
                        assert!(window.frame.is_some(), "expected window frame");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected column projection"),
        },
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_multiple_window_functions() {
    let src = r#"
SELECT 
    ROW_NUMBER() OVER (ORDER BY id) AS row_num,
    RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS rank,
    SUM(salary) OVER (PARTITION BY department) AS dept_total
FROM employees
"#;

    let script = parse_sql(src).expect("failed to parse multiple window functions");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => {
            match &sel.projection.kind {
                lexega_core::ast::AstProjectionKind::Columns(cols) => {
                    assert_eq!(cols.len(), 3);
                    for col in cols {
                        match &as_select_item(col).expr {
                            AstExpr::WindowFn { .. } => {
                                // All three should be window functions
                            }
                            _ => panic!("expected WindowFn"),
                        }
                    }
                }
                _ => panic!("expected column projection"),
            }
        }
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_window_with_empty_over() {
    let src = "SELECT ROW_NUMBER() OVER () AS row_num FROM users";

    let script = parse_sql(src).expect("failed to parse empty OVER()");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                assert_eq!(cols.len(), 1);
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { window, .. } => {
                        assert_eq!(window.partition_by.len(), 0);
                        assert_eq!(window.order_by.len(), 0);
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected column projection"),
        },
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_ntile_function() {
    let src = "SELECT NTILE(4) OVER (ORDER BY salary DESC) AS quartile FROM employees";

    let script = parse_sql(src).expect("failed to parse NTILE");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_window_in_subquery() {
    let src = r#"
SELECT * FROM (
    SELECT 
        id,
        ROW_NUMBER() OVER (PARTITION BY category ORDER BY price) AS row_num
    FROM products
) WHERE row_num = 1
"#;

    let script = parse_sql(src).expect("failed to parse window in subquery");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_window_with_case_insensitive_keywords() {
    let src = "SELECT row_number() over (partition by dept order by sal) FROM emp";

    let script = parse_sql(src).expect("failed to parse case-insensitive window");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_percent_rank() {
    let src = "SELECT PERCENT_RANK() OVER (ORDER BY score) AS pct_rank FROM scores";

    let script = parse_sql(src).expect("failed to parse PERCENT_RANK");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_cume_dist() {
    let src = "SELECT CUME_DIST() OVER (ORDER BY score) AS cum_dist FROM scores";

    let script = parse_sql(src).expect("failed to parse CUME_DIST");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_window_function_in_cte() {
    let src = r#"
WITH ranked_sales AS (
    SELECT 
        product_id,
        sales_amount,
        ROW_NUMBER() OVER (PARTITION BY product_id ORDER BY sales_date DESC) AS rn
    FROM sales
)
SELECT product_id, sales_amount
FROM ranked_sales
WHERE rn = 1
"#;

    let script = parse_sql(src).expect("failed to parse window in CTE");
    assert_eq!(script.stmts.len(), 1);
}
