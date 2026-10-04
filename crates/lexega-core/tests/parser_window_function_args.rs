// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for window function argument validation based on Snowflake documentation
///
/// Key differences per Snowflake docs:
/// - ROW_NUMBER(): No arguments (must be empty parentheses)
/// - NTILE(n): Requires exactly one positive integer argument
/// - RANK(), DENSE_RANK(), PERCENT_RANK(), CUME_DIST(): No arguments
/// - LAG(expr [, offset [, default]]): 1 to 3 arguments
/// - LEAD(expr [, offset [, default]]): 1 to 3 arguments
/// - FIRST_VALUE(expr), LAST_VALUE(expr): Exactly 1 argument
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

// ============================================================================
// ROW_NUMBER() - No arguments allowed
// ============================================================================

#[test]
fn test_row_number_no_args() {
    let src = "SELECT ROW_NUMBER() OVER (ORDER BY id) FROM t";

    let script = parse_sql(src).expect("ROW_NUMBER() should parse");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 0, "ROW_NUMBER should have no arguments");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_row_number_with_partition_and_order() {
    let src =
        "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) AS row_num FROM emp";

    let script = parse_sql(src).expect("ROW_NUMBER with PARTITION BY should parse");
    assert_eq!(script.stmts.len(), 1);

    // Validate the window spec
    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { window, .. } => {
                        assert_eq!(
                            window.partition_by.len(),
                            1,
                            "Should have 1 PARTITION BY column"
                        );
                        assert_eq!(window.order_by.len(), 1, "Should have 1 ORDER BY column");
                        assert_eq!(window.order_by[0].asc, Some(false), "Should be DESC");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

// ============================================================================
// NTILE(n) - Requires exactly one constant argument
// ============================================================================

#[test]
fn test_ntile_with_constant() {
    let src = "SELECT NTILE(4) OVER (ORDER BY shares) FROM trades";

    let script = parse_sql(src).expect("NTILE(4) should parse");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "NTILE should have exactly 1 argument");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_ntile_various_bucket_sizes() {
    let test_cases = vec![
        ("SELECT NTILE(2) OVER (ORDER BY id) FROM t", 2),
        ("SELECT NTILE(3) OVER (ORDER BY id) FROM t", 3),
        ("SELECT NTILE(4) OVER (ORDER BY id) FROM t", 4),
        ("SELECT NTILE(10) OVER (ORDER BY id) FROM t", 10),
        ("SELECT NTILE(100) OVER (ORDER BY id) FROM t", 100),
    ];

    for (sql, expected_buckets) in test_cases {
        let script = parse_sql(sql).expect(&format!("NTILE({}) should parse", expected_buckets));
        assert_eq!(script.stmts.len(), 1);
    }
}

#[test]
fn test_ntile_with_partition_and_order() {
    let src =
        "SELECT NTILE(4) OVER (PARTITION BY exchange ORDER BY shares) AS quartile FROM trades";

    let script = parse_sql(src).expect("NTILE with PARTITION BY should parse");
    assert_eq!(script.stmts.len(), 1);

    // Validate AST structure
    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, window, .. } => {
                        assert_eq!(args.len(), 1, "NTILE should have 1 argument");
                        assert_eq!(window.partition_by.len(), 1, "Should have 1 PARTITION BY");
                        assert_eq!(window.order_by.len(), 1, "Should have 1 ORDER BY");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

// ============================================================================
// RANK() and DENSE_RANK() - No arguments
// ============================================================================

#[test]
fn test_rank_no_args() {
    let src = "SELECT RANK() OVER (ORDER BY salary DESC) FROM employees";

    let script = parse_sql(src).expect("RANK() should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 0, "RANK should have no arguments");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_dense_rank_no_args() {
    let src = "SELECT DENSE_RANK() OVER (ORDER BY score DESC) FROM scores";

    let script = parse_sql(src).expect("DENSE_RANK() should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 0, "DENSE_RANK should have no arguments");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

// ============================================================================
// LAG() and LEAD() - 1 to 3 arguments
// ============================================================================

#[test]
fn test_lag_one_arg() {
    let src = "SELECT LAG(price) OVER (ORDER BY date) FROM stock_prices";

    let script = parse_sql(src).expect("LAG with 1 arg should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "LAG should have 1 argument");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_lag_two_args() {
    let src = "SELECT LAG(price, 1) OVER (ORDER BY date) FROM stock_prices";

    let script = parse_sql(src).expect("LAG with 2 args should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 2, "LAG should have 2 arguments");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_lag_three_args() {
    let src = "SELECT LAG(price, 1, 0) OVER (ORDER BY date) FROM stock_prices";

    let script = parse_sql(src).expect("LAG with 3 args should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 3, "LAG should have 3 arguments");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_lead_one_arg() {
    let src = "SELECT LEAD(price) OVER (ORDER BY date) FROM stock_prices";

    let script = parse_sql(src).expect("LEAD with 1 arg should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "LEAD should have 1 argument");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_lead_two_args() {
    let src = "SELECT LEAD(price, 1) OVER (ORDER BY date) FROM stock_prices";

    let script = parse_sql(src).expect("LEAD with 2 args should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 2, "LEAD should have 2 arguments");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_lead_three_args() {
    let src = "SELECT LEAD(price, 1, 0) OVER (ORDER BY date) FROM stock_prices";

    let script = parse_sql(src).expect("LEAD with 3 args should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 3, "LEAD should have 3 arguments");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

// ============================================================================
// FIRST_VALUE() and LAST_VALUE() - Exactly 1 argument
// ============================================================================

#[test]
fn test_first_value_one_arg() {
    let src = "SELECT FIRST_VALUE(price) OVER (PARTITION BY product_id ORDER BY date) FROM prices";

    let script = parse_sql(src).expect("FIRST_VALUE with 1 arg should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "FIRST_VALUE should have 1 argument");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_last_value_one_arg() {
    let src = "SELECT LAST_VALUE(price) OVER (PARTITION BY product_id ORDER BY date) FROM prices";

    let script = parse_sql(src).expect("LAST_VALUE with 1 arg should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "LAST_VALUE should have 1 argument");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

// ============================================================================
// Aggregate functions with OVER - SUM, AVG, COUNT, etc.
// ============================================================================

#[test]
fn test_sum_over_with_one_arg() {
    let src = "SELECT SUM(amount) OVER (PARTITION BY customer_id ORDER BY date) FROM orders";

    let script = parse_sql(src).expect("SUM OVER should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "SUM should have 1 argument");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_avg_over_with_one_arg() {
    let src = "SELECT AVG(salary) OVER (PARTITION BY department) FROM employees";

    let script = parse_sql(src).expect("AVG OVER should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "AVG should have 1 argument");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

#[test]
fn test_count_star_over() {
    let src = "SELECT COUNT(*) OVER (PARTITION BY category) FROM products";

    let script = parse_sql(src).expect("COUNT(*) OVER should parse");

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                match &as_select_item(&cols[0]).expr {
                    AstExpr::WindowFn { args, .. } => {
                        assert_eq!(args.len(), 1, "COUNT(*) should have 1 argument (the *)");
                    }
                    _ => panic!("expected WindowFn"),
                }
            }
            _ => panic!("expected columns"),
        },
        _ => panic!("expected SELECT"),
    }
}

// ============================================================================
// Snowflake documentation examples
// ============================================================================

#[test]
fn test_snowflake_doc_examples() {
    // From NTILE documentation
    let ntile_example = r#"
SELECT
    exchange,
    symbol,
    NTILE(4) OVER (PARTITION BY exchange ORDER BY shares) AS ntile_4
FROM trades
ORDER BY exchange, ntile_4
"#;

    let script = parse_sql(ntile_example).expect("NTILE doc example should parse");
    assert_eq!(script.stmts.len(), 1);

    // From ROW_NUMBER documentation
    let row_number_example = r#"
SELECT
    symbol,
    exchange,
    shares,
    ROW_NUMBER() OVER (PARTITION BY exchange ORDER BY shares) AS row_number
FROM trades
"#;

    let script = parse_sql(row_number_example).expect("ROW_NUMBER doc example should parse");
    assert_eq!(script.stmts.len(), 1);
}
