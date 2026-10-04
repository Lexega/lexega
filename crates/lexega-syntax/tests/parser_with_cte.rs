// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// WITH clause (Common Table Expressions) tests
// Based on https://docs.snowflake.com/en/sql-reference/constructs/with
use lexega_syntax::ast::{AstStmt, CteItem};
use lexega_syntax::parse_sql;

#[test]
fn test_with_single_cte_basic() {
    // Basic CTE with simple SELECT
    let src = r#"
WITH albums_1976 AS (
    SELECT * FROM music_albums WHERE album_year = 1976
)
SELECT album_name FROM albums_1976 ORDER BY album_name;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse basic WITH clause");

    if let Ok(script) = script {
        assert_eq!(script.stmts.len(), 1);
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 1);
            assert!(
                with_clause.recursive_span.is_none(),
                "should not be recursive"
            );

            if let CteItem::Cte(cte) = &with_clause.ctes[0] {
                let cte_name = &src[cte.name.span.start as usize..cte.name.span.end as usize];
                assert_eq!(cte_name, "albums_1976");
                assert!(cte.column_list.is_empty(), "no column list specified");
            } else {
                panic!("expected regular CTE");
            }
        } else {
            panic!("expected Select statement");
        }
    }
}

#[test]
fn test_with_cte_column_list() {
    // CTE with explicit column list
    let src = r#"
WITH cte1 (col_a, col_b, col_c) AS (
    SELECT id, name, value FROM table1
)
SELECT * FROM cte1;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse CTE with column list");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            if let CteItem::Cte(cte) = &with_clause.ctes[0] {
                assert_eq!(cte.column_list.len(), 3, "should have 3 columns");
            } else {
                panic!("expected regular CTE");
            }
        }
    }
}

#[test]
fn test_with_multiple_ctes() {
    // Multiple CTEs, second CTE references first
    let src = r#"
WITH
    album_info_1976 AS (
        SELECT m.album_ID, m.album_name, b.band_name
        FROM music_albums AS m INNER JOIN music_bands AS b
        WHERE m.band_id = b.band_id AND album_year = 1976
    ),
    journey_album_info_1976 AS (
        SELECT * FROM album_info_1976 WHERE band_name = 'Journey'
    )
SELECT album_name, band_name FROM journey_album_info_1976;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse multiple CTEs");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 2, "should have 2 CTEs");
        }
    }
}

#[test]
fn test_with_recursive_fibonacci() {
    // Recursive CTE for Fibonacci series
    let src = r#"
WITH RECURSIVE current_f (current_val, previous_val) AS (
    SELECT 0, 1
    UNION ALL 
    SELECT current_val + previous_val, current_val 
    FROM current_f
    WHERE current_val + previous_val < 100
)
SELECT current_val FROM current_f ORDER BY current_val;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse recursive CTE");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert!(with_clause.recursive_span.is_some(), "should be RECURSIVE");
            assert_eq!(with_clause.ctes.len(), 1);

            if let CteItem::Cte(cte) = &with_clause.ctes[0] {
                assert_eq!(cte.column_list.len(), 2, "recursive CTE has column list");
            } else {
                panic!("expected regular CTE");
            }
        }
    }
}

#[test]
fn test_with_cte_in_subquery() {
    // CTE query is itself a UNION ALL (common in recursive CTEs)
    let src = r#"
WITH cte AS (
    SELECT id FROM table1
    UNION ALL
    SELECT id FROM table2
)
SELECT * FROM cte;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse CTE with UNION ALL");
}

#[test]
fn test_with_cte_no_recursive_keyword_but_recursive() {
    // RECURSIVE keyword is optional per docs
    let src = r#"
WITH
    numbered (n) AS (
        SELECT 1
        UNION ALL
        SELECT n + 1 FROM numbered WHERE n < 10
    )
SELECT n FROM numbered;
"#;

    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse recursive CTE without RECURSIVE keyword"
    );
}

#[test]
fn test_with_mixed_recursive_and_non_recursive() {
    // Mix of recursive and non-recursive CTEs
    let src = r#"
WITH RECURSIVE
    base_data AS (
        SELECT id, name FROM employees
    ),
    hierarchy (emp_id, manager_id, level) AS (
        SELECT id, manager_id, 1 FROM base_data WHERE manager_id IS NULL
        UNION ALL
        SELECT e.id, e.manager_id, h.level + 1
        FROM base_data e
        JOIN hierarchy h ON e.manager_id = h.emp_id
    )
SELECT * FROM hierarchy;
"#;

    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse mixed recursive/non-recursive CTEs"
    );
}

#[test]
fn test_with_three_ctes() {
    // Three CTEs to test comma-separated list parsing
    let src = r#"
WITH
    cte1 AS (SELECT 1 AS n),
    cte2 AS (SELECT 2 AS n),
    cte3 AS (SELECT 3 AS n)
SELECT * FROM cte1
UNION ALL SELECT * FROM cte2
UNION ALL SELECT * FROM cte3;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse three CTEs");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 3, "should have 3 CTEs");
        }
    }
}

#[test]
fn test_with_cte_aggregation_and_window_functions() {
    // CTE with aggregations and window functions (including SUM...OVER)
    let src = r#"
WITH
    sales_summary AS (
        SELECT 
            region,
            product,
            SUM(amount) AS total_sales,
            AVG(amount) AS avg_sale,
            ROW_NUMBER() OVER (PARTITION BY region ORDER BY SUM(amount) DESC) AS rank
        FROM sales
        GROUP BY region, product
    ),
    top_products AS (
        SELECT * FROM sales_summary WHERE rank <= 3
    )
SELECT 
    region,
    product,
    total_sales,
    ROUND(total_sales / SUM(total_sales) OVER (PARTITION BY region) * 100, 2) AS pct_of_region
FROM top_products
ORDER BY region, rank;
"#;

    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CTE with aggregations and window functions"
    );

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 2, "should have 2 CTEs");
        }
    }
}

#[test]
fn test_with_cte_nested_subqueries() {
    // CTE containing nested subqueries in SELECT list
    let src = r#"
WITH
    customer_orders AS (
        SELECT 
            customer_id,
            order_id,
            order_date,
            quantity
        FROM orders o1
        WHERE order_id IN (
            SELECT order_id FROM order_items WHERE quantity > 5
        )
    ),
    customer_metrics AS (
        SELECT
            customer_id,
            COUNT(order_id) AS order_count,
            SUM(quantity) AS total_quantity
        FROM customer_orders
        GROUP BY customer_id
    )
SELECT 
    cm.customer_id,
    cm.order_count,
    cm.total_quantity
FROM customer_metrics cm
WHERE cm.order_count > 3
ORDER BY cm.order_count DESC
LIMIT 100;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse CTE with nested subqueries");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 2, "should have 2 CTEs");
            assert!(select.where_clause.is_some(), "main query has WHERE");
            assert!(select.order_by.is_some(), "main query has ORDER BY");
            assert!(select.limit.is_some(), "main query has LIMIT");
        }
    }
}

#[test]
fn test_with_recursive_graph_traversal() {
    // Recursive CTE for graph/tree traversal with path tracking
    let src = r#"
WITH RECURSIVE
    path_finder (
        node_id,
        parent_id,
        level,
        path,
        cycle
    ) AS (
        SELECT 
            id,
            parent_id,
            0 AS level,
            ARRAY_CONSTRUCT(id) AS path,
            FALSE AS cycle
        FROM graph_nodes
        WHERE parent_id IS NULL
        
        UNION ALL
        
        SELECT 
            n.id,
            n.parent_id,
            pf.level + 1,
            ARRAY_APPEND(pf.path, n.id),
            ARRAY_CONTAINS(n.id, pf.path) AS cycle
        FROM graph_nodes n
        INNER JOIN path_finder pf ON n.parent_id = pf.node_id
        WHERE pf.level < 10 
        AND NOT pf.cycle
    )
SELECT 
    node_id,
    level,
    ARRAY_TO_STRING(path, ' -> ') AS path_str,
    cycle
FROM path_finder
WHERE NOT cycle
ORDER BY level, node_id;
"#;

    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse recursive graph traversal CTE"
    );

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 1, "should have 1 recursive CTE");
            assert!(with_clause.recursive_span.is_some(), "should be RECURSIVE");

            if let CteItem::Cte(cte) = &with_clause.ctes[0] {
                assert_eq!(cte.column_list.len(), 5, "recursive CTE has 5 columns");
            } else {
                panic!("expected regular CTE");
            }
        }
    }
}

#[test]
fn test_with_cte_lateral_join_and_qualify() {
    // CTE with window functions and QUALIFY clause
    let src = r#"
WITH
    base_events AS (
        SELECT 
            user_id,
            event_type,
            event_timestamp
        FROM events
        WHERE event_date >= '2024-01-01'
    ),
    user_sessions AS (
        SELECT
            user_id,
            event_type,
            event_timestamp,
            ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY event_timestamp) AS row_num
        FROM base_events
        QUALIFY ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY event_timestamp) <= 100
    ),
    session_summary AS (
        SELECT
            user_id,
            MIN(event_timestamp) AS session_start,
            MAX(event_timestamp) AS session_end,
            COUNT(*) AS event_count
        FROM user_sessions
        GROUP BY user_id
    )
SELECT
    ss.user_id,
    ss.session_start,
    ss.event_count
FROM session_summary ss
WHERE ss.event_count >= 3
ORDER BY ss.user_id
OFFSET 10 ROWS FETCH FIRST 50 ROWS ONLY;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse CTE with QUALIFY");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 3, "should have 3 CTEs");
            assert!(select.where_clause.is_some(), "main query has WHERE");
            assert!(select.order_by.is_some(), "main query has ORDER BY");
            assert!(select.offset.is_some(), "main query has OFFSET");
            assert!(select.limit.is_some(), "main query has LIMIT (via FETCH)");
        }
    }
}

#[test]
fn test_with_recursive_bill_of_materials() {
    // Recursive CTE for hierarchical BOM (Bill of Materials)
    let src = r#"
WITH RECURSIVE
    bom_explosion (
        product_id,
        component_id,
        component_name,
        quantity_needed,
        level
    ) AS (
        SELECT
            p.id AS product_id,
            p.id AS component_id,
            p.name AS component_name,
            1 AS quantity_needed,
            0 AS level
        FROM products p
        WHERE p.id = 12345
        
        UNION ALL
        
        SELECT
            bom.product_id,
            c.component_id,
            p.name AS component_name,
            c.quantity * bom.quantity_needed,
            bom.level + 1
        FROM bom_explosion bom
        INNER JOIN components c ON bom.component_id = c.parent_id
        INNER JOIN products p ON c.component_id = p.id
        WHERE bom.level < 20
    )
SELECT
    component_name,
    component_id,
    quantity_needed,
    level
FROM bom_explosion
WHERE level > 0
ORDER BY level, component_id;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse recursive BOM CTE");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert!(with_clause.recursive_span.is_some(), "should be RECURSIVE");

            if let CteItem::Cte(cte) = &with_clause.ctes[0] {
                assert_eq!(cte.column_list.len(), 5, "BOM CTE has 5 columns");
            } else {
                panic!("expected regular CTE");
            }
        }
    }
}

#[test]
fn test_with_cte_pivoting_and_unpivoting() {
    // CTE demonstrating manual pivoting with CASE statements
    let src = r#"
WITH
    monthly_sales AS (
        SELECT
            product_id,
            product_name,
            MONTH(sale_date) AS sale_month,
            SUM(amount) AS monthly_total
        FROM sales
        WHERE YEAR(sale_date) = 2024
        GROUP BY product_id, product_name, MONTH(sale_date)
    ),
    pivoted_sales AS (
        SELECT
            product_id,
            product_name,
            SUM(CASE WHEN sale_month = 1 THEN monthly_total ELSE 0 END) AS jan,
            SUM(CASE WHEN sale_month = 2 THEN monthly_total ELSE 0 END) AS feb,
            SUM(CASE WHEN sale_month = 3 THEN monthly_total ELSE 0 END) AS mar,
            SUM(CASE WHEN sale_month = 4 THEN monthly_total ELSE 0 END) AS apr,
            SUM(CASE WHEN sale_month = 5 THEN monthly_total ELSE 0 END) AS may,
            SUM(CASE WHEN sale_month = 6 THEN monthly_total ELSE 0 END) AS jun,
            SUM(CASE WHEN sale_month = 7 THEN monthly_total ELSE 0 END) AS jul,
            SUM(CASE WHEN sale_month = 8 THEN monthly_total ELSE 0 END) AS aug,
            SUM(CASE WHEN sale_month = 9 THEN monthly_total ELSE 0 END) AS sep,
            SUM(CASE WHEN sale_month = 10 THEN monthly_total ELSE 0 END) AS oct,
            SUM(CASE WHEN sale_month = 11 THEN monthly_total ELSE 0 END) AS nov,
            SUM(CASE WHEN sale_month = 12 THEN monthly_total ELSE 0 END) AS dec
        FROM monthly_sales
        GROUP BY product_id, product_name
    )
SELECT
    product_name,
    jan, feb, mar, apr, may, jun, jul, aug, sep, oct, nov, dec,
    jan + feb + mar + apr + may + jun + jul + aug + sep + oct + nov + dec AS total_year,
    GREATEST(jan, feb, mar, apr, may, jun, jul, aug, sep, oct, nov, dec) AS peak_month_value
FROM pivoted_sales
WHERE jan + feb + mar + apr + may + jun + jul + aug + sep + oct + nov + dec > 10000
ORDER BY total_year DESC;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse pivoting CTE");

    if let Ok(script) = script {
        if let AstStmt::Select(select) = &script.stmts[0] {
            let with_clause = select.with_clause.as_ref().expect("WITH clause");
            assert_eq!(with_clause.ctes.len(), 2, "should have 2 CTEs for pivoting");
        }
    }
}
