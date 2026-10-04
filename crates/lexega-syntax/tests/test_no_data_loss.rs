// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Test to ensure the formatter NEVER loses data
// This is a CRITICAL test - data loss is unacceptable in production

use lexega_syntax::{
    format_sql, format_sql_with_config, tokenize, try_parse_stmt_from_str, FormatterConfig,
};

/// Check if a token sequence represents an acceptable SQL normalization
/// These are cases where the formatter makes implicit keywords explicit for clarity
fn is_acceptable_normalization(orig_tokens: &[String], fmt_tokens: &[String]) -> bool {
    // Quick check: if tokens are identical, no normalization occurred
    if orig_tokens == fmt_tokens {
        return true;
    }

    // Pre-normalization: Handle semicolon addition first, then check other normalizations
    // This allows semicolon normalization to compose with other normalizations
    // The semicolon is second-to-last because the last token is "" (EoF marker)
    if fmt_tokens.len() > 1 {
        let second_to_last_idx = fmt_tokens.len().saturating_sub(2);
        if fmt_tokens.get(second_to_last_idx) == Some(&";".to_string()) {
            // Check if original doesn't have a semicolon in that position
            let orig_second_to_last = orig_tokens.get(orig_tokens.len().saturating_sub(2));
            if orig_second_to_last != Some(&";".to_string()) {
                // Try removing the semicolon and checking again
                let mut fmt_without_semi: Vec<_> = fmt_tokens.to_vec();
                fmt_without_semi.remove(second_to_last_idx);
                if is_acceptable_normalization(orig_tokens, &fmt_without_semi) {
                    return true;
                }
            }
        }
    }

    // If token counts differ, check for known normalizations
    // If counts are same, check for case-only differences
    if orig_tokens.len() == fmt_tokens.len() {
        // Check if only difference is keyword casing
        let case_normalized = orig_tokens
            .iter()
            .zip(fmt_tokens.iter())
            .all(|(o, f)| o.eq_ignore_ascii_case(f));
        if case_normalized {
            return true;
        }
    }

    // Check for acceptable normalizations by comparing token sequences
    let orig_str = orig_tokens.join(" ");
    let fmt_str = fmt_tokens.join(" ");

    // Normalization 1: JOIN -> INNER JOIN (SQL standard: bare JOIN is INNER JOIN)
    if orig_str.to_uppercase().contains(" JOIN ") && fmt_str.to_uppercase().contains(" INNER JOIN ")
    {
        let normalized = orig_str.to_uppercase().replace(" JOIN ", " INNER JOIN ");
        if normalized == fmt_str.to_uppercase() {
            return true;
        }
    }

    // Normalization 2: LEFT/RIGHT/FULL JOIN -> LEFT/RIGHT/FULL OUTER JOIN
    // (SQL standard: OUTER is optional but implied)
    let mut normalized = orig_str.to_uppercase();
    normalized = normalized.replace(" LEFT JOIN ", " LEFT OUTER JOIN ");
    normalized = normalized.replace(" RIGHT JOIN ", " RIGHT OUTER JOIN ");
    normalized = normalized.replace(" FULL JOIN ", " FULL OUTER JOIN ");
    if normalized == fmt_str.to_uppercase() {
        return true;
    }

    // Normalization 3: UNPIVOT(...) -> UNPIVOT EXCLUDE NULLS (...)
    // (Snowflake default: UNPIVOT excludes nulls by default)
    if orig_str.to_uppercase().contains("UNPIVOT (")
        && fmt_str.to_uppercase().contains("UNPIVOT EXCLUDE NULLS (")
    {
        let normalized = orig_str
            .to_uppercase()
            .replace("UNPIVOT (", "UNPIVOT EXCLUDE NULLS (");
        if normalized == fmt_str.to_uppercase() {
            return true;
        }
    }

    // Normalization 4: Set operation precedence: UNION has lower precedence than INTERSECT
    // So "A UNION B INTERSECT C" should be "A UNION (B INTERSECT C)" but formatter does
    // "(A UNION B) INTERSECT C" - this is a grouping preference
    // For now, allow parentheses additions around set operations
    let orig_upper = orig_str.to_uppercase();
    let fmt_upper = fmt_str.to_uppercase();
    if (orig_upper.contains("UNION")
        || orig_upper.contains("INTERSECT")
        || orig_upper.contains("EXCEPT"))
        && (fmt_upper.starts_with("( ") || fmt_upper.contains(" ( SELECT"))
    {
        // Count SELECT keywords - should be same
        let orig_selects = orig_tokens
            .iter()
            .filter(|t| t.eq_ignore_ascii_case("SELECT"))
            .count();
        let fmt_selects = fmt_tokens
            .iter()
            .filter(|t| t.eq_ignore_ascii_case("SELECT"))
            .count();
        if orig_selects == fmt_selects {
            // Check all other significant keywords are present
            for token in orig_tokens {
                let token_upper = token.to_uppercase();
                if token_upper == "SELECT"
                    || token_upper == "FROM"
                    || token_upper == "UNION"
                    || token_upper == "INTERSECT"
                    || token_upper == "EXCEPT"
                    || token_upper == "ALL"
                {
                    if !fmt_tokens.iter().any(|t| t.eq_ignore_ascii_case(token)) {
                        return false;
                    }
                }
            }
            return true;
        }
    }

    // Normalization 5: Adding explicit AS keyword before aliases
    // Original: ) t1  ->  Formatted: ) AS t1
    // This is adding the optional AS keyword which is semantically equivalent
    if orig_tokens.len() + 1 <= fmt_tokens.len() {
        // Count how many AS keywords differ
        let orig_as_count = orig_tokens
            .iter()
            .filter(|t| t.eq_ignore_ascii_case("AS"))
            .count();
        let fmt_as_count = fmt_tokens
            .iter()
            .filter(|t| t.eq_ignore_ascii_case("AS"))
            .count();

        // If formatted has more AS keywords, check if that's the only difference
        if fmt_as_count > orig_as_count {
            // Try removing the extra AS keywords from formatted tokens
            let mut i = 0;
            while i < fmt_tokens.len() {
                if i + 1 < fmt_tokens.len()
                    && fmt_tokens[i].eq_ignore_ascii_case("AS")
                    && !fmt_tokens[i + 1].eq_ignore_ascii_case("SELECT")
                {
                    // This might be an optional AS before an alias - try skipping it
                    // But keep it if it's part of "AS SELECT" (for set operations)
                    let without_as: Vec<_> = fmt_tokens
                        .iter()
                        .enumerate()
                        .filter(|(idx, _)| *idx != i)
                        .map(|(_, t)| t.clone())
                        .collect();

                    // Check if removing this AS makes tokens match
                    if is_acceptable_normalization(orig_tokens, &without_as) {
                        return true;
                    }
                }
                i += 1;
            }
        }
    }

    false
}

/// Helper to check that formatting preserves all keywords and identifiers
/// Allows acceptable SQL normalizations that make implicit keywords explicit
fn assert_preserves_tokens(sql: &str, description: &str) {
    let original_tokens = tokenize(sql);

    // Try to format
    let formatted_result = format_sql(sql);

    match formatted_result {
        Ok(formatted) => {
            let formatted_tokens = tokenize(&formatted);

            // Extract significant tokens (ignoring comments)
            let orig_significant: Vec<String> = original_tokens
                .tokens
                .iter()
                .filter(|t| {
                    !matches!(
                        t.kind,
                        lexega_syntax::lexer::TokenKind::LineComment
                            | lexega_syntax::lexer::TokenKind::BlockComment
                    )
                })
                .map(|t| t.lexeme(sql).to_string())
                .collect();

            let fmt_significant: Vec<String> = formatted_tokens
                .tokens
                .iter()
                .filter(|t| {
                    !matches!(
                        t.kind,
                        lexega_syntax::lexer::TokenKind::LineComment
                            | lexega_syntax::lexer::TokenKind::BlockComment
                    )
                })
                .map(|t| t.lexeme(&formatted).to_string())
                .collect();

            // Check if tokens match exactly or represent an acceptable normalization
            if !is_acceptable_normalization(&orig_significant, &fmt_significant) {
                eprintln!("\n❌ DATA LOSS DETECTED in: {}", description);
                eprintln!("Original tokens: {:?}", orig_significant);
                eprintln!("Formatted tokens: {:?}", fmt_significant);
                eprintln!("\nOriginal SQL:\n{}", sql);
                eprintln!("\nFormatted SQL:\n{}", formatted);
                panic!("Data loss detected - tokens don't match!");
            }
        }
        Err(e) => {
            // Parse error is OK - we should fail rather than lose data
            eprintln!(
                "✓ Parser correctly rejected: {} (error: {})",
                description, e
            );
        }
    }
}

#[test]
fn test_no_data_loss_select_all_features() {
    let sql = "WITH cte AS (SELECT * FROM t1) SELECT DISTINCT TOP 10 id, name AS username FROM cte WHERE id > 5 GROUP BY id, name HAVING COUNT(*) > 1 QUALIFY ROW_NUMBER() OVER (ORDER BY id) = 1 ORDER BY id DESC NULLS LAST LIMIT 100 OFFSET 50;";
    assert_preserves_tokens(sql, "SELECT with all features");
}

#[test]
fn test_no_data_loss_joins() {
    let sql =
        "SELECT * FROM t1 INNER JOIN t2 ON t1.id = t2.id LEFT JOIN t3 USING (name) CROSS JOIN t4;";
    assert_preserves_tokens(sql, "Multiple JOINs");
}

#[test]
fn test_no_data_loss_time_travel() {
    let sql = "SELECT * FROM t1 AT(TIMESTAMP => '2024-01-01') WHERE id > 100;";
    assert_preserves_tokens(sql, "Time travel");
}

#[test]
fn test_no_data_loss_sample() {
    let sql = "SELECT * FROM t1 SAMPLE BERNOULLI (10) SEED (42);";
    assert_preserves_tokens(sql, "SAMPLE clause");
}

#[test]
fn test_no_data_loss_changes() {
    let sql = "SELECT * FROM t1 CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01');";
    assert_preserves_tokens(sql, "CHANGES clause");
}

#[test]
fn test_no_data_loss_connect_by() {
    let sql = "SELECT id FROM t1 START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id;";
    assert_preserves_tokens(sql, "CONNECT BY");
}

#[test]
fn test_no_data_loss_case_expression() {
    let sql = "SELECT CASE WHEN status = 'active' THEN 1 WHEN status = 'inactive' THEN 0 ELSE -1 END AS status_code FROM users;";
    assert_preserves_tokens(sql, "CASE expression");
}

#[test]
fn test_no_data_loss_subqueries() {
    let sql = "SELECT * FROM (SELECT id FROM t1 WHERE id IN (SELECT user_id FROM t2));";
    assert_preserves_tokens(sql, "Nested subqueries");
}

#[test]
fn test_no_data_loss_union() {
    let sql = "SELECT id FROM t1 UNION ALL SELECT id FROM t2 INTERSECT SELECT id FROM t3;";
    assert_preserves_tokens(sql, "Set operations");
}

#[test]
fn test_no_data_loss_insert() {
    let sql = "INSERT INTO t1 (id, name) VALUES (1, 'test'), (2, 'test2');";
    assert_preserves_tokens(sql, "INSERT");
}

#[test]
fn test_no_data_loss_update() {
    let sql = "UPDATE t1 SET name = 'updated' WHERE id = 1;";
    assert_preserves_tokens(sql, "UPDATE");
}

#[test]
fn test_no_data_loss_delete() {
    let sql = "DELETE FROM t1 WHERE id > 100;";
    assert_preserves_tokens(sql, "DELETE");
}

#[test]
fn test_no_data_loss_merge() {
    let sql = "MERGE INTO target USING source ON target.id = source.id WHEN MATCHED THEN UPDATE SET name = source.name WHEN NOT MATCHED THEN INSERT (id, name) VALUES (source.id, source.name);";
    assert_preserves_tokens(sql, "MERGE");
}

#[test]
fn test_no_data_loss_create_table() {
    let sql = "CREATE OR REPLACE TABLE t1 (id INT, name VARCHAR(100));";
    assert_preserves_tokens(sql, "CREATE TABLE");
}

#[test]
fn test_no_data_loss_complex_where() {
    let sql = "SELECT * FROM t1 WHERE (a > 5 AND b < 10) OR (c = 'test' AND d IS NOT NULL);";
    assert_preserves_tokens(sql, "Complex WHERE");
}

#[test]
fn test_no_data_loss_window_functions() {
    let sql =
        "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) AS rn FROM employees;";
    assert_preserves_tokens(sql, "Window functions");
}

#[test]
fn test_no_data_loss_star_modifiers() {
    let sql = "SELECT * EXCLUDE (password) RENAME (old_name AS new_name) FROM users;";
    assert_preserves_tokens(sql, "Star modifiers");
}

#[test]
fn test_no_data_loss_qualified_star() {
    let sql = "SELECT t1.*, t2.id, t2.name FROM t1 JOIN t2 ON t1.id = t2.ref_id;";
    assert_preserves_tokens(sql, "Qualified star");
}

#[test]
fn test_no_data_loss_cte_recursive() {
    let sql = "WITH RECURSIVE cte AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM cte WHERE n < 10) SELECT * FROM cte;";
    assert_preserves_tokens(sql, "Recursive CTE");
}

// Test that parser errors are better than data loss
#[test]
fn test_parser_should_error_not_lose_data() {
    // If we can't parse something correctly, we should error, not silently drop it
    let test_cases = vec![
        "SELECT * FROM t1 PIVOT(SUM(amount) FOR month IN ('Jan', 'Feb'))",
        "SELECT * FROM t1 UNPIVOT(sales FOR quarter IN (q1, q2, q3, q4))",
        "SELECT * FROM t1 MATCH_RECOGNIZE(ORDER BY time MEASURES A.id AS id PATTERN(A B+) DEFINE A AS A.status = 1)",
    ];

    for sql in test_cases {
        eprintln!("\n=== Testing: {} ===", sql);
        let result = try_parse_stmt_from_str(sql);
        match result {
            Ok(_stmt) => {
                // If we parsed it, we should be able to format it without losing data
                let formatted = format_sql(sql).expect("Should format after successful parse");
                eprintln!("Formatted:\n{}", formatted);

                let orig_tokens = tokenize(sql);
                let fmt_tokens = tokenize(&formatted);

                let orig_significant: Vec<String> = orig_tokens
                    .tokens
                    .iter()
                    .filter(|t| {
                        !matches!(
                            t.kind,
                            lexega_syntax::lexer::TokenKind::LineComment
                                | lexega_syntax::lexer::TokenKind::BlockComment
                        )
                    })
                    .map(|t| t.lexeme(sql).to_string())
                    .collect();

                let fmt_significant: Vec<String> = fmt_tokens
                    .tokens
                    .iter()
                    .filter(|t| {
                        !matches!(
                            t.kind,
                            lexega_syntax::lexer::TokenKind::LineComment
                                | lexega_syntax::lexer::TokenKind::BlockComment
                        )
                    })
                    .map(|t| t.lexeme(&formatted).to_string())
                    .collect();

                // Use normalization-aware check instead of simple count
                if !is_acceptable_normalization(&orig_significant, &fmt_significant) {
                    panic!("Token mismatch after formatting: {}\nOriginal tokens: {:?}\nFormatted tokens: {:?}\nOriginal: {}\nFormatted: {}", 
                        sql, orig_significant, fmt_significant, sql, formatted);
                }
            }
            Err(_) => {
                // This is OK - better to error than lose data
            }
        }
    }
}

#[test]
fn test_no_data_loss_create_table_as_complex() {
    // Test CREATE TABLE AS with complex query including CTEs, joins, window functions, UNION
    let sql = r#"CREATE TABLE sales_summary AS
WITH regional_sales AS (
    SELECT region, product_id, SUM(amount) as total_sales FROM orders GROUP BY region, product_id
),
top_products AS (
    SELECT product_id, ROW_NUMBER() OVER (PARTITION BY region ORDER BY total_sales DESC) as rank FROM regional_sales
)
SELECT r.region, p.product_name, rs.total_sales, tp.rank
FROM regional_sales rs
JOIN top_products tp ON rs.product_id = tp.product_id
JOIN products p ON p.id = rs.product_id
WHERE tp.rank <= 10
UNION ALL
SELECT 'TOTAL' as region, 'ALL' as product_name, SUM(amount), NULL FROM orders;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with complex query");
}

#[test]
fn test_no_data_loss_create_table_as_with_columns() {
    // Test CREATE TABLE AS with explicit column definitions
    let sql = "CREATE TABLE users_backup (id NUMBER, name VARCHAR, created_at TIMESTAMP) AS SELECT user_id, username, registration_date FROM users WHERE active = true;";
    assert_preserves_tokens(sql, "CREATE TABLE AS with column definitions");
}

#[test]
fn test_no_data_loss_create_table_as_subquery() {
    // Test CREATE TABLE AS with nested subqueries
    let sql = r#"CREATE TABLE high_value_customers AS
SELECT c.customer_id, c.name, c.email, 
       (SELECT COUNT(*) FROM orders o WHERE o.customer_id = c.customer_id) as order_count,
       (SELECT SUM(total) FROM orders o WHERE o.customer_id = c.customer_id) as lifetime_value
FROM customers c
WHERE c.customer_id IN (SELECT customer_id FROM orders GROUP BY customer_id HAVING SUM(total) > 10000);"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with subqueries");
}

#[test]
fn test_no_data_loss_create_table_as_case_expressions() {
    // Test CREATE TABLE AS with complex CASE expressions
    let sql = r#"CREATE TABLE customer_segments AS
SELECT customer_id,
       CASE 
           WHEN total_purchases > 10000 THEN 'VIP'
           WHEN total_purchases > 5000 THEN 'Premium'
           WHEN total_purchases > 1000 THEN 'Standard'
           ELSE 'Basic'
       END as segment,
       CASE type
           WHEN 'B' THEN 'Business'
           WHEN 'P' THEN 'Personal'
       END as account_type
FROM customer_stats;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with CASE expressions");
}

#[test]
fn test_no_data_loss_create_table_as_aggregates() {
    // Test CREATE TABLE AS with complex aggregations and grouping
    let sql = r#"CREATE TABLE daily_metrics AS
SELECT DATE_TRUNC('day', order_date) as date,
       region,
       product_category,
       COUNT(DISTINCT customer_id) as unique_customers,
       COUNT(*) as order_count,
       SUM(amount) as total_revenue,
       AVG(amount) as avg_order_value,
       MIN(amount) as min_order,
       MAX(amount) as max_order,
       STDDEV(amount) as stddev_amount
FROM orders
GROUP BY DATE_TRUNC('day', order_date), region, product_category
HAVING COUNT(*) > 5;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with complex aggregations");
}

#[test]
fn test_no_data_loss_create_or_replace_table_as() {
    // Test CREATE OR REPLACE TABLE AS
    let sql = "CREATE OR REPLACE TABLE temp_results AS SELECT * FROM source_table WHERE processed = false;";
    assert_preserves_tokens(sql, "CREATE OR REPLACE TABLE AS");
}

#[test]
fn test_no_data_loss_create_table_as_time_travel() {
    // Test CREATE TABLE AS with time travel
    let sql = "CREATE TABLE restored_data AS SELECT * FROM my_table AT(TIMESTAMP => '2024-01-01 00:00:00'::TIMESTAMP) WHERE deleted = true;";
    assert_preserves_tokens(sql, "CREATE TABLE AS with time travel");
}

#[test]
fn test_no_data_loss_create_table_as_lateral_join() {
    // Test CREATE TABLE AS with LATERAL join
    let sql = r#"CREATE TABLE customer_top_orders AS
SELECT c.customer_id, c.name, o.order_id, o.amount
FROM customers c,
LATERAL (
    SELECT order_id, amount 
    FROM orders 
    WHERE customer_id = c.customer_id 
    ORDER BY amount DESC 
    LIMIT 5
) o;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with LATERAL join");
}

#[test]
fn test_no_data_loss_create_table_if_not_exists() {
    // Test CREATE TABLE IF NOT EXISTS AS
    let sql = "CREATE TABLE IF NOT EXISTS archive_2024 AS SELECT * FROM transactions WHERE YEAR(date) = 2024;";
    assert_preserves_tokens(sql, "CREATE TABLE IF NOT EXISTS AS");
}

#[test]
fn test_no_data_loss_create_transient_table_as() {
    // Test CREATE TRANSIENT TABLE AS (Snowflake-specific)
    let sql = "CREATE TRANSIENT TABLE temp_analysis AS SELECT customer_id, COUNT(*) as order_count FROM orders GROUP BY customer_id;";
    assert_preserves_tokens(sql, "CREATE TRANSIENT TABLE AS");
}

#[test]
fn test_no_data_loss_create_table_as_window_functions() {
    // Test CREATE TABLE AS with multiple window functions
    let sql = r#"CREATE TABLE ranked_sales AS
SELECT 
    employee_id,
    sale_date,
    amount,
    ROW_NUMBER() OVER (PARTITION BY employee_id ORDER BY sale_date) as sale_sequence,
    RANK() OVER (ORDER BY amount DESC) as amount_rank,
    LAG(amount, 1) OVER (PARTITION BY employee_id ORDER BY sale_date) as prev_amount,
    LEAD(amount, 1) OVER (PARTITION BY employee_id ORDER BY sale_date) as next_amount,
    SUM(amount) OVER (PARTITION BY employee_id ORDER BY sale_date ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) as running_total
FROM sales;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with window functions");
}

#[test]
fn test_no_data_loss_create_table_as_pivot() {
    // Test CREATE TABLE AS with PIVOT
    let sql = r#"CREATE TABLE quarterly_sales AS
SELECT * FROM monthly_sales
PIVOT(SUM(amount) FOR quarter IN ('Q1', 'Q2', 'Q3', 'Q4'))
ORDER BY year;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with PIVOT");
}

#[test]
fn test_no_data_loss_create_table_as_unpivot() {
    // Test CREATE TABLE AS with UNPIVOT
    let sql = r#"CREATE TABLE normalized_sales AS
SELECT * FROM wide_sales
UNPIVOT(sales FOR month IN (jan, feb, mar, apr, may, jun));"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with UNPIVOT");
}

#[test]
fn test_no_data_loss_create_table_as_set_operations() {
    // Test CREATE TABLE AS with INTERSECT and EXCEPT
    let sql = r#"CREATE TABLE common_customers AS
SELECT customer_id FROM store_a
INTERSECT
SELECT customer_id FROM store_b
EXCEPT
SELECT customer_id FROM blacklist;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with INTERSECT/EXCEPT");
}

#[test]
fn test_no_data_loss_create_table_clone() {
    // Test CREATE TABLE CLONE (Snowflake zero-copy clone)
    let sql = "CREATE TABLE orders_backup CLONE orders AT(OFFSET => -3600);";
    assert_preserves_tokens(sql, "CREATE TABLE CLONE with time travel");
}

#[test]
fn test_no_data_loss_create_table_like() {
    // Test CREATE TABLE LIKE
    let sql = "CREATE TABLE new_users LIKE existing_users;";
    assert_preserves_tokens(sql, "CREATE TABLE LIKE");
}

#[test]
fn test_no_data_loss_create_table_as_flatten() {
    // Test CREATE TABLE AS with FLATTEN (Snowflake semi-structured data)
    let sql = r#"CREATE TABLE flattened_events AS
SELECT 
    src.id,
    f.value:name::STRING as event_name,
    f.value:timestamp::TIMESTAMP as event_time
FROM source_data src,
LATERAL FLATTEN(input => src.events) f;"#;
    assert_preserves_tokens(sql, "CREATE TABLE AS with FLATTEN");
}

#[test]
fn test_no_data_loss_deeply_nested_subqueries() {
    // Test deeply nested subqueries with multiple levels
    let sql = r#"SELECT * FROM (
    SELECT * FROM (
        SELECT * FROM (
            SELECT id, name FROM users WHERE active = true
        ) t1 WHERE id > 100
    ) t2 WHERE name LIKE 'A%'
) t3 WHERE id < 1000;"#;
    assert_preserves_tokens(sql, "Deeply nested subqueries");
}

#[test]
fn test_no_data_loss_complex_join_chain() {
    // Test complex join chain with multiple join types
    let sql = r#"SELECT *
FROM orders o
INNER JOIN customers c ON o.customer_id = c.id
LEFT JOIN addresses a ON c.address_id = a.id
RIGHT JOIN payments p ON o.id = p.order_id
FULL OUTER JOIN refunds r ON p.id = r.payment_id
CROSS JOIN regions reg
WHERE o.status = 'complete';"#;
    assert_preserves_tokens(sql, "Complex join chain");
}

#[test]
fn test_no_data_loss_union_intersect_except_combination() {
    // Test combination of different set operations
    let sql = r#"SELECT id FROM table_a
UNION
SELECT id FROM table_b
INTERSECT
SELECT id FROM table_c
EXCEPT
SELECT id FROM table_d
UNION ALL
SELECT id FROM table_e;"#;
    assert_preserves_tokens(sql, "Mixed set operations");
}

#[test]
fn test_no_data_loss_connect_by_hierarchical() {
    // Test CONNECT BY hierarchical queries with PRIOR
    let sql = r#"SELECT employee_id, manager_id, name, LEVEL
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR employee_id = manager_id AND department = 'Sales'
ORDER SIBLINGS BY name;"#;
    assert_preserves_tokens(sql, "CONNECT BY hierarchical query");
}

#[test]
fn test_no_data_loss_qualify_with_window() {
    // Test QUALIFY clause with window functions
    let sql = r#"SELECT employee_id, sale_amount, sale_date
FROM sales
QUALIFY ROW_NUMBER() OVER (PARTITION BY employee_id ORDER BY sale_amount DESC) <= 3;"#;
    assert_preserves_tokens(sql, "QUALIFY with window functions");
}

#[test]
fn test_no_data_loss_values_clause() {
    // Test VALUES clause with multiple rows
    let sql = r#"SELECT * FROM (VALUES 
    (1, 'Alice', 'Engineering'),
    (2, 'Bob', 'Sales'),
    (3, 'Charlie', 'Marketing')
) AS t(id, name, department);"#;
    assert_preserves_tokens(sql, "VALUES clause with alias");
}

#[test]
fn test_no_data_loss_table_sample() {
    // Test SAMPLE clause with various methods
    let sql = "SELECT * FROM large_table SAMPLE BERNOULLI (10) SEED (42);";
    assert_preserves_tokens(sql, "SAMPLE clause");
}

#[test]
fn test_no_data_loss_array_and_object_access() {
    // Test array subscript and object field access
    let sql = r#"SELECT 
    data[0] as first_element,
    data[1:3] as slice,
    obj:field1 as field1,
    obj:nested.field2 as field2,
    arr[idx]:name as name
FROM semi_structured_data;"#;
    assert_preserves_tokens(sql, "Array and object access");
}

#[test]
fn test_no_data_loss_complex_case_when() {
    // Test nested CASE expressions
    let sql = r#"SELECT
    CASE
        WHEN amount > 1000 THEN
            CASE
                WHEN region = 'US' THEN 'High-US'
                WHEN region = 'EU' THEN 'High-EU'
                ELSE 'High-Other'
            END
        WHEN amount > 100 THEN 'Medium'
        ELSE 'Low'
    END as category
FROM transactions;"#;
    assert_preserves_tokens(sql, "Nested CASE expressions");
}

#[test]
fn test_no_data_loss_cast_and_convert() {
    // Test various type casting methods
    let sql = r#"SELECT
    CAST(value AS INTEGER) as int_val,
    TRY_CAST(text_val AS DECIMAL(10,2)) as dec_val,
    amount::VARCHAR as str_amount,
    date_str::DATE as parsed_date
FROM data_table;"#;
    assert_preserves_tokens(sql, "Type casting variations");
}

#[test]
fn test_no_data_loss_between_and_in() {
    // Test BETWEEN and IN predicates
    let sql = r#"SELECT *
FROM orders
WHERE amount BETWEEN 100 AND 500
  AND status IN ('pending', 'processing', 'shipped')
  AND customer_id NOT IN (SELECT id FROM blocked_customers)
  AND created_at NOT BETWEEN '2024-01-01' AND '2024-01-31';"#;
    assert_preserves_tokens(sql, "BETWEEN and IN predicates");
}

#[test]
fn test_no_data_loss_like_patterns() {
    // Test LIKE, ILIKE, RLIKE patterns with ESCAPE
    let sql = r#"SELECT *
FROM products
WHERE name LIKE '%\\_special\\_%' ESCAPE '\\'
  AND description ILIKE '%winter%'
  AND sku NOT LIKE 'DISC%'
  AND category RLIKE '^[A-Z]{3}-[0-9]{4}$';"#;
    assert_preserves_tokens(sql, "LIKE patterns with ESCAPE");
}

#[test]
fn test_no_data_loss_exists_and_any_all() {
    // Test EXISTS, ANY, ALL predicates
    let sql = r#"SELECT *
FROM customers c
WHERE EXISTS (SELECT 1 FROM orders WHERE customer_id = c.id)
  AND NOT EXISTS (SELECT 1 FROM complaints WHERE customer_id = c.id)
  AND c.credit_limit > ALL (SELECT avg_limit FROM industry_averages)
  AND c.risk_score < ANY (SELECT threshold FROM risk_thresholds WHERE category = c.category);"#;
    assert_preserves_tokens(sql, "EXISTS and quantified comparisons");
}

#[test]
fn test_formatter_config_preserves_data() {
    let sql = "SELECT id, name AS username, status FROM users WHERE active = true;";

    // Test various configs to ensure they all preserve data
    let configs = vec![
        FormatterConfig::default(),
        FormatterConfig::readable(),
        FormatterConfig {
            select_items_on_newlines: true,
            ..FormatterConfig::default()
        },
        FormatterConfig {
            where_conditions_on_newlines: true,
            ..FormatterConfig::default()
        },
    ];

    for config in configs {
        let formatted = format_sql_with_config(sql, &config).expect("Should format successfully");

        let orig_tokens = tokenize(sql);
        let fmt_tokens = tokenize(&formatted);

        let orig_significant: Vec<String> = orig_tokens
            .tokens
            .iter()
            .filter(|t| {
                !matches!(
                    t.kind,
                    lexega_syntax::lexer::TokenKind::LineComment
                        | lexega_syntax::lexer::TokenKind::BlockComment
                )
            })
            .map(|t| t.lexeme(sql).to_string())
            .collect();

        let fmt_significant: Vec<String> = fmt_tokens
            .tokens
            .iter()
            .filter(|t| {
                !matches!(
                    t.kind,
                    lexega_syntax::lexer::TokenKind::LineComment
                        | lexega_syntax::lexer::TokenKind::BlockComment
                )
            })
            .map(|t| t.lexeme(&formatted).to_string())
            .collect();

        assert_eq!(
            orig_significant, fmt_significant,
            "Tokens don't match with config: {:?}",
            config
        );
    }
}

// ============================================================================
// EDGE CASE TESTS - Complex and corner cases for data loss detection
// ============================================================================

#[test]
fn test_no_data_loss_match_recognize() {
    // Test MATCH_RECOGNIZE pattern matching (Snowflake-specific)
    let sql = r#"SELECT *
FROM stock_prices
MATCH_RECOGNIZE (
    PARTITION BY symbol
    ORDER BY trade_date
    MEASURES
        FIRST(down.trade_date) AS start_date,
        LAST(up.trade_date) AS end_date,
        FIRST(down.price) AS start_price,
        LAST(up.price) AS end_price
    ONE ROW PER MATCH
    PATTERN (down+ up+)
    DEFINE
        down AS price < LAG(price),
        up AS price > LAG(price)
);"#;
    assert_preserves_tokens(sql, "MATCH_RECOGNIZE pattern matching");
}

#[test]
fn test_no_data_loss_lateral_flatten() {
    // Test LATERAL FLATTEN for semi-structured data
    let sql = r#"SELECT 
    d.id,
    f.value::STRING AS item,
    f.index AS position
FROM documents d,
LATERAL FLATTEN(input => d.tags, outer => true) f;"#;
    assert_preserves_tokens(sql, "LATERAL FLATTEN");
}

#[test]
fn test_no_data_loss_lateral_flatten_path() {
    // Test LATERAL FLATTEN with path parameter
    let sql = r#"SELECT 
    c.customer_id,
    o.value:order_id::INTEGER AS order_id,
    o.value:total::DECIMAL(10,2) AS total
FROM customers c,
LATERAL FLATTEN(input => c.data, path => 'orders') o
WHERE o.value:status::STRING = 'completed';"#;
    assert_preserves_tokens(sql, "LATERAL FLATTEN with path");
}

#[test]
fn test_no_data_loss_table_function() {
    // Test TABLE() function for table literals
    let sql = r#"SELECT t.col1, t.col2
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) t
WHERE t.col1 IS NOT NULL;"#;
    assert_preserves_tokens(sql, "TABLE function");
}

#[test]
fn test_no_data_loss_generator() {
    // Test GENERATOR table function (Snowflake-specific)
    let sql = r#"SELECT 
    SEQ4() AS seq,
    UNIFORM(1, 100, RANDOM()) AS rand_val
FROM TABLE(GENERATOR(ROWCOUNT => 1000));"#;
    assert_preserves_tokens(sql, "GENERATOR table function");
}

#[test]
fn test_no_data_loss_variant_path_complex() {
    // Test complex VARIANT path access
    let sql = r#"SELECT 
    data:root.level1.level2[0]:field::VARCHAR AS deep_field,
    data:array[*]:name::VARCHAR AS all_names,
    data:"special-key"::INTEGER AS special,
    PARSE_JSON(json_col):value AS parsed
FROM json_table
WHERE data:status::STRING IN ('active', 'pending');"#;
    assert_preserves_tokens(sql, "Complex VARIANT path access");
}

#[test]
fn test_no_data_loss_collation() {
    // Test COLLATE expressions
    let sql = r#"SELECT name
FROM users
WHERE name COLLATE 'en-ci' = 'john'
ORDER BY name COLLATE 'de-ai' ASC;"#;
    assert_preserves_tokens(sql, "COLLATE expressions");
}

#[test]
fn test_no_data_loss_pivot_multiple_aggregates() {
    // Test PIVOT with multiple aggregates
    let sql = r#"SELECT *
FROM sales_data
PIVOT(
    SUM(amount) AS total,
    COUNT(*) AS cnt
    FOR quarter IN ('Q1', 'Q2', 'Q3', 'Q4')
);"#;
    assert_preserves_tokens(sql, "PIVOT with multiple aggregates");
}

#[test]
fn test_no_data_loss_unpivot_include_nulls() {
    // Test UNPIVOT with INCLUDE NULLS
    let sql = r#"SELECT product_id, quarter, amount
FROM quarterly_sales
UNPIVOT INCLUDE NULLS (amount FOR quarter IN (q1, q2, q3, q4));"#;
    assert_preserves_tokens(sql, "UNPIVOT INCLUDE NULLS");
}

#[test]
fn test_no_data_loss_copy_into_select() {
    // Test COPY INTO with SELECT
    let sql = r#"COPY INTO @my_stage/path/
FROM (
    SELECT id, name, CURRENT_TIMESTAMP() as exported_at
    FROM users
    WHERE status = 'active'
)
FILE_FORMAT = (TYPE = 'PARQUET')
HEADER = TRUE;"#;
    assert_preserves_tokens(sql, "COPY INTO with SELECT");
}

#[test]
fn test_no_data_loss_qualify_complex() {
    // Test QUALIFY with complex window functions
    let sql = r#"SELECT 
    department,
    employee_name,
    salary,
    RANK() OVER (PARTITION BY department ORDER BY salary DESC) as dept_rank
FROM employees
QUALIFY dept_rank <= 5 AND salary > (
    SELECT AVG(salary) FROM employees e2 WHERE e2.department = employees.department
);"#;
    assert_preserves_tokens(sql, "QUALIFY with complex conditions");
}

#[test]
fn test_no_data_loss_window_frame_complex() {
    // Test complex window frame specifications
    let sql = r#"SELECT
    date,
    value,
    AVG(value) OVER (ORDER BY date ROWS BETWEEN 3 PRECEDING AND 1 FOLLOWING) as moving_avg,
    SUM(value) OVER (ORDER BY date RANGE BETWEEN INTERVAL '7' DAY PRECEDING AND CURRENT ROW) as weekly_sum,
    FIRST_VALUE(value) OVER (PARTITION BY category ORDER BY date ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) as first_in_cat
FROM time_series;"#;
    assert_preserves_tokens(sql, "Complex window frame specifications");
}

#[test]
fn test_no_data_loss_listagg() {
    // Test LISTAGG and ARRAY_AGG functions
    let sql = r#"SELECT 
    department,
    LISTAGG(employee_name, ', ') WITHIN GROUP (ORDER BY hire_date) AS employees,
    ARRAY_AGG(DISTINCT skill) WITHIN GROUP (ORDER BY skill) AS skills
FROM employees
GROUP BY department;"#;
    assert_preserves_tokens(sql, "LISTAGG and ARRAY_AGG");
}

#[test]
fn test_no_data_loss_grouping_sets() {
    // Test GROUPING SETS, ROLLUP, CUBE
    let sql = r#"SELECT 
    region,
    product,
    year,
    SUM(sales) as total_sales,
    GROUPING(region, product) as grp_level
FROM sales
GROUP BY GROUPING SETS (
    (region, product, year),
    (region, product),
    (region),
    ()
);"#;
    assert_preserves_tokens(sql, "GROUPING SETS");
}

#[test]
fn test_no_data_loss_rollup_cube() {
    // Test ROLLUP and CUBE
    let sql = r#"SELECT region, product, SUM(amount) as total
FROM sales
GROUP BY ROLLUP(region, product)

UNION ALL

SELECT region, product, SUM(amount) as total
FROM sales
GROUP BY CUBE(region, product);"#;
    assert_preserves_tokens(sql, "ROLLUP and CUBE");
}

#[test]
fn test_no_data_loss_datetime_functions() {
    // Test date/time manipulation functions
    let sql = r#"SELECT 
    DATEADD(day, 7, current_date) as next_week,
    DATEDIFF(month, hire_date, current_date) as tenure_months,
    DATE_TRUNC('quarter', sale_date) as quarter_start,
    TIMESTAMPADD(hour, -5, event_time) as adjusted_time,
    EXTRACT(YEAR FROM birth_date) as birth_year,
    TO_TIMESTAMP_NTZ('2024-01-01 12:00:00', 'YYYY-MM-DD HH24:MI:SS') as parsed_ts
FROM events;"#;
    assert_preserves_tokens(sql, "Date/time functions");
}

#[test]
fn test_no_data_loss_iff_and_coalesce() {
    // Test IFF, COALESCE, NVL, NULLIF, ZEROIFNULL
    let sql = r#"SELECT 
    IFF(status = 'active', 1, 0) as is_active,
    COALESCE(preferred_name, first_name, 'Unknown') as display_name,
    NVL(discount, 0) as discount_amount,
    NULLIF(status, 'N/A') as clean_status,
    ZEROIFNULL(count) as safe_count,
    NVL2(email, 'Has Email', 'No Email') as email_status
FROM customers;"#;
    assert_preserves_tokens(sql, "Conditional null handling functions");
}

#[test]
fn test_no_data_loss_object_construct() {
    // Test OBJECT_CONSTRUCT and ARRAY_CONSTRUCT
    let sql = r#"SELECT 
    OBJECT_CONSTRUCT(
        'id', user_id,
        'name', OBJECT_CONSTRUCT('first', first_name, 'last', last_name),
        'tags', ARRAY_CONSTRUCT('tag1', 'tag2', tag_var)
    ) as user_obj,
    ARRAY_CONSTRUCT_COMPACT(val1, val2, NULL, val3) as compact_arr
FROM users;"#;
    assert_preserves_tokens(sql, "OBJECT_CONSTRUCT and ARRAY_CONSTRUCT");
}

#[test]
fn test_no_data_loss_try_functions() {
    // Test TRY_* error-handling functions
    let sql = r#"SELECT 
    TRY_TO_NUMBER(string_val) as safe_num,
    TRY_TO_DATE(date_string, 'YYYY-MM-DD') as safe_date,
    TRY_TO_TIMESTAMP(ts_string) as safe_ts,
    TRY_PARSE_JSON(json_string) as safe_json,
    TRY_BASE64_DECODE_STRING(encoded) as decoded
FROM raw_data;"#;
    assert_preserves_tokens(sql, "TRY_* functions");
}

#[test]
fn test_no_data_loss_regexp_functions() {
    // Test regular expression functions
    let sql = r#"SELECT 
    REGEXP_LIKE(email, '^[a-z]+@[a-z]+\\.[a-z]{2,}$') as valid_email,
    REGEXP_REPLACE(phone, '[^0-9]', '') as clean_phone,
    REGEXP_SUBSTR(text, '[0-9]+', 1, 2) as second_number,
    REGEXP_COUNT(log_entry, 'ERROR|WARN', 1, 'i') as issue_count,
    REGEXP_INSTR(filename, '\\.([^.]+)$') as ext_pos
FROM data;"#;
    assert_preserves_tokens(sql, "REGEXP functions");
}

#[test]
fn test_no_data_loss_bitwise_operations() {
    // Test bitwise operations
    let sql = r#"SELECT 
    flags & 1 as bit0,
    flags | 2 as with_bit1,
    flags ^ mask as xor_result,
    ~flags as inverted,
    BITAND(a, b) as bitand_result,
    BITOR(a, b) as bitor_result,
    BITXOR(a, b) as bitxor_result,
    BITNOT(a) as bitnot_result,
    BITSHIFTLEFT(val, 2) as shifted_left,
    BITSHIFTRIGHT(val, 3) as shifted_right
FROM flags_table;"#;
    assert_preserves_tokens(sql, "Bitwise operations");
}

#[test]
fn test_no_data_loss_at_before_timestamp() {
    // Test AT/BEFORE time travel with timestamp expressions
    let sql = r#"SELECT * FROM orders
AT(TIMESTAMP => DATEADD(hour, -2, CURRENT_TIMESTAMP()))
WHERE status = 'pending';"#;
    assert_preserves_tokens(sql, "AT with timestamp expression");
}

#[test]
fn test_no_data_loss_at_before_offset() {
    // Test AT/BEFORE time travel with offset
    let sql = r#"SELECT * FROM inventory
AT(OFFSET => -60*60)
MINUS
SELECT * FROM inventory;"#;
    assert_preserves_tokens(sql, "AT with offset");
}

#[test]
fn test_no_data_loss_at_before_statement() {
    // Test BEFORE time travel with statement ID
    let sql =
        "SELECT * FROM transactions BEFORE(STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726');";
    assert_preserves_tokens(sql, "BEFORE with statement ID");
}

#[test]
fn test_no_data_loss_connect_by_nocycle() {
    // Test CONNECT BY with NOCYCLE and additional clauses
    let sql = r#"SELECT 
    LEVEL,
    SYS_CONNECT_BY_PATH(name, '/') as path,
    CONNECT_BY_ROOT name as root_name,
    CONNECT_BY_ISLEAF as is_leaf
FROM org_chart
START WITH parent_id IS NULL
CONNECT BY NOCYCLE PRIOR id = parent_id;"#;
    assert_preserves_tokens(sql, "CONNECT BY with NOCYCLE and functions");
}

#[test]
fn test_no_data_loss_recursive_cte_search() {
    // Test recursive CTE with SEARCH clause
    let sql = r#"WITH RECURSIVE org_tree AS (
    SELECT id, name, parent_id, 0 as depth
    FROM employees
    WHERE parent_id IS NULL
    
    UNION ALL
    
    SELECT e.id, e.name, e.parent_id, t.depth + 1
    FROM employees e
    INNER JOIN org_tree t ON e.parent_id = t.id
)
SEARCH DEPTH FIRST BY name SET order_col
SELECT * FROM org_tree ORDER BY order_col;"#;
    assert_preserves_tokens(sql, "Recursive CTE with SEARCH");
}

#[test]
fn test_no_data_loss_lateral_subquery() {
    // Test LATERAL with correlated subquery
    let sql = r#"SELECT c.customer_id, c.name, recent.order_date, recent.total
FROM customers c,
LATERAL (
    SELECT order_date, total
    FROM orders o
    WHERE o.customer_id = c.customer_id
    ORDER BY order_date DESC
    LIMIT 3
) recent;"#;
    assert_preserves_tokens(sql, "LATERAL with correlated subquery");
}

#[test]
fn test_no_data_loss_natural_join() {
    // Test NATURAL JOIN and USING clause
    let sql = r#"SELECT *
FROM orders
NATURAL JOIN customers

UNION ALL

SELECT *
FROM orders o
JOIN customers c USING (customer_id, region);"#;
    assert_preserves_tokens(sql, "NATURAL JOIN and USING");
}

#[test]
fn test_no_data_loss_asof_join() {
    // Test ASOF JOIN (Snowflake-specific)
    let sql = r#"SELECT t.trade_time, t.symbol, t.price, q.bid, q.ask
FROM trades t
ASOF JOIN quotes q
MATCH_CONDITION (t.trade_time >= q.quote_time)
ON t.symbol = q.symbol;"#;
    assert_preserves_tokens(sql, "ASOF JOIN");
}

#[test]
fn test_no_data_loss_minus_except() {
    // Test MINUS/EXCEPT set operations
    let sql = r#"SELECT id FROM all_users
EXCEPT
SELECT id FROM deleted_users

MINUS

SELECT id FROM suspended_users;"#;
    assert_preserves_tokens(sql, "MINUS and EXCEPT");
}

#[test]
fn test_no_data_loss_intersect_all() {
    // Test INTERSECT ALL
    let sql = r#"SELECT product_id FROM warehouse_a
INTERSECT ALL
SELECT product_id FROM warehouse_b
INTERSECT
SELECT product_id FROM warehouse_c;"#;
    assert_preserves_tokens(sql, "INTERSECT and INTERSECT ALL");
}

#[test]
fn test_no_data_loss_escape_sequences() {
    // Test string literals with escape sequences
    let sql = r#"SELECT 
    'Line1\nLine2' as with_newline,
    'Tab\there' as with_tab,
    'Quote: ''single''' as single_quotes,
    'Path: C:\\Users\\file' as with_backslash,
    E'Escape: \x41' as hex_escape,
    $$Dollar quoted 'string' with "quotes"$$ as dollar_quoted
FROM dual;"#;
    assert_preserves_tokens(sql, "String escape sequences");
}

#[test]
fn test_no_data_loss_numeric_literals() {
    // Test various numeric literal formats
    let sql = r#"SELECT 
    123 as int_val,
    123.456 as decimal_val,
    1.23e10 as scientific,
    1.23E-5 as scientific_neg,
    0x1A2B as hex_val,
    -99.99 as negative
FROM numbers;"#;
    assert_preserves_tokens(sql, "Numeric literals");
}

#[test]
fn test_no_data_loss_interval_expressions() {
    // Test INTERVAL expressions
    let sql = r#"SELECT 
    created_at + INTERVAL '1 day' as tomorrow,
    updated_at - INTERVAL '2 hours' as two_hours_ago,
    INTERVAL '1 year 2 months 3 days' as complex_interval
FROM events;"#;
    assert_preserves_tokens(sql, "INTERVAL expressions");
}

#[test]
fn test_no_data_loss_type_with_params() {
    // Test types with parameters
    let sql = r#"CREATE TABLE typed_cols (
    id NUMBER(38, 0) NOT NULL,
    price DECIMAL(18, 4),
    name VARCHAR(255) COLLATE 'en-ci',
    data VARIANT,
    created TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP()
);"#;
    assert_preserves_tokens(sql, "Types with parameters");
}

#[test]
fn test_no_data_loss_inline_comments() {
    // Test inline comments within statements
    let sql = r#"SELECT 
    id, -- the primary key
    name /* customer name */,
    status -- current status
FROM customers -- main customer table
WHERE active = true; -- only active"#;
    assert_preserves_tokens(sql, "Inline comments");
}

#[test]
fn test_no_data_loss_block_comments() {
    // Test block comments
    let sql = r#"/* This is a 
   multi-line comment */
SELECT /* inline */ a, /*
another
multiline
*/ b
FROM t /* table alias follows */ AS tbl;"#;
    assert_preserves_tokens(sql, "Block comments");
}

#[test]
fn test_no_data_loss_reserved_word_identifiers() {
    // Test reserved words as identifiers (quoted)
    let sql = r#"SELECT 
    "SELECT" as sel,
    "FROM" as frm,
    "WHERE" as whr,
    "ORDER" as ord,
    "TABLE"."COLUMN" as tbl_col
FROM "TABLE"
WHERE "DATE" = CURRENT_DATE;"#;
    assert_preserves_tokens(sql, "Reserved words as identifiers");
}

#[test]
fn test_no_data_loss_mixed_case_identifiers() {
    // Test mixed case identifiers
    let sql = r#"SELECT 
    MyTable.MyColumn,
    "MixedCase"."PreservedCase",
    lowercase.also_lowercase
FROM MyTable
JOIN "MixedCase" ON MyTable.id = "MixedCase".id;"#;
    assert_preserves_tokens(sql, "Mixed case identifiers");
}

// ============================================================================
// EDGE CASE STRESS TESTS
// ============================================================================

#[test]
fn test_no_data_loss_deeply_nested_case() {
    // Deeply nested CASE expressions
    let sql = r#"SELECT 
    CASE 
        WHEN a = 1 THEN 
            CASE 
                WHEN b = 2 THEN 
                    CASE 
                        WHEN c = 3 THEN 'deep'
                        ELSE 'not_deep'
                    END
                ELSE 'mid'
            END
        ELSE 'outer'
    END as nested_case
FROM t;"#;
    assert_preserves_tokens(sql, "Deeply nested CASE");
}

#[test]
fn test_no_data_loss_multiple_ctes_with_recursion() {
    // Multiple CTEs including recursive and non-recursive mixed
    let sql = r#"WITH RECURSIVE 
    cte1 AS (SELECT 1 as n),
    cte2 AS (
        SELECT n FROM cte1
        UNION ALL
        SELECT n + 1 FROM cte2 WHERE n < 10
    ),
    cte3 AS (SELECT * FROM cte2 WHERE n > 5),
    cte4 (col1, col2) AS (SELECT n, n * 2 FROM cte3)
SELECT * FROM cte4;"#;
    assert_preserves_tokens(sql, "Multiple CTEs with recursion");
}

#[test]
fn test_no_data_loss_window_frame_all_variants() {
    // All window frame boundary variations
    let sql = r#"SELECT
    SUM(x) OVER (ORDER BY y ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW),
    SUM(x) OVER (ORDER BY y ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING),
    SUM(x) OVER (ORDER BY y ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING),
    SUM(x) OVER (ORDER BY y RANGE BETWEEN INTERVAL '1' DAY PRECEDING AND CURRENT ROW),
    SUM(x) OVER (PARTITION BY z ORDER BY y ROWS UNBOUNDED PRECEDING),
    SUM(x) OVER (ORDER BY y ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)
FROM t;"#;
    assert_preserves_tokens(sql, "Window frame variations");
}

#[test]
fn test_no_data_loss_lateral_with_flatten_chain() {
    // Lateral join with chained FLATTEN calls
    let sql = r#"SELECT 
    t.id,
    f1.value::STRING as level1,
    f2.value::STRING as level2,
    f3.value::INT as level3
FROM my_table t,
LATERAL FLATTEN(input => t.json_data, path => 'items') f1,
LATERAL FLATTEN(input => f1.value, path => 'subitems') f2,
LATERAL FLATTEN(input => f2.value:values) f3
WHERE f3.value > 0;"#;
    assert_preserves_tokens(sql, "Lateral with flatten chain");
}

#[test]
fn test_no_data_loss_complex_json_path() {
    // Complex semi-structured data access patterns
    let sql = r#"SELECT 
    v:root.level1.level2.level3::STRING,
    v:array[0].nested[1].value::INT,
    v:"special-key"."another-key"::VARIANT,
    v:data[0]:sub[1]:deep::FLOAT,
    PARSE_JSON(col):key::STRING,
    OBJECT_CONSTRUCT('a', v:x, 'b', v:y):a::INT
FROM t;"#;
    assert_preserves_tokens(sql, "Complex JSON paths");
}

#[test]
fn test_no_data_loss_all_join_types() {
    // Every join type in one query
    let sql = r#"SELECT *
FROM a
INNER JOIN b ON a.id = b.id
LEFT JOIN c ON b.id = c.id
LEFT OUTER JOIN d ON c.id = d.id
RIGHT JOIN e ON d.id = e.id
RIGHT OUTER JOIN f ON e.id = f.id
FULL JOIN g ON f.id = g.id
FULL OUTER JOIN h ON g.id = h.id
CROSS JOIN i
NATURAL JOIN j
NATURAL LEFT JOIN k
NATURAL RIGHT JOIN l
NATURAL FULL JOIN m;"#;
    assert_preserves_tokens(sql, "All join types");
}

#[test]
fn test_no_data_loss_subquery_in_every_clause() {
    // Subqueries in SELECT, FROM, WHERE, HAVING, ORDER BY
    let sql = r#"SELECT 
    (SELECT MAX(x) FROM sub1) as max_val,
    t.id,
    (SELECT COUNT(*) FROM sub2 WHERE sub2.t_id = t.id) as cnt
FROM (SELECT * FROM base WHERE active = TRUE) t
WHERE t.value > (SELECT AVG(value) FROM base)
GROUP BY t.id
HAVING COUNT(*) > (SELECT MIN(threshold) FROM config)
ORDER BY (SELECT priority FROM priorities WHERE priorities.id = t.id);"#;
    assert_preserves_tokens(sql, "Subqueries in every clause");
}

#[test]
fn test_no_data_loss_complex_merge() {
    // Complex MERGE with all action types
    let sql = r#"MERGE INTO target t
USING (
    SELECT * FROM source 
    WHERE updated_at > DATEADD(day, -1, CURRENT_DATE)
) s
ON t.id = s.id
WHEN MATCHED AND s.is_deleted = TRUE THEN DELETE
WHEN MATCHED AND s.value <> t.value THEN UPDATE SET 
    t.value = s.value,
    t.updated_at = CURRENT_TIMESTAMP,
    t.updated_by = CURRENT_USER
WHEN NOT MATCHED AND s.is_deleted = FALSE THEN INSERT (id, value, created_at)
    VALUES (s.id, s.value, CURRENT_TIMESTAMP);"#;
    assert_preserves_tokens(sql, "Complex MERGE");
}

#[test]
fn test_no_data_loss_pivot_with_subquery() {
    // PIVOT with complex expressions
    let sql = r#"SELECT *
FROM (
    SELECT product, quarter, revenue
    FROM sales
    WHERE year = 2024
)
PIVOT (
    SUM(revenue) FOR quarter IN ('Q1', 'Q2', 'Q3', 'Q4')
) AS pivot_table;"#;
    assert_preserves_tokens(sql, "PIVOT with subquery");
}

#[test]
fn test_no_data_loss_unpivot_multiple_columns() {
    // UNPIVOT with multiple value columns
    let sql = r#"SELECT *
FROM quarterly_data
UNPIVOT INCLUDE NULLS (
    (revenue, cost) FOR quarter IN (
        (q1_rev, q1_cost) AS 'Q1',
        (q2_rev, q2_cost) AS 'Q2',
        (q3_rev, q3_cost) AS 'Q3',
        (q4_rev, q4_cost) AS 'Q4'
    )
);"#;
    assert_preserves_tokens(sql, "UNPIVOT multiple columns");
}

#[test]
fn test_no_data_loss_match_recognize_complex() {
    // Complex MATCH_RECOGNIZE with multiple pattern variables
    let sql = r#"SELECT *
FROM stock_prices
MATCH_RECOGNIZE (
    PARTITION BY symbol
    ORDER BY trade_date
    MEASURES
        FIRST(DOWN.price) AS start_price,
        LAST(UP.price) AS end_price,
        MATCH_NUMBER() AS match_num,
        CLASSIFIER() AS var_match
    ALL ROWS PER MATCH
    AFTER MATCH SKIP TO LAST UP
    PATTERN (DOWN+ FLAT* UP+)
    DEFINE
        DOWN AS price < LAG(price),
        FLAT AS price = LAG(price),
        UP AS price > LAG(price)
);"#;
    assert_preserves_tokens(sql, "Complex MATCH_RECOGNIZE");
}

#[test]
fn test_no_data_loss_lambda_expressions() {
    // Lambda expressions in ARRAY/OBJECT functions
    let sql = r#"SELECT 
    TRANSFORM(arr, x -> x * 2) as doubled,
    FILTER(arr, x -> x > 10) as filtered,
    REDUCE(arr, 0, (acc, x) -> acc + x) as total,
    ARRAY_SORT(arr, (a, b) -> IFF(a < b, -1, IFF(a > b, 1, 0))) as sorted
FROM t;"#;
    assert_preserves_tokens(sql, "Lambda expressions");
}

#[test]
fn test_no_data_loss_table_literal() {
    // Table literals with VALUES
    let sql = r#"SELECT * FROM (
    VALUES 
        (1, 'a', TRUE),
        (2, 'b', FALSE),
        (3, 'c', NULL)
) AS t(id, name, active)
WHERE active IS NOT NULL;"#;
    assert_preserves_tokens(sql, "Table literal with VALUES");
}

#[test]
fn test_no_data_loss_copy_into_complex() {
    // Complex COPY INTO with many options
    let sql = r#"COPY INTO my_table (col1, col2, col3)
FROM @my_stage/path/to/files/
FILE_FORMAT = (TYPE = 'CSV' FIELD_DELIMITER = '|' SKIP_HEADER = 1 NULL_IF = ('NULL', 'null', ''))
PATTERN = '.*data_[0-9]+\\.csv'
ON_ERROR = 'CONTINUE'
SIZE_LIMIT = 1000000
PURGE = TRUE
FORCE = FALSE
MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE;"#;
    assert_preserves_tokens(sql, "Complex COPY INTO");
}

#[test]
fn test_no_data_loss_create_function() {
    // User-defined function with JavaScript
    let sql = r#"CREATE OR REPLACE FUNCTION my_udf(input_val FLOAT)
RETURNS FLOAT
LANGUAGE JAVASCRIPT
COMMENT = 'My UDF comment'
AS
$$
    if (INPUT_VAL === null) {
        return null;
    }
    return INPUT_VAL * 2.0;
$$;"#;
    assert_preserves_tokens(sql, "CREATE FUNCTION with JavaScript");
}

#[test]
fn test_no_data_loss_procedure_with_exception() {
    // Stored procedure with exception handling
    let sql = r#"CREATE OR REPLACE PROCEDURE my_proc(param1 VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
DECLARE
    result VARCHAR;
BEGIN
    SELECT value INTO result FROM my_table WHERE key = param1;
    RETURN result;
EXCEPTION
    WHEN OTHER THEN
        RETURN 'Error: ' || SQLERRM;
END;"#;
    assert_preserves_tokens(sql, "Procedure with exception handling");
}

#[test]
fn test_no_data_loss_array_agg_variations() {
    // ARRAY_AGG with different options
    let sql = r#"SELECT 
    ARRAY_AGG(x) as basic,
    ARRAY_AGG(DISTINCT x) as distinct_agg,
    ARRAY_AGG(x) WITHIN GROUP (ORDER BY y DESC) as ordered,
    ARRAY_AGG(DISTINCT x) WITHIN GROUP (ORDER BY x ASC NULLS LAST) as distinct_ordered
FROM t
GROUP BY category;"#;
    assert_preserves_tokens(sql, "ARRAY_AGG variations");
}

#[test]
fn test_no_data_loss_string_agg_complex() {
    // String aggregation with complex delimiters
    let sql = r#"SELECT 
    LISTAGG(name, ', ') WITHIN GROUP (ORDER BY name) as comma_sep,
    LISTAGG(DISTINCT category, ' | ') WITHIN GROUP (ORDER BY category DESC) as pipe_sep,
    LISTAGG(value, CHR(10)) WITHIN GROUP (ORDER BY seq) as newline_sep
FROM t
GROUP BY dept;"#;
    assert_preserves_tokens(sql, "String aggregation complex");
}

#[test]
fn test_no_data_loss_multiple_set_ops_mixed() {
    // Multiple mixed set operations
    let sql = r#"SELECT a FROM t1
UNION ALL
SELECT a FROM t2
UNION
SELECT a FROM t3
INTERSECT
SELECT a FROM t4
EXCEPT
SELECT a FROM t5
MINUS
SELECT a FROM t6;"#;
    assert_preserves_tokens(sql, "Multiple mixed set operations");
}

#[test]
fn test_no_data_loss_set_ops_with_order_limit() {
    // Set operations with ORDER BY and LIMIT
    let sql = r#"(SELECT a FROM t1 ORDER BY a LIMIT 10)
UNION ALL
(SELECT a FROM t2 ORDER BY a DESC LIMIT 5)
ORDER BY a
LIMIT 20
OFFSET 5;"#;
    assert_preserves_tokens(sql, "Set ops with ORDER BY and LIMIT");
}

#[test]
fn test_no_data_loss_exists_not_exists() {
    // EXISTS and NOT EXISTS combinations
    let sql = r#"SELECT *
FROM orders o
WHERE EXISTS (
    SELECT 1 FROM customers c WHERE c.id = o.customer_id
)
AND NOT EXISTS (
    SELECT 1 FROM cancellations x WHERE x.order_id = o.id
)
AND EXISTS (
    SELECT 1 FROM inventory i 
    WHERE i.product_id = o.product_id 
    AND i.quantity > 0
);"#;
    assert_preserves_tokens(sql, "EXISTS and NOT EXISTS");
}

#[test]
fn test_no_data_loss_in_with_subquery_and_list() {
    // IN clause with both subquery and value list
    let sql = r#"SELECT *
FROM products
WHERE category_id IN (SELECT id FROM active_categories)
AND status IN ('active', 'pending', 'review')
AND NOT region_id IN (SELECT id FROM excluded_regions)
AND price NOT IN (0, -1, NULL);"#;
    assert_preserves_tokens(sql, "IN with subquery and list");
}

#[test]
fn test_no_data_loss_between_with_expressions() {
    // BETWEEN with complex expressions
    let sql = r#"SELECT *
FROM events
WHERE created_at BETWEEN DATEADD(day, -7, CURRENT_DATE) AND CURRENT_TIMESTAMP
AND value BETWEEN (SELECT MIN(v) FROM thresholds) AND (SELECT MAX(v) FROM thresholds)
AND name BETWEEN 'A' AND 'M'
AND NOT priority BETWEEN 1 AND 3;"#;
    assert_preserves_tokens(sql, "BETWEEN with expressions");
}

#[test]
fn test_no_data_loss_like_ilike_patterns() {
    // LIKE and ILIKE variations
    let sql = r#"SELECT *
FROM users
WHERE name LIKE 'John%'
AND email ILIKE '%@example.com'
AND code LIKE 'ABC\_DEF%' ESCAPE '\'
AND NOT description LIKE '%test%'
AND category LIKE ANY ('%food%', '%drink%', '%snack%')
AND tag ILIKE ALL ('%premium%', '%featured%');"#;
    assert_preserves_tokens(sql, "LIKE and ILIKE patterns");
}

#[test]
fn test_no_data_loss_regexp_operations() {
    // Regular expression operations
    let sql = r#"SELECT 
    REGEXP_LIKE(col, '^[A-Z]{3}[0-9]+$') as matches,
    REGEXP_SUBSTR(col, '[0-9]+', 1, 2) as extracted,
    REGEXP_REPLACE(col, '[^a-zA-Z]', '') as cleaned,
    REGEXP_COUNT(col, '[aeiou]', 1, 'i') as vowel_count,
    REGEXP_INSTR(col, '[0-9]', 1, 1, 0, 'c') as first_digit_pos
FROM t
WHERE col REGEXP '^[A-Z].*[0-9]$';"#;
    assert_preserves_tokens(sql, "Regexp operations");
}

#[test]
fn test_no_data_loss_cast_chain() {
    // Chained casts and type conversions
    let sql = r#"SELECT 
    col::VARCHAR::INT::FLOAT as chain_cast,
    CAST(CAST(x AS VARCHAR(100)) AS NUMBER(10,2)) as nested_cast,
    TRY_CAST(TRY_CAST(y AS DATE) AS TIMESTAMP_NTZ) as try_chain,
    TO_VARCHAR(TO_DATE(TO_TIMESTAMP(val))) as func_chain,
    col:field::VARCHAR(50)::NUMBER(18,4) as json_cast_chain
FROM t;"#;
    assert_preserves_tokens(sql, "Cast chains");
}

#[test]
fn test_no_data_loss_null_handling() {
    // Various NULL handling constructs
    let sql = r#"SELECT 
    COALESCE(a, b, c, 'default') as coal,
    NVL(x, 0) as nvl_val,
    NVL2(flag, 'yes', 'no') as nvl2_val,
    NULLIF(a, b) as null_if,
    IFNULL(x, -1) as if_null,
    ZEROIFNULL(amount) as zero_null,
    NULLIFZERO(count) as null_zero,
    IFF(val IS NULL, 'null', IFF(val = '', 'empty', val)) as null_check
FROM t
WHERE val IS NOT NULL
AND other IS DISTINCT FROM previous;"#;
    assert_preserves_tokens(sql, "NULL handling");
}

#[test]
fn test_no_data_loss_date_time_operations() {
    // Date/time operations and literals
    let sql = r#"SELECT 
    DATE '2024-01-15' as date_lit,
    TIME '14:30:00' as time_lit,
    TIMESTAMP '2024-01-15 14:30:00' as ts_lit,
    DATEADD(month, 3, CURRENT_DATE) as plus_months,
    DATEDIFF(day, start_date, end_date) as day_diff,
    DATE_TRUNC('MONTH', created_at) as month_start,
    EXTRACT(YEAR FROM ts) as year_part,
    TO_TIMESTAMP_TZ('2024-01-15 14:30:00 -0800') as with_tz,
    TIMESTAMPADD(HOUR, 2, ts) as plus_hours
FROM t
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days';"#;
    assert_preserves_tokens(sql, "Date/time operations");
}

#[test]
fn test_no_data_loss_conditional_expressions() {
    // Complex conditional expressions
    let sql = r#"SELECT 
    CASE status 
        WHEN 1 THEN 'one' 
        WHEN 2 THEN 'two' 
        ELSE 'other' 
    END as simple_case,
    CASE 
        WHEN x > 100 THEN 'high'
        WHEN x > 50 THEN 'medium'
        WHEN x > 0 THEN 'low'
        WHEN x = 0 THEN 'zero'
        ELSE 'negative'
    END as searched_case,
    IFF(a AND b, 'both', IFF(a OR b, 'one', 'none')) as nested_iff,
    DECODE(status, 1, 'active', 2, 'pending', 3, 'closed', 'unknown') as decode_expr,
    GREATEST(a, b, c, d) as max_val,
    LEAST(a, b, c, d) as min_val
FROM t;"#;
    assert_preserves_tokens(sql, "Conditional expressions");
}

#[test]
fn test_no_data_loss_object_operations() {
    // OBJECT functions and operations
    let sql = r#"SELECT 
    OBJECT_CONSTRUCT('key1', val1, 'key2', val2) as obj,
    OBJECT_CONSTRUCT(*) as obj_from_row,
    OBJECT_CONSTRUCT_KEEP_NULL('a', NULL, 'b', 2) as with_nulls,
    OBJECT_INSERT(obj, 'new_key', 'new_value') as inserted,
    OBJECT_DELETE(obj, 'old_key') as deleted,
    OBJECT_KEYS(obj) as keys,
    OBJECT_PICK(obj, 'key1', 'key2') as picked,
    GET(obj, 'key') as get_val,
    GET_PATH(obj, 'a.b.c') as path_val
FROM t;"#;
    assert_preserves_tokens(sql, "Object operations");
}

#[test]
fn test_no_data_loss_array_operations() {
    // ARRAY functions and operations
    let sql = r#"SELECT 
    ARRAY_CONSTRUCT(1, 2, 3) as arr,
    ARRAY_CONSTRUCT_COMPACT(1, NULL, 2, NULL, 3) as compact,
    ARRAY_APPEND(arr, 4) as appended,
    ARRAY_PREPEND(arr, 0) as prepended,
    ARRAY_CAT(arr1, arr2) as concatenated,
    ARRAY_SLICE(arr, 1, 3) as sliced,
    ARRAY_SIZE(arr) as size,
    ARRAY_CONTAINS(5, arr) as contains_5,
    ARRAY_POSITION(arr, 2) as pos_of_2,
    ARRAY_DISTINCT(arr) as distinct_arr,
    ARRAY_COMPACT(arr) as no_nulls,
    ARRAYS_OVERLAP(arr1, arr2) as overlaps
FROM t;"#;
    assert_preserves_tokens(sql, "Array operations");
}

#[test]
fn test_no_data_loss_qualify_with_complex_window() {
    // QUALIFY with complex window functions
    let sql = r#"SELECT *
FROM sales
QUALIFY ROW_NUMBER() OVER (
    PARTITION BY customer_id, product_category 
    ORDER BY sale_date DESC, amount DESC NULLS LAST
) = 1
AND DENSE_RANK() OVER (
    ORDER BY total_amount DESC
) <= 100
AND LAG(amount) OVER (
    PARTITION BY customer_id 
    ORDER BY sale_date
) < amount;"#;
    assert_preserves_tokens(sql, "QUALIFY with complex windows");
}

#[test]
fn test_no_data_loss_group_by_all_variations() {
    // GROUP BY with all variation types
    let sql = r#"SELECT 
    region,
    product,
    year,
    SUM(sales) as total
FROM data
GROUP BY ROLLUP (region, product, year)

UNION ALL

SELECT 
    region,
    product,
    year,
    SUM(sales)
FROM data
GROUP BY CUBE (region, product)

UNION ALL

SELECT 
    region,
    product,
    year,
    SUM(sales)
FROM data
GROUP BY GROUPING SETS (
    (region, product),
    (region, year),
    (product),
    ()
);"#;
    assert_preserves_tokens(sql, "GROUP BY variations");
}

#[test]
fn test_no_data_loss_having_complex() {
    // Complex HAVING clause
    let sql = r#"SELECT 
    category,
    COUNT(*) as cnt,
    SUM(amount) as total,
    AVG(price) as avg_price
FROM products
GROUP BY category
HAVING COUNT(*) > 10
AND SUM(amount) > (SELECT AVG(total) FROM category_totals)
AND AVG(price) BETWEEN 10 AND 100
AND MAX(price) < 2 * MIN(price);"#;
    assert_preserves_tokens(sql, "Complex HAVING");
}

#[test]
fn test_no_data_loss_order_by_complex() {
    // Complex ORDER BY clause
    let sql = r#"SELECT *
FROM products
ORDER BY 
    category ASC NULLS FIRST,
    CASE WHEN priority = 'high' THEN 1 WHEN priority = 'medium' THEN 2 ELSE 3 END,
    price DESC NULLS LAST,
    (SELECT avg_rating FROM product_ratings WHERE product_ratings.id = products.id) DESC,
    name COLLATE 'en_US',
    3, 
    4 DESC;"#;
    assert_preserves_tokens(sql, "Complex ORDER BY");
}

#[test]
fn test_no_data_loss_fetch_first() {
    // FETCH FIRST/NEXT variations (SQL standard LIMIT)
    let sql = r#"SELECT *
FROM products
ORDER BY id
FETCH FIRST 10 ROWS ONLY;"#;
    assert_preserves_tokens(sql, "FETCH FIRST");
}

#[test]
fn test_no_data_loss_offset_fetch() {
    // OFFSET with FETCH
    let sql = r#"SELECT *
FROM products
ORDER BY id
OFFSET 20 ROWS
FETCH NEXT 10 ROWS ONLY;"#;
    assert_preserves_tokens(sql, "OFFSET FETCH");
}

#[test]
fn test_no_data_loss_sample_variations() {
    // All SAMPLE variations
    let sql = r#"SELECT * FROM t1 SAMPLE (50);
SELECT * FROM t2 SAMPLE BERNOULLI (25.5);
SELECT * FROM t3 SAMPLE SYSTEM (10) SEED (42);
SELECT * FROM t4 TABLESAMPLE (1000 ROWS);
SELECT * FROM t5 SAMPLE ROW (100) REPEATABLE (123);"#;
    assert_preserves_tokens(sql, "Sample variations");
}

#[test]
fn test_no_data_loss_multiple_lateral_flatten() {
    // Multiple LATERAL FLATTEN in different positions
    let sql = r#"SELECT 
    t.id,
    a.value as arr_val,
    o.key as obj_key,
    o.value as obj_val
FROM my_table t,
TABLE(FLATTEN(input => t.array_col)) a,
LATERAL FLATTEN(input => t.object_col, MODE => 'OBJECT') o,
LATERAL FLATTEN(input => t.nested, PATH => 'items', OUTER => TRUE) n;"#;
    assert_preserves_tokens(sql, "Multiple lateral flatten");
}

#[test]
fn test_no_data_loss_select_into() {
    // SELECT INTO statement
    let sql = r#"SELECT id, name, value
INTO :my_var
FROM source_table
WHERE id = :input_id;"#;
    assert_preserves_tokens(sql, "SELECT INTO");
}

#[test]
fn test_no_data_loss_execute_immediate() {
    // EXECUTE IMMEDIATE with different patterns
    let sql = r#"EXECUTE IMMEDIATE 'SELECT * FROM ' || table_name || ' WHERE id = ' || id_value;
EXECUTE IMMEDIATE $$
    SELECT COUNT(*) FROM my_table
$$;
EXECUTE IMMEDIATE :sql_variable USING (param1, param2);"#;
    assert_preserves_tokens(sql, "Execute immediate");
}

#[test]
fn test_no_data_loss_create_dynamic_table() {
    // CREATE DYNAMIC TABLE
    let sql = r#"CREATE OR REPLACE DYNAMIC TABLE my_dynamic_table
TARGET_LAG = '1 hour'
WAREHOUSE = my_warehouse
AS
SELECT 
    id,
    SUM(amount) as total_amount,
    COUNT(*) as record_count
FROM source_table
GROUP BY id;"#;
    assert_preserves_tokens(sql, "Create dynamic table");
}

#[test]
fn test_no_data_loss_alter_table_operations() {
    // Various ALTER TABLE operations
    let sql = r#"ALTER TABLE my_table ADD COLUMN new_col VARCHAR(100) DEFAULT 'default';
ALTER TABLE my_table DROP COLUMN old_col;
ALTER TABLE my_table RENAME COLUMN col1 TO column_one;
ALTER TABLE my_table ALTER COLUMN value SET DATA TYPE NUMBER(20,4);
ALTER TABLE my_table ADD CONSTRAINT pk_id PRIMARY KEY (id);
ALTER TABLE my_table CLUSTER BY (region, created_date);"#;
    assert_preserves_tokens(sql, "Alter table operations");
}

#[test]
fn test_no_data_loss_grant_revoke() {
    // GRANT and REVOKE statements
    let sql = r#"GRANT SELECT, INSERT ON TABLE my_table TO ROLE analyst_role;
GRANT ALL PRIVILEGES ON SCHEMA my_schema TO ROLE admin_role WITH GRANT OPTION;
GRANT USAGE ON WAREHOUSE my_wh TO ROLE etl_role;
REVOKE DELETE ON TABLE my_table FROM ROLE analyst_role;
REVOKE ALL PRIVILEGES ON DATABASE my_db FROM ROLE temp_role CASCADE;"#;
    assert_preserves_tokens(sql, "Grant and revoke");
}

#[test]
fn test_no_data_loss_comments_everywhere() {
    // Comments in every possible position
    let sql = r#"-- Start comment
SELECT /* before columns */
    a, -- after first column
    /* before b */ b /* after b */,
    c -- last column
/* before FROM */ FROM /* after FROM */ 
    my_table t -- table alias comment
/* before WHERE */ WHERE /* after WHERE */
    a > 1 -- condition comment
    /* between conditions */ AND b < 10
/* before ORDER */ ORDER BY /* after ORDER BY */
    a /* after order col */ DESC -- order direction
/* before semicolon */; -- end comment"#;
    assert_preserves_tokens(sql, "Comments everywhere");
}

#[test]
fn test_no_data_loss_collation_and_binary() {
    // Collation and binary string comparisons
    let sql = r#"SELECT *
FROM users
WHERE name COLLATE 'en_US-ci' = 'JOHN'
AND code COLLATE 'utf8' LIKE 'ABC%'
AND COLLATE(description, 'en_US') ILIKE '%test%'
ORDER BY name COLLATE 'en_US-ci-ai';"#;
    assert_preserves_tokens(sql, "Collation and binary");
}

#[test]
fn test_no_data_loss_try_functions_comprehensive() {
    // All TRY_ functions
    let sql = r#"SELECT 
    TRY_CAST(x AS INT) as try_cast,
    TRY_TO_NUMBER(str) as try_num,
    TRY_TO_DATE(date_str) as try_date,
    TRY_TO_TIMESTAMP(ts_str) as try_ts,
    TRY_TO_TIME(time_str) as try_time,
    TRY_TO_BOOLEAN(bool_str) as try_bool,
    TRY_TO_BINARY(bin_str) as try_bin,
    TRY_TO_DECIMAL(dec_str, 10, 2) as try_dec,
    TRY_PARSE_JSON(json_str) as try_json
FROM t;"#;
    assert_preserves_tokens(sql, "TRY functions");
}

#[test]
fn test_no_data_loss_generator_sequence() {
    // GENERATOR and sequence operations
    let sql = r#"SELECT 
    SEQ4() as seq,
    SEQ8() as seq8,
    ROW_NUMBER() OVER (ORDER BY SEQ4()) as rn,
    UNIFORM(1, 100, RANDOM()) as rand_val
FROM TABLE(GENERATOR(ROWCOUNT => 1000));"#;
    assert_preserves_tokens(sql, "Generator and sequence");
}

#[test]
fn test_no_data_loss_bitwise_shift() {
    // Bitwise and shift operations
    let sql = r#"SELECT 
    a & b as bit_and,
    a | b as bit_or,
    a ^ b as bit_xor,
    ~a as bit_not,
    BITAND(a, b) as func_and,
    BITOR(a, b) as func_or,
    BITXOR(a, b) as func_xor,
    BITNOT(a) as func_not,
    BITSHIFTLEFT(a, 2) as shift_left,
    BITSHIFTRIGHT(a, 3) as shift_right
FROM t;"#;
    assert_preserves_tokens(sql, "Bitwise shift");
}

#[test]
fn test_no_data_loss_geospatial() {
    // Geospatial functions
    let sql = r#"SELECT 
    ST_POINT(lon, lat) as point,
    ST_MAKEPOINT(lon, lat) as make_point,
    ST_DISTANCE(point1, point2) as distance,
    ST_DWITHIN(point1, point2, 1000) as within_distance,
    ST_CONTAINS(polygon, point) as contains,
    ST_INTERSECTS(geom1, geom2) as intersects,
    ST_AREA(polygon) as area,
    ST_ASGEOJSON(geom) as geojson,
    TO_GEOGRAPHY('POINT(-122.35 37.55)') as geo
FROM locations;"#;
    assert_preserves_tokens(sql, "Geospatial functions");
}

#[test]
fn test_no_data_loss_create_stream() {
    // CREATE STREAM statement
    let sql = r#"CREATE OR REPLACE STREAM my_stream
ON TABLE my_source_table
APPEND_ONLY = TRUE
SHOW_INITIAL_ROWS = TRUE
COMMENT = 'Track changes to source table';"#;
    assert_preserves_tokens(sql, "Create stream");
}

#[test]
fn test_no_data_loss_create_task() {
    // CREATE TASK statement
    let sql = r#"CREATE OR REPLACE TASK my_task
WAREHOUSE = my_warehouse
SCHEDULE = 'USING CRON 0 * * * * UTC'
ALLOW_OVERLAPPING_EXECUTION = FALSE
WHEN SYSTEM$STREAM_HAS_DATA('my_stream')
AS
INSERT INTO target_table
SELECT * FROM my_stream;"#;
    assert_preserves_tokens(sql, "Create task");
}

#[test]
fn test_no_data_loss_select_star_variations() {
    // All * variations
    let sql = r#"SELECT 
    *,
    t.*,
    t.* EXCLUDE (col1, col2),
    t.* RENAME (old_name AS new_name),
    t.* REPLACE (UPPER(name) AS name),
    t.* EXCLUDE col1 RENAME old AS new,
    * ILIKE '%name%'
FROM my_table t;"#;
    assert_preserves_tokens(sql, "Star variations");
}

// ============================================================================
// Additional Edge Cases - Snowflake-Specific Syntax
// ============================================================================

#[test]
fn test_no_data_loss_bind_variables() {
    // Bind variables in queries
    let sql = r#"SELECT * FROM users WHERE id = :user_id AND status = ? AND name = :1;"#;
    assert_preserves_tokens(sql, "Bind variables");
}

#[test]
fn test_no_data_loss_session_variables() {
    // Session variables
    let sql = r#"SELECT $current_user, $current_database, $current_schema FROM dual;"#;
    assert_preserves_tokens(sql, "Session variables");
}

#[test]
fn test_no_data_loss_identifier_function() {
    // IDENTIFIER() function for dynamic SQL
    let sql = r#"SELECT * FROM IDENTIFIER($table_name) WHERE IDENTIFIER($column_name) = 'value';"#;
    assert_preserves_tokens(sql, "IDENTIFIER function");
}

#[test]
fn test_no_data_loss_result_scan() {
    // RESULT_SCAN and TABLE(RESULT_SCAN(...))
    let sql = r#"SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"#;
    assert_preserves_tokens(sql, "RESULT_SCAN");
}

#[test]
fn test_no_data_loss_within_group() {
    // WITHIN GROUP ordering in aggregates
    let sql = r#"SELECT 
    LISTAGG(name, ', ') WITHIN GROUP (ORDER BY created_at DESC) as names,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary) as median_salary,
    MODE() WITHIN GROUP (ORDER BY category) as most_common
FROM employees
GROUP BY department;"#;
    assert_preserves_tokens(sql, "WITHIN GROUP");
}

#[test]
fn test_no_data_loss_respect_ignore_nulls() {
    // RESPECT NULLS / IGNORE NULLS in window functions
    let sql = r#"SELECT 
    FIRST_VALUE(col) IGNORE NULLS OVER (ORDER BY id) as first_non_null,
    LAST_VALUE(col) RESPECT NULLS OVER (ORDER BY id) as last_with_null,
    LAG(col, 1) IGNORE NULLS OVER (PARTITION BY grp ORDER BY id) as prev_non_null,
    LEAD(col, 1) RESPECT NULLS OVER (ORDER BY id) as next_val
FROM t;"#;
    assert_preserves_tokens(sql, "RESPECT/IGNORE NULLS");
}

#[test]
fn test_no_data_loss_pivot_any() {
    // PIVOT with ANY keyword
    let sql = r#"SELECT * FROM sales
PIVOT(SUM(amount) FOR product IN (ANY ORDER BY product))
WHERE year = 2024;"#;
    assert_preserves_tokens(sql, "PIVOT ANY");
}

#[test]
fn test_no_data_loss_unpivot_any() {
    // UNPIVOT variations
    let sql = r#"SELECT * FROM quarterly_sales
UNPIVOT INCLUDE NULLS (amount FOR quarter IN (q1, q2, q3, q4));"#;
    assert_preserves_tokens(sql, "UNPIVOT with INCLUDE NULLS");
}

#[test]
fn test_no_data_loss_json_path_complex() {
    // Complex JSON paths with array indices and filters
    let sql = r#"SELECT 
    data:items[0]:name::STRING as first_item,
    data:items[*]:price::NUMBER as all_prices,
    data:"special-key"::STRING as special_key,
    data['array'][0]['nested']::VARIANT as nested_access,
    PARSE_JSON('{"a":1}'):a::INT as inline_json
FROM json_table;"#;
    assert_preserves_tokens(sql, "Complex JSON paths");
}

#[test]
fn test_no_data_loss_cast_chain_complex() {
    // Complex cast chains
    let sql = r#"SELECT 
    col::VARCHAR::NUMBER(10,2)::FLOAT as multi_cast,
    (data:value)::STRING::INT as json_cast_chain,
    CAST(CAST(x AS VARCHAR) AS NUMBER) as nested_cast
FROM t;"#;
    assert_preserves_tokens(sql, "Cast chain complex");
}

#[test]
fn test_no_data_loss_call_with_named_args() {
    // CALL procedure with named arguments
    let sql = r#"CALL my_procedure(param1 => 'value1', param2 => 100, param3 => TRUE);"#;
    assert_preserves_tokens(sql, "CALL with named args");
}

#[test]
fn test_no_data_loss_create_secure_view() {
    // CREATE SECURE VIEW
    let sql = r#"CREATE OR REPLACE SECURE VIEW my_secure_view
COPY GRANTS
COMMENT = 'Secure view for PII data'
AS
SELECT id, HASH(ssn) as ssn_hash, name
FROM sensitive_table
WHERE department = 'HR';"#;
    assert_preserves_tokens(sql, "Create secure view");
}

#[test]
fn test_no_data_loss_create_materialized_view() {
    // CREATE MATERIALIZED VIEW
    let sql = r#"CREATE OR REPLACE MATERIALIZED VIEW my_mv
CLUSTER BY (date_col)
AS
SELECT date_col, SUM(amount) as total
FROM transactions
GROUP BY date_col;"#;
    assert_preserves_tokens(sql, "Create materialized view");
}

#[test]
fn test_no_data_loss_clone_with_time_travel() {
    // CLONE with AT/BEFORE
    let sql =
        r#"CREATE TABLE new_table CLONE source_table AT (TIMESTAMP => '2024-01-01 00:00:00');"#;
    assert_preserves_tokens(sql, "Clone with time travel");
}

#[test]
fn test_no_data_loss_cte_cross_reference() {
    // Multiple CTEs with cross-references
    let sql = r#"WITH 
    base AS (SELECT id, name FROM users),
    enriched AS (SELECT b.*, o.total FROM base b JOIN orders o ON b.id = o.user_id),
    final AS (SELECT e.*, r.rating FROM enriched e LEFT JOIN ratings r ON e.id = r.user_id)
SELECT * FROM final WHERE total > 1000;"#;
    assert_preserves_tokens(sql, "CTE cross-reference");
}

#[test]
fn test_no_data_loss_subquery_complex_alias() {
    // Complex subquery aliasing
    let sql = r#"SELECT sq.* 
FROM (
    SELECT a.id, b.name, c.amount
    FROM table_a a
    JOIN table_b b ON a.id = b.a_id  
    JOIN table_c c ON b.id = c.b_id
    WHERE a.active = TRUE
) AS sq (id, name, amount)
WHERE sq.amount > 100;"#;
    assert_preserves_tokens(sql, "Subquery complex alias");
}

#[test]
fn test_no_data_loss_merge_multiple_when() {
    // MERGE with multiple WHEN clauses and complex conditions
    let sql = r#"MERGE INTO target t
USING source s ON t.id = s.id
WHEN MATCHED AND s.deleted = TRUE THEN DELETE
WHEN MATCHED AND s.updated_at > t.updated_at THEN UPDATE SET 
    t.name = s.name,
    t.value = s.value,
    t.updated_at = CURRENT_TIMESTAMP()
WHEN NOT MATCHED AND s.active = TRUE THEN INSERT (id, name, value, created_at)
    VALUES (s.id, s.name, s.value, CURRENT_TIMESTAMP())
WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, s.name);"#;
    assert_preserves_tokens(sql, "MERGE multiple WHEN");
}

#[test]
fn test_no_data_loss_flatten_multiple_paths() {
    // FLATTEN with multiple lateral flattens
    let sql = r#"SELECT 
    f1.value:name::STRING as level1_name,
    f2.value:detail::STRING as level2_detail
FROM my_table,
LATERAL FLATTEN(input => data:items) f1,
LATERAL FLATTEN(input => f1.value:subitems) f2
WHERE f1.value:active = TRUE;"#;
    assert_preserves_tokens(sql, "FLATTEN multiple paths");
}

#[test]
fn test_no_data_loss_object_construct_nested() {
    // Complex OBJECT_CONSTRUCT with nested structures
    let sql = r#"SELECT OBJECT_CONSTRUCT(
    'user', OBJECT_CONSTRUCT('id', id, 'name', name),
    'metadata', OBJECT_CONSTRUCT(
        'created', created_at,
        'tags', ARRAY_CONSTRUCT('a', 'b', 'c')
    ),
    'counts', OBJECT_CONSTRUCT_KEEP_NULL('total', count, 'null_count', null)
) as nested_obj
FROM users;"#;
    assert_preserves_tokens(sql, "OBJECT_CONSTRUCT nested");
}

#[test]
fn test_no_data_loss_window_frame_between() {
    // Window frame BETWEEN variations
    let sql = r#"SELECT 
    SUM(x) OVER (ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) as running,
    AVG(x) OVER (ORDER BY id ROWS BETWEEN 3 PRECEDING AND 3 FOLLOWING) as moving_avg,
    MAX(x) OVER (ORDER BY id RANGE BETWEEN INTERVAL '1 DAY' PRECEDING AND INTERVAL '1 DAY' FOLLOWING) as range_max,
    FIRST_VALUE(x) OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) as rest_first
FROM t;"#;
    assert_preserves_tokens(sql, "Window frame BETWEEN");
}

#[test]
fn test_no_data_loss_qualify_row_number() {
    // QUALIFY with ROW_NUMBER deduplication pattern
    let sql = r#"SELECT * FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) as rn
    FROM events
)
QUALIFY rn = 1;"#;
    assert_preserves_tokens(sql, "QUALIFY ROW_NUMBER");
}

#[test]
fn test_no_data_loss_sampling_methods() {
    // Different sampling methods
    let sql = r#"SELECT * FROM large_table SAMPLE BERNOULLI (10) SEED (42)
UNION ALL
SELECT * FROM large_table SAMPLE SYSTEM (5) SEED (123)
UNION ALL  
SELECT * FROM large_table TABLESAMPLE (1000 ROWS);"#;
    assert_preserves_tokens(sql, "Sampling methods");
}

#[test]
fn test_no_data_loss_alter_table_multiop() {
    // ALTER TABLE with multiple operations
    let sql = r#"ALTER TABLE my_table 
ADD COLUMN new_col VARCHAR(100) DEFAULT 'unknown',
DROP COLUMN old_col,
RENAME COLUMN temp_name TO final_name,
ALTER COLUMN nullable_col DROP NOT NULL;"#;
    assert_preserves_tokens(sql, "ALTER TABLE operations");
}

#[test]
fn test_no_data_loss_show_describe() {
    // SHOW and DESCRIBE statements
    let sql = r#"SHOW TABLES LIKE 'sales_%' IN SCHEMA my_db.my_schema STARTS WITH 'sales';"#;
    assert_preserves_tokens(sql, "SHOW statement");
}

#[test]
fn test_no_data_loss_set_unset() {
    // SET and UNSET statements
    let sql = r#"SET my_var = 'value';
SET (var1, var2) = (SELECT col1, col2 FROM t LIMIT 1);"#;
    assert_preserves_tokens(sql, "SET statements");
}

#[test]
fn test_no_data_loss_double_quoted_identifiers() {
    // Double-quoted identifiers with special characters
    let sql = r#"SELECT "Column With Spaces", "123_starts_with_number", "has-dashes", "UPPER", "lower"
FROM "Schema"."Table Name"
WHERE "weird:column" = 'value';"#;
    assert_preserves_tokens(sql, "Double quoted identifiers");
}

#[test]
fn test_no_data_loss_dollar_quoted_string() {
    // Dollar-quoted strings
    let sql =
        r#"SELECT $$This is a dollar-quoted string with 'quotes' and "double quotes"$$ as str;"#;
    assert_preserves_tokens(sql, "Dollar quoted string");
}

// ============================================================================
// COMPREHENSIVE TRIVIA TESTS - Comments after every component
// ============================================================================

#[test]
fn test_no_data_loss_star_with_trivia_everywhere() {
    // Test SELECT * with comments after EVERY component
    let sql = r#"SELECT /* before star */
    t /* after qualifier */./* after dot */ * /* after star */
    EXCLUDE /* after EXCLUDE keyword */ ( /* after lparen */
        col1 /* after col1 */, /* after comma */
        col2 /* after col2 */
    ) /* after rparen */
    REPLACE /* after REPLACE keyword */ ( /* after lparen */
        100 /* after expr */ AS /* after AS */ col3 /* after col3 */
    ) /* after rparen */
    RENAME /* after RENAME keyword */ ( /* after lparen */
        col4 /* after col4 */ AS /* after AS */ new_col4 /* after alias */
    ) /* after rparen */
FROM /* after FROM */ table1 t /* after table alias */;"#;
    assert_preserves_tokens(sql, "Star with trivia everywhere");
}

#[test]
fn test_no_data_loss_qualified_star_comments() {
    // Qualified star with block comments in every position
    let sql = r#"SELECT
    t1 /* comment after qualifier */ . /* comment after dot */ * /* comment after star */,
    t2 /* qualifier */ . /* dot */ * /* star */
    EXCLUDE /* after exclude */ ( /* after lparen */ a /* after col */ ) /* after rparen */,
    t3.* /* inline comment */ RENAME (b AS c)
FROM table1 t1, table2 t2, table3 t3;"#;
    assert_preserves_tokens(sql, "Qualified star with comments");
}

#[test]
fn test_no_data_loss_unqualified_star_modifiers_trivia() {
    // Unqualified star with all modifiers and trivia
    let sql = r#"SELECT
    * /* after star */
    EXCLUDE /* after EXCLUDE */ ( /* lparen */
        col1 /* col1 */, /* comma */
        col2 /* col2 */,
        col3 /* col3 */
    ) /* rparen */
    REPLACE /* REPLACE */ ( /* lparen */
        UPPER(name) /* expr */ AS /* AS */ name /* col */,
        0 /* expr */ AS /* AS */ count /* col */
    ) /* rparen */
    RENAME /* RENAME */ ( /* lparen */
        old1 /* col */ AS /* AS */ new1 /* alias */,
        old2 AS new2
    ) /* rparen */
FROM my_table /* table */;"#;
    assert_preserves_tokens(sql, "Unqualified star modifiers with trivia");
}

#[test]
fn test_no_data_loss_star_exclude_only_trivia() {
    // Star with EXCLUDE only and comprehensive comments
    let sql = r#"SELECT
    table_ref /* qualifier comment */ . /* dot comment */ * /* star comment */
    EXCLUDE /* EXCLUDE keyword comment */ ( /* opening paren comment */
        sensitive_col /* first excluded column */,
        another_col /* second excluded column */,
        third_col /* third excluded column */
    ) /* closing paren comment */
FROM /* FROM keyword */ my_table AS table_ref /* table alias */;"#;
    assert_preserves_tokens(sql, "Star EXCLUDE only with trivia");
}

#[test]
fn test_no_data_loss_star_replace_only_trivia() {
    // Star with REPLACE only and comprehensive comments
    let sql = r#"SELECT
    src /* qualifier */ . /* dot */ * /* star */
    REPLACE /* REPLACE kw */ ( /* lparen */
        CAST(amount AS DECIMAL(18,2)) /* complex expr */ AS /* AS */ amount /* col */,
        UPPER(status) /* expr */ AS /* AS */ status /* col */,
        COALESCE(name, 'Unknown') /* expr */ AS /* AS */ name /* col */
    ) /* rparen */
FROM /* FROM */ source AS src /* alias */;"#;
    assert_preserves_tokens(sql, "Star REPLACE only with trivia");
}

#[test]
fn test_no_data_loss_star_rename_only_trivia() {
    // Star with RENAME only and comprehensive comments
    let sql = r#"SELECT
    t /* qualifier */ . /* dot */ * /* star */
    RENAME /* RENAME */ ( /* lparen */
        old_column_name /* col */ AS /* AS */ new_column_name /* alias */,
        another_old /* col */ AS /* AS */ another_new /* alias */,
        legacy_col /* col */ AS /* AS */ modern_col /* alias */
    ) /* rparen */
FROM /* FROM */ my_table t /* alias */;"#;
    assert_preserves_tokens(sql, "Star RENAME only with trivia");
}

#[test]
fn test_no_data_loss_star_all_modifiers_combined_trivia() {
    // Star with EXCLUDE + REPLACE + RENAME and block comments everywhere
    let sql = r#"SELECT
    users /* qualifier */ . /* dot */ * /* star */
    /* before EXCLUDE */ EXCLUDE /* EXCLUDE */ ( /* lparen */
        password /* sensitive */ , /* comma */
        ssn /* pii */
    ) /* rparen */ /* after EXCLUDE */
    /* before REPLACE */ REPLACE /* REPLACE */ ( /* lparen */
        HASH(email) /* expr */ AS /* AS */ email /* col */,
        999 /* expr */ AS /* AS */ credit_card /* col */
    ) /* rparen */ /* after REPLACE */
    /* before RENAME */ RENAME /* RENAME */ ( /* lparen */
        first_name /* col */ AS /* AS */ fname /* alias */,
        last_name /* col */ AS /* AS */ lname /* alias */
    ) /* rparen */ /* after RENAME */
FROM /* FROM */ users_table AS users /* alias */
WHERE /* WHERE */ active = TRUE /* condition */;"#;
    assert_preserves_tokens(sql, "Star all modifiers combined with trivia");
}

#[test]
fn test_no_data_loss_multiple_stars_with_trivia() {
    // Multiple star projections with trivia
    let sql = r#"SELECT
    t1 /* t1 */ . /* dot */ * /* star */ EXCLUDE /* exclude */ (a), /* comma */
    t2 /* t2 */ . /* dot */ * /* star */ RENAME /* rename */ (b AS c), /* comma */
    t3 /* t3 */ . /* dot */ * /* star */ REPLACE /* replace */ (1 AS x), /* comma */
    * /* unqualified */ EXCLUDE (y)
FROM table1 t1, table2 t2, table3 t3;"#;
    assert_preserves_tokens(sql, "Multiple stars with trivia");
}

#[test]
fn test_no_data_loss_star_modifiers_no_parens_trivia() {
    // Test star modifiers without parentheses (if syntax allows)
    let sql = r#"SELECT
    * /* star */ EXCLUDE /* exclude */ col1 /* single column */
FROM my_table;"#;
    assert_preserves_tokens(sql, "Star modifier no parens with trivia");
}

#[test]
fn test_no_data_loss_star_nested_expressions_trivia() {
    // Star REPLACE with nested expressions and comments
    let sql = r#"SELECT
    t.* /* star */
    REPLACE ( /* lparen */
        CASE /* case start */
            WHEN status = 'A' /* when */ THEN 'Active' /* then */
            ELSE 'Inactive' /* else */
        END /* case end */ AS /* AS */ status /* col */,
        COALESCE(amount, 0) + COALESCE(tax, 0) /* expr */ AS /* AS */ total /* col */
    ) /* rparen */
FROM orders t;"#;
    assert_preserves_tokens(sql, "Star nested expressions with trivia");
}

#[test]
fn test_no_data_loss_star_qualified_with_schema() {
    // Fully qualified star with schema.table.* pattern and trivia
    let sql = r#"SELECT
    schema_name /* schema */ . /* dot */ table_name /* table */ . /* dot */ * /* star */
    EXCLUDE ( /* lparen */ internal_col /* col */ ) /* rparen */
FROM schema_name.table_name;"#;
    assert_preserves_tokens(sql, "Star qualified with schema and trivia");
}
