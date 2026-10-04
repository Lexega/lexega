// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for LIKE, ILIKE, RLIKE operators with ESCAPE clause
use lexega_syntax::parse_sql;

#[test]
fn test_like_basic() {
    let sql = "SELECT * FROM employees WHERE name LIKE 'John%';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse basic LIKE");
}

#[test]
fn test_like_with_underscore_wildcard() {
    let sql = "SELECT * FROM users WHERE email LIKE 'j___@example.com';";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse LIKE with underscore wildcard"
    );
}

#[test]
fn test_ilike_case_insensitive() {
    let sql = "SELECT * FROM products WHERE description ILIKE '%snowflake%';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse ILIKE");
}

#[test]
fn test_rlike_regex() {
    let sql = "SELECT * FROM logs WHERE message RLIKE '^ERROR.*timeout$';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse RLIKE");
}

#[test]
fn test_not_like() {
    let sql = "SELECT * FROM customers WHERE country NOT LIKE 'US%';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse NOT LIKE");
}

#[test]
fn test_not_ilike() {
    let sql = "SELECT * FROM items WHERE category NOT ILIKE '%temp%';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse NOT ILIKE");
}

#[test]
fn test_not_rlike() {
    let sql = "SELECT * FROM data WHERE field NOT RLIKE '[0-9]+';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse NOT RLIKE");
}

#[test]
fn test_like_with_escape() {
    let sql = "SELECT * FROM files WHERE filename LIKE '%.txt' ESCAPE '.';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse LIKE with ESCAPE");
}

#[test]
fn test_like_with_escape_backslash() {
    let sql = r#"SELECT * FROM paths WHERE path LIKE 'C:\%' ESCAPE '\';"#;
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse LIKE with backslash ESCAPE");
}

#[test]
fn test_ilike_with_escape() {
    let sql = "SELECT * FROM tags WHERE name ILIKE '#%tag%' ESCAPE '#';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse ILIKE with ESCAPE");
}

#[test]
fn test_like_in_where_with_and() {
    let sql = "SELECT * FROM orders WHERE status LIKE 'SHIP%' AND total > 100;";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse LIKE with AND");
}

#[test]
fn test_like_in_where_with_or() {
    let sql = "SELECT * FROM users WHERE name LIKE 'A%' OR name LIKE 'B%';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse LIKE with OR");
}

#[test]
fn test_like_with_column_reference() {
    let sql = "SELECT * FROM t1, t2 WHERE t1.name LIKE t2.pattern;";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse LIKE with column reference as pattern"
    );
}

#[test]
fn test_multiple_like_conditions() {
    let sql =
        "SELECT * FROM data WHERE field1 LIKE 'A%' AND field2 ILIKE '%B' AND field3 NOT LIKE 'C%';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse multiple LIKE conditions");
}

#[test]
fn test_like_in_case_expression() {
    let sql = r#"
SELECT 
    CASE 
        WHEN name LIKE 'A%' THEN 'Group A'
        WHEN name ILIKE 'b%' THEN 'Group B'
        ELSE 'Other'
    END as category
FROM employees;
"#;
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse LIKE in CASE expression");
}

#[test]
fn test_like_in_scripting_block() {
    let src = r#"
BEGIN
    LET pattern := 'SNOW%';
    SELECT * FROM products WHERE name LIKE :pattern;
    RETURN 'done';
END;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "Failed to parse LIKE in scripting block");
}

#[test]
fn test_like_with_function_call_pattern() {
    let sql = "SELECT * FROM users WHERE email LIKE CONCAT('%', '@example.com');";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse LIKE with function call as pattern"
    );
}

#[test]
fn test_not_like_with_escape() {
    let sql = "SELECT * FROM records WHERE data NOT LIKE '|%%' ESCAPE '|';";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse NOT LIKE with ESCAPE");
}

#[test]
fn test_like_in_subquery() {
    let sql = r#"
SELECT * FROM customers 
WHERE customer_id IN (
    SELECT customer_id FROM orders WHERE product_name LIKE '%Widget%'
);
"#;
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse LIKE in subquery");
}

#[test]
fn test_like_in_cte() {
    let sql = r#"
WITH filtered_users AS (
    SELECT * FROM users WHERE username ILIKE 'admin%'
)
SELECT * FROM filtered_users;
"#;
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse LIKE in CTE");
}

// Additional tests based on Snowflake documentation examples

#[test]
fn test_like_doc_example_multiple_wildcards() {
    // From docs: WHERE name LIKE '%Jo%oe%'
    let sql = "SELECT name FROM like_ex WHERE name LIKE '%Jo%oe%' ORDER BY name;";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse LIKE with multiple wildcards (doc example)"
    );
}

#[test]
fn test_ilike_doc_example_case_insensitive() {
    // From docs: WHERE name ILIKE '%j%h%do%'
    let sql = "SELECT * FROM ilike_ex WHERE name ILIKE '%j%h%do%' ORDER BY 1;";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse ILIKE case insensitive (doc example)"
    );
}

#[test]
fn test_like_doc_example_escape_underscore() {
    // From docs: WHERE name LIKE '%J%h%^_do%' ESCAPE '^'
    let sql = "SELECT name FROM like_ex WHERE name LIKE '%J%h%^_do%' ESCAPE '^' ORDER BY name;";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse LIKE with escaped underscore (doc example)"
    );
}

#[test]
fn test_like_doc_example_escape_percent_literal() {
    // From docs: WHERE name LIKE '100^%' ESCAPE '^'
    let sql = "SELECT * FROM like_ex WHERE name LIKE '100^%' ESCAPE '^' ORDER BY 1;";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse LIKE with escaped percent sign (doc example)"
    );
}

#[test]
fn test_like_doc_example_backslash_escape() {
    // From docs: WHERE name LIKE '100\\%' ESCAPE '\\'
    let sql = r"SELECT * FROM like_ex WHERE name LIKE '100\\%' ESCAPE '\\' ORDER BY 1;";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse LIKE with backslash escape (doc example)"
    );
}

#[test]
fn test_rlike_doc_example_regex_pattern() {
    // From docs: WHERE city RLIKE 'San.* [fF].*'
    let sql = "SELECT * FROM rlike_ex WHERE city RLIKE 'San.* [fF].*';";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse RLIKE with regex pattern (doc example)"
    );
}

#[test]
fn test_not_ilike_doc_example() {
    // From docs: WHERE name NOT ILIKE '%j%h%do%'
    let sql = "SELECT * FROM ilike_ex WHERE name NOT ILIKE '%j%h%do%' ORDER BY 1;";
    let result = parse_sql(sql);
    assert!(result.is_ok(), "Failed to parse NOT ILIKE (doc example)");
}

#[test]
fn test_ilike_doc_example_escape_underscore() {
    // From docs: WHERE name ILIKE '%j%h%^_do%' ESCAPE '^'
    let sql = "SELECT * FROM ilike_ex WHERE name ILIKE '%j%h%^_do%' ESCAPE '^' ORDER BY 1;";
    let result = parse_sql(sql);
    assert!(
        result.is_ok(),
        "Failed to parse ILIKE with escaped underscore (doc example)"
    );
}
