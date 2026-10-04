// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Smart Jinja Positioning Tests
//!
//! Tests for Jinja control blocks ({% if %}, {% for %}) in expression contexts:
//! - FROM clause: table name selection
//! - WHERE clause: conditional filters
//! - JOIN conditions: dynamic join logic
//! - GROUP BY, ORDER BY, HAVING: conditional clauses

use lexega_syntax::{format_sql, parse_select_from_tokens, tokenize};

/// Helper to format SQL and return result
fn format(sql: &str) -> String {
    match format_sql(sql) {
        Ok(formatted) => formatted,
        Err(e) => panic!("Format error: {}", e),
    }
}

/// Helper to verify SQL parses successfully
fn assert_parses(sql: &str) {
    let lex_result = tokenize(sql);
    assert!(!lex_result.tokens.is_empty(), "Lexer should produce tokens");

    let stmt = parse_select_from_tokens(sql, &lex_result.tokens);
    assert!(stmt.is_some(), "Parser should successfully parse: {}", sql);
}

#[test]
fn test_jinja_if_in_from_clause() {
    let sql = r#"
SELECT *
FROM {% if env == 'prod' %}production{% else %}development{% endif %}.orders
"#;

    assert_parses(sql);
    let formatted = format(sql);

    // Should preserve Jinja structure
    assert!(formatted.contains("{% if env == 'prod' %}"));
    assert!(formatted.contains("{% else %}"));
    assert!(formatted.contains("{% endif %}"));
}

#[test]
fn test_jinja_if_in_from_clause_with_elif() {
    let sql = r#"
SELECT *
FROM {% if env == 'prod' %}prod{% elif env == 'staging' %}stage{% else %}dev{% endif %}.orders
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("{% if env == 'prod' %}"));
    assert!(formatted.contains("{% elif env == 'staging' %}"));
    assert!(formatted.contains("{% else %}"));
    assert!(formatted.contains("{% endif %}"));
}

#[test]
fn test_jinja_if_in_where_clause() {
    let sql = r#"
SELECT *
FROM orders
WHERE status = 'active'
  {% if min_amount %}AND amount >= {{ min_amount }}{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("WHERE"));
    assert!(formatted.contains("{% if min_amount %}"));
    assert!(formatted.contains("{% endif %}"));
}

#[test]
fn test_jinja_for_in_where_clause() {
    let sql = r#"
SELECT *
FROM orders
WHERE {% for status in statuses %}status = '{{ status }}'{% if not loop.last %} OR {% endif %}{% endfor %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("{% for status in statuses %}"));
    assert!(formatted.contains("{% endfor %}"));
}

#[test]
fn test_jinja_in_join_condition() {
    let sql = r#"
SELECT *
FROM orders o
JOIN customers c ON o.customer_id = {% if use_legacy %}c.old_id{% else %}c.id{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("JOIN"));
    assert!(formatted.contains("{% if use_legacy %}"));
    assert!(formatted.contains("{% else %}"));
    assert!(formatted.contains("{% endif %}"));
}

#[test]
fn test_jinja_in_group_by() {
    let sql = r#"
SELECT
    {% if group_by_region %}region,{% endif %}
    SUM(amount) as total
FROM orders
GROUP BY {% if group_by_region %}region{% else %}1{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("GROUP BY"));
    assert!(formatted.contains("{% if group_by_region %}"));
}

#[test]
fn test_jinja_in_order_by() {
    let sql = r#"
SELECT *
FROM orders
ORDER BY {% if sort_desc %}created_at DESC{% else %}created_at ASC{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("ORDER BY"));
    assert!(formatted.contains("{% if sort_desc %}"));
}

#[test]
fn test_jinja_in_having_clause() {
    let sql = r#"
SELECT region, COUNT(*) as count
FROM orders
GROUP BY region
HAVING {% if min_count %}COUNT(*) >= {{ min_count }}{% else %}COUNT(*) > 0{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("HAVING"));
    assert!(formatted.contains("{% if min_count %}"));
}

#[test]
fn test_nested_jinja_in_expression() {
    let sql = r#"
SELECT
    CASE
        WHEN {% if use_new_logic %}status = 'new'{% else %}status = 'pending'{% endif %} THEN 'active'
        ELSE 'inactive'
    END as status_category
FROM orders
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("CASE"));
    assert!(formatted.contains("{% if use_new_logic %}"));
}

#[test]
fn test_complex_where_with_multiple_jinja_blocks() {
    let sql = r#"
SELECT *
FROM orders
WHERE {% if filter_status %}status = '{{ status_value }}'{% endif %}
  {% if filter_amount %}AND amount > {{ min_amount }}{% endif %}
  {% if filter_date %}AND created_at > '{{ start_date }}'{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    // Should preserve all three Jinja blocks
    assert!(formatted.contains("{% if filter_status %}"));
    assert!(formatted.contains("{% if filter_amount %}"));
    assert!(formatted.contains("{% if filter_date %}"));
}

#[test]
fn test_jinja_with_complex_table_reference() {
    let sql = r#"
SELECT *
FROM {% if use_schema %}{{ schema }}.{% endif %}{% if use_prefix %}{{ prefix }}_{% endif %}orders
"#;

    assert_parses(sql);
    let formatted = format(sql);

    // Multiple Jinja expressions building table name
    assert!(formatted.contains("{% if use_schema %}"));
    assert!(formatted.contains("{% if use_prefix %}"));
}

#[test]
fn test_jinja_preserves_existing_projection_blocks() {
    // Ensure existing projection-block functionality still works
    let sql = r#"
SELECT
    {% for col in columns %}
        {{ col }}{% if not loop.last %},{% endif %}
    {% endfor %}
FROM orders
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("{% for col in columns %}"));
    assert!(formatted.contains("{% endfor %}"));
}

#[test]
fn test_jinja_in_subquery_from_clause() {
    let sql = r#"
SELECT *
FROM (
    SELECT *
    FROM {% if use_archive %}archive{% else %}current{% endif %}.orders
) subq
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("{% if use_archive %}"));
    assert!(formatted.contains("{% endif %}"));
}

#[test]
fn test_jinja_in_function_call() {
    let sql = r#"
SELECT
    CONCAT(
        {% if include_prefix %}'PREFIX_'{% else %}''{% endif %},
        name
    ) as formatted_name
FROM customers
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("CONCAT"));
    assert!(formatted.contains("{% if include_prefix %}"));
}

#[test]
fn test_jinja_in_between_expression() {
    let sql = r#"
SELECT *
FROM orders
WHERE amount BETWEEN {% if use_dynamic %}{{ min_val }}{% else %}0{% endif %} AND {% if use_dynamic %}{{ max_val }}{% else %}1000{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("BETWEEN"));
    assert!(formatted.contains("{% if use_dynamic %}"));
}

#[test]
fn test_multiple_jinja_blocks_same_line() {
    let sql = r#"
SELECT *
FROM {% if schema1 %}{{ schema1 }}{% else %}public{% endif %}.{% if prefix %}{{ prefix }}_{% endif %}orders
"#;

    assert_parses(sql);
    let formatted = format(sql);

    // Both blocks should be preserved
    assert!(formatted.contains("{% if schema1 %}"));
    assert!(formatted.contains("{% if prefix %}"));
}

#[test]
fn test_jinja_empty_else_branch() {
    // Test that empty else branches are handled correctly
    let sql = r#"
SELECT *
FROM orders
WHERE status = {% if custom_status %}'{{ status }}'{% else %}'pending'{% endif %}
"#;

    assert_parses(sql);
    let formatted = format(sql);

    assert!(formatted.contains("{% if custom_status %}"));
    assert!(formatted.contains("{% else %}"));
    assert!(formatted.contains("{% endif %}"));
}
