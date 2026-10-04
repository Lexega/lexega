// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Test statement fragments that start with FROM keyword
/// This tests the new functionality where Jinja blocks can wrap entire FROM clauses
use lexega_syntax::{format_sql_with_config, FormatterConfig};

#[test]
fn test_fragment_starting_with_from() {
    // Common dbt pattern: SELECT with projection, then Jinja block containing FROM
    let sql = r#"
SELECT id, name
{% if include_orders %}
FROM orders
WHERE status = 'active'
{% endif %}
"#;

    let result = format_sql_with_config(sql, &FormatterConfig::default());

    // Should parse and format successfully
    assert!(
        result.is_ok(),
        "Failed to format SQL with FROM in fragment: {:?}",
        result.err()
    );
}

#[test]
fn test_fragment_from_with_join() {
    // ClauseFragment with FROM + JOIN + WHERE
    let sql = r#"
{% if mode == 'full' %}
FROM customers c
JOIN orders o ON c.id = o.customer_id
WHERE o.amount > 100
{% endif %}
"#;

    let result = format_sql_with_config(sql, &FormatterConfig::default());

    // Should parse and format successfully as a ClauseFragment
    assert!(
        result.is_ok(),
        "Failed to format SQL with FROM+JOIN in fragment: {:?}",
        result.err()
    );
}

#[test]
fn test_fragment_from_multiple_tables() {
    // ClauseFragment with FROM listing multiple tables
    let sql = r#"
{% if use_full_dataset %}
FROM table1, table2, table3
WHERE table1.id = table2.ref_id
{% endif %}
"#;

    let result = format_sql_with_config(sql, &FormatterConfig::default());

    // Should parse and format successfully as a ClauseFragment
    assert!(
        result.is_ok(),
        "Failed to format SQL with FROM multiple tables in fragment: {:?}",
        result.err()
    );
}

#[test]
fn test_fragment_from_with_elif() {
    // ClauseFragment with FROM in elif branches
    let sql = r#"
{% if env == 'prod' %}
FROM prod_schema.users
WHERE active = true
{% elif env == 'dev' %}
FROM dev_schema.users
WHERE 1=1
{% else %}
FROM test_schema.users
{% endif %}
"#;

    let result = format_sql_with_config(sql, &FormatterConfig::default());

    // Should parse and format successfully as a ClauseFragment with branches
    assert!(
        result.is_ok(),
        "Failed to format SQL with FROM in elif branches: {:?}",
        result.err()
    );
}
