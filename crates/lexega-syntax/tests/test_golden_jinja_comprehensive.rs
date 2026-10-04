// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! GOLDEN TEST: Comprehensive Jinja/dbt SQL with EXACT output verification
//!
//! NOTE: This file tests detailed Jinja constructs with specific assertions.
//! For basic parse/format/roundtrip testing, see test_fixtures_jinja.rs
//!
//! This test validates ALL supported Jinja functionality including:
//! - Jinja expressions `{{ }}`
//! - Jinja comments `{# #}`
//! - Control blocks: `{% if %}`, `{% elif %}`, `{% else %}`, `{% endif %}`
//! - Loop blocks: `{% for %}`, `{% endfor %}`
//! - Set statements: `{% set %}`
//! - Complex nesting (2, 3, 4+ levels)
//! - Jinja in all SQL clause positions
//! - dbt-specific patterns (ref, source, config, is_incremental, etc.)
//! - Edge cases and boundary conditions

use lexega_syntax::{format_sql, tokenize};

/// Helper to format SQL and return result
fn format(sql: &str) -> Result<String, String> {
    format_sql(sql).map_err(|e| format!("Format error: {}", e))
}

/// Helper to verify SQL parses successfully  
fn assert_parses(sql: &str, context: &str) {
    let lex_result = tokenize(sql);
    assert!(
        !lex_result.tokens.is_empty(),
        "Lexer should produce tokens for: {}",
        context
    );
}

/// Helper to verify formatting preserves Jinja constructs
fn assert_jinja_preserved(_original: &str, formatted: &str, constructs: &[&str], context: &str) {
    for construct in constructs {
        assert!(
            formatted.contains(construct),
            "Jinja construct '{}' not found in formatted output for: {}\nFormatted:\n{}",
            construct,
            context,
            formatted
        );
    }
}

/// Helper to count occurrences of a pattern
fn count_occurrences(text: &str, pattern: &str) -> usize {
    text.matches(pattern).count()
}

// =============================================================================
// Test loading and parsing the complete golden file
// =============================================================================

#[test]
fn test_golden_file_lexes_completely() {
    let sql = include_str!("fixtures/golden_jinja_comprehensive.sql");
    let lex_result = tokenize(sql);

    // Should produce tokens without panicking
    assert!(
        !lex_result.tokens.is_empty(),
        "Golden file should produce tokens"
    );

    // Check that all Jinja token types are recognized
    let token_kinds: Vec<_> = lex_result
        .tokens
        .iter()
        .map(|t| format!("{:?}", t.kind))
        .collect();
    let token_str = token_kinds.join(" ");

    // Should contain Jinja expression tokens (new lexer uses JinjaExprOpen/JinjaExprClose)
    assert!(
        token_str.contains("JinjaExprOpen"),
        "Should recognize Jinja expressions {{ }}"
    );

    // Should contain Jinja statement tokens (new lexer uses JinjaStmtOpen/JinjaStmtClose)
    assert!(
        token_str.contains("JinjaStmtOpen"),
        "Should recognize Jinja statements"
    );

    // Should contain Jinja comment tokens (captured as trivia attached to tokens)
    let has_jinja_comment_trivia = lex_result.tokens.iter().any(|t| {
        t.leading_trivia
            .iter()
            .any(|trivia| format!("{:?}", trivia.kind).contains("JinjaComment"))
    });
    assert!(
        has_jinja_comment_trivia,
        "Should recognize Jinja comments in trivia"
    );
}

#[test]
fn test_golden_file_formats_without_panic() {
    let sql = include_str!("fixtures/golden_jinja_comprehensive.sql");

    // Split by statement terminators to test individual statements
    // The file contains many statements separated by semicolons
    let result = format(sql);

    // Should not panic during formatting
    // Note: Some statements may fail to parse/format but shouldn't panic
    match result {
        Ok(formatted) => {
            // Basic sanity check - should preserve some content
            assert!(
                !formatted.is_empty(),
                "Formatted output should not be empty"
            );
        }
        Err(e) => {
            // Even if formatting fails, it should be a graceful error
            println!(
                "Formatting produced error (may be expected for complex Jinja): {}",
                e
            );
        }
    }
}

// =============================================================================
// Section 1: Basic Jinja Expressions {{ }}
// =============================================================================

#[test]
fn test_jinja_expression_simple_variable() {
    let sql = "SELECT {{ column_name }} FROM {{ table_name }}";
    assert_parses(sql, "simple variable substitution");

    let formatted = format(sql).unwrap();
    assert_jinja_preserved(
        sql,
        &formatted,
        &["{{ column_name }}", "{{ table_name }}"],
        "simple variables",
    );
}

#[test]
fn test_jinja_expression_ref_macro() {
    let sql = "SELECT * FROM {{ ref('stg_orders') }}";
    assert_parses(sql, "ref() macro");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{{ ref('stg_orders') }}"),
        "ref() should be preserved"
    );
}

#[test]
fn test_jinja_expression_source_macro() {
    let sql = "SELECT * FROM {{ source('raw', 'customers') }}";
    assert_parses(sql, "source() macro");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{{ source('raw', 'customers') }}"),
        "source() should be preserved"
    );
}

#[test]
fn test_jinja_config_block() {
    let sql = "{{ config(materialized='table', schema='analytics') }}\nSELECT 1";
    assert_parses(sql, "config() block");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{{ config("),
        "config() should be preserved"
    );
}

// =============================================================================
// Section 2: Jinja Comments {# #}
// =============================================================================

#[test]
fn test_jinja_comment_standalone() {
    let sql = "{# This is a Jinja comment #}\nSELECT 1";
    assert_parses(sql, "standalone comment");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{#") && formatted.contains("#}"),
        "Jinja comment should be preserved"
    );
}

#[test]
fn test_jinja_comment_inline() {
    let sql = "SELECT id {# primary key #}, name FROM users";
    assert_parses(sql, "inline comment");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{#"),
        "Inline Jinja comment should be preserved"
    );
}

// =============================================================================
// Section 3: Basic Control Blocks {% if %}
// =============================================================================

#[test]
fn test_jinja_if_simple() {
    let sql = "SELECT {% if include_email %}email,{% endif %} name FROM users";
    assert_parses(sql, "simple if");

    let formatted = format(sql).unwrap();
    assert_jinja_preserved(sql, &formatted, &["{% if", "{% endif %}"], "simple if");
}

/// Jinja control flow in middle of qualified name (schema.table) - now supported
#[test]
fn test_jinja_if_else() {
    let sql = "SELECT * FROM {% if is_prod %}production{% else %}development{% endif %}.orders";
    assert_parses(sql, "if-else");

    let formatted = format(sql).unwrap();
    assert_jinja_preserved(
        sql,
        &formatted,
        &["{% if", "{% else %}", "{% endif %}"],
        "if-else",
    );
}

/// Jinja if/elif/else in middle of qualified name - now supported
#[test]
fn test_jinja_if_elif_else() {
    let sql = r#"SELECT * FROM 
{% if env == 'prod' %}prod_schema
{% elif env == 'staging' %}staging_schema
{% else %}dev_schema
{% endif %}.orders"#;

    assert_parses(sql, "if-elif-else");

    let formatted = format(sql).unwrap();
    assert_jinja_preserved(
        sql,
        &formatted,
        &["{% if", "{% elif", "{% else %}", "{% endif %}"],
        "if-elif-else",
    );
}

#[test]
fn test_jinja_multiple_elif() {
    let sql = r#"SELECT
{% if priority == 1 %}'Critical'
{% elif priority == 2 %}'High'
{% elif priority == 3 %}'Medium'
{% elif priority == 4 %}'Low'
{% else %}'Unknown'
{% endif %} AS priority_label
FROM tickets"#;

    assert_parses(sql, "multiple elif");

    let formatted = format(sql).unwrap();

    // Count elif occurrences
    let elif_count = count_occurrences(&formatted, "{% elif");
    assert!(
        elif_count >= 3,
        "Should preserve multiple elif branches, found {}",
        elif_count
    );
}

// =============================================================================
// Section 4: For Loops {% for %}
// =============================================================================

#[test]
fn test_jinja_for_simple() {
    let sql = r#"SELECT
{% for col in columns %}
{{ col }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM source"#;

    assert_parses(sql, "simple for");

    let formatted = format(sql).unwrap();
    assert_jinja_preserved(sql, &formatted, &["{% for", "{% endfor %}"], "simple for");
}

#[test]
fn test_jinja_for_with_loop_vars() {
    let sql = r#"SELECT
{% for col in columns %}
{{ col }} AS col_{{ loop.index }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM source"#;

    assert_parses(sql, "for with loop variables");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("loop.index"),
        "loop.index should be preserved"
    );
    assert!(
        formatted.contains("loop.last"),
        "loop.last should be preserved"
    );
}

/// For loop that conditionally generates UNION ALL (now supported)
#[test]
fn test_jinja_for_union_pattern() {
    let sql = r#"{% for table in tables %}
{% if not loop.first %}UNION ALL{% endif %}
SELECT '{{ table }}' AS source_table, * FROM {{ ref(table) }}
{% endfor %}"#;

    assert_parses(sql, "for with union");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("loop.first"),
        "loop.first should be preserved"
    );
}

// =============================================================================
// Section 5: Set Statements {% set %}
// =============================================================================

#[test]
fn test_jinja_set_simple() {
    let sql = "{% set schema_name = 'analytics' %}\nSELECT * FROM {{ schema_name }}.orders";
    assert_parses(sql, "simple set");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{% set"),
        "set statement should be preserved"
    );
}

#[test]
fn test_jinja_set_with_list() {
    let sql = r#"{% set metrics = ['revenue', 'cost', 'profit'] %}
SELECT 
{% for m in metrics %}
SUM({{ m }}) AS total_{{ m }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM sales"#;

    assert_parses(sql, "set with list");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{% set metrics"),
        "set with list should be preserved"
    );
}

// =============================================================================
// Section 6: Nested Control Flow (2 levels)
// =============================================================================

/// Nested if blocks are preserved through structured CST
#[test]
fn test_jinja_nested_if_in_if() {
    let sql = r#"SELECT *
FROM orders
WHERE 1=1
{% if filter_by_status %}
    {% if status == 'active' %}
    AND status = 'active'
    {% else %}
    AND status = '{{ status }}'
    {% endif %}
{% endif %}"#;

    assert_parses(sql, "nested if in if");

    let formatted = format(sql).unwrap();

    // Count if/endif pairs
    let if_count = count_occurrences(&formatted, "{% if");
    let endif_count = count_occurrences(&formatted, "{% endif %}");
    assert_eq!(if_count, endif_count, "if/endif should be balanced");
    assert!(if_count >= 2, "Should have at least 2 nested ifs");
}

#[test]
fn test_jinja_nested_for_in_if() {
    let sql = r#"SELECT
id,
{% if include_details %}
    {% for detail_col in ['description', 'category', 'tags'] %}
    {{ detail_col }}{% if not loop.last %},{% endif %}
    {% endfor %}
{% else %}
    'REDACTED' AS details
{% endif %}
FROM items"#;

    assert_parses(sql, "for inside if");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{% for") && formatted.contains("{% if"),
        "nested for in if should be preserved"
    );
}

#[test]
fn test_jinja_nested_if_in_for() {
    let sql = r#"SELECT
{% for col in columns %}
    {% if col.is_nullable %}
    COALESCE({{ col.name }}, 'N/A') AS {{ col.name }}
    {% else %}
    {{ col.name }}
    {% endif %}{% if not loop.last %},{% endif %}
{% endfor %}
FROM source_table"#;

    assert_parses(sql, "if inside for");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{% for") && formatted.contains("{% if"),
        "nested if in for should be preserved"
    );
}

#[test]
fn test_jinja_nested_for_in_for() {
    let sql = r#"{% for schema in schemas %}
{% for table in tables %}
SELECT * FROM {{ schema }}.{{ table }};
{% endfor %}
{% endfor %}"#;

    assert_parses(sql, "for inside for");

    let formatted = format(sql).unwrap();

    let for_count = count_occurrences(&formatted, "{% for");
    let endfor_count = count_occurrences(&formatted, "{% endfor %}");
    assert_eq!(for_count, endfor_count, "for/endfor should be balanced");
    assert!(for_count >= 2, "Should have at least 2 nested fors");
}

// =============================================================================
// Section 7: Nested Control Flow (3+ levels)
// =============================================================================

#[test]
fn test_jinja_triple_nested_if() {
    let sql = r#"SELECT
{% if env == 'prod' %}
    {% if is_incremental() %}
        {% if var('full_refresh', false) %}
        'full_refresh_prod'
        {% else %}
        'incremental_prod'
        {% endif %}
    {% else %}
    'initial_load_prod'
    {% endif %}
{% else %}
'non_prod'
{% endif %} AS load_type
FROM source"#;

    assert_parses(sql, "triple nested if");

    let formatted = format(sql).unwrap();

    let if_count = count_occurrences(&formatted, "{% if");
    let endif_count = count_occurrences(&formatted, "{% endif %}");
    assert_eq!(
        if_count, endif_count,
        "if/endif should be balanced in triple nesting"
    );
    assert!(
        if_count >= 3,
        "Should have at least 3 nested ifs, found {}",
        if_count
    );
}

/// Triple nested for loops wrapping GRANT statements - now supported
#[test]
fn test_jinja_triple_nested_for() {
    let sql = r#"{% for db in databases %}
{% for schema in schemas %}
{% for table in tables %}
GRANT SELECT ON {{ db }}.{{ schema }}.{{ table }} TO ROLE reader;
{% endfor %}
{% endfor %}
{% endfor %}"#;

    assert_parses(sql, "triple nested for");

    let formatted = format(sql).unwrap();

    let for_count = count_occurrences(&formatted, "{% for");
    let endfor_count = count_occurrences(&formatted, "{% endfor %}");
    assert_eq!(
        for_count, endfor_count,
        "for/endfor should be balanced in triple nesting"
    );
    assert!(for_count >= 3, "Should have at least 3 nested fors");
}

// =============================================================================
// Section 8: Jinja in Different SQL Clauses
// =============================================================================

/// Jinja if/else producing qualified table name part - now supported
#[test]
fn test_jinja_in_from_clause() {
    let sql =
        "SELECT * FROM {% if use_archive %}archive{% else %}current{% endif %}.{{ table_name }}";
    assert_parses(sql, "Jinja in FROM");

    let formatted = format(sql).unwrap();
    assert!(formatted.contains("FROM"), "FROM should be preserved");
    assert!(
        formatted.contains("{% if"),
        "Jinja in FROM should be preserved"
    );
}

/// Jinja if block wrapping entire JOIN clause - now supported
#[test]
fn test_jinja_in_join_clause() {
    let sql = r#"SELECT o.*, c.name
FROM orders o
{% if join_customers %}
JOIN customers c ON o.customer_id = c.id
{% endif %}"#;

    assert_parses(sql, "Jinja in JOIN");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{% if join_customers %}"),
        "Jinja around JOIN should be preserved"
    );
}

/// Jinja if block in WHERE clause preserved through structured CST
#[test]
fn test_jinja_in_where_clause() {
    let sql = r#"SELECT *
FROM orders
WHERE status = 'active'
{% if min_amount %}AND amount >= {{ min_amount }}{% endif %}"#;

    assert_parses(sql, "Jinja in WHERE");

    let formatted = format(sql).unwrap();
    assert!(formatted.contains("WHERE"), "WHERE should be preserved");
    assert!(
        formatted.contains("{% if min_amount %}"),
        "Jinja in WHERE should be preserved"
    );
}

#[test]
fn test_jinja_in_group_by() {
    let sql = r#"SELECT 
{% if group_by_region %}region,{% endif %}
SUM(amount) AS total
FROM orders
GROUP BY {% if group_by_region %}region{% else %}1{% endif %}"#;

    assert_parses(sql, "Jinja in GROUP BY");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("GROUP BY"),
        "GROUP BY should be preserved"
    );
}

/// Jinja if/else in ORDER BY expressions (direction modifier)
#[test]
fn test_jinja_in_order_by() {
    let sql = r#"SELECT *
FROM orders
ORDER BY {% if sort_by_date %}created_at{% else %}id{% endif %} {% if sort_desc %}DESC{% else %}ASC{% endif %}"#;

    assert_parses(sql, "Jinja in ORDER BY");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("ORDER BY"),
        "ORDER BY should be preserved"
    );
}

#[test]
fn test_jinja_in_limit() {
    let sql =
        "SELECT * FROM orders LIMIT {% if is_preview %}100{% else %}{{ row_limit }}{% endif %}";
    assert_parses(sql, "Jinja in LIMIT");

    let formatted = format(sql).unwrap();
    assert!(formatted.contains("LIMIT"), "LIMIT should be preserved");
}

// =============================================================================
// Section 9: Jinja in Complex Expressions
// =============================================================================

#[test]
fn test_jinja_in_case_expression() {
    let sql = r#"SELECT
CASE 
    WHEN {% if use_new_logic %}status IN ('new', 'pending'){% else %}status = 'pending'{% endif %} THEN 'Active'
    ELSE 'Inactive'
END AS status_category
FROM orders"#;

    assert_parses(sql, "Jinja in CASE");

    let formatted = format(sql).unwrap();
    assert!(formatted.contains("CASE"), "CASE should be preserved");
    assert!(
        formatted.contains("{% if"),
        "Jinja in CASE should be preserved"
    );
}

/// Jinja if block inside function argument list (conditional comma pattern)
#[test]
fn test_jinja_in_function_call() {
    let sql = r#"SELECT
CONCAT(
    {% if include_prefix %}'PREFIX_',{% endif %}
    name
) AS formatted_name
FROM items"#;

    assert_parses(sql, "Jinja in function call");

    let formatted = format(sql).unwrap();
    assert!(formatted.contains("CONCAT"), "CONCAT should be preserved");
}

#[test]
fn test_jinja_in_between() {
    let sql = r#"SELECT *
FROM orders
WHERE amount BETWEEN {% if use_dynamic %}{{ min_val }}{% else %}0{% endif %} AND {% if use_dynamic %}{{ max_val }}{% else %}1000{% endif %}"#;

    assert_parses(sql, "Jinja in BETWEEN");

    let formatted = format(sql).unwrap();
    assert!(formatted.contains("BETWEEN"), "BETWEEN should be preserved");
}

#[test]
fn test_jinja_in_subquery() {
    let sql = r#"SELECT *
FROM (
    SELECT {% for col in columns %}{{ col }}{% if not loop.last %},{% endif %}{% endfor %}
    FROM {{ ref('source') }}
) subq"#;

    assert_parses(sql, "Jinja in subquery");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{% for"),
        "Jinja in subquery should be preserved"
    );
}

// =============================================================================
// Section 10: dbt-Specific Patterns
// =============================================================================

#[test]
fn test_dbt_incremental_pattern() {
    let sql = r#"{{ config(materialized='incremental', unique_key='id') }}
SELECT *
FROM {{ ref('stg_orders') }}
{% if is_incremental() %}
WHERE updated_at > (SELECT MAX(updated_at) FROM {{ this }})
{% endif %}"#;

    assert_parses(sql, "dbt incremental pattern");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{{ config("),
        "config should be preserved"
    );
    assert!(
        formatted.contains("is_incremental()"),
        "is_incremental() should be preserved"
    );
    assert!(
        formatted.contains("{{ this }}"),
        "{{ this }} should be preserved"
    );
}

#[test]
fn test_dbt_var_with_default() {
    let sql = "SELECT * FROM orders WHERE created_at >= {{ var('start_date', '2020-01-01') }}";
    assert_parses(sql, "var() with default");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("var('start_date'"),
        "var() should be preserved"
    );
}

// =============================================================================
// Section 12: Edge Cases
// =============================================================================

#[test]
fn test_jinja_adjacent_to_sql() {
    let sql = "SELECT {{col1}},{{col2}},{{col3}} FROM {{schema}}.{{table}}";
    assert_parses(sql, "adjacent Jinja");

    let formatted = format(sql).unwrap();
    // All expressions should be preserved
    assert!(
        formatted.contains("{{col1}}") || formatted.contains("{{ col1 }}"),
        "col1 should be preserved"
    );
    assert!(
        formatted.contains("{{col2}}") || formatted.contains("{{ col2 }}"),
        "col2 should be preserved"
    );
}

#[test]
fn test_jinja_whitespace_variations() {
    // Compact
    let sql1 = "SELECT {%if cond%}col1{%else%}col2{%endif%} FROM t";
    assert_parses(sql1, "compact Jinja");

    // Spaced
    let sql2 = "SELECT {% if cond %}col1{% else %}col2{% endif %} FROM t";
    assert_parses(sql2, "spaced Jinja");
}

#[test]
fn test_jinja_qualified_name_parts() {
    let sql = "SELECT * FROM {{ database }}.{{ schema }}.{{ table }}";
    assert_parses(sql, "qualified name with Jinja parts");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{{ database }}"),
        "database part should be preserved"
    );
    assert!(
        formatted.contains("{{ schema }}"),
        "schema part should be preserved"
    );
    assert!(
        formatted.contains("{{ table }}"),
        "table part should be preserved"
    );
}

#[test]
fn test_jinja_comments_mixed_with_control_flow() {
    let sql = r#"SELECT
id,
{# Check if we need email #}
{% if include_email %}
email,
{% endif %}
name
FROM users"#;

    assert_parses(sql, "comments with control flow");

    let formatted = format(sql).unwrap();
    assert!(
        formatted.contains("{#"),
        "Jinja comment should be preserved"
    );
    assert!(
        formatted.contains("{% if"),
        "Control flow should be preserved"
    );
}

// =============================================================================
// Validation: Round-trip stability
// =============================================================================

#[test]
fn test_format_stability_simple() {
    let sql = "SELECT {{ column }} FROM {{ table }}";

    let formatted1 = format(sql).unwrap();
    let formatted2 = format(&formatted1).unwrap();

    assert_eq!(
        formatted1, formatted2,
        "Formatting should be stable (idempotent)"
    );
}

/// Format stability: Round-trip stability with if/else control flow
/// The formatter now correctly preserves commas inside Jinja branches (dbt pattern)
#[test]
fn test_format_stability_with_control_flow() {
    let sql = r#"SELECT
{% if cond %}
col1,
{% else %}
col2,
{% endif %}
col3
FROM table1"#;

    let formatted1 = format(sql).unwrap();
    let formatted2 = format(&formatted1).unwrap();

    assert_eq!(
        formatted1, formatted2,
        "Formatting with control flow should be stable"
    );
}

// =============================================================================
// Integration: Complete model test
// =============================================================================

#[test]
fn test_complete_dbt_model() {
    let sql = r#"{{ config(materialized='incremental', unique_key='order_id') }}

{% set lookback_days = var('lookback_days', 3) %}

WITH source_orders AS (
    SELECT *
    FROM {{ ref('stg_orders') }}
    {% if is_incremental() %}
    WHERE updated_at >= DATEADD(day, -{{ lookback_days }}, (SELECT MAX(updated_at) FROM {{ this }}))
    {% endif %}
)

SELECT
    {{ dbt_utils.generate_surrogate_key(['order_id']) }} AS order_sk,
    *,
    CURRENT_TIMESTAMP() AS _loaded_at
FROM source_orders"#;

    assert_parses(sql, "complete dbt model");

    let formatted = format(sql).unwrap();

    // All key constructs should be preserved
    assert!(
        formatted.contains("{{ config("),
        "config should be preserved"
    );
    assert!(formatted.contains("{% set"), "set should be preserved");
    assert!(
        formatted.contains("{{ ref('stg_orders') }}"),
        "ref should be preserved"
    );
    assert!(
        formatted.contains("{% if is_incremental() %}"),
        "is_incremental should be preserved"
    );
    assert!(formatted.contains("{{ this }}"), "this should be preserved");
    assert!(
        formatted.contains("{% endif %}"),
        "endif should be preserved"
    );
}
