-- =============================================================================
-- GOLDEN TEST: Comprehensive Jinja/dbt SQL Test
-- =============================================================================
-- This file exercises ALL supported Jinja functionality with complex nesting.
-- The parser and formatter must handle each pattern correctly.
-- =============================================================================
-- ===========================================================================
-- SECTION 1: Basic Jinja Expressions {{ }}
-- ===========================================================================
-- 1.1: Simple variable substitution
SELECT {{ column_name }}
FROM {{ table_name }};
-- 1.2: ref() and source() macros
SELECT *
FROM {{ ref('stg_orders') }};
SELECT *
FROM {{ source('raw', 'customers') }};
-- 1.3: config() block
{{ config(materialized='table', schema='analytics') }}
SELECT 1;
-- 1.4: Expression in column list
SELECT
    id,
    {{ dbt_utils.star(from=ref('orders')) }},
    created_at
FROM {{ ref('orders') }};
-- 1.5: Expressions in complex positions
SELECT
    {{ 'literal_string' }},
    {{ 123 }},
    {{ var('column_list', 'id, name') }}
FROM {{ ref('source') }}
WHERE {{ var('filter_condition', '1=1') }};
-- ===========================================================================
-- SECTION 2: Jinja Comments {# #}
-- ===========================================================================
-- 2.1: Standalone comment
{# This is a Jinja comment that should be preserved #} SELECT 1;
-- 2.2: Inline comment
SELECT id {# primary key #} , name
FROM users;
-- 2.3: Multi-line Jinja comment
{# 
   Multi-line Jinja comment
   spanning several lines
   with context about the query
#} SELECT *
FROM orders;
-- ===========================================================================
-- SECTION 3: Basic Control Blocks {% if %}
-- ===========================================================================
-- 3.1: Simple if block
SELECT {% if include_email %}
    email,
{% endif %} name
FROM users;
-- 3.2: if-else block
SELECT *
FROM {% if is_prod %}production{% else %}development{% endif %}.orders;
-- 3.3: if-elif-else block
SELECT *
FROM {% if env == 'prod' %}prod_schema
    {% elif env == 'staging' %}staging_schema
    {% elif env == 'dev' %}dev_schema
    {% else %}sandbox_schema
    {% endif %}.orders;
-- 3.4: Multiple elif branches
SELECT
    {% if priority == 1 %}
        'Critical'
    {% elif priority == 2 %}
        'High'
    {% elif priority == 3 %}
        'Medium'
    {% elif priority == 4 %}
        'Low'
    {% elif priority == 5 %}
        'Trivial'
    {% else %}
        'Unknown'
    {% endif %} AS priority_label
FROM tickets;
-- ===========================================================================
-- SECTION 4: For Loops {% for %}
-- ===========================================================================
-- 4.1: Simple for loop in SELECT
SELECT {% for col in columns %}
    {{ col }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM {{ ref('source') }};
-- 4.2: For loop with loop variables
SELECT {% for col in columns %}
    {{ col }} AS col_
    {{ loop.index }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM source;
-- 4.3: For loop with loop.first and loop.last
{% for table in tables %}
{% if not loop.first %}
UNION ALL
{% endif %}
SELECT '{{ table }}' AS source_table, *
FROM {{ ref(table) }}
{% endfor %};
-- 4.4: For loop generating WHERE conditions
SELECT *
FROM orders
WHERE
    {% for status in valid_statuses %}
        status = '{{ status }}'{% if not loop.last %} OR {% endif %}
    {% endfor %};
-- ===========================================================================
-- SECTION 5: Set Statements {% set %}
-- ===========================================================================
-- 5.1: Simple set
{% set schema_name = 'analytics' %}
SELECT *
FROM {{ schema_name }}.orders;
-- 5.2: Set with expression
{% set date_filter = "DATE_TRUNC('month', CURRENT_DATE)" %}
SELECT *
FROM orders
WHERE created_at >= {{ date_filter }};
-- 5.3: Set with list
{% set metrics = ['revenue', 'cost', 'profit'] %}
SELECT {% for m in metrics %}
    SUM({{ m }}) AS total_
    {{ m }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM sales;
-- 5.4: Set with dictionary
{% set column_map = {'old_id': 'legacy_id', 'new_id': 'current_id'} %}
SELECT {% for old , new in column_map . items ( ) %}
    {{ old }} AS {{ new }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM mapping_table;
-- ===========================================================================
-- SECTION 6: Nested Control Flow (2 levels)
-- ===========================================================================
-- 6.1: If inside if
SELECT *
FROM orders
WHERE 1 = 1{% if filter_by_status %}{% if status == 'active' %} AND status = 'active' AND is_verified = TRUE{% else %} AND status = '{{ status }}'{% endif %}{% endif %};
-- 6.2: For inside if
SELECT
    id,
    {% if include_details %}
        {% for detail_col in ['description', 'category', 'tags'] %}
            {{ detail_col }}{% if not loop.last %},{% endif %}
        {% endfor %}
    {% else %}
        'REDACTED' AS details
    {% endif %}
FROM items;
-- 6.3: If inside for
SELECT {% for col in columns %}
    {% if col.is_nullable %}
        COALESCE({{ col.name }},'N/A') AS {{ col.name }}
    {% else %}
        {{ col.name }}
    {% endif %}{% if not loop.last %},{% endif %}
{% endfor %}
FROM source_table;
-- 6.4: For inside for
{% for schema in schemas %}
{% for table in tables %}
SELECT *
FROM {{ schema }}.{{ table }};
{% endfor %}
{% endfor %}
-- ===========================================================================
-- SECTION 7: Nested Control Flow (3+ levels)
-- ===========================================================================
-- 7.1: Triple-nested if
SELECT
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
FROM {{ this }};
-- 7.2: Triple-nested for
{% for db in databases %}
{% for schema in schemas %}
{% for table in tables %}
GRANT SELECT ON {{ db }}.{{ schema }}.{{ table }} TO ROLE reader;
{% endfor %}
{% endfor %}
{% endfor %}
-- 7.3: Mixed deep nesting (if-for-if-for)
{% if generate_unions %}
{% for region in regions %}
{% if region != 'UNKNOWN' %}
{% for year in years %}
SELECT
    '{{ region }}' AS region,
    {{ year }} AS year,
    SUM(sales) AS total
FROM regional_sales
WHERE region = '{{ region }}' AND YEAR(sale_date) = {{ year }}
GROUP BY 1,2
{% if not loop.last %}
    UNION ALL
{% endif %}
{% endfor %}
{% endif %}
{% if not loop.last %}
UNION ALL
{% endif %}
{% endfor %}
{% endif %};
-- 7.4: Deeply nested with elif branches
{% if tier == 'enterprise' %}
{% if region == 'us' %}
{% if var('use_new_pricing', false) %}
SELECT *
FROM us_enterprise_new_pricing
{% elif var('use_legacy_pricing', false) %}
SELECT *
FROM us_enterprise_legacy_pricing
{% else %}
SELECT *
FROM us_enterprise_standard_pricing
{% endif %}
{% elif region == 'eu' %}
SELECT *
FROM eu_enterprise_pricing
{% else %}
SELECT *
FROM global_enterprise_pricing
{% endif %}
{% elif tier == 'pro' %}
SELECT *
FROM pro_pricing
{% else %}
SELECT *
FROM free_pricing
{% endif %};
-- ===========================================================================
-- SECTION 8: Jinja in Different SQL Clauses
-- ===========================================================================
-- 8.1: Jinja in FROM clause (table selection)
SELECT *
FROM {% if use_archive %}archive{% else %}current{% endif %}.{{ table_name }};
-- 8.2: Jinja in JOIN clause
SELECT o.*, c.name
FROM orders o{% if join_customers %}
JOIN customers c ON o.customer_id = c.id{% endif %}{% if join_products %}
LEFT JOIN products p ON o.product_id = p.id{% endif %};
-- 8.3: Jinja in JOIN condition
SELECT *
FROM
orders o
JOIN customers c ON o.customer_id = 
{% if use_legacy_id %}
    c.legacy_id
{% else %}
    c.id
{% endif %};
-- 8.4: Jinja in WHERE clause
SELECT *
FROM orders
WHERE status = 'active'{% if min_amount %} AND amount >= {{ min_amount }}{% endif %}{% if max_amount %} AND amount <= {{ max_amount }}{% endif %}{% if category %} AND category = '{{ category }}'{% endif %};
-- 8.5: Jinja in GROUP BY clause
SELECT {% if group_by_region %}
    region,
{% endif %}{% if group_by_category %}category,{% endif %}SUM(amount) AS total
FROM orders
GROUP BY 
{% if group_by_region %}
    region{% if group_by_category %},{% endif %}
{% endif %}
{% if group_by_category %}
    category
{% endif %};
-- 8.6: Jinja in HAVING clause
SELECT region, COUNT(*) AS cnt
FROM orders
GROUP BY region
HAVING COUNT(*) >= 
{% if min_count %}
    {{ min_count }}
{% else %}
    10
{% endif %};
-- 8.7: Jinja in ORDER BY clause
SELECT *
FROM orders
ORDER BY 
{% if sort_by_date %}
    created_at
{% else %}
    id
{% endif %}
{% if sort_desc %}
    DESC
{% else %}
    ASC
{% endif %};
-- 8.8: Jinja in LIMIT clause
SELECT *
FROM orders
LIMIT 
{% if is_preview %}
    100
{% else %}
    {{ row_limit }}
{% endif %};
-- 8.9: Jinja in QUALIFY clause
SELECT *
FROM orders
QUALIFY ROW_NUMBER() OVER (
    PARTITION BY customer_id
    ORDER BY created_at DESC
) <= 
{% if keep_latest %}
    1
{% else %}
    {{ max_records }}
{% endif %};
-- ===========================================================================
-- SECTION 9: Jinja in Complex Expressions
-- ===========================================================================
-- 9.1: Jinja in CASE expression
SELECT CASE
    WHEN 
    {% if use_new_logic %}
        status IN ('new','pending')
    {% else %}
        status = 'pending'
    {% endif %} THEN 'Active'
    ELSE 'Inactive'
END AS status_category
FROM orders;
-- 9.2: Jinja in function calls
SELECT CONCAT(
{% if include_prefix %}
    'PREFIX_',
{% endif %}name,
{% if include_suffix %}
    '_SUFFIX'
{% endif %}) AS formatted_name
FROM items;
-- 9.3: Jinja in BETWEEN expression
SELECT *
FROM orders
WHERE amount BETWEEN 
{% if use_dynamic_range %}
    {{ min_val }}
{% else %}
    0
{% endif %} AND 
{% if use_dynamic_range %}
    {{ max_val }}
{% else %}
    1000
{% endif %};
-- 9.4: Jinja in IN clause
SELECT *
FROM orders
WHERE status IN (
{% for s in valid_statuses %}
    '{{ s }}'{% if not loop.last %},{% endif %}
    {% endfor %});
-- 9.5: Jinja in subquery
SELECT *
FROM (
    SELECT {% for col in columns %}
        {{ col }}{% if not loop.last %},{% endif %}
    {% endfor %}
    FROM {{ ref('source') }}{% if filter_condition %}
    WHERE {{ filter_condition }}{% endif %}
) subq;
-- ===========================================================================
-- SECTION 10: dbt-Specific Patterns
-- ===========================================================================
-- 10.1: Incremental model pattern
{{ config(materialized='incremental', unique_key='id') }}
SELECT *
FROM {{ ref('stg_orders') }}{% if is_incremental() %}
WHERE updated_at > (SELECT MAX(updated_at)
FROM {{ this }}){% endif %};
-- 10.2: Conditional schema/table based on target
{{ config(schema=target.schema ~ '_staging') }}
SELECT *
FROM {{ target.database }}.{{ target.schema }}.raw_orders;
-- 10.3: Using var() with defaults
SELECT *
FROM orders
WHERE created_at >= {{ var('start_date', '2020-01-01') }} AND created_at < {{ var('end_date', 'CURRENT_DATE') }};
-- 10.4: Star macro with exclusions
SELECT {{ dbt_utils.star(from=ref('orders'), except=['internal_id', 'deprecated_field']) }}
FROM {{ ref('orders') }};
-- 10.5: date_spine pattern
{{ dbt_utils.date_spine(
    datepart="day",
    start_date="cast('2020-01-01' as date)",
    end_date="current_date"
) }};
-- ===========================================================================
-- SECTION 11: Complex Real-World Patterns
-- ===========================================================================
-- 11.1: Dynamic column generation with conditions
{% set columns = [
    {'name': 'revenue', 'agg': 'SUM', 'filter': 'is_complete'},
    {'name': 'cost', 'agg': 'SUM', 'filter': none},
    {'name': 'quantity', 'agg': 'COUNT', 'filter': 'is_valid'}
] %}
SELECT
    date,
    {% for col in columns %}
        {% if col.filter %}
            {{ col.agg }}
            (CASE
                WHEN {{ col.filter }} THEN {{ col.name }}
            END) AS {{ col.name }}
        {% else %}
            {{ col.agg }}
            ({{ col.name }}) AS {{ col.name }}
        {% endif %}{% if not loop.last %},{% endif %}
    {% endfor %}
FROM transactions
GROUP BY date;
-- 11.2: Multi-environment deployment pattern
{% if target.name == 'prod' %}
{% set database = 'PROD_DB' %}
{% set warehouse = 'PROD_WH' %}
{% elif target.name == 'staging' %}
{% set database = 'STAGING_DB' %}
{% set warehouse = 'DEV_WH' %}
{% else %}
{% set database = 'DEV_DB' %}
{% set warehouse = 'DEV_WH' %}
{% endif %}
USE DATABASE {{ database }};
USE WAREHOUSE {{ warehouse }};
SELECT *
FROM {{ ref('dim_customers') }};
-- 11.3: PII masking pattern with nested conditions
{% set is_prod = target.name == 'prod' %}
{% set mask_pii = var('mask_pii', true) %}
SELECT
    id,
    {% if is_prod and mask_pii %}
        {% if var('partial_mask', false) %}
            CONCAT('***-**-',RIGHT(ssn,4)) AS ssn,
            CONCAT(LEFT(email,2),'***@',SPLIT_PART(email,'@',2)) AS email
        {% else %}
            'REDACTED' AS ssn,
            MD5(email) AS email_hash
        {% endif %}
    {% else %}
        ssn,
        email
    {% endif %}
FROM {{ ref('stg_customers') }};
-- 11.4: Dynamic union pattern
{% set sources = ['web', 'mobile', 'api'] %}
{% for source in sources %}
SELECT
    '{{ source }}' AS source_system,
    event_id,
    event_type,
    event_timestamp,
    {% if source == 'web' %}
        page_url,
        referrer
    {% elif source == 'mobile' %}
        app_version,
        device_type
    {% else %}
        api_version,
        client_id
    {% endif %}
FROM {{ ref('raw_' ~ source ~ '_events') }}{% if is_incremental() %}
WHERE event_timestamp > (SELECT MAX(event_timestamp)
FROM {{ this }}
WHERE source_system = '{{ source }}'){% endif %}
{% if not loop.last %}
UNION ALL
{% endif %}
{% endfor %};
-- 11.5: Pivot-like pattern with Jinja
{% set metrics = ['impressions', 'clicks', 'conversions'] %}
{% set periods = ['day', 'week', 'month'] %}
SELECT campaign_id, {% for period in periods %}
    {% for metric in metrics %}
        SUM(CASE
            WHEN date_trunc('{{ period }}',event_date) = date_trunc('{{ period }}',CURRENT_DATE) THEN {{ metric }}
            ELSE 0
        END) AS {{ metric }}_this_{{ period }}{% if not (loop.last and loop.parent.last) %},{% endif %}
    {% endfor %}
{% endfor %}
FROM campaign_metrics
GROUP BY campaign_id;
-- ===========================================================================
-- SECTION 12: Edge Cases and Boundary Conditions
-- ===========================================================================
-- 12.1: Empty for loop (should handle gracefully)
SELECT id {% for col in [] %}
    ,
    {{ col }}
{% endfor %}
FROM table1;
-- 12.2: Multiple set statements in sequence
{% set a = 1 %}
{% set b = 2 %}
{% set c = a + b %}
SELECT
    {{ a }},
    {{ b }},
    {{ c }};
-- 12.3: Jinja expressions adjacent to SQL tokens
SELECT
    {{ col1 }},
    {{ col2 }},
    {{ col3 }}
FROM {{schema}}.{{table}};
-- 12.4: Whitespace variations
SELECT {% if cond %}
    col1
{% else %}
    col2
{% endif %}
FROM table1;
SELECT {% if cond %}
    col1
{% else %}
    col2
{% endif %}
FROM table1;
-- 12.5: Nested Jinja in string literals (should be preserved as-is)
SELECT '{% if x %}{{ y }}{% endif %}' AS jinja_template_string;
-- 12.6: Comments mixed with control flow
SELECT id, {# Check if we need email #} {% if include_email %}
    email,
{# User email address #} {% endif %} name
FROM users;
-- 12.7: Jinja across statement boundaries
{% if create_table %}
CREATE TABLE {{ table_name }}
AS
{% endif %}
SELECT *
FROM source;
-- 12.8: Qualified name with Jinja parts
SELECT *
FROM {{ database }}.{{ schema }}.{{ table }};
SELECT *
FROM {{ var('db', 'PROD') }}.{{ var('schema', 'PUBLIC') }}.orders;
-- 12.9: Jinja in alias position
SELECT col1 AS {% if use_alias %}{{ alias_name }}{% else %}column_one{% endif %}
FROM table1;
-- 12.10: Complex boolean expressions in Jinja
{% if (is_prod and not is_test) or (force_run and var('override', false)) %}
SELECT *
FROM production_table
{% elif (is_staging or is_dev) and not var('skip_staging', false) %}
SELECT *
FROM staging_table
{% else %}
SELECT *
FROM fallback_table
{% endif %};
-- ===========================================================================
-- SECTION 13: Statement Fragment Patterns
-- ===========================================================================
-- 13.1: Jinja wrapping JOIN clause
SELECT o.*
FROM orders o{% if join_details %}
LEFT JOIN order_details d ON o.id = d.order_id
LEFT JOIN products p ON d.product_id = p.id{% endif %};
-- 13.2: Jinja wrapping WHERE + additional clauses
SELECT *
FROM orders
{% if apply_filters %}
    WHERE status = 'active' AND amount > 0
    GROUP BY category
    HAVING COUNT(*) > 5
{% endif %};
-- 13.3: Jinja for loop wrapping UNION ALL
{% for year in [2020, 2021, 2022, 2023] %}
SELECT *
FROM orders_
{{ year }}
{% if not loop.last %}
UNION ALL
{% endif %}
{% endfor %};
-- ===========================================================================
-- SECTION 14: Macro Calls and Complex Expressions
-- ===========================================================================
-- 14.1: Macro with named arguments
SELECT {{ dbt_utils.generate_surrogate_key(['customer_id', 'order_date']) }} sk, *
FROM orders;
-- 14.2: Nested macro calls
SELECT {{ dbt_utils.pivot(column='status', values=dbt_utils.get_column_values(ref('orders'), 'status'), then_value=1, else_value=0) }}
FROM orders;
-- 14.3: Filters in expressions
SELECT
    {{ 'hello world' | upper }},
    {{ column_name | default('id') }},
    {{ date_value | string | replace('-', '') }}
FROM table1;
-- 14.4: Tests in conditionals
{% if column_list is defined and column_list | length > 0 %}
SELECT {% for c in column_list %}
    {{ c }}{% if not loop.last %},{% endif %}
{% endfor %}
{% else %}
SELECT *
{% endif %}
FROM source;
-- ===========================================================================
-- SECTION 15: Final Integration Tests
-- ===========================================================================
-- 15.1: Complete dbt model with all features
{{ config(
    materialized='incremental',
    unique_key='order_id',
    schema='marts',
    tags=['daily', 'core']
) }}
{# 
   Orders Fact Table
   Combines orders with customer and product dimensions
   Supports incremental loads with configurable lookback
#} {% set lookback_days = var('lookback_days', 3) %}
{% set include_cancelled = var('include_cancelled', false) %}
WITH
    source_orders AS (
        SELECT *
        FROM {{ ref('stg_orders') }}{% if is_incremental() %}
        WHERE updated_at >= DATEADD(day, - {{ lookback_days }},(SELECT MAX(updated_at)
        FROM {{ this }})){% endif %}
    ),
    enriched AS (
        SELECT
            o.order_id,
            o.customer_id,
            o.order_date,
            o.status,
            {% for metric in ['subtotal', 'tax', 'shipping', 'total'] %}
                o.{{ metric }}{% if not loop.last %},{% endif %}
            {% endfor %},
            c.customer_segment,
            c.region,
            {% if var('include_product_details', true) %}
                p.product_name,
                p.category,
                p.brand,
            {% endif %}
            o.updated_at
        FROM
        source_orders o
        LEFT JOIN {{ ref('dim_customers') }} c ON o.customer_id = c.customer_id{% if var('include_product_details', true) %}
        LEFT JOIN {{ ref('dim_products') }} p ON o.product_id = p.product_id{% endif %}{% if not include_cancelled %}
        WHERE o.status != 'cancelled'{% endif %}
    )
SELECT
    {{ dbt_utils.generate_surrogate_key(['order_id']) }} AS order_sk,
    *,
    CURRENT_TIMESTAMP() AS _loaded_at
FROM enriched;