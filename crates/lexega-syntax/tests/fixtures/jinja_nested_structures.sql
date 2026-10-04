-- Test file for deeply nested Jinja structures
-- This exercises recursive descent in both NativeRenderer and SQL parser
{{ config(materialized='incremental', unique_key='id') }}
{# Test 1: Nested if statements #} {% if target.name == 'prod' %}
{% if is_incremental() %}
{% if var('full_refresh', false) %}
-- Full refresh in prod incremental
SELECT *
FROM {{ ref('source_data') }}
WHERE 1 = 1
{% else %}
-- Normal incremental in prod
SELECT *
FROM {{ ref('source_data') }}
WHERE updated_at > (SELECT MAX(updated_at)
FROM {{ this }})
{% endif %}
{% else %}
-- Initial load in prod
SELECT *
FROM {{ ref('source_data') }}
{% endif %}
{% elif target.name == 'staging' %}
{% if var('sample_data', true) %}
-- Sampled data for staging
SELECT *
FROM {{ ref('source_data') }} SAMPLE (10)
{% else %}
SELECT *
FROM {{ ref('source_data') }}
{% endif %}
{% else %}
-- Dev environment
SELECT *
FROM {{ ref('source_data') }}
LIMIT 1000
{% endif %};
{# Test 2: Nested for loops #} {% set schemas = ['raw', 'staging', 'analytics'] %}
{% set tables = ['users', 'orders', 'products'] %}
{% for schema in schemas %}
{% for table in tables %}
{% if not loop.first %}
UNION ALL
{% endif %}
SELECT
    '{{ schema }}' AS source_schema,
    '{{ table }}' AS source_table,
    {% for col in ['id', 'created_at', 'updated_at'] %}
        {{ col }}{% if not loop.last %},{% endif %}
    {% endfor %}
FROM {{ schema }}.{{ table }}{% if schema == 'raw' %}
WHERE _loaded_at > CURRENT_DATE - 7{% endif %}
{% endfor %}
{% endfor %};
{# Test 3: Mixed nesting - for inside if, if inside for #} SELECT
    {% for dimension in var('dimensions', ['region', 'category']) %}
        {% if dimension == 'region' %}
            COALESCE({{ dimension }},'Unknown') AS {{ dimension }},
        {% elif dimension == 'category' %}
            UPPER({{ dimension }}) AS {{ dimension }},
        {% else %}
            {{ dimension }},
        {% endif %}
    {% endfor %}
    {% if var('include_metrics', true) %}
        {% for metric in ['revenue', 'cost', 'profit'] %}
            {% if metric == 'profit' %}
                (revenue - cost) AS {{ metric }}{% if not loop.last %},{% endif %}
            {% else %}
                SUM({{ metric }}) AS {{ metric }}{% if not loop.last %},{% endif %}
            {% endif %}
        {% endfor %}
    {% else %}
        COUNT(*) AS row_count
    {% endif %}
FROM {{ ref('fact_sales') }}
{% if var('filter_active', true) %}
    WHERE is_active = TRUE{% if var('date_filter', none) is not none %} AND sale_date >= '{{ var("date_filter") }}'{% endif %}
{% endif %}
GROUP BY 
{% for dimension in var('dimensions', ['region', 'category']) %}
    {{ loop.index }}{% if not loop.last %},{% endif %}
    {% endfor %};
{# Test 4: Deeply nested conditionals (4+ levels) #} {% set env = target.name %}
{% set mode = var('mode', 'standard') %}
SELECT
    id,
    {% if env == 'prod' %}
        {% if mode == 'full' %}
            {% if var('include_pii', false) %}
                {% if var('mask_ssn', true) %}
                    CONCAT('XXX-XX-',RIGHT(ssn,4)) AS ssn_masked,
                {% else %}
                    ssn,
                {% endif %}
                email,
                phone
            {% else %}
                NULL AS ssn_masked,
                MD5(email) AS email_hash,
                NULL AS phone
            {% endif %}
        {% else %}
            -- Standard mode in prod
            MD5(email) AS email_hash
        {% endif %}
    {% elif env == 'staging' %}
        {% if mode == 'test' %}
            'test@example.com' AS email,
            '555-0100' AS phone
        {% else %}
            email,
            phone
        {% endif %}
    {% else %}
        -- Dev: show everything
        ssn,
        email,
        phone
    {% endif %}
FROM {{ ref('customers') }};
{# Test 5: Triple-nested for loops #} {% set databases = ['db1', 'db2'] %}
{% set schemas_list = ['schema_a', 'schema_b'] %}
{% set objects = ['table1', 'table2'] %}
{% for db in databases %}
{% for schema in schemas_list %}
{% for obj in objects %}
GRANT SELECT ON {{ db }}.{{ schema }}.{{ obj }} TO ROLE analyst;
{% endfor %}
{% endfor %}
{% endfor %};
{# Test 7: Nested structures with filters #} {% set raw_columns = ['First Name', 'Last Name', 'Email Address'] %}
SELECT {% for col in raw_columns %}
    {% set clean_col = col | lower | replace ( ' ' , '_' ) %}
    "{{ col }}" AS {{ clean_col }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM source_table;
{# Test 8: Complex boolean logic in nested ifs #} {% set feature_flags = {'new_logic': true, 'legacy_support': false, 'experimental': true} %}
SELECT
    {% if feature_flags.new_logic and not feature_flags.legacy_support %}
        {% if feature_flags.experimental or var('force_experimental', false) %}
            -- New experimental path
            NEW_FUNCTION(value) AS computed_value
        {% else %}
            -- New standard path
            STANDARD_FUNCTION(value) AS computed_value
        {% endif %}
    {% elif feature_flags.legacy_support %}
        -- Legacy path
        OLD_FUNCTION(value) AS computed_value
    {% else %}
        -- Fallback
        value AS computed_value
    {% endif %}
FROM {{ ref('source') }}