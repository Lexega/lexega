-- models/marts/customer_summary.sql
{{ config(
    materialized='table',
    schema='analytics'
) }}
WITH
    customer_orders as (
        SELECT
            customer_id,
            count(*) AS order_count,
            sum(order_amount) AS total_spent,
            max(order_date) AS last_order_date
        FROM {{ ref('stg_orders') }}
        WHERE order_date >= dateadd(day, - {{ var('lookback_days', 90) }},current_date){% if var('exclude_cancelled', true) %} AND status != 'cancelled'{% endif %}
    ),
    customer_info as (
        SELECT
            customer_id,
            customer_name,
            email,
            signup_date
        FROM {{ source('crm', 'customers') }}
        WHERE is_active = TRUE
    )
SELECT
    ci.customer_id,
    ci.customer_name,
    ci.email,
    ci.signup_date,
    coalesce(co.order_count,0) AS order_count,
    coalesce(co.total_spent,0) AS total_spent,
    co.last_order_date
FROM
customer_info AS ci
LEFT JOIN customer_orders AS co ON ci.customer_id = co.customer_id
WHERE co.order_count > {{ var('min_orders', 1) }};