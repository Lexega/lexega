-- Simple Jinja test with WHERE clause
SELECT
    order_id,
    customer_id,
    order_date,
    amount
FROM {{ source('raw_data', 'orders') }}
WHERE order_date >= CURRENT_DATE(){% if var('exclude_cancelled', true) %} AND status != 'CANCELLED'{% endif %};