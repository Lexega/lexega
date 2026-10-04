-- Simple Jinja test
SELECT
    customer_id,
    customer_name,
    order_count
FROM {{ ref('customers') }}
WHERE is_active = true;