-- Sample staging model
SELECT
    order_id,
    customer_id,
    order_date,
    amount,
    status
FROM {{ source('raw_data', 'orders') }}
WHERE order_date >= dateadd(day,-90,current_date);