SELECT
    {{ ref("stg_orders") }},
    {{ source("raw", "customers") }},
    order_total
FROM orders
WHERE region IN (
{% if active %}
    'US','CA'
{% endif %});