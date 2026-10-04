SELECT {{ x + y }}, order_total
FROM orders
WHERE status IN (
{% if active %}
    'US','CA'
{% endif %});