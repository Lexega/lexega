SELECT {{ x + y }}, order_total
FROM orders
WHERE region IN (
{% if active %}
    'US','CA'
{% endif %});