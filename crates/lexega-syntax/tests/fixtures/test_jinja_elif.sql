{% if env == 'prod' %}
SELECT customer_id, sum(amount) AS total
FROM production.orders
WHERE status = 'active'
GROUP BY customer_id
{% elif env == 'staging' %}
SELECT customer_id, sum(amount) AS total
FROM staging.orders
WHERE status = 'active'
GROUP BY customer_id
{% else %}
SELECT customer_id, sum(amount) AS total
FROM dev.orders
GROUP BY customer_id
{% endif %}