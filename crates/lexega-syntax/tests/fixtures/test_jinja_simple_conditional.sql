{% if env == 'prod' %}
SELECT *
FROM production.orders
{% else %}
SELECT *
FROM dev.orders
{% endif %}