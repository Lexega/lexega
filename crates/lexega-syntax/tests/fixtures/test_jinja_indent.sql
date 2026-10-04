SELECT *
FROM orders
WHERE order_date >= CURRENT_DATE(){% if var('exclude_cancelled', true) %} AND status != 'CANCELLED'{% endif %}