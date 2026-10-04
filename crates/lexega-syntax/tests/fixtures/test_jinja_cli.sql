-- Test Jinja template for CLI
SELECT *
FROM {{ ref('orders') }}
WHERE order_date >= DATEADD(day, - {{ lookback_days }},CURRENT_DATE){% if region %} AND region = '{{ region }}'{% endif %}
AND status = 'active'