SELECT {% if group_by_category %}
    category,
{% endif %} SUM(amount)
FROM orders
GROUP BY 
{% if group_by_category %}
    category
{% endif %}