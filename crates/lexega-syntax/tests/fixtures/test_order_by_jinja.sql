SELECT *
FROM orders
ORDER BY 
{% if sort_desc %}
    created_at DESC
{% else %}
    created_at ASC
{% endif %}