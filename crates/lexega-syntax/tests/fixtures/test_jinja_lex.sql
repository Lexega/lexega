SELECT {{ column_name | upper }}
FROM {{ table_name }}
WHERE id = {{ user_id }} AND status{% if active %} = 'active'{% endif %}