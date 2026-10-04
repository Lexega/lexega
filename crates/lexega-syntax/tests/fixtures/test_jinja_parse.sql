-- Test Jinja expression parsing integration
SELECT {{ column_name | upper }}
FROM {{ table_name }}
WHERE id = {{ user_id }} AND status = 'active'