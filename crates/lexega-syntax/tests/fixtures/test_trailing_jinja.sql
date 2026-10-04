-- Test case: Jinja block appearing between table ref and JOIN
SELECT a, b
FROM table1{% if include_users %}
LEFT JOIN users ON table1.user_id = users.id{% endif %}
WHERE a > 10;