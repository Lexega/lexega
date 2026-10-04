-- Simple test: conditional UNION ALL
{% for table in tables %}
{% if not loop.first %}
UNION ALL
{% endif %}
SELECT '{{ table }}' AS source_table, *
FROM {{ ref(table) }}
{% endfor %};