{% set env = 'dev' %}
SELECT {% if env == 'prod' %}
    'production' AS environment
{% else %}
    'development' AS environment
{% endif %}
FROM my_table;