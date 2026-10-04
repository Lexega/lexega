{% if env == 'prod' %}
SELECT 1
{% elif env == 'staging' %}
SELECT 2
{% else %}
SELECT 3
{% endif %}