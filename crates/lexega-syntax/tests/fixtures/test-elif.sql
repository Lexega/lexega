{% set score = 75 %}
SELECT
    {% if score >= 90 %}
        'A'
    {% elif score >= 80 %}
        'B'
    {% elif score >= 70 %}
        'C'
    {% else %}
        'F'
    {% endif %} AS grade
FROM grades;