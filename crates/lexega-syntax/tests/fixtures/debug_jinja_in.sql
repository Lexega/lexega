SELECT *
FROM t
WHERE x IN (
{% for et in event_types %}
    '{{ et }}'{% if not loop.last %}, {% endif %}
    {% endfor %})