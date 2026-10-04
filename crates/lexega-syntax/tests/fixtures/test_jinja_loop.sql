{% set metric_keys = ["clicks", "impressions", "spend"] %}
SELECT user_id, {% for k in metric_keys %}
    sum(iff(metric_key = '{{ k }}',metric_value,0)) AS {{ k }}{% if not loop.last %},{% endif %}
{% endfor %}
FROM flattened
GROUP BY user_id;