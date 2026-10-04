-- Test WHERE clause with conditional Jinja blocks
SELECT *
FROM base
WHERE created_date >= '2024-01-01'{% if var('region_filter', none) is not none %} and region = '{{ var("region_filter") }}'{% endif %};