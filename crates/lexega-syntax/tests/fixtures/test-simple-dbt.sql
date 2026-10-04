{{ config(materialized='table') }}
{% set my_var = 'hello' %}
{% set my_list = ['a', 'b', 'c'] %}
SELECT
    col1,
    col2,
    '{{ my_var }}' AS greeting
FROM {{ ref('orders') }}
WHERE status IN (
{% for item in my_list %}
    '{{ item }}'{% if not loop.last %},{% endif %}
    {% endfor %});