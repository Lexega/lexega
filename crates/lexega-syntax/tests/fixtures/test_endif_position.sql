WITH
    base AS (
        SELECT {% if true %}
            a,
            b
        {% endif %}
    ),
    final AS (
        SELECT 1
    )
SELECT *
FROM final;