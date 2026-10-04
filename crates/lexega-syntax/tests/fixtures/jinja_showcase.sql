-- Test Jinja template formatting with complex dbt models
-- This file tests the template system with realistic dbt patterns
{{ config(
    materialized = 'incremental',
    unique_key = 'customer_id',
    on_schema_change = 'sync_all_columns'
) }}
{% set inactivity_minutes = var("session_gap_minutes", 30) %}
{% set allowed_statuses = var('allowed_statuses', ['active', 'pending']) %}
WITH
    base_events AS (
        SELECT
            user_id,
            event_id,
            event_type,
            event_ts::timestamp_ntz AS event_ts
        FROM {{ source('raw', 'events') }}
        WHERE event_ts >= DATEADD('day',-30,CURRENT_TIMESTAMP()){% if is_incremental() %} AND event_ts > (SELECT MAX(event_ts)
        FROM {{ this }}){% endif %}
    ),
    user_aggregates AS (
        SELECT
            user_id,
            COUNT(*) AS event_count,
            MIN(event_ts) AS first_event,
            MAX(event_ts) AS last_event
        FROM base_events
        GROUP BY user_id
    ),
    with_windows AS (
        SELECT
            a.*,
            ROW_NUMBER() OVER (
                ORDER BY event_count DESC
            ) AS user_rank,
            SUM(event_count) OVER (
                ORDER BY first_event
            ) AS cumulative_events
        FROM user_aggregates AS a
    )
SELECT *
FROM with_windows
WHERE user_rank <= 100 AND event_count > {{ var('min_events', 10) }}{% if var('exclude_test_users', true) %} AND user_id NOT LIKE 'test_%'{% endif %}
QUALIFY ROW_NUMBER() OVER (
    PARTITION BY user_id
    ORDER BY last_event DESC
) = 1;