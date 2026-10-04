{{ config(
    materialized = 'view',
    tags = ['staging', 'orders'],
    grant_select_to = 'ANALYST_ROLE'
) }}
{# Optional env-specific filter #} {% set env = target.name %}
{% set apply_recent_filter = var('stg_orders_recent_only', true) %}
WITH
    raw AS (
        SELECT
            o.ORDER_ID::NUMBER AS order_id,
            o.CUSTOMER_ID::NUMBER AS customer_id,
            o.ORDER_STATUS::STRING AS order_status,
            o.ORDER_TS::TIMESTAMP_NTZ AS order_ts,
            o.ORDER_CHANNEL::STRING AS order_channel,
            o.ORDER_AMOUNT::NUMBER(18,2) AS order_amount,
            o.METADATA::VARIANT AS metadata,
            CURRENT_TIMESTAMP() AS _loaded_at
        FROM {{ source('raw', 'orders') }} AS o{% if env in ['prod', 'qa'] and apply_recent_filter %}
        WHERE o.ORDER_TS >= DATEADD('day',-90,CURRENT_TIMESTAMP()){% endif %}
    ),
    normalized AS (
        SELECT
            order_id,
            customer_id,
            upper(order_status) AS order_status,
            order_ts,
            order_channel,
            order_amount,
            metadata,
            metadata:"shipping"::VARIANT AS shipping_metadata,
            TRY_PARSE_JSON(metadata:"tags") AS tags,
            _loaded_at
        FROM raw
    ),
    exploded_tags AS (
        SELECT
            n.order_id,
            n.customer_id,
            n.order_status,
            n.order_ts,
            n.order_channel,
            n.order_amount,
            n._loaded_at,
            t.value::string AS tag
        FROM normalized AS n,LATERAL FLATTEN(input => n.tags) AS t
    ),
    deduped AS (
        SELECT
            order_id,
            customer_id,
            order_status,
            order_ts,
            order_channel,
            order_amount,
            ARRAY_AGG(tag) AS tags,
            MIN(_loaded_at) AS first_loaded_at,
            MAX(_loaded_at) AS last_loaded_at
        FROM exploded_tags
        GROUP BY order_id,customer_id,order_status,order_ts,order_channel,order_amount
    )
SELECT
    order_id,
    customer_id,
    order_status,
    order_ts,
    order_channel,
    order_amount,
    tags,
    first_loaded_at,
    last_loaded_at
FROM deduped;
{{ config(
    materialized = 'incremental',
    unique_key   = 'customer_id',
    on_schema_change = 'sync_all_columns',
    cluster_by = ['customer_id'],
    tags = ['fact', 'revenue']
) }}
{% set is_full_refresh = flags.FULL_REFRESH %}
{% set use_soft_deletes = var('use_soft_deletes', false) %}
WITH
    base_orders AS (
        SELECT
            o.customer_id,
            o.order_id,
            o.order_ts,
            o.order_amount,
            IFF(o.order_status ILIKE 'CANCEL%',1,0) AS is_cancelled
        FROM {{ ref('stg_orders') }} AS o{% if is_incremental() and not is_full_refresh %}
        WHERE o.order_ts > (SELECT COALESCE(MAX(order_ts),'1900-01-01'::timestamp_ntz)
        FROM {{ this }}){% endif %}
    ),
    agg AS (
        SELECT
            customer_id,
            COUNT(*) AS order_count,
            SUM(order_amount) AS gross_revenue,
            SUM(IFF(is_cancelled = 1,order_amount,0)) AS cancelled_revenue,
            SUM(IFF(is_cancelled = 0,order_amount,0)) AS net_revenue,
            MIN(order_ts) AS first_order_ts,
            MAX(order_ts) AS last_order_ts
        FROM base_orders
        GROUP BY customer_id
    ),
    with_windows AS (
        SELECT
            a.*,
            ROW_NUMBER() OVER (
                ORDER BY net_revenue DESC
            ) AS revenue_rank,
            PERCENT_RANK() OVER (
                ORDER BY net_revenue DESC
            ) AS revenue_percentile,
            NTILE(10) OVER (
                ORDER BY net_revenue DESC NULLS LAST
            ) AS revenue_decile,
            AVG(net_revenue) OVER () AS avg_customer_net_revenue
        FROM agg AS a
    ),
    final AS (
        SELECT
            customer_id,
            order_count,
            gross_revenue,
            cancelled_revenue,
            net_revenue,
            first_order_ts,
            last_order_ts,
            revenue_rank,
            revenue_percentile,
            revenue_decile,
            avg_customer_net_revenue,
            CURRENT_TIMESTAMP() AS updated_at,
            {% if use_soft_deletes %}
                0::boolean AS is_deleted
            {% else %}
                NULL::boolean AS is_deleted
            {% endif %}
        FROM with_windows
    )
SELECT *
FROM final;
{{ config(
    materialized = 'table',
    tags = ['events', 'pivot']
) }}
{% set event_types = var('event_types', ['view', 'click', 'purchase']) %}
WITH
    raw_events AS (
        SELECT
            user_id,
            session_id,
            event_type,
            event_ts,
            1 AS event_count
        FROM {{ source('raw', 'events') }}
        WHERE event_type IN (
        {% for et in event_types %}
            '{{ et }}'{% if not loop.last %}, {% endif %}
        {% endfor %})
    ),
    by_user_session_and_type AS (
        SELECT
            user_id,
            session_id,
            event_type,
            COUNT(*) AS events
        FROM raw_events
        GROUP BY user_id,session_id,event_type
    ),
    pivoted AS (
        SELECT *
        FROM by_user_session_and_type PIVOT(SUM(events) FOR event_type IN (
        {% for et in event_types %}
            '{{ et }}'{% if not loop.last %}, {% endif %}
            {% endfor %})) AS p
    ),
    final AS (
        SELECT
            user_id,
            session_id,
            COALESCE("view",0) AS views,
            COALESCE("click",0) AS clicks,
            COALESCE("purchase",0) AS purchases,
            COALESCE("view",0) + COALESCE("click",0) + COALESCE("purchase",0) AS total_tracked_events
        FROM pivoted
    )
SELECT *
FROM final;
{{ config(
    materialized = 'incremental',
    unique_key   = ['customer_id', 'order_month'],
    tags = ['intermediate', 'orders']
) }}
WITH
    orders AS (
        SELECT
            customer_id,
            DATE_TRUNC('month',order_ts) AS order_month,
            order_amount,
            order_status
        FROM {{ ref('stg_orders') }}
    ),
    base_agg AS (
        SELECT
            customer_id,
            order_month,
            COUNT(*) AS order_count,
            SUM(order_amount) AS total_amount,
            SUM(IFF(order_status ILIKE 'CANCEL%',1,0)) AS cancelled_count
        FROM orders
        GROUP BY customer_id,order_month
    ),
    merged AS (
        SELECT
            b.customer_id,
            b.order_month,
            b.order_count,
            b.total_amount,
            b.cancelled_count
        FROM base_agg AS b{% if is_incremental() %}
        LEFT JOIN {{ this }} AS existing ON existing.customer_id = b.customer_id AND existing.order_month = b.order_month
        WHERE existing.customer_id IS NULL{% endif %}
    )
SELECT *
FROM merged;