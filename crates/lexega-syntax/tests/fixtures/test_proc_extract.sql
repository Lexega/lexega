CREATE OR REPLACE PROCEDURE util_db.public.rebuild_customer_activity(p_days INTEGER, p_dry_run BOOLEAN)
RETURNS VARCHAR LANGUAGE SQL AS $$
DECLARE
    v_start_date DATE;
    v_end_date DATE;
    v_rows_merged NUMBER DEFAULT 0;
    v_rows_updated NUMBER DEFAULT 0;
    v_rows_deleted NUMBER DEFAULT 0;
    v_is_dry_run BOOLEAN := p_dry_run;
    v_sql STRING;
BEGIN
    LET v_end_date := CURRENT_DATE();
    LET v_start_date := DATEADD('day', - p_days,v_end_date); /* basic sanity check */ 
    IF (p_days <= 0) THEN
        RETURN 'p_days must be > 0';
    END IF; /* temp staging from semi-structured events + stage */ 
    CREATE TEMP TABLE tmp_raw_events
    AS
    SELECT
        e:"userId"::NUMBER AS user_id,
        e:"eventType"::STRING AS event_type,
        e:"eventTime"::TIMESTAMP_NTZ AS event_ts,
        COALESCE(e:"properties":"device"::STRING,'unknown') AS device,
        e AS raw_payload
    FROM @ingest_stage/events/ ( FILE_FORMAT => 'raw_db.public.events_json_ff' ) src,LATERAL FLATTEN(input => src.$1) f,LATERAL (
        SELECT f.value::VARIANT AS e
    ) v
    WHERE e:"eventTime"::TIMESTAMP_NTZ BETWEEN v_start_date::TIMESTAMP_NTZ AND (v_end_date::TIMESTAMP_NTZ + 0.999999::DECIMAL); /* aggregate into daily activity and MERGE into fact table */ 
    MERGE INTO analytics_db.fact_customer_activity tgt
    USING (SELECT
        user_id,
        DATE_TRUNC('day',event_ts) AS activity_date,
        COUNT_IF(event_type = 'login') AS logins,
        COUNT_IF(event_type = 'logout') AS logouts,
        COUNT_IF(event_type = 'purchase') AS purchases,
        MAX(event_ts) AS last_event_ts
    FROM tmp_raw_events
    GROUP BY user_id,DATE_TRUNC('day',event_ts)) src
    ON tgt.user_id = src.user_id AND tgt.activity_date = src.activity_date
    WHEN MATCHED THEN
    UPDATE SET tgt.logins = src.logins, tgt.logouts = src.logouts, tgt.purchases = src.purchases, tgt.last_event_ts = src.last_event_ts, tgt.updated_at = CURRENT_TIMESTAMP()
    WHEN NOT MATCHED THEN
    INSERT (user_id, activity_date, logins, logouts, purchases, last_event_ts, created_at, updated_at) VALUES (src.user_id, src.activity_date, src.logins, src.logouts, src.purchases, src.last_event_ts, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP());
    SELECT COUNT(*) INTO :v_rows_merged
    FROM analytics_db.fact_customer_activity
    WHERE activity_date BETWEEN v_start_date AND v_end_date; /* pattern-based churn-ish banding from activity */ 
    UPDATE analytics_db.dim_customer d
    SET churn_risk_band = a.risk_band
    FROM (
        SELECT
            user_id,
            start_ts,
            end_ts,
            total_change,
            CASE
                WHEN total_change <= -0.5 THEN 'HIGH_RISK'
                WHEN total_change <= -0.2 THEN 'MEDIUM_RISK'
                ELSE 'LOW_RISK'
            END AS risk_band
        FROM analytics_db.fact_customer_activity
        MATCH_RECOGNIZE( PARTITION BY user_id ORDER BY activity_date MEASURES FIRST(activity_date) AS start_ts, LAST(activity_date) AS end_ts, (LAST(logins) - FIRST(logins)) / NULLIF(GREATEST(FIRST(logins),1),0) AS total_change ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN (A +) DEFINE A AS TRUE)
    ) a
    WHERE d.customer_id = a.user_id;
    SELECT COUNT(*) INTO :v_rows_updated
    FROM analytics_db.dim_customer
    WHERE churn_risk_band IS NOT NULL; /* optional cleanup of temp staging */ 
    IF (NOT v_is_dry_run) THEN
        DELETE FROM tmp_raw_events
        WHERE event_ts < v_start_date::TIMESTAMP_NTZ;
        SELECT COUNT(*) INTO :v_rows_deleted
        FROM tmp_raw_events;
    END IF; /* dynamic DDL (opaque to formatter) */ 
    v_sql := 'ALTER TABLE analytics_db.fact_customer_activity CLUSTER BY (activity_date, user_id)';
    IF (NOT v_is_dry_run) THEN
        EXECUTE IMMEDIATE :v_sql;
    END IF;
    RETURN 'OK: merged=' || v_rows_merged || ', updated=' || v_rows_updated || ', deleted=' || v_rows_deleted || ', dry_run=' || IFF(v_is_dry_run,'TRUE','FALSE');
    EXCEPTION
        WHEN OTHER THEN
            RETURN 'ERROR in rebuild_customer_activity: ' || :sqlerrm;
END;
$$;