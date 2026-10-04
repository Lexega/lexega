CREATE OR REPLACE PROCEDURE util_db.public.rebuild_customer_activity(p_days INTEGER, p_dry_run BOOLEAN)
RETURNS VARCHAR
LANGUAGE SQL
AS $$
DECLARE
    v_start_date DATE;
BEGIN
    LET v_start_date := CURRENT_DATE();
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
                ELSE 'LOW_RISK'
            END AS risk_band
        FROM analytics_db.fact_customer_activity
        MATCH_RECOGNIZE( PARTITION BY user_id ORDER BY activity_date MEASURES FIRST(activity_date) AS start_ts, LAST(activity_date) AS end_ts, (LAST(logins) - FIRST(logins)) / NULLIF(GREATEST(FIRST(logins),1),0) AS total_change ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN (A +) DEFINE A AS TRUE)
    ) a
    WHERE d.customer_id = a.user_id;
    RETURN 'OK';
END;
$$;