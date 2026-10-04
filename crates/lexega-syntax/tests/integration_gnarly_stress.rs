// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Comprehensive stress test with complex real-world SQL scenarios
//! Tests: precedence hell, join chains, semi-structured data, time travel,
//! MATCH_RECOGNIZE patterns, and stored procedures with all features combined

use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_gnarly_precedence_hell() {
    let sql = r#"SELECT /* precedence hell */  t.id , t.flag_active , t.flag_deleted , t.status_code , t.created_at , CASE WHEN NOT t.flag_deleted AND t.status_code = 'ACTIVE' OR t.status_code = 'PENDING' AND ( t.flag_active = TRUE OR t.flag_active IS NULL /* treat null as active-ish */ ) AND NOT ( t.status_code = 'BANNED' OR t.status_code = 'SUSPENDED' AND t.flag_deleted = TRUE ) THEN 'IN_SCOPE' ELSE 'OUT_OF_SCOPE' END AS scope_label FROM  app_db.core_users   t  WHERE      NOT t.flag_deleted AND t.status_code = 'ACTIVE' OR t.status_code = 'PENDING' AND ( t.flag_active = TRUE OR t.flag_active IS NULL ) AND NOT ( t.status_code = 'BANNED' OR t.status_code = 'SUSPENDED' AND t.flag_deleted = TRUE ) AND ( ( t.created_at >= '2024-01-01'::TIMESTAMP_NTZ AND t.created_at < '2025-01-01'::TIMESTAMP_NTZ ) OR t.created_at IS NULL /* legacy load */ ) ORDER BY t.id"#;

    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
    // Parsing succeeds - that's the test
}

#[test]
fn test_gnarly_join_chain_from_hell() {
    let sql = r#"SELECT /* join chain from hell */  o.order_id , o.customer_id , c.customer_name , r.region_name , o.status , o.order_date , o.order_total , p.promo_code , p.discount_amount , CASE WHEN ( o.status = 'CANCELLED' AND p.promo_code IS NOT NULL ) THEN 'CANCELLED_WITH_PROMO' WHEN ( o.status = 'COMPLETE' AND p.promo_code IS NULL AND r.region_name ILIKE '%east%' ) THEN 'COMPLETE_NO_PROMO_EAST' ELSE 'OTHER' END AS weird_bucket FROM fact_orders      o LEFT JOIN dim_customers  c ON c.customer_id = o.customer_id AND c.is_deleted = FALSE RIGHT JOIN dim_regions    r ON r.region_id = c.region_id AND r.is_active = TRUE LEFT JOIN dim_promotions p ON p.promo_id = o.promo_id AND p.is_expired = FALSE WHERE ( o.order_date >= '2024-01-01'::DATE AND o.order_date < '2025-01-01'::DATE ) AND ( o.status IN ( 'COMPLETE' , 'CANCELLED' , 'PENDING' ) OR o.status IS NULL ) AND ( r.region_type = 'SALES' OR r.region_type IS NULL ) /* moving this into ON materially changes result set */ ORDER BY r.region_name , c.customer_name , o.order_date"#;

    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_gnarly_semi_structured_junk() {
    let sql = r#"SELECT /* semi-structured junk */  e."EVENT_ID"                           AS "EventId" , e."USER_ID"                             AS "User" , e.event_time::TIMESTAMP_NTZ              AS "Ts" , ( e.payload:"metadata"::OBJECT )              AS "meta" , ( e.payload:"metadata":"source"::STRING )     AS "source" , ( e.payload:"metadata":"campaignId"::NUMBER ) AS "campaign" , v:"productId"::STRING                        AS product_id , v:"price"::NUMBER(18,2)                        AS price , v:"attributes":"color"::STRING                 AS color , v:"attributes":"size"::STRING                  AS size , CASE WHEN ( v:"discount" IS NOT NULL AND v:"discount"::NUMBER > 0 ) THEN 'DISCOUNTED' ELSE 'FULL' END AS price_flag , COUNT(*) OVER ( PARTITION BY e."USER_ID" ORDER BY e.event_time ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW ) AS seq_for_user FROM raw_events e , LATERAL FLATTEN( input => e.payload:"items", outer => TRUE ) f , LATERAL ( SELECT f.value::VARIANT AS v ) AS vv WHERE ( e.event_time >= '2024-01-01'::TIMESTAMP_NTZ ) AND ( e.event_time <  '2024-03-01'::TIMESTAMP_NTZ ) AND ( e.payload:"metadata":"source"::STRING ILIKE '%web%' OR e.payload:"metadata":"source"::STRING ILIKE '%mobile%' ) AND ( v:"productId" IS NOT NULL OR v:"price" IS NOT NULL OR v IS NULL /* keep some garbage rows */ ) ORDER BY e."USER_ID", e.event_time, product_id"#;

    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_gnarly_time_travel_with_subqueries() {
    let sql = r#"SELECT /* time travel and nasty CASE */  u.user_id , u.email , u.created_at , u.status , CONVERT_TIMEZONE('America/Chicago', u.created_at) AS created_local , ( SELECT COUNT(*) FROM user_logins l WHERE l.user_id = u.user_id AND l.login_ts >= DATEADD('day', -30, CURRENT_TIMESTAMP()) ) AS logins_30d , CASE WHEN ( u.status = 'ACTIVE' AND ( SELECT COUNT(*) FROM user_logins l2 WHERE l2.user_id = u.user_id AND l2.login_ts >= DATEADD('day', -7, CURRENT_TIMESTAMP()) ) >= 3 ) THEN 'HIGH_ENGAGEMENT' WHEN ( u.status = 'ACTIVE' AND ( SELECT COUNT(*) FROM user_logins l3 WHERE l3.user_id = u.user_id AND l3.login_ts >= DATEADD('day', -7, CURRENT_TIMESTAMP()) ) BETWEEN 1 AND 2 ) THEN 'MEDIUM_ENGAGEMENT' WHEN ( u.status = 'ACTIVE' AND ( SELECT COUNT(*) FROM user_logins l4 WHERE l4.user_id = u.user_id AND l4.login_ts >= DATEADD('day', -7, CURRENT_TIMESTAMP()) ) = 0 ) THEN 'AT_RISK' WHEN ( u.status = 'INACTIVE' AND ( SELECT COUNT(*) FROM user_logins l5 WHERE l5.user_id = u.user_id AND l5.login_ts >= DATEADD('day', -365, CURRENT_TIMESTAMP()) ) > 0 ) THEN 'RECENTLY_INACTIVE' ELSE 'DORMANT' END AS engagement_segment FROM users u AT ( TIMESTAMP => '2024-06-01 00:00:00'::TIMESTAMP_NTZ ) WHERE ( u.created_at < '2024-06-01'::TIMESTAMP_NTZ ) AND ( u.status IN ( 'ACTIVE', 'INACTIVE', 'SUSPENDED' ) ) ORDER BY u.created_at, u.user_id"#;

    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_gnarly_match_recognize_pattern_chaos() {
    let sql = r#"SELECT /* match_recognize pattern chaos */  * FROM price_ticks t MATCH_RECOGNIZE ( PARTITION BY t.symbol ORDER BY t.ts MEASURES FIRST(A.ts) AS start_ts , LAST(C.ts) AS end_ts , FIRST(A.price) AS first_price , LAST(C.price) AS last_price , MIN(B.price) AS min_mid_price , ( last_price - first_price ) / NULLIF(first_price,0) AS total_change ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN ( A+ /* initial rise */ B* C+ ) DEFINE A AS A.price >= PREV(A.price) OR PREV(A.price) IS NULL , B AS ( B.price <= PREV(B.price) AND B.price >= PREV(A.price) /* middle wiggle */ ) , C AS ( C.price >= PREV(C.price) AND C.price > B.price /* breakout */ ) ) WHERE total_change >= 0.05 ORDER BY t.symbol, start_ts"#;

    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_gnarly_stored_procedure_mega_complex() {
    let sql = r#"CREATE OR REPLACE PROCEDURE util_db.public.rebuild_customer_activity(p_days INTEGER, p_dry_run BOOLEAN) RETURNS VARCHAR LANGUAGE SQL AS $$ DECLARE v_start_date DATE; v_end_date DATE; v_rows_merged NUMBER DEFAULT 0; v_rows_updated NUMBER DEFAULT 0; v_rows_deleted NUMBER DEFAULT 0; v_is_dry_run BOOLEAN := p_dry_run; v_sql STRING; BEGIN LET v_end_date := CURRENT_DATE(); LET v_start_date := DATEADD('day', -p_days, v_end_date); /* basic sanity check */ IF (p_days <= 0) THEN RETURN 'p_days must be > 0'; END IF; /* temp staging from semi-structured events + stage */ CREATE TEMP TABLE tmp_raw_events AS SELECT e:"userId"::NUMBER AS user_id, e:"eventType"::STRING AS event_type, e:"eventTime"::TIMESTAMP_NTZ AS event_ts, COALESCE(e:"properties":"device"::STRING, 'unknown') AS device, e AS raw_payload FROM @ingest_stage/events/ ( FILE_FORMAT => 'raw_db.public.events_json_ff' ) src, LATERAL FLATTEN(input => src.$1) f, LATERAL (SELECT f.value::VARIANT AS e) v WHERE e:"eventTime"::TIMESTAMP_NTZ BETWEEN v_start_date::TIMESTAMP_NTZ AND (v_end_date::TIMESTAMP_NTZ + 0.999999::DECIMAL); /* aggregate into daily activity and MERGE into fact table */ MERGE INTO analytics_db.fact_customer_activity tgt USING (SELECT user_id, DATE_TRUNC('day', event_ts) AS activity_date, COUNT_IF(event_type = 'login') AS logins, COUNT_IF(event_type = 'logout') AS logouts, COUNT_IF(event_type = 'purchase') AS purchases, MAX(event_ts) AS last_event_ts FROM tmp_raw_events GROUP BY user_id, DATE_TRUNC('day', event_ts)) src ON tgt.user_id = src.user_id AND tgt.activity_date = src.activity_date WHEN MATCHED THEN UPDATE SET tgt.logins = src.logins, tgt.logouts = src.logouts, tgt.purchases = src.purchases, tgt.last_event_ts = src.last_event_ts, tgt.updated_at = CURRENT_TIMESTAMP() WHEN NOT MATCHED THEN INSERT (user_id, activity_date, logins, logouts, purchases, last_event_ts, created_at, updated_at) VALUES (src.user_id, src.activity_date, src.logins, src.logouts, src.purchases, src.last_event_ts, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()); SELECT COUNT(*) INTO :v_rows_merged FROM analytics_db.fact_customer_activity WHERE activity_date BETWEEN v_start_date AND v_end_date; /* pattern-based churn-ish banding from activity */ UPDATE analytics_db.dim_customer d SET churn_risk_band = a.risk_band FROM (SELECT user_id, start_ts, end_ts, total_change, CASE WHEN total_change <= -0.5 THEN 'HIGH_RISK' WHEN total_change <= -0.2 THEN 'MEDIUM_RISK' ELSE 'LOW_RISK' END AS risk_band FROM analytics_db.fact_customer_activity MATCH_RECOGNIZE(PARTITION BY user_id ORDER BY activity_date MEASURES FIRST(activity_date) AS start_ts, LAST(activity_date) AS end_ts, (LAST(logins) - FIRST(logins)) / NULLIF(GREATEST(FIRST(logins), 1), 0) AS total_change ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN (A+) DEFINE A AS TRUE)) a WHERE d.customer_id = a.user_id; SELECT COUNT(*) INTO :v_rows_updated FROM analytics_db.dim_customer WHERE churn_risk_band IS NOT NULL; /* optional cleanup of temp staging */ IF (NOT v_is_dry_run) THEN DELETE FROM tmp_raw_events WHERE event_ts < v_start_date::TIMESTAMP_NTZ; SELECT COUNT(*) INTO :v_rows_deleted FROM tmp_raw_events; END IF; /* dynamic DDL (opaque to formatter) */ v_sql := 'ALTER TABLE analytics_db.fact_customer_activity CLUSTER BY (activity_date, user_id)'; IF (NOT v_is_dry_run) THEN EXECUTE IMMEDIATE :v_sql; END IF; RETURN 'OK: merged=' || v_rows_merged || ', updated=' || v_rows_updated || ', deleted=' || v_rows_deleted || ', dry_run=' || IFF(v_is_dry_run, 'TRUE', 'FALSE'); EXCEPTION WHEN OTHER THEN RETURN 'ERROR in rebuild_customer_activity: ' || :sqlerrm; END; $$"#;

    let _stmt = parse_stmt_from_str(sql).expect("Parse failed");
}

#[test]
fn test_gnarly_all_statements_parse_independently() {
    // Verify each major statement can be parsed separately
    let statements = vec![
        r#"SELECT t.id FROM app_db.core_users t WHERE NOT t.flag_deleted"#,
        r#"SELECT o.order_id FROM fact_orders o LEFT JOIN dim_customers c ON c.customer_id = o.customer_id"#,
        r#"SELECT e."EVENT_ID" FROM raw_events e, LATERAL FLATTEN(input => e.payload:"items") f"#,
        r#"SELECT u.user_id FROM users u AT (TIMESTAMP => '2024-06-01 00:00:00'::TIMESTAMP_NTZ)"#,
        r#"SELECT * FROM price_ticks MATCH_RECOGNIZE(PATTERN(A+) DEFINE A AS TRUE)"#,
    ];

    for sql in statements {
        let _result = parse_stmt_from_str(sql).expect(&format!("Failed to parse: {}", sql));
    }
}
