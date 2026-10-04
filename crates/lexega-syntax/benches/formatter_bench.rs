// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lexega_syntax::context::RenderContext;
use lexega_syntax::formatter::Formatter;
use lexega_syntax::lexer::tokenize;
use lexega_syntax::parser::parse_script;

/// Format SQL using the formatter API
fn format_sql(source: &str) -> String {
    let tokens = tokenize(source);
    let script = parse_script(source, &tokens.tokens).expect("Parse failed");
    let context = RenderContext::from_source(source.to_string());
    let formatter = Formatter::new();
    let result = formatter
        .format_script(context, &script)
        .expect("Format failed");
    result
        .formatted()
        .map(|f| f.formatted_sql().to_string())
        .expect("No formatted output")
}

fn format_simple_select(c: &mut Criterion) {
    let sql = "SELECT id, name, email FROM users WHERE active = true ORDER BY created_at DESC";

    c.bench_function("format_simple_select", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_complex_select(c: &mut Criterion) {
    let sql = r#"
        SELECT 
            u.id,
            u.name,
            u.email,
            COUNT(o.id) as order_count,
            SUM(o.total) as total_spent,
            AVG(o.total) as avg_order
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.active = true
            AND u.created_at >= '2024-01-01'
            AND o.status IN ('completed', 'shipped')
        GROUP BY u.id, u.name, u.email
        HAVING COUNT(o.id) > 5
        ORDER BY total_spent DESC
        LIMIT 100
    "#;

    c.bench_function("format_complex_select", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_with_cte(c: &mut Criterion) {
    let sql = r#"
        WITH active_users AS (
            SELECT id, name, email FROM users WHERE active = true
        ),
        user_orders AS (
            SELECT user_id, COUNT(*) as order_count 
            FROM orders 
            GROUP BY user_id
        )
        SELECT 
            au.id,
            au.name,
            COALESCE(uo.order_count, 0) as orders
        FROM active_users au
        LEFT JOIN user_orders uo ON au.id = uo.user_id
        ORDER BY orders DESC
    "#;

    c.bench_function("format_with_cte", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_window_functions(c: &mut Criterion) {
    let sql = r#"
        SELECT 
            id,
            name,
            salary,
            ROW_NUMBER() OVER (ORDER BY salary DESC) as rank,
            LAG(salary, 1) OVER (ORDER BY salary DESC) as prev_salary,
            LEAD(salary, 1) OVER (ORDER BY salary DESC) as next_salary,
            AVG(salary) OVER (PARTITION BY department_id) as dept_avg
        FROM employees
    "#;

    c.bench_function("format_window_functions", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_subqueries(c: &mut Criterion) {
    let sql = r#"
        SELECT 
            u.id,
            u.name,
            (SELECT COUNT(*) FROM orders WHERE user_id = u.id) as order_count,
            (SELECT MAX(created_at) FROM orders WHERE user_id = u.id) as last_order
        FROM users u
        WHERE u.id IN (
            SELECT DISTINCT user_id 
            FROM orders 
            WHERE created_at >= '2024-01-01'
        )
    "#;

    c.bench_function("format_subqueries", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_varying_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("format_by_size");

    let sizes = vec![
        ("tiny", "SELECT id FROM users"),
        ("small", "SELECT id, name FROM users WHERE active = true"),
        ("medium", "SELECT u.id, u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.name"),
        ("large", r#"
            SELECT 
                u.id, u.name, u.email,
                COUNT(o.id) as orders,
                SUM(o.total) as spent,
                AVG(o.total) as avg
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            LEFT JOIN products p ON o.product_id = p.id
            WHERE u.active = true
                AND o.status = 'completed'
                AND p.category IN ('electronics', 'books')
            GROUP BY u.id, u.name, u.email
            HAVING COUNT(o.id) > 10
            ORDER BY spent DESC
            LIMIT 100
        "#),
    ];

    for (name, sql) in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(name), &sql, |b, sql| {
            b.iter(|| {
                let formatted = format_sql(black_box(sql));
                black_box(formatted)
            });
        });
    }

    group.finish();
}

/*
fn format_pipe_chain(c: &mut Criterion) {
    let sql = r#"
        SELECT *
        FROM raw_events
        WHERE event_date >= '2025-01-01'

        ->> SELECT user_id, COUNT(*) AS event_count
            FROM TABLE(FLATTEN(@stage, input => raw_events))
            GROUP BY user_id

        ->> INSERT INTO analytics.daily_user_events (user_id, event_count)
    "#;

    c.bench_function("format_pipe_chain", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}
*/

fn format_scripting_block(c: &mut Criterion) {
    let sql = r#"
        BEGIN
            DECLARE
                v_total NUMBER;
            BEGIN
                SELECT SUM(amount)
                  INTO :v_total
                  FROM payments
                 WHERE payment_date >= '2025-01-01';

                IF (v_total > 100000) THEN
                    INSERT INTO alerts(id, message)
                    SELECT RANDOM(), 'High payment volume';
                END IF;
            END;
        END;
    "#;

    c.bench_function("format_scripting_block", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_time_travel_and_changes(c: &mut Criterion) {
    let sql = r#"
        SELECT *
        FROM orders CHANGES(information => APPEND_ONLY)
        AT(OFFSET => -60 * 60)
        WHERE status = 'COMPLETED'
    "#;

    c.bench_function("format_time_travel_and_changes", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_gnarly_queries_file_1(c: &mut Criterion) {
    // Derived from tests/test_gnarly.sql (multiple heavy statements).
    let sql = r#"-- gnarly test queries
SELECT /* precedence hell */  t.id , t.flag_active , t.flag_deleted , t.status_code , t.created_at , CASE WHEN NOT t.flag_deleted AND t.status_code = 'ACTIVE' OR t.status_code = 'PENDING' AND ( t.flag_active = TRUE OR t.flag_active IS NULL /* treat null as active-ish */ ) AND NOT ( t.status_code = 'BANNED' OR t.status_code = 'SUSPENDED' AND t.flag_deleted = TRUE ) THEN 'IN_SCOPE' ELSE 'OUT_OF_SCOPE' END AS scope_label FROM  app_db.core_users   t  WHERE      NOT t.flag_deleted AND t.status_code = 'ACTIVE' OR t.status_code = 'PENDING' AND ( t.flag_active = TRUE OR t.flag_active IS NULL ) AND NOT ( t.status_code = 'BANNED' OR t.status_code = 'SUSPENDED' AND t.flag_deleted = TRUE ) AND ( ( t.created_at >= '2024-01-01'::TIMESTAMP_NTZ AND t.created_at < '2025-01-01'::TIMESTAMP_NTZ ) OR t.created_at IS NULL /* legacy load */ ) ORDER BY t.id;
SELECT /* join chain from hell */  o.order_id , o.customer_id , c.customer_name , r.region_name , o.status , o.order_date , o.order_total , p.promo_code , p.discount_amount , CASE WHEN ( o.status = 'CANCELLED' AND p.promo_code IS NOT NULL ) THEN 'CANCELLED_WITH_PROMO' WHEN ( o.status = 'COMPLETE' AND p.promo_code IS NULL AND r.region_name ILIKE '%east%' ) THEN 'COMPLETE_NO_PROMO_EAST' ELSE 'OTHER' END AS weird_bucket FROM fact_orders      o LEFT JOIN dim_customers  c ON c.customer_id = o.customer_id AND c.is_deleted = FALSE RIGHT JOIN dim_regions    r ON r.region_id = c.region_id AND r.is_active = TRUE LEFT JOIN dim_promotions p ON p.promo_id = o.promo_id AND p.is_expired = FALSE WHERE ( o.order_date >= '2024-01-01'::DATE AND o.order_date < '2025-01-01'::DATE ) AND ( o.status IN ( 'COMPLETE' , 'CANCELLED' , 'PENDING' ) OR o.status IS NULL ) AND ( r.region_type = 'SALES' OR r.region_type IS NULL ) /* moving this into ON materially changes result set */ ORDER BY r.region_name , c.customer_name , o.order_date;
SELECT /* semi-structured junk */  e."EVENT_ID"                           AS "EventId" , e."USER_ID"                             AS "User" , e.event_time::TIMESTAMP_NTZ              AS "Ts" , ( e.payload:"metadata"::OBJECT )              AS "meta" , ( e.payload:"metadata":"source"::STRING )     AS "source" , ( e.payload:"metadata":"campaignId"::NUMBER ) AS "campaign" , v:"productId"::STRING                        AS product_id , v:"price"::NUMBER(18,2)                        AS price , v:"attributes":"color"::STRING                 AS color , v:"attributes":"size"::STRING                  AS size , CASE WHEN ( v:"discount" IS NOT NULL AND v:"discount"::NUMBER > 0 ) THEN 'DISCOUNTED' ELSE 'FULL' END AS price_flag , COUNT(*) OVER ( PARTITION BY e."USER_ID" ORDER BY e.event_time ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW ) AS seq_for_user FROM raw_events e , LATERAL FLATTEN( input => e.payload:"items", outer => TRUE ) f , LATERAL ( SELECT f.value::VARIANT AS v ) AS vv WHERE ( e.event_time >= '2024-01-01'::TIMESTAMP_NTZ ) AND ( e.event_time <  '2024-03-01'::TIMESTAMP_NTZ ) AND ( e.payload:"metadata":"source"::STRING ILIKE '%web%' OR e.payload:"metadata":"source"::STRING ILIKE '%mobile%' ) AND ( v:"productId" IS NOT NULL OR v:"price" IS NOT NULL OR v IS NULL /* keep some garbage rows */ ) ORDER BY e."USER_ID", e.event_time, product_id;
SELECT /* time travel and nasty CASE */  u.user_id , u.email , u.created_at , u.status , CONVERT_TIMEZONE('America/Chicago', u.created_at) AS created_local , ( SELECT COUNT(*) FROM user_logins l WHERE l.user_id = u.user_id AND l.login_ts >= DATEADD('day', -30, CURRENT_TIMESTAMP()) ) AS logins_30d , CASE WHEN ( u.status = 'ACTIVE' AND ( SELECT COUNT(*) FROM user_logins l2 WHERE l2.user_id = u.user_id AND l2.login_ts >= DATEADD('day', -7, CURRENT_TIMESTAMP()) ) >= 3 ) THEN 'HIGH_ENGAGEMENT' WHEN ( u.status = 'ACTIVE' AND ( SELECT COUNT(*) FROM user_logins l3 WHERE l3.user_id = u.user_id AND l3.login_ts >= DATEADD('day', -7, CURRENT_TIMESTAMP()) ) BETWEEN 1 AND 2 ) THEN 'MEDIUM_ENGAGEMENT' WHEN ( u.status = 'ACTIVE' AND ( SELECT COUNT(*) FROM user_logins l4 WHERE l4.user_id = u.user_id AND l4.login_ts >= DATEADD('day', -7, CURRENT_TIMESTAMP()) ) = 0 ) THEN 'AT_RISK' WHEN ( u.status = 'INACTIVE' AND ( SELECT COUNT(*) FROM user_logins l5 WHERE l5.user_id = u.user_id AND l5.login_ts >= DATEADD('day', -365, CURRENT_TIMESTAMP()) ) > 0 ) THEN 'RECENTLY_INACTIVE' ELSE 'DORMANT' END AS engagement_segment FROM users u AT ( TIMESTAMP => '2024-06-01 00:00:00'::TIMESTAMP_NTZ ) WHERE ( u.created_at < '2024-06-01'::TIMESTAMP_NTZ ) AND ( u.status IN ( 'ACTIVE', 'INACTIVE', 'SUSPENDED' ) ) ORDER BY u.created_at, u.user_id;
SELECT /* match_recognize pattern chaos */  * FROM price_ticks t MATCH_RECOGNIZE ( PARTITION BY t.symbol ORDER BY t.ts MEASURES FIRST(A.ts) AS start_ts , LAST(C.ts) AS end_ts , FIRST(A.price) AS first_price , LAST(C.price) AS last_price , MIN(B.price) AS min_mid_price , ( last_price - first_price ) / NULLIF(first_price,0) AS total_change ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN ( A+ /* initial rise */ B* C+ ) DEFINE A AS A.price >= PREV(A.price) OR PREV(A.price) IS NULL , B AS ( B.price <= PREV(B.price) AND B.price >= PREV(A.price) /* middle wiggle */ ) , C AS ( C.price >= PREV(C.price) AND C.price > B.price /* breakout */ ) ) WHERE total_change >= 0.05 ORDER BY t.symbol, start_ts;
CREATE OR REPLACE PROCEDURE util_db.public.rebuild_customer_activity(p_days INTEGER, p_dry_run BOOLEAN) RETURNS VARCHAR LANGUAGE SQL AS $$ DECLARE v_start_date DATE; v_end_date DATE; v_rows_merged NUMBER DEFAULT 0; v_rows_updated NUMBER DEFAULT 0; v_rows_deleted NUMBER DEFAULT 0; v_is_dry_run BOOLEAN := p_dry_run; v_sql STRING; BEGIN LET v_end_date := CURRENT_DATE(); LET v_start_date := DATEADD('day', -p_days, v_end_date); /* basic sanity check */ IF (p_days <= 0) THEN RETURN 'p_days must be > 0'; END IF; /* temp staging from semi-structured events + stage */ CREATE TEMP TABLE tmp_raw_events AS SELECT e:"userId"::NUMBER AS user_id, e:"eventType"::STRING AS event_type, e:"eventTime"::TIMESTAMP_NTZ AS event_ts, COALESCE(e:"properties":"device"::STRING, 'unknown') AS device, e AS raw_payload FROM @ingest_stage/events/ ( FILE_FORMAT => 'raw_db.public.events_json_ff' ) src, LATERAL FLATTEN(input => src.$1) f, LATERAL (SELECT f.value::VARIANT AS e) v WHERE e:"eventTime"::TIMESTAMP_NTZ BETWEEN v_start_date::TIMESTAMP_NTZ AND (v_end_date::TIMESTAMP_NTZ + 0.999999::DECIMAL); /* aggregate into daily activity and MERGE into fact table */ MERGE INTO analytics_db.fact_customer_activity tgt USING (SELECT user_id, DATE_TRUNC('day', event_ts) AS activity_date, COUNT_IF(event_type = 'login') AS logins, COUNT_IF(event_type = 'logout') AS logouts, COUNT_IF(event_type = 'purchase') AS purchases, MAX(event_ts) AS last_event_ts FROM tmp_raw_events GROUP BY user_id, DATE_TRUNC('day', event_ts)) src ON tgt.user_id = src.user_id AND tgt.activity_date = src.activity_date WHEN MATCHED THEN UPDATE SET tgt.logins = src.logins, tgt.logouts = src.logouts, tgt.purchases = src.purchases, tgt.last_event_ts = src.last_event_ts, tgt.updated_at = CURRENT_TIMESTAMP() WHEN NOT MATCHED THEN INSERT (user_id, activity_date, logins, logouts, purchases, last_event_ts, created_at, updated_at) VALUES (src.user_id, src.activity_date, src.logins, src.logouts, src.purchases, src.last_event_ts, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()); SELECT COUNT(*) INTO :v_rows_merged FROM analytics_db.fact_customer_activity WHERE activity_date BETWEEN v_start_date AND v_end_date; /* pattern-based churn-ish banding from activity */ UPDATE analytics_db.dim_customer d SET churn_risk_band = a.risk_band FROM (SELECT user_id, start_ts, end_ts, total_change, CASE WHEN total_change <= -0.5 THEN 'HIGH_RISK' WHEN total_change <= -0.2 THEN 'MEDIUM_RISK' ELSE 'LOW_RISK' END AS risk_band FROM analytics_db.fact_customer_activity MATCH_RECOGNIZE(PARTITION BY user_id ORDER BY activity_date MEASURES FIRST(activity_date) AS start_ts, LAST(activity_date) AS end_ts, (LAST(logins) - FIRST(logins)) / NULLIF(GREATEST(FIRST(logins), 1), 0) AS total_change ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN (A+) DEFINE A AS TRUE)) a WHERE d.customer_id = a.user_id; SELECT COUNT(*) INTO :v_rows_updated FROM analytics_db.dim_customer WHERE churn_risk_band IS NOT NULL; /* optional cleanup of temp staging */ IF (NOT v_is_dry_run) THEN DELETE FROM tmp_raw_events WHERE event_ts < v_start_date::TIMESTAMP_NTZ; SELECT COUNT(*) INTO :v_rows_deleted FROM tmp_raw_events; END IF; /* dynamic DDL (opaque to formatter) */ v_sql := 'ALTER TABLE analytics_db.fact_customer_activity CLUSTER BY (activity_date, user_id)'; IF (NOT v_is_dry_run) THEN EXECUTE IMMEDIATE :v_sql; END IF; RETURN 'OK: merged=' || v_rows_merged || ', updated=' || v_rows_updated || ', deleted=' || v_rows_deleted || ', dry_run=' || IFF(v_is_dry_run, 'TRUE', 'FALSE'); EXCEPTION WHEN OTHER THEN RETURN 'ERROR in rebuild_customer_activity: ' || :sqlerrm; END; $$;
"#;

    c.bench_function("format_gnarly_queries_file_1", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn format_gnarly_queries_file_2(c: &mut Criterion) {
    // Derived from tests/test_gnarly2_in.sql (procedure + heavy CTEs).
    let sql = r#"/* reconciler */ CREATE OR REPLACE PROCEDURE util_db.public.reconcile_row_counts(p_days INTEGER,p_max_tables INTEGER) RETURNS VARCHAR LANGUAGE SQL AS $$ DECLARE v_cutoff_date DATE; v_processed INTEGER DEFAULT 0; v_failed INTEGER DEFAULT 0; v_msg STRING; v_sql STRING; v_err_msg STRING; c_tables CURSOR FOR SELECT table_name,date_column_name FROM control_db.etl_table_config WHERE is_active=TRUE AND COALESCE(retention_days,9999)>=p_days ORDER BY priority,table_name LIMIT p_max_tables; BEGIN LET v_cutoff_date:=DATEADD('day',-p_days,CURRENT_DATE()); CREATE TABLE IF NOT EXISTS audit_db.table_row_counts(table_name STRING,as_of_date DATE,row_count NUMBER,sampled BOOLEAN,created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()); FOR rec IN c_tables DO LET v_sql:='INSERT INTO audit_db.table_row_counts(table_name,as_of_date,row_count,sampled) SELECT '''||rec.table_name||''' AS table_name,CURRENT_DATE() AS as_of_date,COUNT(*) AS row_count,FALSE AS sampled FROM '||rec.table_name||' t WHERE t.'||rec.date_column_name||' >= :1'; EXECUTE IMMEDIATE :v_sql USING (v_cutoff_date); v_processed:=v_processed+1; END FOR; v_msg:='Rowcount reconcile complete. processed='||v_processed||', failed='||v_failed; RETURN v_msg; EXCEPTION WHEN OTHER THEN RETURN 'FATAL reconcile_row_counts error: '||SQLERRM; END; $$;
/* 2) recursive + pivot */ WITH RECURSIVE calendar AS (SELECT DATEADD('day',-30,CURRENT_DATE()) AS d UNION ALL SELECT DATEADD('day',1,d) FROM calendar WHERE d < CURRENT_DATE()), order_base AS (SELECT c.d AS order_date,o.customer_id,o.status,o.order_total,o.region_code,o.channel FROM calendar AS c LEFT JOIN sales_db.fact_orders AT(OFFSET => -3600) AS o ON o.order_date::DATE=c.d AND o.is_test=FALSE AND o.deleted_at IS NULL), order_enriched AS (SELECT b.order_date,b.customer_id,COALESCE(b.status,'UNKNOWN') AS status,COALESCE(b.region_code,'NA') AS region_code,COALESCE(b.channel,'UNSPECIFIED') AS channel,b.order_total,SUM(b.order_total) OVER (PARTITION BY b.customer_id ORDER BY b.order_date ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS running_total_for_customer,COUNT(*) OVER (PARTITION BY b.customer_id) AS orders_for_customer FROM order_base AS b), order_flags AS (SELECT *,CASE WHEN running_total_for_customer>=10000 THEN 'HIGH_VALUE' WHEN running_total_for_customer>=1000 THEN 'MID_VALUE' ELSE 'LOW_VALUE' END AS value_segment FROM order_enriched), pivoted_by_status AS (SELECT * FROM (SELECT order_date,region_code,channel,status,order_total FROM order_flags) src PIVOT (SUM(order_total) AS amt FOR status IN ('COMPLETE','CANCELLED','PENDING','UNKNOWN')) AS p) SELECT order_date,region_code,channel,COMPLETE_AMT,CANCELLED_AMT,PENDING_AMT,UNKNOWN_AMT,COALESCE(COMPLETE_AMT,0)+COALESCE(PENDING_AMT,0) AS non_cancel_revenue,ROW_NUMBER() OVER (PARTITION BY region_code ORDER BY COALESCE(COMPLETE_AMT,0) DESC) AS rn_region_top FROM pivoted_by_status QUALIFY rn_region_top<=5 ORDER BY order_date DESC,region_code,channel;
/* 3) generator + unpivot */ WITH raw_json AS (SELECT SEQ4() AS id,OBJECT_CONSTRUCT('metrics',ARRAY_CONSTRUCT(OBJECT_CONSTRUCT('name','clicks','value',UNIFORM(0,1000,RANDOM())),OBJECT_CONSTRUCT('name','impressions','value',UNIFORM(1000,100000,RANDOM())),OBJECT_CONSTRUCT('name','conversions','value',UNIFORM(0,100,RANDOM()))),'campaignId','cmp_'||TO_VARCHAR(SEQ4()),'ts',DATEADD('minute',-SEQ4(),CURRENT_TIMESTAMP()))::VARIANT AS payload FROM TABLE(GENERATOR(ROWCOUNT=>500))), flattened AS (SELECT r.id,r.payload:"campaignId"::STRING AS campaign_id,r.payload:"ts"::TIMESTAMP_NTZ AS event_ts,m.value:"name"::STRING AS metric_name,m.value:"value"::NUMBER AS metric_value FROM raw_json AS r,LATERAL FLATTEN(input=>r.payload:"metrics") AS m), aggregated AS (SELECT DATE_TRUNC('hour',event_ts) AS hour_bucket,campaign_id,SUM(CASE WHEN metric_name='clicks' THEN metric_value ELSE 0 END) AS clicks,SUM(CASE WHEN metric_name='impressions' THEN metric_value ELSE 0 END) AS impressions,SUM(CASE WHEN metric_name='conversions' THEN metric_value ELSE 0 END) AS conversions FROM flattened GROUP BY DATE_TRUNC('hour',event_ts),campaign_id), unpivoted AS (SELECT * FROM aggregated UNPIVOT (metric_value FOR metric_name IN (clicks,impressions,conversions)) AS u), with_rates AS (SELECT hour_bucket,campaign_id,metric_name,metric_value,SUM(metric_value) OVER (PARTITION BY campaign_id,metric_name ORDER BY hour_bucket ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_metric_value,CASE WHEN metric_name='conversions' THEN metric_value / NULLIF(LAG(metric_value) OVER (PARTITION BY campaign_id ORDER BY hour_bucket),0) ELSE NULL END AS weird_rate FROM unpivoted) SELECT w.hour_bucket,w.campaign_id,w.metric_name,w.metric_value,w.cumulative_metric_value,w.weird_rate,AVG(w.metric_value) OVER (PARTITION BY w.metric_name ORDER BY w.hour_bucket ROWS BETWEEN 3 PRECEDING AND CURRENT ROW) AS moving_avg_last_4,COUNT(*) OVER (PARTITION BY w.campaign_id) AS points_for_campaign,d.segment_code,d.created_at FROM with_rates AS w LEFT JOIN dim_db.campaign_dim BEFORE(TIMESTAMP => DATEADD('day',-1,CURRENT_TIMESTAMP())) AS d ON d.campaign_id=w.campaign_id QUALIFY moving_avg_last_4 IS NOT NULL AND (metric_name='clicks' OR weird_rate IS NOT NULL) ORDER BY w.hour_bucket,w.campaign_id,w.metric_name;"#;

    c.bench_function("format_gnarly_queries_file_2", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

// ============================================================================
// COMMENT PRESERVATION BENCHMARKS (measure trivia_builder.rs overhead)
// ============================================================================

fn bench_scripting_no_comments(c: &mut Criterion) {
    let sql = r#"
BEGIN
    LET x := 10;
    LET y := 20;
    LET z := x + y;
    RETURN z;
END;
"#;

    c.bench_function("scripting_no_comments", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn bench_scripting_with_comments(c: &mut Criterion) {
    let sql = r#"
-- Leading comment
BEGIN
    -- Before x
    LET x := 10;
    -- Before y
    LET y := 20;
    /* Block comment
       spanning multiple lines */
    LET z := x + y;
    -- Before return
    RETURN z;
END;
-- Trailing comment
"#;

    c.bench_function("scripting_with_comments", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn bench_nested_blocks_no_comments(c: &mut Criterion) {
    let sql = r#"
BEGIN
    LET x := 10;
    IF (x > 5) THEN
        BEGIN
            LET y := 20;
            LET z := x + y;
            IF (z > 25) THEN
                BEGIN
                    LET a := 100;
                    RETURN a;
                END;
            END IF;
        END;
    END IF;
END;
"#;

    c.bench_function("nested_blocks_no_comments", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn bench_nested_blocks_with_comments(c: &mut Criterion) {
    let sql = r#"
-- Outer block
BEGIN
    -- Initialize x
    LET x := 10;
    -- Check threshold
    IF (x > 5) THEN
        -- Inner block level 1
        BEGIN
            -- Calculate y
            LET y := 20;
            -- Calculate z
            LET z := x + y;
            -- Check result
            IF (z > 25) THEN
                -- Inner block level 2
                BEGIN
                    -- Final value
                    LET a := 100;
                    -- Return result
                    RETURN a;
                END;
            END IF;
        END;
    END IF;
END;
"#;

    c.bench_function("nested_blocks_with_comments", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

fn bench_large_script_no_comments(c: &mut Criterion) {
    let mut sql = String::from("BEGIN\n");
    for i in 0..100 {
        sql.push_str(&format!("    LET var_{} := {};\n", i, i));
    }
    sql.push_str("    RETURN var_99;\nEND;");

    c.bench_function("large_script_100_stmts_no_comments", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(&sql));
            black_box(formatted)
        });
    });
}

fn bench_large_script_with_comments(c: &mut Criterion) {
    let mut sql = String::from("-- Large block\nBEGIN\n");
    for i in 0..100 {
        sql.push_str(&format!(
            "    -- Variable {}\n    LET var_{} := {};\n",
            i, i, i
        ));
    }
    sql.push_str("    -- Final return\n    RETURN var_99;\nEND;\n-- End of block");

    c.bench_function("large_script_100_stmts_with_comments", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(&sql));
            black_box(formatted)
        });
    });
}

fn bench_scaling_by_comment_density(c: &mut Criterion) {
    let mut group = c.benchmark_group("comment_density");

    for comments_per_stmt in [0, 1, 2, 5].iter() {
        let mut sql = String::from("BEGIN\n");
        for i in 0..50 {
            for _ in 0..*comments_per_stmt {
                sql.push_str(&format!("    -- Comment for statement {}\n", i));
            }
            sql.push_str(&format!("    LET var_{} := {};\n", i, i));
        }
        sql.push_str("    RETURN var_49;\nEND;");

        group.bench_with_input(
            BenchmarkId::from_parameter(comments_per_stmt),
            comments_per_stmt,
            |b, _| {
                b.iter(|| {
                    let formatted = format_sql(black_box(&sql));
                    black_box(formatted)
                });
            },
        );
    }

    group.finish();
}

fn bench_scaling_by_statement_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("statement_count");

    for stmt_count in [10, 25, 50, 100, 200].iter() {
        let mut sql = String::from("BEGIN\n");
        for i in 0..*stmt_count {
            sql.push_str(&format!("    LET var_{} := {};\n", i, i));
        }
        sql.push_str(&format!("    RETURN var_{};\nEND;", stmt_count - 1));

        group.bench_with_input(
            BenchmarkId::from_parameter(stmt_count),
            stmt_count,
            |b, _| {
                b.iter(|| {
                    let formatted = format_sql(black_box(&sql));
                    black_box(formatted)
                });
            },
        );
    }

    group.finish();
}

fn bench_deeply_nested_blocks(c: &mut Criterion) {
    let sql = r#"
BEGIN
    LET x := 1;
    IF (x > 0) THEN
        BEGIN
            LET y := 2;
            IF (y > 0) THEN
                BEGIN
                    LET z := 3;
                    IF (z > 0) THEN
                        BEGIN
                            LET a := 4;
                            IF (a > 0) THEN
                                BEGIN
                                    LET b := 5;
                                    RETURN b;
                                END;
                            END IF;
                        END;
                    END IF;
                END;
            END IF;
        END;
    END IF;
END;
"#;

    c.bench_function("deeply_nested_blocks", |b| {
        b.iter(|| {
            let formatted = format_sql(black_box(sql));
            black_box(formatted)
        });
    });
}

criterion_group!(
    benches,
    format_simple_select,
    format_complex_select,
    format_with_cte,
    format_window_functions,
    format_subqueries,
    format_varying_sizes,
    // format_pipe_chain,  // Not implemented yet
    format_scripting_block,
    format_time_travel_and_changes,
    format_gnarly_queries_file_1,
    format_gnarly_queries_file_2,
    // Comment preservation benchmarks
    bench_scripting_no_comments,
    bench_scripting_with_comments,
    bench_nested_blocks_no_comments,
    bench_nested_blocks_with_comments,
    bench_large_script_no_comments,
    bench_large_script_with_comments,
    bench_scaling_by_comment_density,
    bench_scaling_by_statement_count,
    bench_deeply_nested_blocks,
);
criterion_main!(benches);
