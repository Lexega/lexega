-- Databricks gnarly golden fixture
-- Purpose: parser/formatter gap discovery, not just happy-path coverage.
-- This file intentionally mixes standard SQL, Delta/Unity Catalog DDL,
-- DML guardrails, time travel, table maintenance, and edge grammar forms.
USE CATALOG main;

USE SCHEMA analytics;

CREATE OR REPLACE TABLE main.analytics.events_raw (
    id BIGINT,
    user_id STRING,
    event_ts TIMESTAMP,
    payload STRING,
    event_date DATE
)
USING DELTA
PARTITIONED BY (event_date)
TBLPROPERTIES (
  'delta.autoOptimize.optimizeWrite'='true',
  'delta.autoOptimize.autoCompact'='true',
  'delta.appendOnly'='false'
);

CREATE TABLE IF NOT EXISTS main.analytics.events_clone
DEEP CLONE main.analytics.events_raw TIMESTAMP AS OF '2024-07-01T00:00:00Z'
TBLPROPERTIES ('delta.enableChangeDataFeed'='true')
LOCATION 's3://warehouse/prod/events_clone';

ALTER TABLE main.analytics.events_raw
    SET TBLPROPERTIES (
  delta.deletedFileRetentionDuration='interval 7 days',
  'delta.logRetentionDuration'='interval 30 days',
  quality_tier='gold'
);

ALTER TABLE main.analytics.events_raw
    UNSET TBLPROPERTIES IF EXISTS (
  'deprecated.flag',
  legacy_mode
);

-- Databricks Delta MERGE with schema evolution + star actions
MERGE WITH SCHEMA EVOLUTION INTO main.analytics.events_raw t
USING (
    SELECT
        CAST(src.id AS BIGINT)     AS id,
        src.user_id,
        src.event_ts,
        src.payload,
        CAST(src.event_ts AS DATE) AS event_date
    FROM staging.events_ingest src
) s
ON t.id = s.id
WHEN MATCHED AND t.payload <> s.payload THEN
UPDATE SET *
WHEN NOT MATCHED BY TARGET THEN
INSERT *
WHEN NOT MATCHED BY SOURCE AND t.event_date < DATE_SUB(CURRENT_DATE(), 90) THEN
DELETE;

-- Time travel syntaxes
SELECT
    e.id,
    e.user_id,
    e.payload,
    e.event_ts
FROM main.analytics.events_raw e VERSION AS OF 128
WHERE
    e.event_ts >= TIMESTAMP '2024-06-01 00:00:00'
QUALIFY ROW_NUMBER() OVER (
    PARTITION BY e.user_id
    ORDER BY e.event_ts DESC
) = 1;

SELECT *
FROM main.analytics.events_raw @v64 TABLESAMPLE (10 PERCENT)
ORDER BY id
LIMIT 250;

SELECT
    f.id,
    f.item.col AS item_col,
    f.item.val AS item_val
FROM main.analytics.events_raw f, LATERAL VIEW OUTER explode(from_json(f.payload, 'array<struct<col:string,val:string>>')) exploded AS item
WHERE
    f.event_date >= DATE '2024-06-01';

CACHE LAZY TABLE main.analytics.events_hot
OPTIONS ('storageLevel' = 'MEMORY_AND_DISK_SER')
AS
SELECT
  user_id,
  COUNT(*) AS event_count,
  MAX(event_ts) AS last_seen
FROM main.analytics.events_raw
GROUP BY user_id;

UNCACHE TABLE IF EXISTS main.analytics.events_hot;

OPTIMIZE main.analytics.events_raw
WHERE event_date >= DATE '2024-01-01'
ZORDER BY (user_id, event_ts);

DESCRIBE HISTORY main.analytics.events_raw;

RESTORE TABLE main.analytics.events_raw TO VERSION AS OF 127;

VACUUM main.analytics.events_raw RETAIN 24 HOURS DRY RUN;

MSCK REPAIR TABLE main.analytics.partitioned_events SYNC PARTITIONS;

CREATE CATALOG IF NOT EXISTS uc_sales
COMMENT 'Sales catalog'
MANAGED LOCATION 's3://uc/sales/'
DEFAULT COLLATION 'utf8_general_ci'
OPTIONS (owner='sales-platform', pii='mixed');

ALTER CATALOG uc_sales SET TAGS ('domain'='sales','tier'='gold');

ALTER CATALOG uc_sales ENABLE PREDICTIVE OPTIMIZATION;

ALTER CATALOG uc_sales DEFAULT COLLATION 'utf8mb4_bin';

CREATE EXTERNAL LOCATION IF NOT EXISTS ext_sales_raw
    URL 's3://ext/sales/raw/'
    WITH (STORAGE CREDENTIAL sc_prod)
    COMMENT 'Raw sales landing zone';

ALTER EXTERNAL LOCATION ext_sales_raw
    SET URL 's3://ext/sales/raw-v2/' FORCE;

ALTER EXTERNAL LOCATION ext_sales_raw
    SET STORAGE CREDENTIAL sc_prod_rotated;

CREATE STORAGE CREDENTIAL IF NOT EXISTS sc_prod
COMMENT 'prod credential';

ALTER STORAGE CREDENTIAL sc_prod SET OWNER TO `data-platform-admins`;

CREATE CONNECTION IF NOT EXISTS conn_partner_dw
TYPE POSTGRESQL
OPTIONS (
  host 'partner-dw.example.com',
  port '5432',
  database 'analytics',
  user secret('secops','partner_user'),
  password secret('secops','partner_password')
)
COMMENT 'Partner data warehouse';

ALTER CONNECTION conn_partner_dw OPTIONS (
  host 'partner-dw-dr.example.com',
  port '5432'
);

DROP CONNECTION IF EXISTS conn_partner_dw;

DROP EXTERNAL LOCATION IF EXISTS ext_sales_raw;

-- Intentionally edgy / parser-gap probes (Databricks + DLT flavored)
CREATE OR REFRESH LIVE TABLE dlt_events_enriched
AS
SELECT
    id,
    user_id,
    event_ts,
    payload
FROM STREAM(LIVE.events_raw)
WHERE
    event_ts >= current_timestamp() - INTERVAL 7 DAYS;

APPLY CHANGES INTO LIVE.events_scd
FROM STREAM(LIVE.events_cdc)
KEYS (id)
SEQUENCE BY event_ts
STORED AS SCD TYPE 2
TRACK HISTORY ON * EXCEPT (ingest_ts);

COPY INTO main.analytics.events_raw
FROM 's3://landing/events/'
FILEFORMAT = JSON
FORMAT_OPTIONS (
  'inferSchema'='true',
  'multiLine'='false',
  'mode'='PERMISSIVE'
)
COPY_OPTIONS (
  'mergeSchema'='true',
  'force'='false'
)
VALIDATE ALL;

-- Named parameter invocation and semi-structured paths (dbx nuance)
SELECT
    from_json(payload => payload, schema => 'struct<device:struct<os:string,ver:string>>') AS parsed,
    payload:device.os::STRING                                    AS device_os,
    payload:device.ver::STRING                                   AS device_ver
FROM main.analytics.events_raw
WHERE
    payload:device.os IS NOT NULL;

-- Additional clone variants (shallow + version/time travel forms)
CREATE TABLE IF NOT EXISTS main.analytics.events_clone_shallow
SHALLOW CLONE main.analytics.events_raw VERSION AS OF 120;

CREATE TABLE main.analytics.events_clone_recent
DEEP CLONE main.analytics.events_raw VERSION AS OF 126
TBLPROPERTIES ('delta.enableChangeDataFeed'='false')
LOCATION 's3://warehouse/prod/events_clone_recent';

-- Explicit MERGE actions (non-star UPDATE/INSERT branch coverage)
MERGE INTO main.analytics.events_raw AS t
USING staging.events_corrections AS s
ON t.id = s.id
WHEN MATCHED THEN
UPDATE SET
  t.payload = s.payload,
  t.event_ts = s.event_ts,
  t.event_date = CAST(s.event_ts AS DATE)
WHEN NOT MATCHED THEN
INSERT (id, user_id, event_ts, payload, event_date) VALUES (s.id, s.user_id, s.event_ts, s.payload, CAST(s.event_ts AS DATE));

-- COPY INTO unload variant (location target + subquery source)
COPY INTO 's3://exports/events/daily/'
FROM (
  SELECT
    id,
    user_id,
    event_ts,
    payload
  FROM main.analytics.events_raw
  WHERE event_date >= DATE '2024-06-01'
)
FILEFORMAT = PARQUET
COPY_OPTIONS ('overwrite'='true');

-- Unity Catalog volume lifecycle coverage
CREATE EXTERNAL VOLUME IF NOT EXISTS uc_sales.analytics.raw_volume
LOCATION 's3://uc-sales-volumes/raw/'
COMMENT 'Raw files for sales ingestion';

ALTER VOLUME uc_sales.analytics.raw_volume SET TAGS ('domain'='sales','zone'='raw');

ALTER VOLUME uc_sales.analytics.raw_volume UNSET TAGS ('zone');

ALTER VOLUME uc_sales.analytics.raw_volume SET OWNER TO `data-platform-admins`;

ALTER VOLUME uc_sales.analytics.raw_volume RENAME TO uc_sales.analytics.raw_volume_v2;

DROP VOLUME IF EXISTS uc_sales.analytics.raw_volume_v2;

-- Additional external location action variant
ALTER EXTERNAL LOCATION ext_sales_raw
    SET OWNER TO `data-platform-admins`;

-- Lakeflow modern syntax coverage: CREATE FLOW wrappers
CREATE FLOW flow_events_scd
AS AUTO CDC INTO LIVE.events_scd_auto
FROM STREAM(LIVE.events_cdc)
KEYS (id)
SEQUENCE BY event_ts
STORED AS SCD TYPE 1;

CREATE OR REFRESH FLOW flow_events_scd_apply
AS APPLY CHANGES INTO LIVE.events_scd_apply
FROM STREAM(LIVE.events_cdc)
KEYS (id)
SEQUENCE BY event_ts
STORED AS SCD TYPE 2
TRACK HISTORY ON * EXCEPT (ingest_ts);

-- Identifier edge cases: backtick-quoted multipart names with spaces/hyphens
CREATE EXTERNAL VOLUME IF NOT EXISTS `uc-sales`.`analytics zone`.`raw-volume 01`
LOCATION 's3://uc-sales-volumes/raw-quoted/'
COMMENT 'Quoted multipart volume identifier';

ALTER VOLUME `uc-sales`.`analytics zone`.`raw-volume 01`
SET TAGS ('owner-team'='data-platform','zone-type'='raw');

ALTER VOLUME `uc-sales`.`analytics zone`.`raw-volume 01`
RENAME TO `uc-sales`.`analytics zone`.`raw-volume 01-renamed`;

DROP VOLUME IF EXISTS `uc-sales`.`analytics zone`.`raw-volume 01-renamed`;

CREATE EXTERNAL LOCATION IF NOT EXISTS `ext-sales raw-zone`
    URL 's3://ext/sales/raw-quoted/'
    WITH (STORAGE CREDENTIAL sc_prod)
    COMMENT 'Quoted location identifier';

ALTER EXTERNAL LOCATION `ext-sales raw-zone`
    SET URL 's3://ext/sales/raw-quoted-v2/' FORCE;

ALTER EXTERNAL LOCATION `ext-sales raw-zone`
    SET OWNER TO `data-platform-admins`;

DROP EXTERNAL LOCATION IF EXISTS `ext-sales raw-zone`;
