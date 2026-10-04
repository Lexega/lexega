-- Test stage reference with FILE_FORMAT option
SELECT src.$1 AS data
FROM @ingest_stage/events/ ( FILE_FORMAT => 'raw_db.public.events_json_ff' ) src;