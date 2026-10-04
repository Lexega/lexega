-- Test stage with options followed by another table
SELECT f.value
FROM @ingest_stage/events/ ( FILE_FORMAT => 'raw_db.public.events_json_ff' ) src,my_table t;