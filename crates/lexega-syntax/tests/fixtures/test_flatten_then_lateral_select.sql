-- Test LATERAL FLATTEN followed by LATERAL (SELECT ...) in regular SELECT
SELECT e:"userId"::NUMBER AS user_id
FROM @ingest_stage/events/ ( FILE_FORMAT => 'raw_db.public.events_json_ff' ) src,LATERAL FLATTEN(input => src.$1) f,LATERAL (
    SELECT f.value::VARIANT AS e
) v;