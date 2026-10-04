-- Test without FILE_FORMAT options
SELECT f.value
FROM @ingest_stage/events/ src,LATERAL FLATTEN(input => src.$1) f;