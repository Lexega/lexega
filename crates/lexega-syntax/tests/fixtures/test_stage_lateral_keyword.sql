-- Check what gets parsed after stage
SELECT src.$1
FROM @ingest_stage/events/ src, LATERAL FLATTEN(input => src.$1) f;