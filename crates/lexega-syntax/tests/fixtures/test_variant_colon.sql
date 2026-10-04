-- Test case: Semi-structured data access with colon notation
-- This is VARIANT/OBJECT field access, NOT variable reference
SELECT
    e:"userId"::number AS user_id,
    e:"eventType"::string AS event_type,
    e:"properties":"device"::string AS device
FROM raw_events AS e;