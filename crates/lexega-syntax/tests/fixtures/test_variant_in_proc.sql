CREATE OR REPLACE PROCEDURE test_variant_in_proc()
RETURNS VARCHAR
  LANGUAGE SQL
AS
$$
declare
    v_count NUMBER DEFAULT 0;
begin
    -- This should work: VARIANT field access with colon inside procedure
    CREATE TEMP TABLE tmp
    AS
    SELECT e:"userId"::NUMBER AS user_id, e:"eventType"::STRING AS event_type
    FROM raw_events e;
    SELECT count(*) INTO :v_count
    FROM tmp;
    RETURN 'OK: ' || :v_count;
end;
$$;