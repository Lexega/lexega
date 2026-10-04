CREATE TABLE my_table
AS
SELECT
    user_id,
    event_type,
    event_ts
FROM raw_events
WHERE event_type = 'login';