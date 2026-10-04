CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
  LANGUAGE SQL
AS
$$
declare
    v_count NUMBER DEFAULT 0;
begin
    -- This should work: INTO with colon-prefixed variable
    SELECT count(*) INTO :v_count
    FROM users;
    -- This should also work: using variable in RETURN
    RETURN 'Count: ' || :v_count;
end;
$$;