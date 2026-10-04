CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
  LANGUAGE SQL
AS
$$
declare
    v1 DATE;
    v2 NUMBER DEFAULT 0;
    v3 BOOLEAN := TRUE;
begin
    RETURN 'OK';
    exception
        when OTHER then
            RETURN 'ERROR';
end;
$$;