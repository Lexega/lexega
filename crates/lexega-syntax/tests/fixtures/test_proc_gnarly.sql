CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
  LANGUAGE SQL
AS
$$
declare
    v1 DATE;
    v2 NUMBER;
    v3 STRING;
begin
    RETURN 'OK';
end;
$$;