CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
  LANGUAGE SQL
AS
$$
declare
    v1 DATE;
begin
    CREATE TEMP TABLE t
    AS
    SELECT 1;
    MERGE into t2
    USING t1
    ON t2.id = t1.id
    WHEN MATCHED THEN
    update set x = 1;
    SELECT 1 INTO :v1;
    if (v1 IS NULL) then
        RETURN 'NULL';
    end IF;
    RETURN 'OK';
end;
$$;