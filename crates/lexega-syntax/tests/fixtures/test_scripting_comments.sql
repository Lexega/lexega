CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
  LANGUAGE SQL
AS
$$
BEGIN
    /* comment before create */ CREATE TEMP TABLE t
    AS
    SELECT 1;
    /* comment before merge */ MERGE INTO t2
    USING t1
    ON t2.id = t1.id
    WHEN MATCHED THEN
    UPDATE SET x = 1;
    /* comment at end */ RETURN 'OK';
END;
$$;