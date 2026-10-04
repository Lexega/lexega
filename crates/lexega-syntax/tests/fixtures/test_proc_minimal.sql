CREATE OR REPLACE PROCEDURE util_db.public.test_proc(p_days INTEGER)
RETURNS VARCHAR
LANGUAGE SQL
AS $$
DECLARE
    v_start_date DATE;
BEGIN
    LET v_start_date := CURRENT_DATE();
    IF (p_days <= 0) THEN
        RETURN 'p_days must be > 0';
    END IF;
    RETURN 'OK';
END;
$$;