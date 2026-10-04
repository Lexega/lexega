CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    -- This is a comment before x
    x INTEGER DEFAULT 10;
    -- This is a comment before y
    y VARCHAR DEFAULT 'hello';
BEGIN
    -- Comment before LET
    LET z := x + 1;
    -- Comment before IF
    IF (z > 10) THEN
        -- Comment before RETURN
        RETURN 'big';
    ELSE
        RETURN 'small';
    END IF;
END;
$$;