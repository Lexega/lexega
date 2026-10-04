DECLARE
    id INTEGER;
BEGIN
    SELECT id
    FROM some_data
    WHERE id = :id;
END;