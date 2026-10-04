-- Test CASE expression inside FLATTEN
SELECT *
FROM base,LATERAL FLATTEN(input => CASE
    WHEN IS_OBJECT(x.value) THEN x.value
    ELSE PARSE_JSON('{}')
END,OUTER => TRUE) result;