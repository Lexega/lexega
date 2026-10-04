-- Test => operator in FLATTEN within scalar subquery
SELECT CASE
    WHEN x > 0 THEN (SELECT COUNT(*)
    FROM TABLE(FLATTEN(input => data:items)) t)
    ELSE 0
END AS result
FROM base;