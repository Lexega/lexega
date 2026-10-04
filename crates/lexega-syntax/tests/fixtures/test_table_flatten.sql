-- Test TABLE(FLATTEN(...)) in scalar subquery
SELECT CASE
    WHEN x > 0 THEN (SELECT SUM(li.value:quantity::NUMBER)
    FROM TABLE(FLATTEN(input => arr)) li)
    ELSE 0
END AS result
FROM t;