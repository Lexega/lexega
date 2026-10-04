-- Test file for centralized trivia handling
SELECT
    /* block before col */ a,
    b, /* inline comment */ 
    -- line comment before c
    c
FROM
    t1
    INNER JOIN t2
        ON t1.id = t2.id
WHERE
    a > 10
    AND /* inline in where */ b < 20;