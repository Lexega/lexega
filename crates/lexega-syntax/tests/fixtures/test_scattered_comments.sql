-- File-level comment at the very top
-- Another top-level comment
/* Block comment before SELECT */ SELECT /* inline after SELECT */ 
    -- Comment before first column
    col1, /* trailing comment on col1 */ 
    -- Comment between columns
    col2 /* another trailing */ , -- line comment after comma
    /* block before col3 */ col3,
    col4, -- trailing on col4
    /* leading comma style comment */ col5,
    col6 /* comment */ AS /* comment in alias */ alias6 -- end of alias
FROM /* comment after FROM */ 
-- Comment before table
schema1.table1 /* trailing on table */ t1 -- alias comment
/* block before JOIN */ LEFT /* mid-keyword?! */ JOIN -- comment after JOIN keyword
/* comment before second table */ schema2.table2 t2 /* after alias */ ON /* after ON */ t1.id /* after left side */ = /* after equals */ t2.id /* after right side */ AND /* comment in multi-condition */ t1.flag = TRUE -- end of ON
-- Comment between joins
INNER JOIN table3 t3 ON t3.id = t1.id
WHERE /* after WHERE */ 
-- Comment before first condition
t1.status /* after column */ = /* after operator */ 'ACTIVE' -- end of condition
/* block before AND */ AND /* after AND */ (
-- Comment inside parens
t2.value > 100 /* after comparison */ OR /* after OR */ t2.value IS NULL -- null check comment
) /* after closing paren */ AND t1.created_at >= '2024-01-01'::DATE -- cast comment
GROUP /* comment mid GROUP */ BY /* comment after BY */ 
-- Comment before group column
col1, /* after first group col */ col2 -- after second group col
HAVING /* after HAVING */ COUNT(*) /* after count */ > /* after operator */ 10 -- threshold comment
ORDER /* mid ORDER */ BY /* after BY */ col1 /* after order col */ ASC /* after ASC */ NULLS /* mid NULLS */ FIRST, -- first sort
col2 DESC -- second sort
LIMIT /* after LIMIT */ 100 /* after number */ 
OFFSET /* after OFFSET */ 50 -- pagination
; -- statement terminator comment
-- Comment between statements
/* Multi-line block comment
   that spans several lines
   with various content */ SELECT /* second statement */ CASE /* after CASE */ 
    -- Comment before WHEN
    WHEN /* after WHEN */ x = 1 /* after condition */ THEN /* after THEN */ 'one' -- result comment
    /* block before second WHEN */ WHEN x = 2 THEN 'two'
    -- Comment before ELSE
    ELSE /* after ELSE */ 'other' -- default comment
END /* after END */ AS /* after AS */ result -- alias comment
FROM dual /* table comment */ ;
-- Comment before CTE
WITH /* after WITH */ 
    -- CTE comment
    cte1 /* after cte name */ AS /* after AS */ ( -- before subquery
        /* inside CTE */ SELECT /* cte select */ id, /* col comment */ value
        FROM source /* source comment */ 
        WHERE active = TRUE -- filter comment
    ) /* after CTE close */ , -- comma comment
    /* second CTE block */ cte2 AS (
        SELECT *
        FROM cte1 -- reference comment
    )
/* main query comment */ SELECT /* final select */ * /* star comment */ 
FROM cte2 /* from cte */ ;
-- Subquery stress test
SELECT /* outer */ ( /* subquery start */ SELECT /* inner select */ MAX(val) /* after max */ 
FROM /* inner from */ (
    /* deeply nested */ SELECT val /* nested col */ 
    FROM nested_table /* nested table */ 
) /* close inner */ sub /* sub alias */ ) /* close outer subquery */ AS max_val /* outer alias */ 
FROM dual /* final table */ ;
-- Function calls with comments
SELECT
    COALESCE( /* after func open */ 
    -- first arg comment
    nullable_col, /* after first arg */ /* before second arg */ 'default' -- second arg comment
    ) /* after func close */ AS val,
    NVL2(flag, /* condition */ 'yes', /* true branch */ 'no' /* false branch */ ) AS flag_text,
    DECODE( /* decode start */ status, /* input */ 1, /* match 1 */ 'active', /* result 1 */ 2, /* match 2 */ 'pending', /* result 2 */ 'unknown' /* default */ ) AS status_text
FROM t;
-- Window function stress
SELECT col, SUM(val) /* after agg */ OVER /* after OVER */ ( /* after open */ 
    PARTITION /* mid PARTITION */ BY /* after BY */ group_col /* after partition col */ 
    ORDER /* mid ORDER */ BY /* after BY */ sort_col /* after sort col */ DESC /* after DESC */ ROWS /* after ROWS */ BETWEEN /* after BETWEEN */ UNBOUNDED /* after UNBOUNDED */ PRECEDING /* after PRECEDING */ AND /* after AND */ CURRENT /* after CURRENT */ ROW /* after ROW */ 
) /* after window close */ AS running_sum /* alias */ 
FROM t;
-- UNION with comments
SELECT /* first union member */ col1, col2
FROM t1 /* first table */ 
UNION /* after UNION */ ALL /* after ALL */ -- union comment
SELECT /* second union member */ col1, col2
FROM t2 /* second table */ 
UNION -- simple union
SELECT col1, col2
FROM t3;
-- INSERT with comments
INSERT /* after INSERT */ INTO /* after INTO */ target_table /* table comment */ (
    -- column list comment
    col1, /* first col */
    col2 /* second col */
) /* after cols */ 
SELECT /* insert select */ * FROM source /* source table */ ;
-- UPDATE with comments
UPDATE /* after UPDATE */ target /* table */ 
SET /* after SET */ col1 /* first */ = /* equals */ val1, /* after val */ 
col2 = val2 -- second assignment
WHERE /* condition */ id = 123 /* specific id */ ;
-- MERGE with comments
MERGE /* after MERGE */ INTO /* after INTO */ target /* target table */ t /* alias */ 
USING /* after USING */ source /* source table */ s /* source alias */ 
ON /* after ON */ t.id /* left */ = /* op */ s.id /* right */ 
WHEN /* after WHEN */ MATCHED /* after MATCHED */ THEN /* after THEN */ 
UPDATE /* matched update */ SET /* after set */ t.val = s.val /* assignment */ 
WHEN NOT MATCHED THEN
INSERT /* not matched insert */ (id, val) /* cols */ VALUES /* after values */ (s.id, s.val) /* vals */ ;
-- End of file comment
