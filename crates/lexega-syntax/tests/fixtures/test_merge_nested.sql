MERGE INTO target t
USING (SELECT *
FROM (
    SELECT *
    FROM (
        SELECT *
        FROM (
            SELECT *
            FROM src1
        )
    )
)) s
ON t.id = s.id
WHEN MATCHED THEN
UPDATE SET val = s.val;