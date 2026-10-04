-- Test regular table followed by LATERAL FLATTEN
SELECT f.value
FROM my_table src,LATERAL FLATTEN(input => src.array_col) f;