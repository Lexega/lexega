-- Simplest possible LATERAL FLATTEN
SELECT f.value
FROM my_table t,LATERAL FLATTEN(input => t.array_col) f;