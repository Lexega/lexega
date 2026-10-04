-- Test src.$1 expression inside FLATTEN
SELECT $1
FROM @stage/path/ src,LATERAL FLATTEN(input => src.$1) f;