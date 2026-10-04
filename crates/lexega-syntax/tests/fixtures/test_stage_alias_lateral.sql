-- Test stage with alias followed by LATERAL
SELECT $1
FROM @stage/path/ src,LATERAL FLATTEN(input => ARRAY_CONSTRUCT(1,2)) f;