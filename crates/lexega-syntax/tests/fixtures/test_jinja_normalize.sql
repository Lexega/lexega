-- Test Jinja content normalization
-- This file tests Jinja that can't be rendered (just formatting)
SELECT col1, col2
FROM table1
WHERE
    {%if region%}
        region = 'US'
    {%endif%}{% set x = [ 1 , 2 , 3 ] %}