-- Test unclosed Jinja block error handling
SELECT 
{%iftrue%}col1,col2
-- Missing the endif tag
FROMtable1;