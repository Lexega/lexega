-- Test USE statement with various comment positions
-- Comment before statement
/* comment after USE */ USE /* comment after DATABASE */ DATABASE my_db;
USE -- line comment after ROLE
ROLE admin_role;
/* block comment */ USE WAREHOUSE compute_wh;
/* Block comment before */ USE SCHEMA my_schema;
USE DATABASE /* comment on new line */ prod_db;
-- Multiple comments
/* c1 */ USE /* c2 */ ROLE /* c3 */ security_role;
-- Trailing comment at EOF
USE WAREHOUSE -- final comment
analytics_wh; -- final comment
