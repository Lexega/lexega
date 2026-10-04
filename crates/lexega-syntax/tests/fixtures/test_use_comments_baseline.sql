-- Test USE statement with various comment positions
-- Comment before statement
USE /* comment after USE */ DATABASE /* comment after DATABASE */ my_db;
USE ROLE -- line comment after ROLE
admin_role;
USE /* block comment */ WAREHOUSE compute_wh;
/* Block comment before */ USE SCHEMA my_schema;
USE DATABASE /* comment on new line */ prod_db;
-- Multiple comments
USE /* c1 */ ROLE /* c2 */ security_role /* c3 */ ;
-- Trailing comment at EOF
USE WAREHOUSE analytics_wh; -- final comment
