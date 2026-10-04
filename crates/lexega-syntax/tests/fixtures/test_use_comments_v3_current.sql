-- Test USE statement with various comment positions
-- Comment before statement
USE /* comment after USE */ DATABASE /* comment after DATABASE */ my_db;
USE ROLE -- line comment after ROLE
admin_role;
USE /* block comment */ WAREHOUSE compute_wh;
USE SCHEMA my_schema;
USE DATABASE prod_db;
USE /* c1 */ ROLE /* c2 */ security_role /* c3 */ ;
USE WAREHOUSE analytics_wh; -- final comment
