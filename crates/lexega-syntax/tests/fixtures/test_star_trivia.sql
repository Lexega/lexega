-- Test trivia preservation in SELECT * with modifiers
-- Each component should preserve its inline/block comments
-- Basic qualified star with comments
SELECT t /* after qualifier */ . /* after dot */ * /* after star */ 
FROM table1 t;
-- EXCLUDE with comments
SELECT t /* after qualifier */ . /* after dot */ * /* after star */ EXCLUDE /* after EXCLUDE keyword */ ( /* after lparen */ col1 /* after col1 */ , /* after comma */ col2 /* after col2 */ ) /* after rparen */ 
FROM table1 t;
-- REPLACE with comments
SELECT t /* after qualifier */ . /* after dot */ * /* after star */ REPLACE /* after REPLACE keyword */ ( /* after lparen */ 100 /* after expr */ AS /* after AS */ col1 /* after col1 */ , /* after comma */ 200 /* after expr */ AS /* after AS */ col2 /* after col2 */ ) /* after rparen */ 
FROM table1 t;
-- RENAME with comments
SELECT t /* after qualifier */ . /* after dot */ * /* after star */ RENAME /* after RENAME keyword */ ( /* after lparen */ col1 /* after col1 */ AS /* after AS */ new_col1 /* after alias */ , /* after comma */ col2 /* after col2 */ AS /* after AS */ new_col2 /* after alias */ ) /* after rparen */ 
FROM table1 t;
-- Combined EXCLUDE + REPLACE + RENAME with comments everywhere
SELECT t /* after qualifier */ . /* after dot */ * /* after star */ EXCLUDE /* after EXCLUDE */ ( /* after lparen */ col3 /* after col3 */ ) /* after rparen */ REPLACE /* after REPLACE */ ( /* after lparen */ 999 /* after expr */ AS /* after AS */ col1 /* after col1 */ ) /* after rparen */ RENAME /* after RENAME */ ( /* after lparen */ col2 /* after col2 */ AS /* after AS */ renamed_col2 /* after alias */ ) /* after rparen */ 
FROM table1 t;
-- Unqualified star with all modifiers and comments
SELECT * /* after star */ EXCLUDE /* after EXCLUDE */ ( /* after lparen */ col1 /* after col1 */ , /* after comma */ col2 /* after col2 */ ) /* after rparen */ REPLACE /* after REPLACE */ ( /* after lparen */ 100 /* after expr */ AS /* after AS */ col3 /* after col3 */ ) /* after rparen */ RENAME /* after RENAME */ ( /* after lparen */ col4 /* after col4 */ AS /* after AS */ new_col4 /* after alias */ ) /* after rparen */ 
FROM table1;
-- Multiple qualified stars in projection with comments
SELECT
    t1 /* after t1 */ . /* after dot */ * /* after star */ EXCLUDE /* after EXCLUDE */ (col1) /* after rparen */ ,
    t2 /* after t2 */ . /* after dot */ * /* after star */ REPLACE /* after REPLACE */ (200 AS col2) /* after rparen */ ,
    t3 /* after t3 */ . /* after dot */ * /* after star */ RENAME /* after RENAME */ (col3 AS new_col3) /* after rparen */ 
FROM table1 t1,table2 t2,table3 t3;