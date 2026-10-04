-- Hostile comment test: ALL statement types
-- This file tests comment preservation across every AST node type
-- =============================================================================
-- SECTION 1: DDL Statements
-- =============================================================================
-- CREATE TABLE with comments everywhere
CREATE /* after CREATE */ OR /* after OR */ REPLACE /* after REPLACE */ TABLE /* after TABLE */ IF /* after IF */ NOT /* after NOT */ EXISTS /* after EXISTS */ my_schema /* after schema */ . /* after dot */ my_table /* after name */ (
    /* before col1 */ id /* after id */ INTEGER /* after type */ NOT /* after NOT */ NULL /* after NULL */ ,
    /* before col2 */ name /* after name */ VARCHAR /* after VARCHAR */ ( /* after open */ 100 /* after size */ ) /* after close */ DEFAULT /* after DEFAULT */ 'unknown' /* after default value */ ,
    /* before col3 */ created_at /* after col name */ TIMESTAMP /* after type */ DEFAULT /* default kw */ CURRENT_TIMESTAMP /* after expr */ () /* after parens */ 
    -- line comment before constraint
    /* before PRIMARY */ ,
    PRIMARY /* after PRIMARY */ KEY /* after KEY */ ( /* after open */ id /* after id in pk */ ) /* after close pk */ 
) /* after columns */ 
CLUSTER /* after CLUSTER */ BY /* after BY */ ( /* after open cluster */ id /* in cluster */ ) /* after cluster close */ ;
-- CREATE VIEW with comments
CREATE /* v1 */ OR /* v2 */ REPLACE /* v3 */ VIEW /* v4 */ my_view /* v5 */ 
AS /* v6 */ 
SELECT /* v7 */ a /* v8 */ , /* v9 */ b /* v10 */ 
FROM /* v11 */ t /* v12 */ ;
-- CREATE STAGE with all clauses and comments
CREATE /* s1 */ OR /* s2 */ REPLACE /* s3 */ TEMPORARY /* s4 */ STAGE /* s5 */ IF /* s6 */ NOT /* s7 */ EXISTS /* s8 */ my_stage /* s9 */ 
    URL /* s10 */ = /* s11 */ 's3://bucket/path' /* s12 */ 
    STORAGE_INTEGRATION /* s13 */ = /* s14 */ my_integration /* s15 */ 
    DIRECTORY /* s16 */ = /* s17 */ ( /* s18 */ ENABLE /* s19 */ = /* s20 */ TRUE /* s21 */ ) /* s22 */ 
    FILE_FORMAT /* s23 */ = /* s24 */ ( /* s25 */ TYPE /* s26 */ = /* s27 */ CSV /* s28 */ ) /* s29 */ 
    COMMENT /* s30 */ = /* s31 */ 'test stage' /* s32 */ ;
-- DROP statements
DROP /* d1 */ TABLE /* d2 */ IF /* d3 */ EXISTS /* d4 */ my_table /* d5 */ CASCADE /* d6 */ ;
DROP /* d7 */ VIEW /* d8 */ my_view /* d9 */ ;
DROP /* d10 */ STAGE /* d11 */ IF /* d12 */ EXISTS /* d13 */ my_stage /* d14 */ ;
-- TRUNCATE statement
TRUNCATE /* t1 */ TABLE /* t2 */ IF /* t3 */ EXISTS /* t4 */ my_table /* t5 */ ;
-- =============================================================================
-- SECTION 2: DML Statements
-- =============================================================================
-- SELECT with all clauses
SELECT /* sel1 */ DISTINCT /* sel2 */ 
    a /* sel3 */ AS /* sel4 */ col_a /* sel5 */ ,
    /* sel6 */ b /* sel7 */ + /* sel8 */ 1 /* sel9 */ AS /* sel10 */ col_b /* sel11 */ ,
    -- line comment in select list
    /* sel12 */ CASE /* sel13 */ 
        WHEN /* sel14 */ c /* sel15 */ > /* sel16 */ 0 /* sel17 */ THEN /* sel18 */ 'pos' /* sel19 */ 
        ELSE /* sel20 */ 'neg' /* sel21 */ 
    END /* sel22 */ AS /* sel23 */ sign /* sel24 */ 
FROM /* sel25 */ 
my_table /* sel26 */ t1 /* sel27 */ 
LEFT /* sel28 */ OUTER /* sel29 */ JOIN /* sel30 */ other_table /* sel31 */ t2 /* sel32 */ ON /* sel33 */ t1 /* sel34 */ . /* sel35 */ id /* sel36 */ = /* sel37 */ t2 /* sel38 */ . /* sel39 */ id /* sel40 */ 
WHERE /* sel41 */ a /* sel42 */ > /* sel43 */ 10 /* sel44 */ AND /* sel45 */ ( /* sel46 */ b /* sel47 */ < /* sel48 */ 20 /* sel49 */ OR /* sel50 */ c /* sel51 */ = /* sel52 */ 'x' /* sel53 */ ) /* sel54 */ 
GROUP /* sel55 */ BY /* sel56 */ a /* sel57 */ , /* sel58 */ b /* sel59 */ 
HAVING /* sel60 */ COUNT /* sel61 */ ( /* sel62 */ * /* sel63 */ ) /* sel64 */ > /* sel65 */ 5 /* sel66 */ 
ORDER /* sel67 */ BY /* sel68 */ a /* sel69 */ DESC /* sel70 */ , /* sel71 */ b /* sel72 */ ASC /* sel73 */ NULLS /* sel74 */ FIRST /* sel75 */ 
LIMIT /* sel76 */ 100 /* sel77 */ 
OFFSET /* sel78 */ 10 /* sel79 */ ;
-- INSERT statement
INSERT /* ins1 */ INTO /* ins2 */ my_table /* ins3 */ ( /* ins4 */ id /* ins5 */, /* ins6 */ name /* ins7 */ ) /* ins8 */ 
SELECT /* ins9 */ id /* ins10 */, /* ins11 */ name /* ins12 */ FROM /* ins13 */ source_table /* ins14 */
WHERE /* ins15 */ active /* ins16 */ = /* ins17 */ TRUE /* ins18 */ ;
-- UPDATE statement
UPDATE /* upd1 */ my_table /* upd2 */ t /* upd3 */ 
SET /* upd4 */ name /* upd5 */ = /* upd6 */ 'new_name' /* upd7 */ ,
/* upd8 */ updated_at /* upd9 */ = /* upd10 */ CURRENT_TIMESTAMP /* upd11 */ ( /* upd12 */ ) /* upd13 */ 
FROM /* upd14 */ other_table /* upd15 */ o /* upd16 */ 
WHERE /* upd17 */ t /* upd18 */ . /* upd19 */ id /* upd20 */ = /* upd21 */ o /* upd22 */ . /* upd23 */ id /* upd24 */ AND /* upd25 */ o /* upd26 */ . /* upd27 */ status /* upd28 */ = /* upd29 */ 'active' /* upd30 */ ;
-- DELETE statement
DELETE /* del1 */ FROM /* del2 */ my_table /* del3 */ t /* del4 */ 
USING /* del5 */ other_table /* del6 */ o /* del7 */ 
WHERE /* del8 */ t /* del9 */ . /* del10 */ id /* del11 */ = /* del12 */ o /* del13 */ . /* del14 */ id /* del15 */ AND /* del16 */ o /* del17 */ . /* del18 */ deleted /* del19 */ = /* del20 */ TRUE /* del21 */ ;
-- MERGE statement
MERGE /* mrg1 */ INTO /* mrg2 */ target_table /* mrg3 */ t /* mrg4 */ 
USING /* mrg5 */ ( /* mrg6 */ SELECT /* mrg7 */ * /* mrg8 */ 
FROM /* mrg9 */ source /* mrg10 */ ) /* mrg11 */ s /* mrg12 */ 
ON /* mrg13 */ t /* mrg14 */ . /* mrg15 */ id /* mrg16 */ = /* mrg17 */ s /* mrg18 */ . /* mrg19 */ id /* mrg20 */ 
WHEN /* mrg21 */ MATCHED /* mrg22 */ AND /* mrg23 */ s /* mrg24 */ . /* mrg25 */ deleted /* mrg26 */ THEN /* mrg27 */ 
DELETE /* mrg28 */ 
WHEN /* mrg29 */ MATCHED /* mrg30 */ THEN /* mrg31 */ 
UPDATE /* mrg32 */ SET /* mrg33 */ name /* mrg34 */ = /* mrg35 */ s /* mrg36 */ . /* mrg37 */ name /* mrg38 */ 
WHEN /* mrg39 */ NOT /* mrg40 */ MATCHED /* mrg41 */ THEN /* mrg42 */ 
INSERT /* mrg43 */ ( /* mrg44 */ id /* mrg45 */ , /* mrg46 */ name /* mrg47 */ ) /* mrg48 */ VALUES /* mrg49 */ ( /* mrg50 */ s /* mrg51 */ . /* mrg52 */ id /* mrg53 */ , /* mrg54 */ s /* mrg55 */ . /* mrg56 */ name /* mrg57 */ ) /* mrg58 */ ;
-- =============================================================================
-- SECTION 3: Set Operations
-- =============================================================================
SELECT /* set1 */ a /* set2 */ 
FROM /* set3 */ t1 /* set4 */ 
UNION /* set5 */ ALL /* set6 */ 
SELECT /* set7 */ a /* set8 */ 
FROM /* set9 */ t2 /* set10 */ 
EXCEPT /* set11 */ 
SELECT /* set12 */ a /* set13 */ 
FROM /* set14 */ t3 /* set15 */ 
INTERSECT /* set16 */ 
SELECT /* set17 */ a /* set18 */ 
FROM /* set19 */ t4 /* set20 */ ;
-- =============================================================================
-- SECTION 4: Utility Statements
-- =============================================================================
-- SHOW statements
SHOW /* sh1 */ TABLES /* sh2 */ LIKE /* sh3 */ 'my_%' /* sh4 */ IN /* sh5 */ SCHEMA /* sh6 */ my_schema /* sh7 */ ;
SHOW /* sh8 */ VIEWS /* sh9 */ ;
SHOW /* sh10 */ STAGES /* sh11 */ ;
-- DESCRIBE statements
DESCRIBE /* desc1 */ TABLE /* desc2 */ my_table /* desc3 */ ;
DESC /* desc4 */ VIEW /* desc5 */ my_view /* desc6 */ ;
-- USE statements
USE /* use1 */ DATABASE /* use2 */ my_db /* use3 */ ;
USE /* use4 */ SCHEMA /* use5 */ my_schema /* use6 */ ;
USE /* use7 */ WAREHOUSE /* use8 */ my_wh /* use9 */ ;
-- =============================================================================
-- SECTION 5: Stored Procedure with Scripting
-- =============================================================================
CREATE /* proc1 */ OR /* proc2 */ REPLACE /* proc3 */ PROCEDURE /* proc4 */ test_all_scripting /* proc5 */ (
    /* p1 */ p_input /* p2 */ INTEGER /* p3 */,
    /* p4 */ p_flag /* p5 */ BOOLEAN /* p6 */
) /* proc7 */ 
RETURNS /* proc8 */ VARCHAR /* proc9 */
LANGUAGE /* proc10 */ SQL /* proc11 */
AS /* proc12 */
$$ /* after open delimiter */ 
DECLARE /* decl1 */ 
    -- variable declarations
    v_result /* decl2 */ VARCHAR /* decl3 */ DEFAULT /* decl4 */ 'init' /* decl5 */ ;
    v_counter /* decl6 */ NUMBER /* decl7 */ := /* decl8 */ 0 /* decl9 */ ;
    v_cursor /* decl10 */ CURSOR /* decl11 */ FOR /* decl12 */ 
        SELECT /* decl13 */ id /* decl14 */ 
        FROM /* decl15 */ t /* decl16 */ ;
BEGIN /* begin1 */ 
    -- LET statement
    LET /* let1 */ x := /* let2 */ /* let3 */ 10 /* let4 */ ;
    LET /* let5 */ y := /* let6 */ /* let7 */ 'hello' /* let8 */ ;
    -- Assignment
    v_counter /* asgn1 */ := /* asgn2 */ v_counter /* asgn3 */ + /* asgn4 */ 1 /* asgn5 */ ;
    -- IF statement
    IF /* if1 */ ( /* if2 */ p_flag /* if3 */ = /* if4 */ TRUE /* if5 */ ) /* if6 */ THEN /* if7 */ 
        v_result /* if8 */ := /* if9 */ 'flag is true' /* if10 */ ;
    ELSEIF /* if11 */ ( /* if12 */ p_input /* if13 */ > /* if14 */ 0 /* if15 */ ) /* if16 */ THEN /* if17 */ 
        v_result /* if18 */ := /* if19 */ 'input positive' /* if20 */ ;
    ELSE /* if21 */ 
        v_result /* if22 */ := /* if23 */ 'default' /* if24 */ ;
    END /* if25 */ IF /* if26 */ ;
    -- CASE statement
    CASE /* case1 */ p_input /* case2 */ 
        WHEN /* case3 */ 1 /* case4 */ THEN /* case5 */ 
            v_result /* case6 */ := /* case7 */ 'one' /* case8 */ ;
        WHEN /* case9 */ 2 /* case10 */ THEN /* case11 */ 
            v_result /* case12 */ := /* case13 */ 'two' /* case14 */ ;
        ELSE /* case15 */ 
            v_result /* case16 */ := /* case17 */ 'other' /* case18 */ ;
    END /* case19 */ CASE /* case20 */ ;
    -- FOR loop
    FOR /* for1 */ i /* for2 */ IN /* for3 */ 1 /* for4 */ TO /* for5 */ 10 /* for6 */ DO /* for7 */ 
        v_counter /* for8 */ := /* for9 */ v_counter /* for10 */ + /* for11 */ 1 /* for12 */ ;
    END /* for13 */ FOR /* for14 */ ;
    -- FOR cursor loop
    FOR /* forc1 */ rec /* forc2 */ IN /* forc3 */ v_cursor /* forc4 */ DO /* forc5 */ 
        v_counter /* forc6 */ := /* forc7 */ v_counter /* forc8 */ + /* forc9 */ 1 /* forc10 */ ;
    END /* forc11 */ FOR /* forc12 */ ;
    -- WHILE loop
    WHILE /* while1 */ ( /* while2 */ v_counter /* while3 */ < /* while4 */ 100 /* while5 */ ) /* while6 */ DO /* while7 */ 
        v_counter /* while8 */ := /* while9 */ v_counter /* while10 */ + /* while11 */ 1 /* while12 */ ;
        IF /* while13 */ ( /* while14 */ v_counter /* while15 */ = /* while16 */ 50 /* while17 */ ) /* while18 */ THEN /* while19 */ 
            BREAK /* while20 */ ;
        END /* while21 */ IF /* while22 */ ;
    END /* while23 */ WHILE /* while24 */ ;
    -- REPEAT loop
    REPEAT /* rep1 */ 
        v_counter /* rep2 */ := /* rep3 */ v_counter /* rep4 */ + /* rep5 */ 1 /* rep6 */ ;
    UNTIL /* rep7 */ ( /* rep8 */ v_counter /* rep9 */ >= /* rep10 */ 200 /* rep11 */ ) /* rep12 */ END /* rep13 */ REPEAT /* rep14 */ ;
    -- LOOP with EXIT
    LOOP /* loop1 */ 
        v_counter /* loop2 */ := /* loop3 */ v_counter /* loop4 */ + /* loop5 */ 1 /* loop6 */ ;
        IF /* loop7 */ ( /* loop8 */ v_counter /* loop9 */ > /* loop10 */ 300 /* loop11 */ ) /* loop12 */ THEN /* loop13 */ 
            EXIT /* loop14 */ ;
        END /* loop15 */ IF /* loop16 */ ;
    END /* loop17 */ LOOP /* loop18 */ ;
    -- Cursor operations
    OPEN /* cur1 */ v_cursor /* cur2 */ ;
    FETCH /* cur3 */ v_cursor /* cur4 */ INTO /* cur5 */ v_counter /* cur6 */ ;
    CLOSE /* cur7 */ v_cursor /* cur8 */ ;
    -- EXECUTE IMMEDIATE
    EXECUTE /* exec1 */ IMMEDIATE /* exec2 */ 'SELECT 1' /* exec3 */ ;
    -- RETURN statement
    RETURN /* ret1 */ v_result /* ret2 */ ;
    EXCEPTION /* exc1 */ 
        WHEN /* exc2 */ statement_error /* exc3 */ THEN /* exc4 */ 
            RETURN /* exc5 */ 'Error: ' /* exc6 */ || /* exc7 */ :SQLERRM /* exc8 */ ;
        WHEN /* exc9 */ OTHER /* exc10 */ THEN /* exc11 */ 
            RETURN /* exc12 */ 'Unknown error' /* exc13 */ ;
END /* end1 */ ;
$$ /* after close delimiter */ ;
-- =============================================================================
-- SECTION 6: Expressions with comments
-- =============================================================================
SELECT /* expr1 */ 
    -- Arithmetic
    1 /* e1 */ + /* e2 */ 2 /* e3 */ * /* e4 */ 3 /* e5 */ / /* e6 */ 4 /* e7 */ - /* e8 */ 5 /* e9 */ ,
    -- Comparison
    a /* e10 */ = /* e11 */ b /* e12 */ AND /* e13 */ c /* e14 */ <> /* e15 */ d /* e16 */ ,
    -- BETWEEN
    x /* e17 */ BETWEEN /* e18 */ 1 /* e19 */ AND /* e20 */ 10 /* e21 */ ,
    -- IN list
    y /* e22 */ IN /* e23 */ ( /* e24 */ 1 /* e25 */ , /* e26 */ 2 /* e27 */ , /* e28 */ 3 /* e29 */ ) /* e30 */ ,
    -- LIKE
    name /* e31 */ LIKE /* e32 */ '%test%' /* e33 */ ,
    -- IS NULL
    val /* e34 */ IS /* e35 */ NOT /* e36 */ NULL /* e37 */ ,
    -- Function call
    COALESCE /* e38 */ ( /* e39 */ a /* e40 */ , /* e41 */ b /* e42 */ , /* e43 */ c /* e44 */ ) /* e45 */ ,
    -- Window function
    ROW_NUMBER /* e46 */ ( /* e47 */ ) /* e48 */ OVER /* e49 */ ( /* e50 */ 
        PARTITION /* e51 */ BY /* e52 */ a /* e53 */ 
        ORDER /* e54 */ BY /* e55 */ b /* e56 */ 
    ) /* e57 */ ,
    -- Subquery
    ( /* e58 */ SELECT /* e59 */ MAX /* e60 */ ( /* e61 */ x /* e62 */ ) /* e63 */ 
    FROM /* e64 */ t /* e65 */ ) /* e66 */ ,
    -- CASE expression
    CASE /* e67 */ 
        WHEN /* e68 */ a /* e69 */ = /* e70 */ 1 /* e71 */ THEN /* e72 */ 'one' /* e73 */ 
        ELSE /* e74 */ 'other' /* e75 */ 
    END /* e76 */ ,
    -- Cast
    CAST /* e77 */ ( /* e78 */ x /* e79 */ AS /* e80 */ VARCHAR /* e81 */ ) /* e82 */ ,
    -- Semi-structured
    data /* e83 */ : /* e84 */ field /* e85 */ :: /* e86 */ STRING /* e87 */ 
FROM /* expr_from */ t /* expr_t */ ;
-- End of hostile test
