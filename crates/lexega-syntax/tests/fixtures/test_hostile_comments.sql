-- Test file: Hostile comment placement in Snowflake Scripting
-- Every possible location where comments could cause issues
CREATE OR REPLACE PROCEDURE /* proc comment */ hostile_comments_test /* after name */ (
    /* before param */ p_input /* after param name */ INTEGER /* after type */,
    /* second param */ p_flag BOOLEAN /* trailing */
) /* after params */ 
RETURNS /* before return type */ VARCHAR /* after return type */
LANGUAGE /* before SQL */ SQL /* after SQL */
AS /* before delimiter */
$$ /* after open delimiter */ 
DECLARE /* after DECLARE */ 
    -- line comment before first decl
    v_result /* after var name */ VARCHAR /* after type */ DEFAULT /* after DEFAULT */ 'init' /* after value */ ;
    /* block before second decl */ v_counter NUMBER /* between type and DEFAULT */ DEFAULT 0; -- trailing on decl
    v_flag BOOLEAN; /* no default, trailing comment */ 
    -- standalone line comment in declarations
    /* standalone block comment in declarations */ v_cursor CURSOR FOR /* before query */ 
        SELECT /* in query */ id
        FROM t; /* after cursor */ 
BEGIN /* after BEGIN */ 
    -- line comment after BEGIN
    /* block comment after BEGIN */ LET /* after LET */ v_result := /* after name */ /* after assign */ 'start' /* after value */ ;
    v_counter /* before assign op */ := /* after assign op */ 1 /* after number */ ; -- trailing on assign
    /* comment before IF */ IF /* after IF */ ( /* after open paren */ v_counter /* after var */ > /* after op */ 0 /* after zero */ ) /* after close paren */ THEN /* after THEN */ 
        -- line comment in IF body
        v_result := 'positive'; /* trailing in IF */ 
        /* block in IF body */ SELECT /* in nested select */ COUNT(*) /* after count */ INTO /* after INTO */ :v_counter
        FROM /* after FROM */ my_table /* after table */ 
        WHERE /* after WHERE */ id /* after id */ = /* after eq */ 1; /* trailing on SELECT */ 
    ELSEIF /* after ELSEIF */ (v_counter < 0) /* after condition */ THEN /* after THEN */ 
        -- line comment in ELSEIF
        v_result := 'negative'; /* trailing */ 
    ELSE /* after ELSE */ 
        -- line comment in ELSE
        v_result := 'zero'; /* trailing in ELSE */ 
    /* block comment before END IF */ END /* between END and IF */ IF /* after IF */ ; -- trailing on END IF
    /* comment before CASE */ CASE /* after CASE */ v_counter /* after operand */ 
        WHEN /* after WHEN */ 1 /* after value */ THEN /* after THEN */ 
            -- line in WHEN 1
            v_result := 'one'; /* trailing WHEN 1 */ 
        WHEN /* second WHEN */ 2 THEN
            v_result := 'two'; -- trailing WHEN 2
        /* block before next WHEN */ ELSE /* after ELSE in CASE */ 
            -- line in CASE ELSE
            v_result := 'other'; /* trailing CASE ELSE */ 
    END /* between END and CASE */ CASE; /* after END CASE */ -- trailing END CASE
    /* comment before WHILE */ WHILE /* after WHILE */ ( /* open */ v_counter < 10 /* in condition */ ) /* close */ DO /* after DO */ 
        -- line in WHILE
        v_counter := v_counter + 1; /* trailing in WHILE */ 
        IF (v_counter = 5) THEN
            BREAK /* after BREAK */ ; -- trailing BREAK
        END IF;
        /* block before CONTINUE check */ IF (v_counter = 3) THEN
            CONTINUE /* after CONTINUE */ ; /* trailing CONTINUE */ 
        END IF;
    END /* between END and WHILE */ WHILE; /* after END WHILE */ -- trailing END WHILE
    /* comment before FOR */ FOR /* after FOR */ i /* after loop var */ IN /* after IN */ 1 /* after start */ TO /* after TO */ 5 /* after end */ DO /* after DO */ 
        -- line in FOR
        v_counter := v_counter + i; /* trailing in FOR */ 
    END /* between END and FOR */ FOR; /* after END FOR */ 
    /* comment before FOR cursor */ FOR /* after FOR */ rec /* after rec */ IN /* after IN */ v_cursor /* after cursor name */ DO /* after DO */ 
        -- line in cursor FOR
        v_result := v_result || rec.id::VARCHAR; /* trailing cursor FOR */ 
    END FOR; -- trailing END FOR cursor
    /* comment before LOOP */ LOOP /* after LOOP */ 
        -- line in LOOP
        v_counter := v_counter + 1; /* trailing in LOOP */ 
        IF /* in LOOP IF */ (v_counter > 20) THEN
            BREAK; -- exit LOOP
        END IF; /* trailing nested IF in LOOP */ 
    END /* between END and LOOP */ LOOP; /* after END LOOP */ -- trailing END LOOP
    /* comment before REPEAT */ REPEAT /* after REPEAT */ 
        -- line in REPEAT
        v_counter := v_counter - 1; /* trailing in REPEAT */ 
    UNTIL /* after UNTIL */ ( /* open */ v_counter <= 0 /* in until condition */ ) /* close */ END /* between END and REPEAT */ REPEAT; /* after END REPEAT */ 
    /* comment before nested BEGIN block */ BEGIN /* nested BEGIN */ 
        -- line in nested block
        v_result := 'nested'; /* trailing in nested */ 
        /* deeply nested block comment */ BEGIN /* double nested */ 
            v_result := 'deep'; -- trailing deep
        END; /* after inner END */ 
    END; /* after outer nested END */ -- trailing nested block
    /* comment before CREATE in proc */ CREATE /* after CREATE */ OR /* after OR */ REPLACE /* after REPLACE */ TEMP /* after TEMP */ TABLE /* after TABLE */ tmp_hostile /* after name */ 
    AS /* after AS */ 
    SELECT /* in CTAS */ 1 /* after 1 */ AS /* after AS */ id /* after id */ ; -- trailing CTAS
    /* comment before MERGE */ MERGE /* after MERGE */ INTO /* after INTO */ target_table /* after target */ t /* after alias */ 
    USING /* after USING */ ( /* open subquery */ SELECT /* in USING */ id, val /* after cols */ 
    FROM /* in USING FROM */ source_table /* after source */ 
    WHERE /* in USING WHERE */ active = TRUE /* after condition */ ) /* close subquery */ s /* after source alias */ 
    ON /* after ON */ t.id /* after t.id */ = /* after eq */ s.id /* after s.id */ 
    WHEN /* after WHEN */ MATCHED /* after MATCHED */ THEN /* after THEN */ 
    UPDATE /* after UPDATE */ SET /* after SET */ t.val /* after t.val */ = /* after eq */ s.val /* after s.val */ -- trailing UPDATE
    WHEN /* second WHEN */ NOT /* after NOT */ MATCHED /* after MATCHED */ THEN /* after THEN */ 
    INSERT /* after INSERT */ ( /* open */ id, val /* in cols */ ) /* close */ VALUES /* after VALUES */ ( /* open vals */ s.id, s.val /* in vals */ ); /* after MERGE semicolon */ -- trailing MERGE
    /* comment before INSERT */ INSERT /* after INSERT */ INTO /* after INTO */ log_table /* after table */ ( /* open */ msg /* in cols */ ) /* close */ 
    VALUES /* after VALUES */ ( /* open vals */ 'hostile test complete' /* in vals */ ); /* after INSERT semicolon */ 
    /* comment before UPDATE */ UPDATE /* after UPDATE */ status_table /* after table */ 
    SET /* after SET */ status /* after col */ = /* after eq */ 'done' /* after val */ 
    WHERE /* after WHERE */ id /* after id */ = /* after eq */ 1; /* after UPDATE semicolon */ -- trailing UPDATE
    /* comment before DELETE */ DELETE /* after DELETE */ FROM /* after FROM */ temp_table /* after table */ 
    WHERE /* after WHERE */ created_at /* after col */ < /* after op */ CURRENT_DATE(); /* after DELETE semicolon */ 
    /* comment before CALL */ CALL /* after CALL */ other_procedure /* after name */ ( /* open */ 'arg1' /* in args */ ,123 /* second arg */ ); /* after CALL semicolon */ -- trailing CALL
    /* comment before RETURN */ RETURN /* after RETURN */ v_result /* after result */ || /* after concat */ ' complete' /* after string */ ; -- trailing RETURN
    EXCEPTION /* after EXCEPTION */ 
        -- line after EXCEPTION
        /* block after EXCEPTION */ WHEN /* after WHEN */ statement_error /* after error type */ THEN /* after THEN */ 
            -- line in handler 1
            RETURN /* in handler */ 'Statement error: ' /* after string */ || /* after concat */ :SQLERRM /* after sqlerrm */ ; /* trailing handler 1 */ 
        WHEN /* second handler */ expression_error /* after expr error */ OR /* after OR */ other_error /* after other */ THEN /* after THEN */ 
            /* block in handler 2 */ RETURN 'Expression or other error'; -- trailing handler 2
        WHEN /* third handler */ OTHER /* after OTHER */ THEN /* after THEN */ 
            -- catch all handler
            RETURN /* in catch all */ 'Unknown error: ' || :SQLERRM; /* trailing catch all */ 
END /* between END and semicolon */ ; /* after block END semicolon */ -- trailing procedure body
$$ /* after close delimiter */ ; -- final trailing comment
