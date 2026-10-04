-- Hostile trivia test: Window functions with complex OVER clauses
SELECT /* select */ 
    /* before id */ id /* col1 */ , /* comma1 */ 
    /* before value */ value /* col2 */ , /* comma2 */ 
    /* before row_number */ ROW_NUMBER /* func */ () /* args */ OVER /* before OVER */ ( /* open window */ 
        PARTITION /* before PARTITION */ BY /* after BY */ category /* partition col */ -- partition comment
        ORDER /* before ORDER */ BY /* after BY */ value /* order col */ DESC /* direction */ -- order comment
        ROWS /* before ROWS */ BETWEEN /* after BETWEEN */ UNBOUNDED /* before UNBOUNDED */ PRECEDING /* after PRECEDING */ AND /* before AND */ CURRENT /* before CURRENT */ ROW /* after ROW */ 
    ) /* close window */ AS /* alias kw */ rn /* alias */ , /* comma3 */ 
    /* before sum */ SUM /* agg */ ( /* open */ value /* arg */ ) /* close */ OVER /* before OVER */ ( /* open window2 */ 
        PARTITION /* before PARTITION */ BY /* after BY */ category /* partition col */ 
        ORDER /* before ORDER */ BY /* after BY */ id /* order col */ RANGE /* before RANGE */ BETWEEN /* after BETWEEN */ INTERVAL /* before INTERVAL */ '1' /* val */ DAY /* unit */ PRECEDING /* after PRECEDING */ AND /* before AND */ INTERVAL /* before INTERVAL */ '1' /* val */ DAY /* unit */ FOLLOWING /* after FOLLOWING */ 
    ) /* close window2 */ AS /* alias kw */ rolling_sum /* alias */ , /* comma4 */ 
    /* before lag */ LAG /* func */ ( /* open args */ value /* arg1 */ , /* comma */ 1 /* offset */ /* no comma */ ) /* close args */ IGNORE /* before IGNORE */ NULLS /* after NULLS */ OVER /* before OVER */ ( /* open window3 */ 
        ORDER /* before ORDER */ BY /* after BY */ id /* order col */ 
    ) /* close window3 */ AS /* alias kw */ prev_value /* alias */ 
FROM /* before FROM */ my_table /* table */ -- table comment
;