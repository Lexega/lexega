-- Window functions with comments in every clause
/* top */ SELECT /* select */ -- line
    /* col1 */ employee_id /* emp */ , /* comma */ -- line
    salary /* salary */ , /* comma */ -- line
    /* window func 1 */ ROW_NUMBER /* func name */ ( /* open */ ) /* close */ -- line
    /* over */ OVER /* over keyword */ ( /* open over */ -- line
        /* partition */ PARTITION /* partition kw */ BY /* by */ -- line
        /* part col */ department /* dept */ , /* comma */ location /* loc */ -- line
        /* order */ ORDER /* order kw */ BY /* by */ -- line
        /* order col */ salary /* sal */ DESC /* desc */ , /* comma */ -- line
        hire_date /* hire */ ASC /* asc */ -- line
    /* close over */ ) /* close */ -- line
    /* as */ AS /* as kw */ row_num /* alias */ , /* comma */ -- line
    /* window func 2 */ SUM /* sum */ ( /* open */ salary /* sal */ ) /* close */ -- line
    /* over2 */ OVER /* over */ ( /* open */ -- line
        /* partition2 */ PARTITION /* part */ BY /* by */ department /* dept */ -- line
        /* rows */ ROWS /* rows kw */ BETWEEN /* between kw */ -- line
        /* rows start */ UNBOUNDED /* unbounded */ PRECEDING /* preceding */ -- line
        /* rows and */ AND /* and */ -- line
        /* rows end */ CURRENT /* current */ ROW /* row */ -- line
    /* close over2 */ ) /* close */ -- line
    /* as2 */ AS /* as */ running_total /* alias */ , /* comma */ -- line
    /* window func 3 */ AVG /* avg */ ( /* open */ salary /* sal */ ) /* close */ -- line
    /* over3 */ OVER /* over */ ( /* open */ -- line
        /* order3 */ ORDER /* order */ BY /* by */ hire_date /* hire */ -- line
        /* range */ RANGE /* range kw */ BETWEEN /* between */ -- line
        /* range start */ INTERVAL /* interval */ '30' /* thirty */ DAY /* day */ PRECEDING /* preceding */ -- line
        /* range and */ AND /* and */ -- line
        /* range end */ INTERVAL /* interval */ '30' /* thirty */ DAY /* day */ FOLLOWING /* following */ -- line
    /* close over3 */ ) /* close */ -- line
    /* as3 */ AS /* as */ moving_avg /* alias */ , /* comma */ -- line
    /* window func 4 */ LEAD /* lead */ ( /* open */ -- line
    /* lead arg */ salary /* sal */ , /* comma */ -- line
    /* lead offset */ 1 /* one */ , /* comma */ -- line
    /* lead default */ 0 /* zero */ -- line
    /* close lead */ ) /* close */ -- line
    /* over4 */ OVER /* over */ ( /* open */ -- line
        /* partition4 */ PARTITION /* part */ BY /* by */ department /* dept */ -- line
        /* order4 */ ORDER /* order */ BY /* by */ salary /* sal */ DESC /* desc */ -- line
    /* close over4 */ ) /* close */ -- line
    /* as4 */ AS /* as */ next_salary /* alias */ -- line
/* from */ FROM /* from kw */ employees /* table */ -- line
/* final */ ; /* semi */ 