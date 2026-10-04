-- Comment carnage: every possible position, every possible combination
/* block before select */ SELECT /* mid select */ -- line after select
    /* before col */ col1 /* after col */ , -- line after comma
    col2 /* mid col2 */ AS /* mid as */ alias /* after alias */ , -- chaos
    -- line before col3
    col3, /* after col3 */ 
    /* before star */ * /* after star */ EXCLUDE /* mid exclude */ ( /* before paren */ col4 /* in paren */ , /* mid list */ col5 /* end list */ ) /* after exclude */ 
/* before from */ FROM /* after from keyword */ -- line
/* before table */ my_table /* after table */ AS /* mid as */ t /* after alias */ 
/* before join */ INNER /* mid inner */ JOIN /* after join */ -- line
/* before table2 */ other_table /* after table2 */ o /* no AS */ /* before on */ ON /* after on */ -- line
/* before expr */ t. /* after dot */ id /* after id */ = /* mid eq */ o. /* second dot */ id /* final id */ 
/* before where */ WHERE /* after where */ -- line
/* before cond */ t. /* dot */ status /* after status */ = /* eq */ 'active' /* after string */ /* before and */ AND /* after and */ -- line
/* nested */ ( /* open */ col1 /* in paren */ > /* op */ 10 /* num */ OR /* or */ col2 /* second */ < /* less */ 5 /* five */ ) /* close */ 
/* before group */ GROUP /* mid group */ BY /* after by */ -- line
/* before gb col */ col1 /* gb col */ , /* gb comma */ col2 /* gb col2 */ 
/* before having */ HAVING /* after having */ -- line
/* before agg */ COUNT /* mid count */ ( /* open count */ * /* star in count */ ) /* close count */ > /* gt */ 0 /* zero */ 
/* before order */ ORDER /* mid order */ BY /* after by */ -- line
/* before ob col */ col1 /* ob col */ ASC /* asc */ , /* ob comma */ -- line
col2 /* ob col2 */ DESC /* desc */ NULLS /* nulls */ FIRST /* first */ 
/* before limit */ LIMIT /* after limit */ 100 /* hundred */ ; /* semicolon */ -- end
