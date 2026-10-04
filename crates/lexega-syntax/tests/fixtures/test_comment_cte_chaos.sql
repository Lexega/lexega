-- CTE with comments in every possible location
/* before with */ WITH /* after with */ -- line after with
    /* before cte1 */ cte1 /* after cte1 name */ -- line
     ( /* before paren */ /* after open paren */ -- line
    /* before col */ col_a /* after col_a */ , /* after comma */ -- line
    col_b /* after col_b */ , /* comma */ col_c /* after col_c */ ) /* before close */ /* after close paren */ -- line
    /* before as */ AS /* after as */ -- line
    /* before cte1 body */ ( /* open cte1 body */ -- line
        /* cte1 select */ SELECT /* after select */ -- line
            /* cte1 col1 */ a /* after a */ , /* comma */ -- line
            b /* after b */ , /* comma */ 
            c /* after c */ 
        /* cte1 from */ FROM /* after from */ table1 /* after table1 */ 
    /* cte1 end */ ) /* close cte1 body */ , /* cte separator */ -- line after cte1
    /* before cte2 */ cte2 /* after cte2 name */ -- line
     ( /* cte2 paren */ /* open */ d /* col d */ , /* comma */ e /* col e */ ) /* close */ /* cte2 as */ AS /* after as */ -- line
    /* cte2 body */ ( /* open */ -- line
        /* cte2 select */ SELECT /* after select */ -- line
        /* cte2 cols */ d /* after d */ , /* comma */ e /* after e */ 
        /* cte2 from */ FROM /* after from */ 
        cte1 /* reference cte1 */ -- line
        /* cte2 join */ JOIN /* after join */ table2 /* after table2 */ -- line
        /* cte2 on */ ON /* after on */ cte1. /* dot */ a /* after a */ = /* eq */ table2. /* dot */ id /* after id */ 
    /* cte2 end */ ) /* close cte2 */ , /* cte2 separator */ -- line
    /* before cte3 */ cte3 /* after cte3 name */ AS /* cte3 as */ ( /* cte3 body open */ 
        /* cte3 select */ SELECT /* after select */ * /* star with comment */ 
        FROM /* from */ cte2 /* ref cte2 */ 
    /* cte3 body close */ ) /* close cte3 */ -- line after cte3
/* main select */ SELECT /* after main select */ -- line
    /* main cols */ cte1. /* dot */ col_a /* col */ , /* comma */ -- line
    cte2. /* dot */ d /* col d */ , /* comma */ 
    cte3. /* dot */ e /* col e */ 
/* main from */ FROM /* after from */ 
cte1 /* ref cte1 */ -- line
/* main join */ JOIN /* after join */ cte2 /* ref cte2 */ ON /* on */ cte1. /* dot */ col_b /* col */ = /* eq */ cte2. /* dot */ d /* d */ 
/* main join2 */ JOIN /* join */ cte3 /* cte3 */ ON /* on */ cte2. /* dot */ e /* e */ = /* eq */ cte3. /* dot */ e /* e */ /* final */ ; /* semicolon */ 