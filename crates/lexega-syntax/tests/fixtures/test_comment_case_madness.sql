-- CASE expressions with comments everywhere
/* top select */ SELECT /* after select */ /* before case */ CASE /* after case keyword */ -- line
    /* before when1 */ WHEN /* after when */ -- line
    /* when1 cond */ status /* after status */ = /* eq */ 'active' /* string */ -- line
    /* when1 and */ AND /* and */ -- line
    /* when1 cond2 */ ( /* open */ amount /* amount */ > /* gt */ 100 /* hundred */ OR /* or */ priority /* priority */ = /* eq */ 1 /* one */ ) /* close */ /* before then1 */ THEN /* after then */ -- line
    /* then1 value */ 'high' /* string */ -- line
    /* before when2 */ WHEN /* after when2 */ -- line
    /* when2 cond */ status /* status */ = /* eq */ 'pending' /* string */ -- line
    /* before then2 */ THEN /* then2 */ -- line
    /* then2 nested case */ CASE /* nested case */ -- line
        /* nested when */ WHEN /* nested when */ days /* days */ < /* lt */ 7 /* seven */ -- line
        /* nested then */ THEN /* nested then */ 'recent' /* string */ -- line
        /* nested else */ ELSE /* nested else */ 'old' /* string */ -- line
    /* nested end */ END /* nested end */ -- line
    /* before when3 */ WHEN /* when3 */ -- line
    /* when3 cond */ status /* status */ IN /* in */ -- line
    /* when3 list */ ( /* open list */ -- line
    /* list item1 */ 'cancelled' /* string */ , /* comma */ -- line
    'rejected' /* string */ , /* comma */ 'failed' /* string */ /* close list */ ) /* close */ -- line
    /* before then3 */ THEN /* then3 */ 'inactive' /* string */ -- line
    /* before else */ ELSE /* after else */ -- line
    /* else value */ 'unknown' /* string */ -- line
/* before end */ END /* after end keyword */ -- line
/* after case */ AS /* as */ status_category /* alias */ , /* comma */ -- line
/* second case */ CASE /* case2 */ -- line
    /* simple when */ WHEN /* when */ amount /* amount */ > /* gt */ 1000 /* thousand */ THEN /* then */ 'large' /* string */ 
    /* simple when2 */ WHEN /* when */ amount /* amount */ > /* gt */ 100 /* hundred */ THEN /* then */ 'medium' /* string */ 
    /* simple else */ ELSE /* else */ 'small' /* string */ 
/* simple end */ END /* end */ AS /* as */ size /* alias */ 
/* from */ FROM /* after from */ orders /* table */ -- line
/* where */ WHERE /* after where */ -- line
/* where cond */ CASE /* case in where */ -- line
    /* where when */ WHEN /* when */ region /* region */ = /* eq */ 'APAC' /* string */ THEN /* then */ priority /* priority */ > /* gt */ 2 /* two */ 
    /* where else */ ELSE /* else */ priority /* priority */ > /* gt */ 3 /* three */ 
/* where end */ END /* end */ -- line
/* final */ ; /* semi */ 