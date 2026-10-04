-- Hostile CASE statement test: comments in every possible position
SELECT
    /* before case */ CASE /* after case keyword */ 
        /* before when 1 */ WHEN /* after when 1 */ col1 /* after col1 */ = /* after equals */ 1 /* after value 1 */ THEN /* after then 1 */ 'one' /* after result 1 */ 
        /* before when 2 */ WHEN /* after when 2 */ col1 /* in condition 2 */ BETWEEN /* after between */ 10 /* after 10 */ AND /* after and */ 20 /* after 20 */ THEN /* after then 2 */ 'teens' /* after result 2 */ 
        /* before when 3 */ WHEN /* after when 3 */ col1 /* in condition 3 */ IN /* after in */ ( /* after lparen */ 100 /* after 100 */ , /* after comma 1 */ 200 /* after 200 */ , /* after comma 2 */ 300 /* after 300 */ ) /* after rparen */ THEN /* after then 3 */ 'hundreds' /* after result 3 */ 
        /* before when 4 */ WHEN /* after when 4 */ col2 /* col2 ref */ IS /* after is */ NULL /* after null */ THEN /* after then 4 */ 'null_value' /* after result 4 */ 
        /* before when 5 */ WHEN /* after when 5 */ col2 /* col2 again */ IS /* is keyword */ NOT /* not keyword */ NULL /* null keyword */ THEN /* after then 5 */ 'not_null' /* after result 5 */ 
        /* before else */ ELSE /* after else keyword */ 'other' /* after else result */ 
    /* before end */ END /* after end keyword */ /* trailing case comment */ ,
    /* before nested case */ CASE /* nested case start */ 
        WHEN /* nested when 1 */ CASE /* inner case start */ 
            WHEN /* inner when */ col3 /* inner col3 */ > /* inner gt */ 0 /* inner zero */ THEN /* inner then */ 1 /* inner one */ 
            ELSE /* inner else */ 0 /* inner zero result */ 
        END /* inner case end */ = /* nested equals */ 1 /* nested one */ THEN /* nested then */ 'positive' /* nested result */ 
        ELSE /* nested else */ 'non-positive' /* nested else result */ 
    END /* nested case end */ /* trailing nested */ ,
    /* before searched case */ CASE /* searched case keyword */ 
        /* searched when 1 */ WHEN /* when keyword */ ( /* condition lparen */ col1 /* in parens */ + /* plus */ col2 /* col2 in expr */ ) /* condition rparen */ > /* gt op */ 100 /* hundred */ THEN /* searched then 1 */ 'large' /* large result */ 
        /* searched when 2 */ WHEN /* when 2 */ col1 /* col1 ref 2 */ * /* multiply */ 2 /* two */ < /* lt */ col2 /* col2 ref 2 */ THEN /* searched then 2 */ 'double' /* double result */ 
        /* searched else */ ELSE /* else searched */ NULL /* null result */ 
    /* searched end */ END /* searched end keyword */ /* trailing searched */ ,
    /* before case in select list */ col4 /* col4 ref */ , /* comma after col4 */ 
    /* deeply nested case */ CASE /* outer deep */ 
        WHEN /* outer when */ CASE /* middle case */ 
            WHEN /* middle when */ CASE /* inner deep case */ 
                WHEN /* innermost when */ col5 /* col5 innermost */ = /* innermost eq */ 'A' /* innermost A */ THEN /* innermost then */ 1 /* innermost 1 */ 
                WHEN /* innermost when 2 */ col5 /* col5 inner 2 */ = /* eq 2 */ 'B' /* B value */ THEN /* inner then 2 */ 2 /* inner 2 */ 
                ELSE /* innermost else */ 3 /* innermost 3 */ 
            END /* innermost end */ > /* middle gt */ 1 /* middle one */ THEN /* middle then */ 'high' /* middle high */ 
            ELSE /* middle else */ 'low' /* middle low */ 
        END /* middle end */ = /* outer eq */ 'high' /* outer high */ THEN /* outer then */ 'priority' /* priority result */ 
        ELSE /* outer else */ 'normal' /* normal result */ 
    END /* outer end */ /* trailing deep nested */ ,
    /* case with complex expressions */ CASE /* complex case */ 
        WHEN /* complex when 1 */ COALESCE /* coalesce func */ ( /* coalesce lparen */ col6 /* col6 in coalesce */ , /* coalesce comma */ 0 /* coalesce default */ ) /* coalesce rparen */ + /* add */ NULLIF /* nullif func */ ( /* nullif lparen */ col7 /* col7 ref */ , /* nullif comma */ 0 /* nullif zero */ ) /* nullif rparen */ > /* complex gt */ 10 /* ten */ THEN /* complex then 1 */ 'sum_large' /* sum result */ 
        WHEN /* complex when 2 */ LENGTH /* length func */ ( /* length lparen */ TRIM /* trim func */ ( /* trim lparen */ col8 /* col8 ref */ ) /* trim rparen */ ) /* length rparen */ > /* len gt */ 5 /* five */ THEN /* complex then 2 */ 'long_string' /* long result */ 
        WHEN /* complex when 3 */ col9 /* col9 */ LIKE /* like keyword */ '%test%' /* pattern */ ESCAPE /* escape keyword */ '\\' /* escape char */ THEN /* complex then 3 */ 'matched' /* matched result */ 
        ELSE /* complex else */ 'no_match' /* no match result */ 
    END /* complex end */ /* trailing complex */ ,
    /* case in aggregate */ SUM /* sum func */ ( /* sum lparen */ CASE /* case in sum */ 
        WHEN /* agg when */ status /* status col */ = /* status eq */ 'active' /* active value */ THEN /* agg then */ amount /* amount col */ 
        ELSE /* agg else */ 0 /* zero amount */ 
    END /* agg case end */ ) /* sum rparen */ /* trailing agg */ ,
    /* case with null handling */ CASE /* null case */ 
        WHEN /* null when 1 */ col10 /* col10 */ IS /* is keyword */ NULL /* null 1 */ OR /* or keyword */ col10 /* col10 again */ = /* eq op */ '' /* empty string */ THEN /* null then 1 */ 'empty' /* empty result */ 
        WHEN /* null when 2 */ col10 /* col10 ref 2 */ IS /* is 2 */ NOT /* not 2 */ NULL /* null 2 */ AND /* and keyword */ LENGTH /* len func */ ( /* len lparen */ TRIM /* trim func 2 */ ( /* trim lparen 2 */ col10 /* col10 in trim */ ) /* trim rparen 2 */ ) /* len rparen */ > /* gt 2 */ 0 /* zero 2 */ THEN /* null then 2 */ 'filled' /* filled result */ 
        ELSE /* null else */ NULL /* null else result */ 
    END /* null end */ /* trailing null case */ 
FROM /* from keyword */ /* before table */ test_table /* table name */ /* after table */ 
WHERE /* where keyword */ /* before where case */ CASE /* where case */ 
    WHEN /* where when */ col1 /* where col1 */ > /* where gt */ 0 /* where zero */ THEN /* where then */ 1 /* where one */ 
    ELSE /* where else */ 0 /* where zero result */ 
END /* where end */ = /* where eq final */ 1 /* where one final */ /* trailing where case */ AND /* and in where */ col2 /* col2 in where */ IS /* is in where */ NOT /* not in where */ NULL /* null in where */ 
ORDER BY /* order by keywords */ /* order case */ CASE /* order case keyword */ 
    WHEN /* order when */ col1 /* order col1 */ < /* order lt */ 10 /* order ten */ THEN /* order then */ 1 /* order one */ 
    WHEN /* order when 2 */ col1 /* order col1 2 */ < /* order lt 2 */ 100 /* order hundred */ THEN /* order then 2 */ 2 /* order two */ 
    ELSE /* order else */ 3 /* order three */ 
END /* order end */ /* trailing order case */ ASC /* asc keyword */ /* trailing asc */ ;