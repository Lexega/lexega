-- Hostile trivia test: CTEs with recursive patterns and multiple references
WITH /* with keyword */ RECURSIVE /* recursive */ -- CTE comment
    /* before first CTE */ cte1 /* name */  ( /* open cols */ id /* col1 */ , /* comma */ parent_id /* col2 */ , /* comma */ level /* col3 */ ) /* close cols */ AS /* before AS */ ( /* open CTE body */ 
        SELECT /* anchor select */
            id /* col1 */, /* comma */
            parent_id /* col2 */, /* comma */
            0 /* literal */ AS /* alias */ level /* alias */
        FROM /* anchor FROM */ base_table /* table */
        WHERE /* anchor WHERE */ parent_id /* col */ IS /* is */ NULL /* null */
        UNION /* before UNION */ ALL /* after ALL */ -- union comment
        SELECT /* recursive select */
            t /* alias */ . /* dot */id /* col1 */, /* comma */
            t /* alias */ . /* dot */parent_id /* col2 */, /* comma */
            c /* alias */ . /* dot */level /* col */ + /* plus */ 1 /* literal */
        FROM /* recursive FROM */ base_table /* table */ t /* alias */
        INNER /* join type */ JOIN /* join */ cte1 /* recursive ref */ c /* alias */
            ON /* before ON */ t /* left */ . /* dot */parent_id /* col */ = /* equals */ c /* right */ . /* dot */id /* col */ 
    ) /* close CTE body */ , /* CTE comma */ 
    /* before second CTE */ cte2 /* name */ AS /* before AS */ ( /* open CTE2 */ 
        SELECT /* select */ id /* col */ , /* comma */ COUNT /* agg */ ( /* open */ * /* star */ ) /* close */ AS /* alias */ cnt /* alias */ 
        FROM /* from */ cte1 /* ref to cte1 */ 
        GROUP /* before GROUP */ BY /* after BY */ id /* group col */ 
        HAVING /* before HAVING */ COUNT /* agg */ ( /* open */ * /* star */ ) /* close */ > /* gt */ 1 /* literal */ 
    ) /* close CTE2 */ 
SELECT /* final select */ -- final comment
    c1 /* alias1 */ . /* dot */ id /* col1 */ , /* comma */ 
    c1 /* alias1 */ . /* dot */ level /* col2 */ , /* comma */ 
    c2 /* alias2 */ . /* dot */ cnt /* col3 */ 
FROM /* final FROM */ 
cte1 /* cte ref */ c1 /* alias1 */ 
LEFT /* join type */ OUTER /* join type2 */ JOIN /* join */ cte2 /* cte ref */ c2 /* alias2 */ ON /* before ON */ c1 /* left */ . /* dot */ id /* col */ = /* equals */ c2 /* right */ . /* dot */ id /* col */ ;