-- Hostile trivia test: MERGE statement with comments in every possible location
MERGE /* after MERGE */ INTO /* after INTO */ target_table /* table name */ AS /* before alias */ t /* alias */ 
USING /* after USING */ (SELECT /* in subquery */ id /* col1 */ , /* comma1 */ value /* col2 */ -- line comment
FROM /* in FROM */ source /* source table */ 
WHERE /* before condition */ status /* col */ = /* equals */ 'active' /* value */ ) /* close subquery */ AS /* before alias */ s /* source alias */ 
ON /* before ON */ ( /* open condition */
    t /* target */./* dot */id /* target col */ = /* equals */ s /* source */./* dot */id /* source col */
) /* close condition */ 
WHEN /* first WHEN */ MATCHED /* after MATCHED */ AND /* before AND */ s /* qual */./* dot */value /* col */ > /* gt */ 100 /* literal */ THEN /* before THEN */ 
UPDATE /* before UPDATE */ SET /* before SET */
    t /* target */./* dot */value /* col */ = /* assign */ s /* source */./* dot */value /* rhs */, /* comma */
    t /* target */./* dot */updated_at /* col2 */ = /* assign2 */ CURRENT_TIMESTAMP /* func */ () /* empty args */ 
WHEN /* second WHEN */ NOT /* before NOT */ MATCHED /* after NOT MATCHED */ THEN /* before INSERT */ 
INSERT /* keyword */ ( /* open cols */ id /* col1 */ , /* comma1 */ value /* col2 */ , /* comma2 */ created_at /* col3 */ ) /* close cols */ VALUES /* before VALUES */ ( /* open values */ s /* source */ . /* dot */ id /* val1 */ , /* comma1 */ s /* source */ . /* dot */ value /* val2 */ , /* comma2 */ CURRENT_TIMESTAMP /* func */ () /* args */ ) /* close values */ 
WHEN /* third WHEN */ NOT /* before NOT */ MATCHED /* after NOT MATCHED */ BY /* before BY */ SOURCE /* after SOURCE */ THEN /* before DELETE */ 
DELETE /* keyword */ ;