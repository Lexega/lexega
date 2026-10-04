-- Hostile trivia test: DDL statements with constraints and comments
CREATE /* create */ OR /* or */ REPLACE /* replace */ TABLE /* table */ my_schema /* schema */ . /* dot */my_table /* table */ ( /* open cols */ 
    /* before id */ id /* col1 */ NUMBER /* type */ ( /* open precision */ 38 /* precision *>, /* comma */ 0 /* scale */ ) /* close precision */ NOT /* not */ NULL /* null */ -- id comment
    CONSTRAINT /* constraint kw */ pk_my_table /* constraint name */ PRIMARY /* primary */ KEY /* key */ -- PK comment
    COMMENT /* comment kw */ 'Primary key column' /* comment text */ ,
    /* col comma */ /* before name */ name /* col2 */ VARCHAR /* type */ ( /* open size */ 255 /* size */ ) /* close size */ NOT /* not */ NULL /* null */ CONSTRAINT /* constraint kw */ chk_name_length /* constraint name */ CHECK /* check */ ( /* open check */
            LENGTH /* func */ ( /* open */ name /* arg */ ) /* close */ > /* gt */ 0 /* literal */
        ) /* close check */ -- check comment
    COMMENT /* comment kw */ 'Customer name must not be empty' /* comment text */ ,
    /* col comma */ /* before email */ email /* col3 */ VARCHAR /* type */ ( /* open size */ 500 /* size */ ) /* close size */ CONSTRAINT /* constraint kw */ uk_email /* constraint name */ UNIQUE /* unique */ -- unique comment
    COMMENT /* comment kw */ 'Email must be unique' /* comment text */ ,
    /* col comma */ /* before parent_id */ parent_id /* col4 */ NUMBER /* type */ ( /* open precision */ 38 /* precision */, /* comma */ 0 /* scale */ ) /* close precision */ CONSTRAINT /* constraint kw */ fk_parent /* constraint name */ FOREIGN /* foreign */ KEY /* key */ -- FK comment
    REFERENCES /* references */ my_schema /* schema */ . /* dot */parent_table /* ref table */ ( /* open cols */ id /* ref col */ ) /* close cols */ ON /* on */ DELETE /* delete */ CASCADE /* cascade */ -- cascade comment
    COMMENT /* comment kw */ 'Reference to parent' /* comment text */ ,
    /* col comma */ /* before status */ status /* col5 */ VARCHAR /* type */ ( /* open size */ 50 /* size */ ) /* close size */ DEFAULT /* default */ 'active' /* default val */ CONSTRAINT /* constraint kw */ chk_status /* constraint name */ CHECK /* check */ ( /* open check */
            status /* col */ IN /* in */ ( /* open list */
                'active' /* val1 */, /* comma */
                'inactive' /* val2 */, /* comma */
                'deleted' /* val3 */
            ) /* close list */
        ) /* close check */ -- status check
    COMMENT /* comment kw */ 'Status can only be active, inactive, or deleted' /* comment text */ ,
    /* col comma */ /* before created_at */ created_at /* col6 */ TIMESTAMP_NTZ /* type */ ( /* open precision */ 9 /* precision */ ) /* close precision */ DEFAULT /* default */ CURRENT_TIMESTAMP /* func */ () /* args */ COMMENT /* comment kw */ 'Record creation timestamp' /* comment text */ 
) /* close cols */ 
CLUSTER /* cluster */ BY /* by */ ( /* open cluster */ id /* cluster col */ ) /* close cluster */ -- cluster comment
COMMENT /* table comment kw */ = /* equals */ 'Main table for customer data' /* table comment text */ ;