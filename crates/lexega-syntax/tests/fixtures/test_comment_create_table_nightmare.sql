-- CREATE TABLE with comments on every clause and constraint
/* before create */ CREATE /* after create */ OR /* or */ REPLACE /* replace */ -- line
/* table kw */ TABLE /* after table */ IF /* if */ NOT /* not */ EXISTS /* exists */ -- line
/* schema */ my_schema /* schema name */ . /* dot */ my_table /* table name */ -- line
/* open paren */ ( /* after open */ -- line
    /* col1 */ id /* after id */ -- line
    /* col1 type */ NUMBER /* number type */ ( /* precision open */ 38 /* precision */ , /* comma */ 0 /* scale */ ) /* precision close */ -- line
    /* col1 constraint */ NOT /* not */ NULL /* null */ -- line
    /* col1 constraint2 */ PRIMARY /* primary */ KEY /* key */ -- line
    /* col1 comment */ COMMENT /* comment kw */ 'Primary identifier' /* comment text */ ,
    /* comma */ -- line
    /* col2 */ name /* after name */ -- line
    /* col2 type */ VARCHAR /* varchar */ ( /* size open */ 255 /* size */ ) /* size close */ -- line
    /* col2 constraint */ NOT /* not */ NULL /* null */ -- line
    /* col2 collate */ COLLATE /* collate kw */ 'en-ci' /* collate spec */ ,
    /* comma */ -- line
    /* col3 */ email /* after email */ -- line
    /* col3 type */ STRING /* string type */ -- line
    /* col3 constraint */ UNIQUE /* unique */ ,
    /* comma */ -- line
    /* col4 */ status /* status */ -- line
    /* col4 type */ VARCHAR /* varchar */ ( /* open */ 50 /* fifty */ ) /* close */ -- line
    /* col4 default */ DEFAULT /* default kw */ 'active' /* default value */ ,
    /* comma */ -- line
    /* col5 */ amount /* amount */ -- line
    /* col5 type */ DECIMAL /* decimal */ ( /* open */ 18 /* p */ , /* comma */ 2 /* s */ ) /* close */ ,
    /* comma */ -- line
    /* col6 */ created_at /* created */ -- line
    /* col6 type */ TIMESTAMP_NTZ /* timestamp type */ -- line
    /* col6 default */ DEFAULT /* default */ CURRENT_TIMESTAMP /* func */ ( /* open */ ) /* close */ ,
    /* comma */ -- line
    /* col7 */ metadata /* metadata */ -- line
    /* col7 type */ VARIANT /* variant type */ /* comma */ -- line
    /* fk constraint */ ,
    FOREIGN /* foreign */ KEY /* key */ -- line
        /* fk cols */ ( /* open */ id /* id */ ) /* close */ -- line
        /* fk references */ REFERENCES /* references kw */ -- line
        /* fk table */ other_schema /* schema */ . /* dot */ parent_table /* table */ -- line
        /* fk ref cols */ ( /* open */ parent_id /* col */ ) /* close */ -- line
/* close paren */ ) /* after close */ -- line
/* cluster by */ CLUSTER /* cluster kw */ BY /* by kw */ -- line
    /* cluster expr */ ( /* open */ id /* id */ , /* comma */ TO_DATE /* func */ ( /* open */ created_at /* col */ ) /* close */ ) /* close */ -- line
/* change tracking */ CHANGE_TRACKING /* ct kw */ = /* eq */ TRUE /* true */ -- line
/* data retention */ DATA_RETENTION_TIME_IN_DAYS /* drt kw */ = /* eq */ 7 /* seven */ -- line
/* comment on table */ COMMENT /* comment kw */ = /* eq */ 'Main transaction table' /* comment */ -- line
/* tags */ WITH /* with */ TAG /* tag */ ( /* open */ -- line
    /* tag1 */ pii /* tag name */ = /* eq */ 'sensitive' /* value */ , /* comma */ -- line
    tier /* tag2 */ = /* eq */ 'gold' /* value */ -- line
/* close tags */ ) /* close */ -- line
/* final */ ; /* semi */ 