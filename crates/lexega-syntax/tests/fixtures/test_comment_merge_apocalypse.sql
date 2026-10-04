-- MERGE with comments in every conceivable location
/* before merge */ MERGE /* after merge */ INTO /* into */ -- line
    /* target schema */ target_schema /* schema */ . /* dot */ target_table /* table */ AS /* as */ tgt /* alias */ -- line
/* using */ USING /* after using */ ( /* subquery open */ -- line
/* subquery select */ SELECT /* select */ -- line
    /* subq cols */ id /* id */ , /* comma */ -- line
    name /* name */ , /* comma */ 
    value /* value */ , /* comma */ 
    updated_at /* updated */ -- line
/* subq from */ FROM /* from */ source_schema /* schema */ . /* dot */ source_table /* table */ -- line
/* subq where */ WHERE /* where */ updated_at /* col */ > /* gt */ -- line
/* subq subquery */ ( /* open */ SELECT /* select */ MAX /* max */ ( /* open */ last_sync /* col */ ) /* close */ 
FROM /* from */ sync_log /* table */ ) /* close */ -- line
/* close subquery */ ) /* close */ AS /* as */ src /* alias */ -- line
/* on clause */ ON /* on keyword */ -- line
    /* on condition */ tgt /* tgt */ . /* dot */ id /* id */ = /* eq */ src /* src */ . /* dot */ id /* id */ -- line
    /* on and */ AND /* and */ -- line
    /* on condition2 */ tgt /* tgt */ . /* dot */ record_type /* col */ = /* eq */ 'active' /* string */ -- line
/* when matched */ WHEN /* when */ MATCHED /* matched */ -- line
/* matched and */ AND /* and */ -- line
    /* matched condition */ src /* src */ . /* dot */ value /* value */ <> /* ne */ tgt /* tgt */ . /* dot */ value /* value */ -- line
/* then update */ THEN /* then */ 
UPDATE /* update */ SET /* set */ -- line
    /* update col1 */ tgt /* tgt */ . /* dot */ name /* name */ = /* eq */ src /* src */ . /* dot */ name /* name */ , /* comma */ -- line
    /* update col2 */ tgt /* tgt */ . /* dot */ value /* value */ = /* eq */ -- line
        /* update case */ CASE /* case */ -- line
            /* update when */ WHEN /* when */ src /* src */ . /* dot */ value /* value */ > /* gt */ 1000 /* thousand */ -- line
            /* update then */ THEN /* then */ src /* src */ . /* dot */ value /* value */ * /* mult */ 0.9 /* discount */ -- line
            /* update else */ ELSE /* else */ src /* src */ . /* dot */ value /* value */ -- line
        /* update end */ END /* end */ , /* comma */ -- line
    /* update col3 */ tgt /* tgt */ . /* dot */ updated_at /* updated */ = /* eq */ CURRENT_TIMESTAMP /* func */ ( /* open */ ) /* close */ , /* comma */ -- line
    /* update col4 */ tgt /* tgt */ . /* dot */ updated_by /* updated_by */ = /* eq */ 'merge_job' /* string */ -- line
/* when matched delete */ WHEN /* when */ MATCHED /* matched */ -- line
/* delete and */ AND /* and */ -- line
    /* delete condition */ src /* src */ . /* dot */ value /* value */ < /* lt */ 0 /* zero */ -- line
/* then delete */ THEN /* then */ 
DELETE /* delete */ -- line
/* when not matched */ WHEN /* when */ NOT /* not */ MATCHED /* matched */ -- line
/* insert and */ AND /* and */ -- line
    /* insert condition */ src /* src */ . /* dot */ value /* value */ IS /* is */ NOT /* not */ NULL /* null */ -- line
/* then insert */ THEN /* then */ 
INSERT /* insert */ -- line
/* insert cols */ ( /* open cols */ -- line
/* insert col1 */ id /* id */ , /* comma */ -- line
name /* name */ , /* comma */ value /* value */ , /* comma */ -- line
created_at /* created */ , /* comma */ updated_at /* updated */ -- line
/* close cols */ ) /* close */ -- line
/* insert values */ VALUES /* values */ -- line
/* values list */ ( /* open values */ -- line
/* value1 */ src /* src */ . /* dot */ id /* id */ , /* comma */ -- line
/* value2 */ src /* src */ . /* dot */ name /* name */ , /* comma */ -- line
/* value3 */ src /* src */ . /* dot */ value /* value */ , /* comma */ -- line
/* value4 */ CURRENT_TIMESTAMP /* func */ ( /* open */ ) /* close */ , /* comma */ -- line
/* value5 */ CURRENT_TIMESTAMP /* func */ ( /* open */ ) /* close */ -- line
/* close values */ ) /* close */ -- line
/* when not matched by source */ WHEN /* when */ NOT /* not */ MATCHED /* matched */ BY /* by */ SOURCE /* source */ -- line
/* source and */ AND /* and */ -- line
    /* source condition */ tgt /* tgt */ . /* dot */ updated_at /* updated */ < /* lt */ -- line
        /* source dateadd */ DATEADD /* func */ ( /* open */ day /* unit */ , /* comma */ - /* minus */ 90 /* ninety */ , /* comma */ CURRENT_DATE /* func */ ( /* open */ ) /* close */ ) /* close */ -- line
/* then delete source */ THEN /* then */ 
DELETE /* delete */ -- line
/* final */ ; /* semi */ 