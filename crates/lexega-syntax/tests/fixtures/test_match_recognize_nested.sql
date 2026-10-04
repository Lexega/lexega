SELECT *
FROM (
    SELECT *
    FROM (
        SELECT *
        FROM ticker
        MATCH_RECOGNIZE( PARTITION BY symbol ORDER BY tstamp MEASURES STRT.tstamp AS start_time ONE ROW PER MATCH PATTERN (STRT DOWN + UP +) DEFINE DOWN AS DOWN.price < PREV(DOWN.price), UP AS UP.price > PREV(UP.price)) mr1
    ) sub1
    MATCH_RECOGNIZE( PARTITION BY symbol ORDER BY tstamp MEASURES STRT.tstamp AS start_time ONE ROW PER MATCH PATTERN (STRT DOWN + UP +) DEFINE DOWN AS DOWN.price < PREV(DOWN.price), UP AS UP.price > PREV(UP.price)) mr2
) sub2;