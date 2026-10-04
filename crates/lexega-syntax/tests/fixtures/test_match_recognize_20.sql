SELECT *
FROM (
    SELECT *
    FROM (
        SELECT *
        FROM (
            SELECT *
            FROM (
                SELECT *
                FROM (
                    SELECT *
                    FROM (
                        SELECT *
                        FROM (
                            SELECT *
                            FROM (
                                SELECT *
                                FROM (
                                    SELECT *
                                    FROM (
                                        SELECT *
                                        FROM (
                                            SELECT *
                                            FROM (
                                                SELECT *
                                                FROM (
                                                    SELECT *
                                                    FROM (
                                                        SELECT *
                                                        FROM (
                                                            SELECT *
                                                            FROM (
                                                                SELECT *
                                                                FROM (
                                                                    SELECT *
                                                                    FROM (
                                                                        SELECT *
                                                                        FROM (
                                                                            SELECT *
                                                                            FROM ticker
                                                                            MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                                                        ) s1
                                                                        MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                                                    ) s2
                                                                    MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                                                ) s3
                                                                MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                                            ) s4
                                                            MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                                        ) s5
                                                        MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                                    ) s6
                                                    MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                                ) s7
                                                MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                            ) s8
                                            MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                        ) s9
                                        MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                    ) s10
                                    MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                                ) s11
                                MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                            ) s12
                            MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                        ) s13
                        MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                    ) s14
                    MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
                ) s15
                MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
            ) s16
            MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
        ) s17
        MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
    ) s18
    MATCH_RECOGNIZE( PARTITION BY s ORDER BY t MEASURES A.t AS x ONE ROW PER MATCH PATTERN (A) DEFINE A AS true) m
) s19;