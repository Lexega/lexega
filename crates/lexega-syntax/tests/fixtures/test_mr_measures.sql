SELECT *
FROM t
MATCH_RECOGNIZE( ORDER BY ts MEASURES FIRST(A.ts) AS start_ts, LAST(C.ts) AS end_ts, FIRST(A.price) AS first_price, LAST(C.price) AS last_price, MIN(B.price) AS min_mid_price ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN (A + /* initial rise */ B * C +) DEFINE A AS TRUE, B AS TRUE, C AS TRUE);