SELECT *
FROM price_ticks t
MATCH_RECOGNIZE( PARTITION BY t.symbol ORDER BY t.ts PATTERN (A + /* initial rise */ B * C +) DEFINE A AS A.price >= PREV(A.price), B AS B.price <= PREV(B.price), C AS C.price >= PREV(C.price));