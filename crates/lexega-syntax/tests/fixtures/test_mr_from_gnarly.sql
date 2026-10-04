SELECT /* match_recognize pattern chaos */ *
FROM price_ticks t
MATCH_RECOGNIZE( PARTITION BY t.symbol ORDER BY t.ts MEASURES FIRST(A.ts) AS start_ts, LAST(C.ts) AS end_ts, FIRST(A.price) AS first_price, LAST(C.price) AS last_price, MIN(B.price) AS min_mid_price, (last_price - first_price) / NULLIF(first_price,0) AS total_change ONE ROW PER MATCH AFTER MATCH SKIP TO NEXT ROW PATTERN (A + /* initial rise */ B * C +) DEFINE A AS A.price >= PREV(A.price) OR PREV(A.price) IS NULL, B AS (B.price <= PREV(B.price) AND B.price >= PREV(A.price) /* middle wiggle */ ), C AS (C.price >= PREV(C.price) AND C.price > B.price /* breakout */ ))
WHERE total_change >= 0.05
ORDER BY t.symbol,start_ts;