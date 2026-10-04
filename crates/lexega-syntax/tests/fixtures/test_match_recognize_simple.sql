-- Simple MATCH_RECOGNIZE test with symbol predicates in subquery
SELECT *
FROM stock_prices
MATCH_RECOGNIZE( PARTITION BY symbol ORDER BY trade_date MEASURES FIRST(A.price) AS start_price ONE ROW PER MATCH PATTERN (A B +) DEFINE A AS A.price > (SELECT AVG(price)
FROM historical
WHERE symbol = A.symbol AND trade_date BETWEEN A.trade_date - INTERVAL '30 days' AND A.trade_date), B AS B.price > LAG(B.price,1)) AS mr;