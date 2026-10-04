-- Test UPDATE with simple FROM (no JOIN)
UPDATE customer_profiles cp
SET cp.lifetime_value = 100
FROM customer_segments cs
WHERE cp.customer_id = cs.customer_id;