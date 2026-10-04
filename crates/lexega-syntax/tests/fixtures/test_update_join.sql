-- Test UPDATE with FROM and JOIN
UPDATE customer_profiles cp
SET cp.lifetime_value = 100
FROM customer_segments cs
INNER JOIN (
    SELECT customer_id, MAX(activity_date) AS last_activity_date
    FROM customer_activities
    GROUP BY customer_id
) ca ON cp.customer_id = ca.customer_id
WHERE cp.customer_id = cs.customer_id;