MERGE into inventory
USING (SELECT 1 AS id, 'widget' AS name, 100 AS qty UNION ALL SELECT 2, 'gadget', 200) AS src
ON inventory.id = src.id
WHEN MATCHED AND inventory.qty < 50 THEN
update set qty = src.qty, updated_at = current_timestamp()
WHEN NOT MATCHED THEN
INSERT (id, name, qty, created_at) VALUES (src.id, src.name, src.qty, CURRENT_TIMESTAMP());