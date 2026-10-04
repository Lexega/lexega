UPDATE customers
SET name = 'Jane',
email = 'jane@example.com',
status = 'active',
updated_at = current_timestamp
WHERE id = 1;