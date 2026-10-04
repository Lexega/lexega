UPDATE products
SET price = price * 1.1,
discount_price = price * 0.9,
stock = stock - sold_count,
last_updated = current_timestamp
WHERE category = 'electronics';