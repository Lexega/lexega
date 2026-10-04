UPDATE users
SET id = 123,
first_name = 'John',
last_name_suffix = 'Jr.',
e = 'test@example.com',
created_timestamp = now()
WHERE user_id = 1;