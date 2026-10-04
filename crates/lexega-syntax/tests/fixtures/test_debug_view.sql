CREATE VIEW test_v (
    ssn,
    email_address
)
AS
SELECT ssn, email
FROM users;