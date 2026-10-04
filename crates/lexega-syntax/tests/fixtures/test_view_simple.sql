-- Simple view test
CREATE VIEW test_view (
    ssn,
    email_address
)
AS
SELECT ssn, email
FROM users;