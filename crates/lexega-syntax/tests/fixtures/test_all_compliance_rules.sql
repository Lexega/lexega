-- Comprehensive test of all compliance rules (C001, C002, C003)
-- SCENARIO 1: No protection (should trigger C001 and C002)
CREATE TABLE employees_no_protection (
    id INT,
    email VARCHAR,
    ssn VARCHAR(11),
    salary DECIMAL(10,2)
);
-- SCENARIO 2: Has row access policy (should trigger nothing)
CREATE TABLE employees_row_policy (
    id INT,
    email VARCHAR,
    ssn VARCHAR(11),
    salary DECIMAL(10,2)
)
ROW ACCESS POLICY hr_policy ON (department);
-- SCENARIO 3: Has column masking policies (should trigger nothing)
CREATE TABLE employees_masked (
    id INT,
    email VARCHAR MASKING POLICY email_mask,
    ssn VARCHAR(11) MASKING POLICY ssn_mask,
    salary DECIMAL(10,2) MASKING POLICY salary_mask
);
-- SCENARIO 4: Mixed - some masked, some not (should trigger C001/C002 for unmasked only)
CREATE TABLE employees_partial (
    id INT,
    email VARCHAR MASKING POLICY email_mask,
    ssn VARCHAR(11),
    salary DECIMAL(10,2)
);
-- SCENARIO 5: Tag-based masking (should trigger C003 for verification)
CREATE TABLE employees_tagged (
    id INT,
    email VARCHAR TAG (pii = 'email'),
    ssn VARCHAR(11) TAG (pii = 'ssn'),
    salary DECIMAL(10,2) TAG (sensitivity = 'high')
);
-- SCENARIO 6: Mixed tags and explicit masking (C003 only for tagged, nothing for masked)
CREATE TABLE employees_mixed_protection (
    id INT,
    email VARCHAR MASKING POLICY email_mask,
    ssn VARCHAR(11) TAG (pii = 'ssn'),
    salary DECIMAL(10,2)
);
-- SCENARIO 7: Non-sensitive data (should trigger nothing)
CREATE TABLE products (
    id INT,
    name VARCHAR,
    price DECIMAL(10,2),
    category VARCHAR
);