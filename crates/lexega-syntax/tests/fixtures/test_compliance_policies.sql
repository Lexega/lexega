-- Test compliance rules: should trigger warnings (no policies defined)
CREATE TABLE employees_unprotected (
    id INT,
    name VARCHAR,
    email VARCHAR,
    ssn VARCHAR(11),
    salary DECIMAL(10,2)
);
-- Test compliance rules: should NOT warn (has row access policy)
CREATE TABLE employees_protected (
    id INT,
    name VARCHAR,
    email VARCHAR,
    ssn VARCHAR(11),
    salary DECIMAL(10,2)
)
ROW ACCESS POLICY hr_policy ON (department);
-- Test compliance rules: should NOT warn (columns have masking policies)
CREATE TABLE customers_protected (
    id INT,
    name VARCHAR,
    email VARCHAR MASKING POLICY email_mask,
    phone VARCHAR MASKING POLICY phone_mask,
    credit_card_number VARCHAR MASKING POLICY credit_card_mask
);
-- Test compliance rules: should warn ONLY about unprotected columns
CREATE TABLE mixed_protection (
    id INT,
    email VARCHAR MASKING POLICY email_mask,
    ssn VARCHAR,
    phone_number VARCHAR
);