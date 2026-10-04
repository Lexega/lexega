-- Test compliance rules for CREATE VIEW statements
-- Scenario 1: View with sensitive columns, no protection
CREATE VIEW employee_salaries
AS
SELECT
    emp_id,
    full_name,
    salary,
    ssn,
    email_address
FROM employees;
-- Scenario 2: View with row access policy (should skip all warnings)
CREATE VIEW protected_patients
WITH ROW ACCESS POLICY patient_privacy_policy ON (patient_id)
AS
SELECT
    patient_id,
    medical_record_number,
    diagnosis
FROM patients;
-- Scenario 3: View with masked columns
CREATE VIEW masked_customers (
    customer_id,
    email_address WITH MASKING POLICY email_mask,
    credit_card_number WITH MASKING POLICY cc_mask,
    phone_number WITH MASKING POLICY phone_mask
)
AS
SELECT
    customer_id,
    email_address,
    credit_card_number,
    phone_number
FROM customers;
-- Scenario 4: View with partial masking (should warn about unmasked columns)
CREATE VIEW partial_masked_employees (
    emp_id,
    salary WITH MASKING POLICY salary_mask,
    ssn,
    home_address
)
AS
SELECT
    emp_id,
    salary,
    ssn, -- No masking!
    home_address -- No masking!
FROM employees;
-- Scenario 5: View with tags on sensitive columns
CREATE VIEW tagged_view (
    patient_id,
    medical_record_number WITH TAG (pii='medical'),
    diagnosis WITH TAG (phi='health_data')
)
AS
SELECT
    patient_id,
    medical_record_number,
    diagnosis
FROM patients;
-- Scenario 6: View with mixed protection
CREATE VIEW mixed_protection (
    emp_id,
    salary WITH MASKING POLICY salary_mask,
    ssn WITH TAG (pii='sensitive'),
    email_address,
    home_address WITH TAG (location='private')
)
AS
SELECT
    emp_id,
    salary,
    ssn,
    email_address, -- No protection
    home_address
FROM employees;
-- Scenario 7: Non-sensitive view (should have no warnings)
CREATE VIEW product_inventory
AS
SELECT
    product_id,
    product_name,
    quantity,
    warehouse_location
FROM inventory;