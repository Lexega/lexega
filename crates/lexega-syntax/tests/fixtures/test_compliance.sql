-- Test compliance rules for sensitive data detection
CREATE TABLE employees (
    id INT,
    name VARCHAR,
    email VARCHAR,
    ssn VARCHAR(11),
    salary DECIMAL(10,2),
    phone_number VARCHAR
);
CREATE TABLE customer_records (
    customer_id INT,
    first_name VARCHAR,
    last_name VARCHAR,
    credit_card_number VARCHAR,
    street_address VARCHAR,
    zip_code VARCHAR
);
CREATE TABLE medical_records (
    patient_id INT,
    medical_record_number VARCHAR,
    diagnosis VARCHAR,
    treatment VARCHAR,
    date_of_birth DATE
);
-- This table should be fine (no sensitive data)
CREATE TABLE products (
    id INT,
    name VARCHAR,
    price DECIMAL(10,2),
    category VARCHAR
);