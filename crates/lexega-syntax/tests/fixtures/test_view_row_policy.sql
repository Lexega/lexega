-- Test WITH ROW ACCESS POLICY on view (correct Snowflake syntax)
-- ROW ACCESS POLICY goes BEFORE the AS clause, not after the SELECT
CREATE VIEW protected_view
WITH ROW ACCESS POLICY my_policy ON (emp_id)
AS
SELECT emp_id, salary
FROM employees;