-- Test WITH ROW ACCESS POLICY on view (correct syntax - before AS clause)
CREATE VIEW protected_view
WITH ROW ACCESS POLICY my_policy ON (emp_id)
AS
SELECT emp_id, salary
FROM employees;