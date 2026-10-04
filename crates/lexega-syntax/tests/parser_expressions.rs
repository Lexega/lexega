// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Expression parsing tests
// Tests for IS NULL, CASE expressions, and other complex expressions
use lexega_syntax::parse_sql;

// IS NULL / IS NOT NULL expression tests

#[test]
fn test_is_null_in_if_condition() {
    let src = r#"
CREATE OR REPLACE FUNCTION test_func(years INTEGER)
RETURNS NUMBER
LANGUAGE SQL
AS
BEGIN
    IF (years IS NULL) THEN
        RETURN 0;
    END IF;
    
    RETURN years;
END;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse IS NULL in IF condition");
}

#[test]
fn test_is_null_in_complex_function() {
    let src = r#"
CREATE OR REPLACE FUNCTION calculate_bonus(employee_id INTEGER, base_salary NUMBER)
RETURNS NUMBER
LANGUAGE SQL
AS
DECLARE
    years_of_service INTEGER;
    performance_rating NUMBER;
    bonus NUMBER DEFAULT 0;
    bonus_pct NUMBER;
BEGIN
    -- Get employee info
    SELECT DATEDIFF(year, hire_date, CURRENT_DATE()), last_performance_rating
    INTO years_of_service, performance_rating
    FROM employees
    WHERE id = :employee_id;
    
    -- Check for NULL
    IF (years_of_service IS NULL) THEN
        RETURN 0;
    END IF;
    
    -- Calculate bonus percentage
    CASE
        WHEN years_of_service < 2 THEN
            LET bonus_pct := 0.03;
        WHEN years_of_service < 5 THEN
            LET bonus_pct := 0.05;
        WHEN years_of_service < 10 THEN
            LET bonus_pct := 0.08;
        ELSE
            LET bonus_pct := 0.12;
    END CASE;
    
    -- Adjust for performance
    IF (performance_rating >= 4.5) THEN
        LET bonus_pct := bonus_pct * 1.5;
    ELSIF (performance_rating >= 3.5) THEN
        LET bonus_pct := bonus_pct * 1.2;
    ELSIF (performance_rating < 2.0) THEN
        LET bonus_pct := bonus_pct * 0.5;
    END IF;
    
    LET bonus := base_salary * bonus_pct;
    
    -- Cap bonus at 20% of salary
    IF (bonus > base_salary * 0.20) THEN
        LET bonus := base_salary * 0.20;
    END IF;
    
    RETURN bonus;
END;
"#;

    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse IS NULL in complex function"
    );
}
