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

#[test]
fn a_collation_named_by_a_name_or_a_string_is_read() {
    use lexega_syntax::dialect::{databricks, mssql, mysql, postgres, snowflake};
    use lexega_syntax::{
        format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect,
        FormatterConfig,
    };

    for (dialect, sql) in [
        (mssql(), "SELECT id FROM t WHERE c COLLATE Latin1_General_CS_AS = 'x'"),
        (mssql(), "SELECT c COLLATE Latin1_General_CI_AS AS n FROM t"),
        (
            mssql(),
            "SELECT a.id FROM a JOIN b ON a.c COLLATE DATABASE_DEFAULT = b.c COLLATE DATABASE_DEFAULT",
        ),
        (mysql(), "SELECT id FROM t WHERE c = 'x' COLLATE utf8mb4_bin"),
        (mysql(), "SELECT id FROM t WHERE c = _utf8mb4'x' COLLATE utf8mb4_bin"),
        (postgres(), "SELECT id FROM t ORDER BY c COLLATE \"C\""),
        (databricks(), "SELECT id FROM t WHERE c COLLATE UTF8_LCASE = 'x'"),
        (snowflake(), "SELECT id FROM t WHERE c COLLATE 'en-ci' = 'x'"),
    ] {
        let script = parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
        assert_eq!(script.stmts.len(), 1, "{sql}: {:?}", script.stmts);
        let tree = format!("{:?}", script.stmts[0]);
        assert!(tree.contains("Collate {"), "{sql}: {tree}");
        assert!(!tree.contains("Error {"), "{sql}: {tree}");
        let config = FormatterConfig { dialect, ..Default::default() };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{sql} -> {formatted}: {e}"));
    }
}

/// The elements `row_elements` reads of the one item `SELECT <expr>` projects.
fn row_element_count(expr: &str) -> Option<usize> {
    use lexega_syntax::ast::{AstProjectionKind, AstStmt, ProjectionItemKind};
    let sql = format!("SELECT {expr}");
    let script = parse_sql(&sql).expect("parses");
    let Some(AstStmt::Select(select)) = script.stmts.first() else {
        panic!("{sql}: not a SELECT");
    };
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("{sql}: no column list");
    };
    let ProjectionItemKind::SelectItem(item) = &items[0].kind else {
        panic!("{sql}: no select item");
    };
    item.expr.row_elements(&sql).map(|elements| elements.len())
}

#[test]
fn a_row_is_a_parenthesised_list_or_a_row_call_without_modifiers() {
    for (expr, expected) in [
        ("(a, b)", Some(2)),
        ("ROW(a, b, 'c')", Some(3)),
        ("row(a, b)", Some(2)),
        ("ROW(DISTINCT a, b)", None),
        ("ROW(a => 1, b)", None),
        ("COALESCE(a, b)", None),
        ("a", None),
    ] {
        assert_eq!(row_element_count(expr), expected, "{expr}");
    }
}
