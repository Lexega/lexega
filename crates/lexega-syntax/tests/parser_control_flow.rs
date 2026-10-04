// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Control flow statement tests
// Tests for CASE, IF/ELSIF/ELSE, REPEAT, and other control flow constructs
use lexega_syntax::lexer::tokenize;
use lexega_syntax::parse_sql;

// CASE statement tests

#[test]
fn test_simple_case_in_procedure() {
    let src = r#"
CREATE PROCEDURE test_case()
RETURNS VARCHAR
AS
BEGIN
    CASE
        WHEN 1 < 2 THEN
            RETURN 'yes';
    END CASE;
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse simple CASE in procedure");
}

#[test]
fn test_case_with_multiple_when_branches() {
    let src = r#"
CREATE OR REPLACE PROCEDURE categorize_order(order_total NUMBER)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    category VARCHAR;
    discount_pct NUMBER DEFAULT 0;
BEGIN
    CASE
        WHEN order_total < 100 THEN
            LET category := 'SMALL';
            LET discount_pct := 0;
        WHEN order_total < 500 THEN
            LET category := 'MEDIUM';
            LET discount_pct := 5;
        WHEN order_total < 1000 THEN
            LET category := 'LARGE';
            LET discount_pct := 10;
        ELSE
            LET category := 'ENTERPRISE';
            LET discount_pct := 15;
    END CASE;
    
    RETURN category || ' order with ' || discount_pct || '% discount';
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CASE with multiple WHEN branches"
    );
}

#[test]
fn test_case_simplified() {
    let src = r#"
CREATE PROCEDURE categorize_order(order_total NUMBER)
RETURNS VARCHAR
AS
BEGIN
    CASE
        WHEN order_total < 100 THEN
            RETURN 'SMALL';
        ELSE
            RETURN 'LARGE';
    END CASE;
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse simplified CASE");
}

#[test]
fn test_case_with_declare_and_multiple_statements() {
    let src = r#"
CREATE PROCEDURE test_proc()
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    x VARCHAR;
BEGIN
    CASE
        WHEN 1 < 2 THEN
            LET x := 'a';
            LET x := x || 'b';
        ELSE
            LET x := 'c';
    END CASE;
    RETURN x;
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CASE with DECLARE and multiple statements"
    );
}

#[test]
fn test_case_with_four_when_clauses() {
    let src = r#"
CREATE PROCEDURE test_proc()
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    x VARCHAR;
    y NUMBER DEFAULT 0;
BEGIN
    CASE
        WHEN 1 < 100 THEN
            LET x := 'a';
            LET y := 1;
        WHEN 1 < 500 THEN
            LET x := 'b';
            LET y := 2;
        WHEN 1 < 1000 THEN
            LET x := 'c';
            LET y := 3;
        ELSE
            LET x := 'd';
            LET y := 4;
    END CASE;
    RETURN x;
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CASE with four WHEN clauses"
    );
}

#[test]
fn test_case_with_complex_return_expression() {
    let src = r#"
CREATE PROCEDURE test_proc()
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    x VARCHAR;
    y NUMBER DEFAULT 0;
BEGIN
    CASE
        WHEN 1 < 100 THEN
            LET x := 'a';
            LET y := 1;
        ELSE
            LET x := 'd';
            LET y := 4;
    END CASE;
    RETURN x || ' value ' || y || ' percent';
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CASE with complex RETURN expression"
    );
}

#[test]
fn test_simple_case_with_multiple_statements_in_block() {
    let src = r#"
BEGIN
    CASE
        WHEN x < 10 THEN
            LET a := 1;
        ELSE
            LET a := 2;
    END CASE;
    RETURN a;
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse simple CASE in block");
}

// RETURN with expressions

#[test]
fn test_return_with_simple_concat() {
    let src = r#"
BEGIN
    RETURN 'a' || 'b';
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse RETURN with simple concat");
}

#[test]
fn test_return_with_multiple_concat() {
    let src = r#"
BEGIN
    RETURN 'a' || ' b' || ' c';
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse RETURN with multiple concat"
    );
}

#[test]
fn test_return_with_variable_concat() {
    let src = r#"
DECLARE
    x VARCHAR;
BEGIN
    LET x := 'test';
    RETURN x || ' suffix';
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse RETURN with variable concat"
    );
}

// REPEAT loop tests

#[test]
fn test_simple_repeat_loop() {
    let src = r#"
BEGIN
    REPEAT
        LET x := 1;
    UNTIL (x > 0)
    END REPEAT;
END;
"#;
    let _tokens = tokenize(src).tokens;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse simple REPEAT loop");
}
