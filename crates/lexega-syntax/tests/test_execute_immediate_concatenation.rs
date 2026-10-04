// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Test EXECUTE IMMEDIATE with concatenation and variables
//! from Snowflake documentation examples

use lexega_syntax::{format_sql, parse_stmt_from_str};

#[test]
fn test_execute_immediate_with_variable_and_using() {
    let sql = r#"
CREATE OR REPLACE PROCEDURE min_max_invoices_sp(minimum_price NUMBER(12,2),maximum_price NUMBER(12,2)) RETURNS TABLE (id INTEGER, price NUMBER(12, 2))
  LANGUAGE SQL
AS
$$
DECLARE
  rs RESULTSET;
  query VARCHAR DEFAULT 'SELECT * FROM invoices WHERE price > ? AND price < ?';
BEGIN
  rs := (EXECUTE IMMEDIATE :query USING (minimum_price, maximum_price));
  RETURN TABLE(rs);
END;
$$;
"#;

    let _stmt = parse_stmt_from_str(sql).expect("Should parse EXECUTE IMMEDIATE with :variable");
    let formatted = format_sql(sql).expect("Should format successfully");

    // Verify key parts are in the formatted output
    assert!(formatted.contains("EXECUTE IMMEDIATE :query"));
    assert!(formatted.contains("USING (minimum_price, maximum_price)"));
}

#[test]
fn test_execute_immediate_with_concatenation() {
    let sql = r#"
CREATE PROCEDURE execute_immediate_local_variable()
RETURNS VARCHAR
AS
$$
DECLARE
  v1 VARCHAR DEFAULT 'CREATE TABLE temporary1 (i INTEGER)';
  v2 VARCHAR DEFAULT 'INSERT INTO temporary1 (i) VALUES (76)';
  result INTEGER DEFAULT 0;
BEGIN
  EXECUTE IMMEDIATE v1;
  EXECUTE IMMEDIATE v2  ||  ',(80)'  ||  ',(84)';
  result := (SELECT SUM(i) FROM temporary1);
  RETURN result::VARCHAR;
END;
$$;
"#;

    let _stmt =
        parse_stmt_from_str(sql).expect("Should parse EXECUTE IMMEDIATE with concatenation");
    let formatted = format_sql(sql).expect("Should format successfully");

    // Verify key parts are in the formatted output
    assert!(formatted.contains("EXECUTE IMMEDIATE v1"));
    assert!(formatted.contains("EXECUTE IMMEDIATE v2"));
    assert!(formatted.contains("||"));
    assert!(formatted.contains("',(80)'"));
    assert!(formatted.contains("',(84)'"));
}

#[test]
fn test_execute_immediate_simple_variable() {
    let sql = r#"
CREATE PROCEDURE test_proc()
RETURNS VARCHAR
AS
$$
DECLARE
  v1 VARCHAR DEFAULT 'SELECT 1';
BEGIN
  EXECUTE IMMEDIATE v1;
END;
$$;
"#;

    let _stmt =
        parse_stmt_from_str(sql).expect("Should parse EXECUTE IMMEDIATE with simple variable");
    let formatted = format_sql(sql).expect("Should format successfully");

    assert!(formatted.contains("EXECUTE IMMEDIATE v1"));
}

#[test]
fn test_execute_immediate_scripting_var_ref() {
    let sql = r#"
CREATE PROCEDURE test_proc()
RETURNS VARCHAR
AS
$$
DECLARE
  query VARCHAR DEFAULT 'SELECT 1';
BEGIN
  EXECUTE IMMEDIATE :query;
END;
$$;
"#;

    let _stmt = parse_stmt_from_str(sql).expect("Should parse EXECUTE IMMEDIATE with :variable");
    let formatted = format_sql(sql).expect("Should format successfully");

    assert!(formatted.contains("EXECUTE IMMEDIATE :query"));
}

#[test]
fn test_execute_immediate_complex_concatenation() {
    let sql = r#"
CREATE PROCEDURE test_proc()
RETURNS VARCHAR
AS
$$
DECLARE
  base_query VARCHAR DEFAULT 'SELECT * FROM ';
  table_name VARCHAR DEFAULT 'users';
BEGIN
  EXECUTE IMMEDIATE base_query || table_name || ' WHERE id > ' || '100';
END;
$$;
"#;

    let _stmt = parse_stmt_from_str(sql)
        .expect("Should parse EXECUTE IMMEDIATE with complex concatenation");
    let formatted = format_sql(sql).expect("Should format successfully");

    assert!(formatted.contains("EXECUTE IMMEDIATE"));
    assert!(formatted.contains("||"));
}
