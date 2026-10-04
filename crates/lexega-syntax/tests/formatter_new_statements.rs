// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// //! Formatter tests for EXECUTE IMMEDIATE, transaction control, and pipe chain statements.
// //!
// //! Note: EXECUTE IMMEDIATE, BEGIN TRANSACTION, COMMIT, and ROLLBACK are scripting statements
// //! that only exist inside BEGIN...END blocks in Snowflake Scripting.

// use lexega_syntax::{format_sql, parse_sql, Formatter, FormatterConfig};

// // ============================================================================
// // EXECUTE IMMEDIATE Tests
// // ============================================================================

// #[test]
// fn test_execute_immediate_simple() {
//     let sql = r#"
// BEGIN
//     EXECUTE IMMEDIATE 'SELECT * FROM my_table';
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("EXECUTE IMMEDIATE"));
//     assert!(result.contains("'SELECT * FROM my_table'"));
// }

// #[test]
// fn test_execute_immediate_with_variable() {
//     let sql = r#"
// BEGIN
//     EXECUTE IMMEDIATE :sql_stmt;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("EXECUTE IMMEDIATE"));
//     assert!(result.contains(":sql_stmt"));
// }

// #[test]
// fn test_execute_immediate_with_session_variable() {
//     let sql = r#"
// BEGIN
//     EXECUTE IMMEDIATE $stmt;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("EXECUTE IMMEDIATE"));
//     assert!(result.contains("$stmt"));
// }

// #[test]
// fn test_execute_immediate_with_using_clause() {
//     let sql = r#"
// BEGIN
//     EXECUTE IMMEDIATE :query USING (table_name, min_value);
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("EXECUTE IMMEDIATE"));
//     assert!(result.contains(":query"));
//     assert!(result.contains("USING"));
//     assert!(result.contains("table_name") && result.contains("min_value"));
// }

// #[test]
// fn test_execute_immediate_with_using_multiple_binds() {
//     let sql = r#"
// BEGIN
//     EXECUTE IMMEDIATE 'SELECT * FROM invoices WHERE price > ? AND price < ?'
//         USING (minimum_price, maximum_price);
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("EXECUTE IMMEDIATE"));
//     assert!(result.contains("USING"));
//     assert!(result.contains("minimum_price") && result.contains("maximum_price"));
// }

// // ============================================================================
// // Transaction Control Tests
// // ============================================================================

// #[test]
// fn test_begin_transaction_simple() {
//     let sql = r#"
// BEGIN
//     BEGIN TRANSACTION;
//     INSERT INTO test VALUES (1);
//     COMMIT;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("BEGIN TRANSACTION") || result.contains("BEGIN"));
//     assert!(result.contains("COMMIT"));
// }

// #[test]
// fn test_begin_transaction_with_name() {
//     let sql = r#"
// BEGIN
//     BEGIN TRANSACTION NAME my_transaction;
//     UPDATE test SET col = 1;
//     COMMIT;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("BEGIN"));
//     assert!(result.contains("NAME"));
//     assert!(result.contains("my_transaction"));
// }

// #[test]
// fn test_commit_and_rollback() {
//     let sql = r#"
// BEGIN
//     BEGIN TRANSACTION;
//     IF (condition = TRUE) THEN
//         COMMIT;
//     ELSE
//         ROLLBACK;
//     END IF;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("COMMIT"));
//     assert!(result.contains("ROLLBACK"));
// }

// #[test]
// fn test_transaction_with_work_keyword() {
//     let sql = r#"
// BEGIN
//     BEGIN WORK;
//     INSERT INTO test VALUES (1);
//     COMMIT WORK;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("BEGIN"));
//     assert!(result.contains("WORK") || result.contains("TRANSACTION"));
//     assert!(result.contains("COMMIT"));
// }

// // ============================================================================
// // Pipe Chain Tests
// // Note: Pipe chains use parse_sql() + manual formatting
// // ============================================================================

// #[test]
// fn test_pipe_chain_simple_selects() {
//     let sql = "SELECT 1 ->> SELECT * FROM $1";
//     let stmt = parse_sql(sql).expect("parse failed");

//     let config = FormatterConfig::default();
//     let formatter = Formatter::new(&config, sql);
//     let result = formatter.format_stmt(&stmt).expect("format failed");

//     assert!(result.contains("SELECT"));
//     assert!(result.contains("->>"));
//     assert!(result.contains("$1"));
// }

// #[test]
// fn test_pipe_chain_show_and_select() {
//     let sql = "SHOW TABLES ->> SELECT \"name\" FROM $1";
//     let stmt = parse_sql(sql).expect("parse failed");

//     let config = FormatterConfig::default();
//     let formatter = Formatter::new(&config, sql);
//     let result = formatter.format_stmt(&stmt).expect("format failed");

//     assert!(result.contains("SHOW"));
//     assert!(result.contains("TABLES"));
//     assert!(result.contains("->>"));
//     assert!(result.contains("SELECT"));
// }

// #[test]
// fn test_pipe_chain_three_stages() {
//     let sql = "SELECT * FROM dept WHERE dname = 'SALES' ->> SELECT * FROM emp WHERE deptno IN (SELECT deptno FROM $1) ->> SELECT ename, sal FROM $1";
//     let stmt = parse_sql(sql).expect("parse failed");

//     let config = FormatterConfig::default();
//     let formatter = Formatter::new(&config, sql);
//     let result = formatter.format_stmt(&stmt).expect("format failed");

//     // Should have two pipe operators
//     let pipe_count = result.matches("->>").count();
//     assert_eq!(pipe_count, 2, "Expected 2 pipe operators");

//     assert!(result.contains("SELECT"));
// }

// #[test]
// fn test_pipe_chain_with_positional_refs() {
//     let sql = "SELECT 1 AS col ->> SELECT col FROM $1 ->> SELECT * FROM $2";
//     let stmt = parse_sql(sql).expect("parse failed");

//     let config = FormatterConfig::default();
//     let formatter = Formatter::new(&config, sql);
//     let result = formatter.format_stmt(&stmt).expect("format failed");

//     // Should preserve positional references
//     assert!(result.contains("$1"));
//     assert!(result.contains("$2"));
// }

// #[test]
// fn test_pipe_chain_truncate_and_select() {
//     let sql = "TRUNCATE TABLE temp_data ->> SELECT 'truncated' AS status";
//     let stmt = parse_sql(sql).expect("parse failed");

//     let config = FormatterConfig::default();
//     let formatter = Formatter::new(&config, sql);
//     let result = formatter.format_stmt(&stmt).expect("format failed");

//     assert!(result.contains("TRUNCATE"));
//     assert!(result.contains("->>"));
//     assert!(result.contains("SELECT"));
// }

// #[test]
// fn test_pipe_chain_with_insert() {
//     let sql = "SELECT * FROM source_table ->> INSERT INTO target_table SELECT * FROM $1";
//     let stmt = parse_sql(sql).expect("parse failed");

//     let config = FormatterConfig::default();
//     let formatter = Formatter::new(&config, sql);
//     let result = formatter.format_stmt(&stmt).expect("format failed");

//     assert!(result.contains("SELECT"));
//     assert!(result.contains("->>"));
//     assert!(result.contains("INSERT"));
// }

// #[test]
// fn test_pipe_chain_formatting() {
//     let sql = "SELECT 1 ->> SELECT * FROM $1 ->> SELECT * FROM $2";
//     let stmt = parse_sql(sql).expect("parse failed");

//     let config = FormatterConfig::default();
//     let formatter = Formatter::new(&config, sql);
//     let result = formatter.format_stmt(&stmt).expect("format failed");

//     let pipe_count = result.matches("->>").count();
//     assert_eq!(pipe_count, 2, "Should have 2 pipe operators");

//     // Formatted output should contain pipe operators
//     assert!(result.contains("->>"));
// }

// // ============================================================================
// // Combined/Integration Tests
// // ============================================================================

// #[test]
// fn test_execute_immediate_in_transaction() {
//     let sql = r#"
// BEGIN
//     BEGIN TRANSACTION;
//     EXECUTE IMMEDIATE 'INSERT INTO test VALUES (1)';
//     COMMIT;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("BEGIN TRANSACTION") || result.contains("BEGIN"));
//     assert!(result.contains("EXECUTE IMMEDIATE"));
//     assert!(result.contains("COMMIT"));
// }

// #[test]
// fn test_complex_scripting_block() {
//     let sql = r#"
// BEGIN
//     LET sql_stmt := 'SELECT COUNT(*) FROM orders';
//     BEGIN TRANSACTION NAME process_orders;
//     EXECUTE IMMEDIATE :sql_stmt;
//     IF (result > 0) THEN
//         COMMIT WORK;
//     ELSE
//         ROLLBACK WORK;
//     END IF;
// END;
// "#;
//     let result = format_sql(sql).expect("format failed");

//     assert!(result.contains("BEGIN"));
//     assert!(result.contains("EXECUTE IMMEDIATE"));
//     assert!(result.contains("COMMIT"));
//     assert!(result.contains("ROLLBACK"));
// }
