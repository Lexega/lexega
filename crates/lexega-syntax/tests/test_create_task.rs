// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CREATE TASK statement parsing
//!
//! Verifies that CREATE TASK statements are correctly parsed and formatted.

use lexega_syntax::{format_sql, verify_formatting_safe};

/// Test basic CREATE TASK parsing
#[test]
fn test_create_task_basic() {
    let sql = "CREATE TASK my_task AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with WAREHOUSE
#[test]
fn test_create_task_warehouse() {
    let sql = "CREATE TASK my_task WAREHOUSE = compute_wh AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE OR REPLACE TASK
#[test]
fn test_create_or_replace_task() {
    let sql = "CREATE OR REPLACE TASK my_task WAREHOUSE = wh AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK IF NOT EXISTS
#[test]
fn test_create_task_if_not_exists() {
    let sql = "CREATE TASK IF NOT EXISTS my_task AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with SCHEDULE
#[test]
fn test_create_task_schedule() {
    let sql = "CREATE TASK my_task SCHEDULE = '5 MINUTES' AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with CRON schedule
#[test]
fn test_create_task_cron() {
    let sql = "CREATE TASK my_task SCHEDULE = 'USING CRON 0 9 * * * UTC' AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with AFTER (predecessor task)
#[test]
fn test_create_task_after() {
    let sql = "CREATE TASK my_task AFTER parent_task AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with multiple AFTER tasks
#[test]
fn test_create_task_after_multiple() {
    let sql = "CREATE TASK my_task AFTER task1, task2, task3 AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with WHEN condition
#[test]
fn test_create_task_when() {
    let sql = "CREATE TASK my_task WHEN SYSTEM$STREAM_HAS_DATA('mystream') AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with EXECUTE AS OWNER
#[test]
fn test_create_task_execute_as_owner() {
    let sql = "CREATE TASK my_task EXECUTE AS OWNER AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with EXECUTE AS CALLER
#[test]
fn test_create_task_execute_as_caller() {
    let sql = "CREATE TASK my_task EXECUTE AS CALLER AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK CLONE
#[test]
fn test_create_task_clone() {
    let sql = "CREATE TASK my_clone CLONE source_task;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with WITH TAG
#[test]
fn test_create_task_with_tag() {
    let sql = "CREATE TASK my_task WITH TAG (cost_center = 'sales') AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with COMMENT
#[test]
fn test_create_task_comment() {
    let sql = "CREATE TASK my_task COMMENT = 'Daily ETL task' AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with many properties
#[test]
fn test_create_task_comprehensive() {
    let sql = r#"CREATE OR REPLACE TASK db.schema.my_task
  WAREHOUSE = compute_wh
  SCHEDULE = '5 MINUTES'
  ALLOW_OVERLAPPING_EXECUTION = FALSE
  USER_TASK_TIMEOUT_MS = 3600000
  SUSPEND_TASK_AFTER_NUM_FAILURES = 3
  COMMENT = 'Test task'
AS
  INSERT INTO target SELECT * FROM source;"#;
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with qualified name
#[test]
fn test_create_task_qualified_name() {
    let sql = "CREATE TASK mydb.myschema.my_task AS SELECT 1;";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}

/// Test CREATE TASK with stored procedure call
#[test]
fn test_create_task_call() {
    let sql = "CREATE TASK my_task AS CALL my_procedure();";
    let formatted = format_sql(sql).expect("should parse");
    verify_formatting_safe(sql, &formatted).expect("should preserve tokens");
}
