// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for ALTER TASK and DROP TASK parsing and formatting

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format successfully");
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
    formatted
}

// ============================================================================
// DROP TASK Tests
// ============================================================================

#[test]
fn test_drop_task_simple() {
    let sql = "DROP TASK my_task;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_drop_task_if_exists() {
    let sql = "DROP TASK IF EXISTS my_task;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_drop_task_qualified_name() {
    let sql = "DROP TASK my_db.my_schema.my_task;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_drop_task_if_exists_qualified() {
    let sql = "DROP TASK IF EXISTS my_db.my_schema.my_task;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - Resume/Suspend Tests
// ============================================================================

#[test]
fn test_alter_task_resume() {
    let sql = "ALTER TASK my_task RESUME;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_suspend() {
    let sql = "ALTER TASK my_task SUSPEND;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_resume_if_exists() {
    let sql = "ALTER TASK IF EXISTS my_task RESUME;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_suspend_qualified() {
    let sql = "ALTER TASK my_db.my_schema.my_task SUSPEND;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - Dependency Tests (ADD AFTER / REMOVE AFTER)
// ============================================================================

#[test]
fn test_alter_task_add_after() {
    let sql = "ALTER TASK my_task ADD AFTER parent_task;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_add_after_multiple() {
    let sql = "ALTER TASK my_task ADD AFTER parent1, parent2, parent3;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_remove_after() {
    let sql = "ALTER TASK my_task REMOVE AFTER parent_task;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_remove_after_multiple() {
    let sql = "ALTER TASK my_task REMOVE AFTER parent1, parent2;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - SET Property Tests
// ============================================================================

#[test]
fn test_alter_task_set_warehouse() {
    let sql = "ALTER TASK my_task SET WAREHOUSE = my_wh;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_set_schedule() {
    let sql = "ALTER TASK my_task SET SCHEDULE = 'USING CRON 0 * * * * UTC';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_set_user_task_managed_initial_warehouse_size() {
    let sql = "ALTER TASK my_task SET USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE = 'XSMALL';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_set_suspend_task_after_num_failures() {
    let sql = "ALTER TASK my_task SET SUSPEND_TASK_AFTER_NUM_FAILURES = 10;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_set_user_task_timeout_ms() {
    let sql = "ALTER TASK my_task SET USER_TASK_TIMEOUT_MS = 3600000;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_set_comment() {
    let sql = "ALTER TASK my_task SET COMMENT = 'This is my task';";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - SET TAG Tests
// ============================================================================

#[test]
fn test_alter_task_set_tag() {
    let sql = "ALTER TASK my_task SET TAG cost_center = 'marketing';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_set_tag_multiple() {
    let sql = "ALTER TASK my_task SET TAG cost_center = 'marketing', owner = 'team_a';";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - UNSET Tests
// ============================================================================

#[test]
fn test_alter_task_unset_warehouse() {
    let sql = "ALTER TASK my_task UNSET WAREHOUSE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_unset_schedule() {
    let sql = "ALTER TASK my_task UNSET SCHEDULE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_unset_multiple() {
    let sql = "ALTER TASK my_task UNSET WAREHOUSE, SCHEDULE, COMMENT;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - UNSET TAG Tests
// ============================================================================

#[test]
fn test_alter_task_unset_tag() {
    let sql = "ALTER TASK my_task UNSET TAG cost_center;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_unset_tag_multiple() {
    let sql = "ALTER TASK my_task UNSET TAG cost_center, owner;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - MODIFY Tests
// ============================================================================

#[test]
fn test_alter_task_modify_as() {
    let sql = "ALTER TASK my_task MODIFY AS INSERT INTO t1 SELECT * FROM t2;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_modify_when() {
    let sql = "ALTER TASK my_task MODIFY WHEN SYSTEM$STREAM_HAS_DATA('my_stream');";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - REMOVE WHEN Tests
// ============================================================================

#[test]
fn test_alter_task_remove_when() {
    let sql = "ALTER TASK my_task REMOVE WHEN;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER TASK - Finalize Tests
// ============================================================================

#[test]
fn test_alter_task_set_finalize() {
    let sql = "ALTER TASK my_task SET FINALIZE = my_finalizer;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_unset_finalize() {
    let sql = "ALTER TASK my_task UNSET FINALIZE;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// Multiple Statement Tests
// ============================================================================

#[test]
fn test_multiple_task_statements() {
    let sql = r#"
DROP TASK IF EXISTS old_task;
ALTER TASK my_task RESUME;
ALTER TASK my_task SET WAREHOUSE = new_wh;
"#;
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_task_complex_workflow() {
    let sql = r#"
ALTER TASK my_task SUSPEND;
ALTER TASK my_task SET WAREHOUSE = my_wh;
ALTER TASK my_task SET SCHEDULE = '5 MINUTE';
ALTER TASK my_task ADD AFTER parent_task;
ALTER TASK my_task SET TAG owner = 'data_team';
ALTER TASK my_task RESUME;
"#;
    let _ = format_and_verify(sql);
}
