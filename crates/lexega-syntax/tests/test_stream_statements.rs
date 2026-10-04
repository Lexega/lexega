// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CREATE/ALTER/DROP STREAM statement parsing and formatting
//!
//! These tests verify:
//! - Basic parsing of all STREAM statement variants
//! - Semantic preservation (formatted output matches original tokens)
//! - Multi-statement handling (verifies NodeId collision bugs are prevented)

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format successfully");
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
    formatted
}

// ============================================================================
// CREATE STREAM - Basic Tests
// ============================================================================

#[test]
fn test_create_stream_basic_on_table() {
    let sql = "CREATE STREAM mystream ON TABLE mytable;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_qualified_names() {
    let sql = "CREATE STREAM mydb.myschema.mystream ON TABLE mydb.myschema.mytable;";
    format_and_verify(sql);
}

#[test]
fn test_create_or_replace_stream() {
    let sql = "CREATE OR REPLACE STREAM mystream ON TABLE mytable;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_if_not_exists() {
    let sql = "CREATE STREAM IF NOT EXISTS mystream ON TABLE mytable;";
    format_and_verify(sql);
}

// ============================================================================
// CREATE STREAM - Source Types
// ============================================================================

#[test]
fn test_create_stream_on_event_table() {
    let sql = "CREATE STREAM event_stream ON EVENT TABLE my_event_table;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_on_external_table() {
    let sql = "CREATE STREAM ext_stream ON EXTERNAL TABLE my_ext_table;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_on_stage() {
    let sql = "CREATE STREAM dirtable_stream ON STAGE mystage;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_on_dynamic_table() {
    let sql = "CREATE STREAM dyn_stream ON DYNAMIC TABLE my_dynamic_table;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_on_view() {
    let sql = "CREATE STREAM view_stream ON VIEW myview;";
    format_and_verify(sql);
}

// ============================================================================
// CREATE STREAM - Options
// ============================================================================

#[test]
fn test_create_stream_with_tag() {
    let sql = "CREATE STREAM tagged_stream WITH TAG (environment = 'production') ON TABLE mytable;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_copy_grants() {
    let sql = "CREATE OR REPLACE STREAM mystream COPY GRANTS ON TABLE mytable;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_append_only() {
    let sql = "CREATE STREAM append_stream ON TABLE mytable APPEND_ONLY = TRUE;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_show_initial_rows() {
    let sql = "CREATE STREAM init_stream ON TABLE mytable SHOW_INITIAL_ROWS = TRUE;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_insert_only() {
    let sql = "CREATE STREAM ext_stream ON EXTERNAL TABLE my_ext_table INSERT_ONLY = TRUE;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_with_comment() {
    let sql = "CREATE STREAM commented_stream ON TABLE mytable COMMENT = 'This is a stream';";
    format_and_verify(sql);
}

// ============================================================================
// CREATE STREAM - Time Travel
// ============================================================================

#[test]
fn test_create_stream_at_timestamp() {
    let sql = "CREATE STREAM mystream ON TABLE mytable AT (TIMESTAMP => '2024-01-01 12:00:00'::TIMESTAMP);";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_at_offset() {
    let sql = "CREATE STREAM mystream ON TABLE mytable AT (OFFSET => -60*5);";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_at_statement() {
    let sql = "CREATE STREAM mystream ON TABLE mytable AT (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726');";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_at_stream() {
    let sql = "CREATE STREAM mystream ON TABLE mytable AT (STREAM => 'oldstream');";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_before_timestamp() {
    let sql =
        "CREATE STREAM mystream ON TABLE mytable BEFORE (TIMESTAMP => TO_TIMESTAMP(40*365*86400));";
    format_and_verify(sql);
}

// ============================================================================
// CREATE STREAM - Clone
// ============================================================================

#[test]
fn test_create_stream_clone() {
    let sql = "CREATE STREAM new_stream CLONE source_stream;";
    format_and_verify(sql);
}

#[test]
fn test_create_stream_clone_copy_grants() {
    let sql = "CREATE OR REPLACE STREAM new_stream CLONE source_stream COPY GRANTS;";
    format_and_verify(sql);
}

// ============================================================================
// ALTER STREAM
// ============================================================================

#[test]
fn test_alter_stream_set_comment() {
    let sql = "ALTER STREAM mystream SET COMMENT = 'Updated comment';";
    format_and_verify(sql);
}

#[test]
fn test_alter_stream_if_exists_set_comment() {
    let sql = "ALTER STREAM IF EXISTS mystream SET COMMENT = 'New comment';";
    format_and_verify(sql);
}

#[test]
fn test_alter_stream_set_tag() {
    let sql = "ALTER STREAM mystream SET TAG environment = 'production';";
    format_and_verify(sql);
}

#[test]
fn test_alter_stream_set_multiple_tags() {
    let sql = "ALTER STREAM mystream SET TAG dept = 'finance', owner = 'data_team';";
    format_and_verify(sql);
}

#[test]
fn test_alter_stream_unset_tag() {
    let sql = "ALTER STREAM mystream UNSET TAG environment;";
    format_and_verify(sql);
}

#[test]
fn test_alter_stream_unset_comment() {
    let sql = "ALTER STREAM mystream UNSET COMMENT;";
    format_and_verify(sql);
}

// ============================================================================
// DROP STREAM
// ============================================================================

#[test]
fn test_drop_stream_basic() {
    let sql = "DROP STREAM mystream;";
    format_and_verify(sql);
}

#[test]
fn test_drop_stream_if_exists() {
    let sql = "DROP STREAM IF EXISTS mystream;";
    format_and_verify(sql);
}

#[test]
fn test_drop_stream_qualified_name() {
    let sql = "DROP STREAM mydb.myschema.mystream;";
    format_and_verify(sql);
}

// ============================================================================
// Multi-Statement Tests (Critical for NodeId collision detection)
// ============================================================================

#[test]
fn test_multi_stream_statements() {
    // CRITICAL: This test catches NodeId collision bugs
    let sql = r#"
CREATE STREAM stream1 ON TABLE table1;
CREATE STREAM stream2 ON TABLE table2;
ALTER STREAM stream1 SET COMMENT = 'First stream';
ALTER STREAM stream2 SET TAG env = 'prod';
DROP STREAM IF EXISTS old_stream;
"#;
    format_and_verify(sql);
}

#[test]
fn test_mixed_stream_and_other_statements() {
    let sql = r#"
CREATE TABLE mytable (id INT);
CREATE STREAM mystream ON TABLE mytable;
ALTER STREAM mystream SET COMMENT = 'Tracking changes';
SELECT * FROM mystream;
DROP STREAM mystream;
DROP TABLE mytable;
"#;
    format_and_verify(sql);
}
