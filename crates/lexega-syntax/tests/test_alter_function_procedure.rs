// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for ALTER FUNCTION and ALTER PROCEDURE parsing and formatting

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

// ============================================================================
// Helper Function
// ============================================================================

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format successfully");
    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");
    formatted
}

// ============================================================================
// ALTER FUNCTION - Basic RENAME TO
// ============================================================================

#[test]
fn test_alter_function_rename_simple() {
    let sql = "ALTER FUNCTION my_func() RENAME TO new_func;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_rename_with_schema() {
    let sql = "ALTER FUNCTION myschema.my_func() RENAME TO myschema.new_func;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_rename_with_signature() {
    let sql = "ALTER FUNCTION my_func(INT, VARCHAR) RENAME TO new_func;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_rename_complex_signature() {
    let sql = "ALTER FUNCTION my_func(VARCHAR(100), NUMBER(10,2)) RENAME TO new_func;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_if_exists_rename() {
    let sql = "ALTER FUNCTION IF EXISTS my_func() RENAME TO new_func;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER FUNCTION - SET/UNSET SECURE
// ============================================================================

#[test]
fn test_alter_function_set_secure() {
    let sql = "ALTER FUNCTION my_func() SET SECURE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_unset_secure() {
    let sql = "ALTER FUNCTION my_func() UNSET SECURE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_secure_with_signature() {
    let sql = "ALTER FUNCTION my_func(INT) SET SECURE;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER FUNCTION - SET Properties
// ============================================================================

#[test]
fn test_alter_function_set_comment() {
    let sql = "ALTER FUNCTION my_func() SET COMMENT = 'Updated comment';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_log_level() {
    let sql = "ALTER FUNCTION my_func() SET LOG_LEVEL = 'DEBUG';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_trace_level() {
    let sql = "ALTER FUNCTION my_func() SET TRACE_LEVEL = 'ALWAYS';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_external_access_integrations() {
    let sql = "ALTER FUNCTION my_func() SET EXTERNAL_ACCESS_INTEGRATIONS = (my_integration);";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_secrets() {
    let sql = "ALTER FUNCTION my_func() SET SECRETS = ('secret1' = my_secret);";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER FUNCTION - UNSET Properties
// ============================================================================

#[test]
fn test_alter_function_unset_comment() {
    let sql = "ALTER FUNCTION my_func() UNSET COMMENT;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_unset_log_level() {
    let sql = "ALTER FUNCTION my_func() UNSET LOG_LEVEL;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_unset_trace_level() {
    let sql = "ALTER FUNCTION my_func() UNSET TRACE_LEVEL;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER FUNCTION - External Function Properties
// ============================================================================

#[test]
fn test_alter_function_set_api_integration() {
    let sql = "ALTER FUNCTION my_ext_func() SET API_INTEGRATION = my_api;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_headers() {
    let sql = "ALTER FUNCTION my_ext_func() SET HEADERS = ('Authorization' = 'Bearer token');";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_max_batch_rows() {
    let sql = "ALTER FUNCTION my_ext_func() SET MAX_BATCH_ROWS = 1000;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_compression() {
    let sql = "ALTER FUNCTION my_ext_func() SET COMPRESSION = 'GZIP';";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER FUNCTION - SET/UNSET TAG
// ============================================================================

#[test]
fn test_alter_function_set_tag() {
    let sql = "ALTER FUNCTION my_func() SET TAG my_tag = 'value';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_set_multiple_tags() {
    let sql = "ALTER FUNCTION my_func() SET TAG tag1 = 'v1', tag2 = 'v2';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_unset_tag() {
    let sql = "ALTER FUNCTION my_func() UNSET TAG my_tag;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER FUNCTION - Complex/Edge Cases
// ============================================================================

#[test]
fn test_alter_function_fully_qualified() {
    let sql = "ALTER FUNCTION db.schema.my_func(INT, VARCHAR, BOOLEAN) SET SECURE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_quoted_identifier() {
    let sql = r#"ALTER FUNCTION "My Function"() RENAME TO "New Function";"#;
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_array_type_in_signature() {
    let sql = "ALTER FUNCTION my_func(ARRAY) SET SECURE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_object_type_in_signature() {
    let sql = "ALTER FUNCTION my_func(OBJECT) SET SECURE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_function_variant_type_in_signature() {
    let sql = "ALTER FUNCTION my_func(VARIANT) SET SECURE;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER PROCEDURE - Basic RENAME TO
// ============================================================================

#[test]
fn test_alter_procedure_rename_simple() {
    let sql = "ALTER PROCEDURE my_proc() RENAME TO new_proc;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_rename_with_schema() {
    let sql = "ALTER PROCEDURE myschema.my_proc() RENAME TO myschema.new_proc;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_rename_with_signature() {
    let sql = "ALTER PROCEDURE my_proc(INT, VARCHAR) RENAME TO new_proc;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_if_exists_rename() {
    let sql = "ALTER PROCEDURE IF EXISTS my_proc() RENAME TO new_proc;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER PROCEDURE - EXECUTE AS
// ============================================================================

#[test]
fn test_alter_procedure_execute_as_owner() {
    let sql = "ALTER PROCEDURE my_proc() EXECUTE AS OWNER;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_execute_as_caller() {
    let sql = "ALTER PROCEDURE my_proc() EXECUTE AS CALLER;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_execute_as_restricted_caller() {
    let sql = "ALTER PROCEDURE my_proc() EXECUTE AS RESTRICTED CALLER;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_execute_as_with_signature() {
    let sql = "ALTER PROCEDURE my_proc(INT, VARCHAR) EXECUTE AS CALLER;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER PROCEDURE - SET/UNSET SECURE
// ============================================================================

#[test]
fn test_alter_procedure_set_secure() {
    let sql = "ALTER PROCEDURE my_proc() SET SECURE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_unset_secure() {
    let sql = "ALTER PROCEDURE my_proc() UNSET SECURE;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER PROCEDURE - SET/UNSET Properties
// ============================================================================

#[test]
fn test_alter_procedure_set_comment() {
    let sql = "ALTER PROCEDURE my_proc() SET COMMENT = 'Updated procedure';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_unset_comment() {
    let sql = "ALTER PROCEDURE my_proc() UNSET COMMENT;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_set_log_level() {
    let sql = "ALTER PROCEDURE my_proc() SET LOG_LEVEL = 'INFO';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_set_trace_level() {
    let sql = "ALTER PROCEDURE my_proc() SET TRACE_LEVEL = 'ON_EVENT';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_set_auto_event_logging() {
    let sql = "ALTER PROCEDURE my_proc() SET AUTO_EVENT_LOGGING = 'LOGGING';";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER PROCEDURE - SET/UNSET TAG
// ============================================================================

#[test]
fn test_alter_procedure_set_tag() {
    let sql = "ALTER PROCEDURE my_proc() SET TAG owner = 'team_a';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_set_multiple_tags() {
    let sql = "ALTER PROCEDURE my_proc() SET TAG tag1 = 'v1', tag2 = 'v2';";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_unset_tag() {
    let sql = "ALTER PROCEDURE my_proc() UNSET TAG old_tag;";
    let _ = format_and_verify(sql);
}

// ============================================================================
// ALTER PROCEDURE - Complex/Edge Cases
// ============================================================================

#[test]
fn test_alter_procedure_fully_qualified() {
    let sql = "ALTER PROCEDURE db.schema.my_proc(INT, VARCHAR, BOOLEAN) SET SECURE;";
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_quoted_identifier() {
    let sql = r#"ALTER PROCEDURE "My Procedure"() EXECUTE AS CALLER;"#;
    let _ = format_and_verify(sql);
}

#[test]
fn test_alter_procedure_complex_signature() {
    let sql =
        "ALTER PROCEDURE my_proc(VARCHAR(100), NUMBER(10,2), TIMESTAMP_LTZ) EXECUTE AS OWNER;";
    let _ = format_and_verify(sql);
}
