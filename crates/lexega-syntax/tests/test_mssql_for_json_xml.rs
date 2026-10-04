// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL FOR JSON / FOR XML PATH clause support.
///
/// Covers:
///   1. FOR JSON AUTO — simplest form
///   2. FOR JSON PATH — explicit path mapping
///   3. FOR JSON PATH with options (ROOT, INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER)
///   4. FOR XML RAW / AUTO / PATH / EXPLICIT — all XML modes
///   5. FOR XML with options (ROOT, TYPE, ELEMENTS, ELEMENTS XSINIL/ABSENT)
///   6. Subquery context — FOR JSON/XML inside subqueries
///   7. ORDER BY + FOR JSON/XML — correct clause ordering
///   8. FOR UPDATE regression — must still work
use lexega_syntax::dialect::mssql;
use lexega_syntax::{format_sql_with_config, FormatterConfig};

// ============================================================================
// Helpers
// ============================================================================

fn mssql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mssql();
    config
}

fn format_and_verify(sql: &str) {
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for MSSQL: {}\nSQL: {}", e, sql));

    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
}

fn format_mssql(sql: &str) -> String {
    let config = mssql_config();
    format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for MSSQL: {}\nSQL: {}", e, sql))
}

// ============================================================================
// 1. FOR JSON AUTO
// ============================================================================

#[test]
fn test_for_json_auto_basic() {
    format_and_verify("SELECT id, name FROM users FOR JSON AUTO;");
}

#[test]
fn test_for_json_auto_preserves_clause() {
    let result = format_mssql("SELECT id, name FROM users FOR JSON AUTO;");
    assert!(
        result.contains("FOR JSON AUTO"),
        "FOR JSON AUTO should be preserved in output: {}",
        result
    );
}

// ============================================================================
// 2. FOR JSON PATH
// ============================================================================

#[test]
fn test_for_json_path_basic() {
    format_and_verify("SELECT id, name, email FROM users FOR JSON PATH;");
}

#[test]
fn test_for_json_path_with_root() {
    format_and_verify("SELECT id, name FROM users FOR JSON PATH, ROOT('employees');");
}

#[test]
fn test_for_json_path_with_include_null_values() {
    format_and_verify("SELECT id, name, email FROM users FOR JSON PATH, INCLUDE_NULL_VALUES;");
}

#[test]
fn test_for_json_path_with_without_array_wrapper() {
    format_and_verify("SELECT id, name FROM users FOR JSON PATH, WITHOUT_ARRAY_WRAPPER;");
}

#[test]
fn test_for_json_path_all_options() {
    format_and_verify(
        "SELECT id, name FROM users FOR JSON PATH, ROOT('data'), INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER;"
    );
}

#[test]
fn test_for_json_path_preserves_all_options() {
    let result = format_mssql(
        "SELECT id, name FROM users FOR JSON PATH, ROOT('data'), INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER;"
    );
    assert!(
        result.contains("FOR JSON PATH"),
        "Should contain FOR JSON PATH: {}",
        result
    );
    assert!(
        result.contains("ROOT('data')"),
        "Should contain ROOT option: {}",
        result
    );
    assert!(
        result.contains("INCLUDE_NULL_VALUES"),
        "Should contain INCLUDE_NULL_VALUES: {}",
        result
    );
    assert!(
        result.contains("WITHOUT_ARRAY_WRAPPER"),
        "Should contain WITHOUT_ARRAY_WRAPPER: {}",
        result
    );
}

// ============================================================================
// 3. FOR XML RAW
// ============================================================================

#[test]
fn test_for_xml_raw_basic() {
    format_and_verify("SELECT id, name FROM users FOR XML RAW;");
}

#[test]
fn test_for_xml_raw_with_element_name() {
    format_and_verify("SELECT id, name FROM users FOR XML RAW('Employee');");
}

// ============================================================================
// 4. FOR XML AUTO
// ============================================================================

#[test]
fn test_for_xml_auto_basic() {
    format_and_verify("SELECT id, name FROM users FOR XML AUTO;");
}

// ============================================================================
// 5. FOR XML PATH
// ============================================================================

#[test]
fn test_for_xml_path_basic() {
    format_and_verify("SELECT id, name FROM users FOR XML PATH;");
}

#[test]
fn test_for_xml_path_with_element_name() {
    format_and_verify("SELECT id, name FROM users FOR XML PATH('Employee');");
}

#[test]
fn test_for_xml_path_with_root() {
    format_and_verify("SELECT id, name FROM users FOR XML PATH('Employee'), ROOT('Employees');");
}

#[test]
fn test_for_xml_path_with_type() {
    format_and_verify("SELECT id, name FROM users FOR XML PATH('Employee'), TYPE;");
}

#[test]
fn test_for_xml_path_with_elements() {
    format_and_verify("SELECT id, name FROM users FOR XML PATH('Employee'), ELEMENTS;");
}

#[test]
fn test_for_xml_path_with_elements_xsinil() {
    format_and_verify("SELECT id, name FROM users FOR XML PATH('Employee'), ELEMENTS XSINIL;");
}

#[test]
fn test_for_xml_path_with_elements_absent() {
    format_and_verify("SELECT id, name FROM users FOR XML PATH('Employee'), ELEMENTS ABSENT;");
}

#[test]
fn test_for_xml_path_all_options() {
    format_and_verify(
        "SELECT id, name FROM users FOR XML PATH('row'), ROOT('data'), TYPE, ELEMENTS XSINIL;",
    );
}

#[test]
fn test_for_xml_path_preserves_all_options() {
    let result = format_mssql(
        "SELECT id, name FROM users FOR XML PATH('row'), ROOT('data'), TYPE, ELEMENTS XSINIL;",
    );
    assert!(
        result.contains("FOR XML PATH('row')"),
        "Should contain FOR XML PATH: {}",
        result
    );
    assert!(
        result.contains("ROOT('data')"),
        "Should contain ROOT option: {}",
        result
    );
    assert!(result.contains("TYPE"), "Should contain TYPE: {}", result);
    assert!(
        result.contains("ELEMENTS XSINIL"),
        "Should contain ELEMENTS XSINIL: {}",
        result
    );
}

// ============================================================================
// 6. FOR XML EXPLICIT
// ============================================================================

#[test]
fn test_for_xml_explicit_basic() {
    format_and_verify("SELECT 1 AS Tag, NULL AS Parent FOR XML EXPLICIT;");
}

// ============================================================================
// 7. Subquery Context
// ============================================================================

#[test]
fn test_for_json_in_subquery() {
    format_and_verify("SELECT * FROM (SELECT id, name FROM users FOR JSON PATH) AS j;");
}

#[test]
fn test_for_xml_in_subquery() {
    format_and_verify("SELECT * FROM (SELECT id, name FROM users FOR XML PATH('emp')) AS x;");
}

// ============================================================================
// 8. ORDER BY + FOR JSON/XML
// ============================================================================

#[test]
fn test_for_json_with_order_by() {
    format_and_verify("SELECT id, name FROM users ORDER BY id FOR JSON PATH;");
}

#[test]
fn test_for_xml_with_order_by() {
    format_and_verify("SELECT id, name FROM users ORDER BY id FOR XML PATH('row');");
}

#[test]
fn test_for_json_with_where_and_order_by() {
    format_and_verify(
        "SELECT id, name FROM users WHERE active = 1 ORDER BY id FOR JSON PATH, ROOT('data');",
    );
}

// ============================================================================
// 9. FOR UPDATE Regression
// ============================================================================

#[test]
fn test_for_update_still_works() {
    format_and_verify("SELECT id FROM t FOR UPDATE;");
}

#[test]
fn test_for_update_nowait_still_works() {
    format_and_verify("SELECT id FROM t FOR UPDATE NOWAIT;");
}

// ============================================================================
// 10. Multi-statement
// ============================================================================

#[test]
fn test_for_json_multi_statement() {
    format_and_verify("SELECT id FROM a FOR JSON AUTO;\nSELECT id FROM b FOR XML PATH('row');");
}

// ============================================================================
// 11. FOR JSON PATH with OPTION (combined extension clauses)
// ============================================================================

#[test]
fn test_for_json_with_option_hint() {
    format_and_verify("SELECT id, name FROM users FOR JSON PATH OPTION (MAXDOP 1);");
}
