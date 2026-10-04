// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for COPY TAGS vs COPY GRANTS parsing in CREATE TABLE.

use lexega_syntax::{
    format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt, FormatterConfig,
};

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("Format failed:\n{e}\nSQL:\n{sql}"));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("Round-trip failed:\n{e}\nFormatted:\n{formatted}"));
    formatted
}

fn extract_create_table(sql: &str) -> lexega_syntax::ast::AstCreateTable {
    let script = parse_sql(sql).expect("should parse");
    match script.stmts.into_iter().next().unwrap() {
        AstStmt::CreateTable(ct) => ct.as_ref().clone(),
        other => panic!("Expected CreateTable, got {:?}", other),
    }
}

// ============================================================================
// AST verification: COPY TAGS vs COPY GRANTS are correctly distinguished
// ============================================================================

#[test]
fn test_copy_tags_only_ast() {
    let ct = extract_create_table("CREATE TABLE t2 LIKE t1 COPY TAGS;");
    assert!(ct.copy_tags_span.is_some(), "copy_tags_span should be set");
    assert!(
        ct.copy_grants_span.is_none(),
        "copy_grants_span should NOT be set"
    );
}

#[test]
fn test_copy_grants_only_ast() {
    let ct = extract_create_table("CREATE TABLE t2 LIKE t1 COPY GRANTS;");
    assert!(
        ct.copy_grants_span.is_some(),
        "copy_grants_span should be set"
    );
    assert!(
        ct.copy_tags_span.is_none(),
        "copy_tags_span should NOT be set"
    );
}

#[test]
fn test_copy_grants_and_tags_ast() {
    let ct = extract_create_table("CREATE TABLE t2 LIKE t1 COPY GRANTS COPY TAGS;");
    assert!(
        ct.copy_grants_span.is_some(),
        "copy_grants_span should be set"
    );
    assert!(ct.copy_tags_span.is_some(), "copy_tags_span should be set");
}

// ============================================================================
// Formatting round-trip tests
// ============================================================================

#[test]
fn test_copy_tags_like_roundtrip() {
    let sql = "CREATE TABLE t2 LIKE t1 COPY TAGS;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("COPY TAGS"),
        "Should preserve COPY TAGS: {fmt}"
    );
}

#[test]
fn test_copy_tags_clone_roundtrip() {
    let sql = "CREATE TABLE t2 CLONE t1 COPY TAGS;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("COPY TAGS"),
        "Should preserve COPY TAGS: {fmt}"
    );
}

#[test]
fn test_copy_grants_and_tags_roundtrip() {
    let sql = "CREATE TABLE t2 LIKE t1 COPY GRANTS COPY TAGS;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("COPY GRANTS"),
        "Should preserve COPY GRANTS: {fmt}"
    );
    assert!(
        fmt.contains("COPY TAGS"),
        "Should preserve COPY TAGS: {fmt}"
    );
}

#[test]
fn test_copy_tags_with_other_options() {
    let sql = "CREATE TABLE t2 LIKE t1 COPY TAGS COMMENT = 'test table';";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("COPY TAGS"),
        "Should preserve COPY TAGS: {fmt}"
    );
    assert!(fmt.contains("COMMENT"), "Should preserve COMMENT: {fmt}");
}

#[test]
fn test_copy_grants_still_works() {
    let sql = "CREATE TABLE t2 LIKE t1 COPY GRANTS;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("COPY GRANTS"),
        "Should preserve COPY GRANTS: {fmt}"
    );
}
