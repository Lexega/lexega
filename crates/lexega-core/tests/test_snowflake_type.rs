// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Comprehensive tests for Snowflake TYPE statements:
/// CREATE [OR REPLACE] TYPE [IF NOT EXISTS] name AS <data_type>[(...)];
/// ALTER TYPE [IF EXISTS] name {SET COMMENT = '...' | UNSET COMMENT};
/// UNDROP TYPE name;
/// DROP TYPE name;
///
/// Also covers PostgreSQL TYPE variants (composite, ENUM, RANGE) to ensure
/// no regressions from the Snowflake additions.
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("Format failed:\n{e}\nSQL:\n{sql}"));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("Round-trip failed:\n{e}\nFormatted:\n{formatted}"));
    formatted
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| {
        let RuleMatch::Analysis(ref p) = s;
        p.matched_rule == rule_id
    })
}

// ============================================================================
// CREATE TYPE — Snowflake scalar types
// ============================================================================

#[test]
fn test_create_type_as_number() {
    let sql = "CREATE TYPE age AS NUMBER(3,0);";
    format_and_verify(sql);
}

#[test]
fn test_create_type_as_varchar() {
    let sql = "CREATE TYPE us_zipcode AS VARCHAR;";
    format_and_verify(sql);
}

#[test]
fn test_create_type_as_object() {
    let sql = "CREATE TYPE address AS OBJECT(city VARCHAR, zip NUMBER(5,0));";
    format_and_verify(sql);
}

#[test]
fn test_create_type_as_array() {
    let sql = "CREATE TYPE phone_list AS ARRAY(VARCHAR);";
    format_and_verify(sql);
}

#[test]
fn test_create_type_as_boolean() {
    let sql = "CREATE TYPE flag AS BOOLEAN;";
    format_and_verify(sql);
}

#[test]
fn test_create_type_as_string() {
    let sql = "CREATE TYPE label AS STRING;";
    format_and_verify(sql);
}

// ============================================================================
// CREATE TYPE — OR REPLACE / IF NOT EXISTS
// ============================================================================

#[test]
fn test_create_or_replace_type() {
    let sql = "CREATE OR REPLACE TYPE address AS OBJECT(city VARCHAR, zip NUMBER(5,0));";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("OR REPLACE"),
        "Should preserve OR REPLACE: {formatted}"
    );
}

#[test]
fn test_create_type_if_not_exists() {
    let sql = "CREATE TYPE IF NOT EXISTS us_zipcode AS VARCHAR;";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("IF NOT EXISTS"),
        "Should preserve IF NOT EXISTS: {formatted}"
    );
}

#[test]
fn test_create_or_replace_type_if_not_exists() {
    let sql = "CREATE OR REPLACE TYPE IF NOT EXISTS age AS NUMBER(3,0);";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("OR REPLACE"),
        "Should preserve OR REPLACE: {formatted}"
    );
    assert!(
        formatted.contains("IF NOT EXISTS"),
        "Should preserve IF NOT EXISTS: {formatted}"
    );
}

// ============================================================================
// CREATE TYPE — with COMMENT
// ============================================================================

#[test]
fn test_create_type_with_comment() {
    let sql = "CREATE TYPE age AS NUMBER(3,0) COMMENT = 'Represents a person age';";
    format_and_verify(sql);
}

#[test]
fn test_create_or_replace_type_with_comment() {
    let sql = "CREATE OR REPLACE TYPE phone_list AS ARRAY(VARCHAR) COMMENT = 'List of phones';";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("OR REPLACE"),
        "Should preserve OR REPLACE: {formatted}"
    );
    assert!(
        formatted.contains("COMMENT"),
        "Should preserve COMMENT clause: {formatted}"
    );
}

// ============================================================================
// CREATE TYPE — qualified names
// ============================================================================

#[test]
fn test_create_type_qualified_name() {
    let sql = "CREATE TYPE my_db.my_schema.age AS NUMBER(3,0);";
    format_and_verify(sql);
}

#[test]
fn test_create_type_schema_qualified() {
    let sql = "CREATE TYPE my_schema.us_zipcode AS VARCHAR;";
    format_and_verify(sql);
}

// ============================================================================
// CREATE TYPE — PostgreSQL composite, ENUM, RANGE (regression)
// ============================================================================

#[test]
fn test_create_type_pg_composite() {
    let sql = "CREATE TYPE inventory_item AS (name TEXT, supplier_id INTEGER, price NUMERIC);";
    format_and_verify(sql);
}

#[test]
fn test_create_type_pg_enum() {
    let sql = "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy');";
    format_and_verify(sql);
}

#[test]
fn test_create_type_pg_range() {
    let sql = "CREATE TYPE float8_range AS RANGE (subtype = float8, subtype_diff = float8mi);";
    format_and_verify(sql);
}

// ============================================================================
// ALTER TYPE — Snowflake SET/UNSET COMMENT
// ============================================================================

#[test]
fn test_alter_type_set_comment() {
    let sql = "ALTER TYPE age SET COMMENT = 'Age type';";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_if_exists_set_comment() {
    let sql = "ALTER TYPE IF EXISTS age SET COMMENT = 'Updated comment';";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("IF EXISTS"),
        "Should preserve IF EXISTS: {formatted}"
    );
}

#[test]
fn test_alter_type_unset_comment() {
    let sql = "ALTER TYPE my_type UNSET COMMENT;";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_if_exists_unset_comment() {
    let sql = "ALTER TYPE IF EXISTS my_type UNSET COMMENT;";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("IF EXISTS"),
        "Should preserve IF EXISTS: {formatted}"
    );
}

// ============================================================================
// ALTER TYPE — PostgreSQL variants (regression)
// ============================================================================

#[test]
fn test_alter_type_pg_add_value() {
    let sql = "ALTER TYPE mood ADD VALUE 'anxious';";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_pg_add_value_if_not_exists() {
    let sql = "ALTER TYPE mood ADD VALUE IF NOT EXISTS 'happy';";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_pg_add_value_before() {
    let sql = "ALTER TYPE mood ADD VALUE 'anxious' BEFORE 'ok';";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_pg_rename_to() {
    let sql = "ALTER TYPE mood RENAME TO emotion;";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_pg_rename_value() {
    let sql = "ALTER TYPE mood RENAME VALUE 'sad' TO 'unhappy';";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_pg_set_schema() {
    let sql = "ALTER TYPE mood SET SCHEMA public;";
    format_and_verify(sql);
}

#[test]
fn test_alter_type_pg_owner_to() {
    let sql = "ALTER TYPE mood OWNER TO admin;";
    format_and_verify(sql);
}

// ============================================================================
// ALTER TYPE — qualified names
// ============================================================================

#[test]
fn test_alter_type_qualified_name() {
    let sql = "ALTER TYPE my_schema.age SET COMMENT = 'Schema-qualified';";
    format_and_verify(sql);
}

// ============================================================================
// UNDROP TYPE
// ============================================================================

#[test]
fn test_undrop_type() {
    let sql = "UNDROP TYPE age;";
    format_and_verify(sql);
}

#[test]
fn test_undrop_type_qualified() {
    let sql = "UNDROP TYPE my_schema.age;";
    format_and_verify(sql);
}

#[test]
fn test_undrop_type_fully_qualified() {
    let sql = "UNDROP TYPE my_db.my_schema.age;";
    format_and_verify(sql);
}

// ============================================================================
// DROP TYPE (existing, regression)
// ============================================================================

#[test]
fn test_drop_type_basic() {
    let sql = "DROP TYPE age;";
    format_and_verify(sql);
}

#[test]
fn test_drop_type_if_exists() {
    let sql = "DROP TYPE IF EXISTS age;";
    format_and_verify(sql);
}

// ============================================================================
// Risk Analysis — signal emission
// ============================================================================

#[test]
fn test_create_type_signal() {
    let sql = "CREATE TYPE age AS NUMBER(3,0);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_signal(&report, "INFO-PG-TYPE-NEW"),
        "Should emit INFO-PG-TYPE-NEW signal for CREATE TYPE"
    );
}

#[test]
fn test_alter_type_signal() {
    let sql = "ALTER TYPE age SET COMMENT = 'test';";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_signal(&report, "INFO-PG-TYPE-CHG"),
        "Should emit INFO-PG-TYPE-CHG signal for ALTER TYPE"
    );
}

#[test]
fn test_undrop_type_signal() {
    let sql = "UNDROP TYPE age;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_signal(&report, "INFO-TYPE-UNDROP"),
        "Should emit INFO-TYPE-UNDROP signal for UNDROP TYPE"
    );
}

#[test]
fn test_drop_type_signal() {
    let sql = "DROP TYPE age;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_signal(&report, "PG-TYPE-DROP"),
        "Should emit PG-TYPE-DROP signal for DROP TYPE"
    );
}

// ============================================================================
// Multi-statement — evidence count
// ============================================================================

#[test]
fn test_multi_create_type_evidence() {
    let sql = r#"
        CREATE TYPE age AS NUMBER(3,0);
        CREATE TYPE zipcode AS VARCHAR;
        CREATE TYPE address AS OBJECT(city VARCHAR);
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    let evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(ref p) if p.matched_rule == "INFO-PG-TYPE-NEW"))
        .map(|s| {
            let RuleMatch::Analysis(ref p) = s;
            p.evidence_count.unwrap_or(1)
        })
        .sum();
    assert!(
        evidence >= 3,
        "Should have evidence for each CREATE TYPE, got {evidence}"
    );
}

#[test]
fn test_multi_statement_all_type_ops() {
    let sql = r#"
        CREATE TYPE age AS NUMBER(3,0);
        ALTER TYPE age SET COMMENT = 'test';
        DROP TYPE age;
        UNDROP TYPE age;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "INFO-PG-TYPE-NEW"),
        "Should have CREATE signal"
    );
    assert!(
        has_signal(&report, "INFO-PG-TYPE-CHG"),
        "Should have ALTER signal"
    );
    assert!(
        has_signal(&report, "PG-TYPE-DROP"),
        "Should have DROP signal"
    );
    assert!(
        has_signal(&report, "INFO-TYPE-UNDROP"),
        "Should have UNDROP signal"
    );
}

#[test]
fn test_multi_statement_formatting() {
    let sql = r#"CREATE TYPE age AS NUMBER(3,0);
CREATE OR REPLACE TYPE address AS OBJECT(city VARCHAR, zip NUMBER(5,0));
ALTER TYPE IF EXISTS age SET COMMENT = 'test';
ALTER TYPE address UNSET COMMENT;
UNDROP TYPE age;
DROP TYPE age;"#;
    format_and_verify(sql);
}
