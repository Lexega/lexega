// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for global metric aggregation across multiple statements
///
/// These tests validate that metrics like cross_database, tables_read, etc.
/// are correctly aggregated ACROSS ALL STATEMENTS, not just within single statements.
///
/// This test file exists because of a critical bug where cross_database was only
/// checking databases within a single statement, causing it to always report "No"
/// even when multiple statements used different databases.
use lexega_core::api::analyze_risk;

#[test]
fn test_cross_database_multiple_statements() {
    let sql = "
        -- Statement 1: Uses DB1
        SELECT * FROM db1.public.table1;
        
        -- Statement 2: Uses DB2
        SELECT * FROM db2.public.table2;
        
        -- Statement 3: Uses DB1 again
        INSERT INTO db1.public.table3 VALUES (1);
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    // Critical: Must detect cross-database access
    assert!(
        report.summary.cross_database,
        "Should detect cross-database access across multiple statements"
    );

    // Should have both databases in set
    assert_eq!(
        report.summary.databases_accessed.len(),
        2,
        "Should track 2 distinct databases"
    );

    let db_names: Vec<String> = report.summary.databases_accessed.iter().cloned().collect();
    assert!(
        db_names.contains(&"DB1".to_string()) && db_names.contains(&"DB2".to_string()),
        "Should contain both DB1 and DB2, got: {:?}",
        db_names
    );
}

#[test]
fn test_cross_database_single_statement_multiple_tables() {
    let sql = "
        -- Single statement with cross-database join
        SELECT * 
        FROM db1.public.table1 t1
        JOIN db2.public.table2 t2 ON t1.id = t2.id;
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    assert!(
        report.summary.cross_database,
        "Should detect cross-database in single statement with multiple tables"
    );

    assert_eq!(
        report.summary.databases_accessed.len(),
        2,
        "Should track 2 databases even in single statement"
    );
}

#[test]
fn test_cross_schema_multiple_statements() {
    let sql = "
        -- Statement 1: Schema PUBLIC
        SELECT * FROM mydb.public.table1;
        
        -- Statement 2: Schema STAGING
        SELECT * FROM mydb.staging.table2;
        
        -- Statement 3: Schema PUBLIC again
        INSERT INTO mydb.public.table3 VALUES (1);
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    assert!(
        report.summary.cross_schema,
        "Should detect cross-schema access across multiple statements"
    );
}

#[test]
fn test_tables_read_across_multiple_statements() {
    let sql = "
        SELECT * FROM table1;
        SELECT * FROM table2;
        SELECT * FROM table3;
        SELECT * FROM table1;  -- Duplicate, should only count once
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    // Should deduplicate table1 (appears twice)
    assert_eq!(
        report.summary.tables_read, 3,
        "Should count 3 unique tables read (table1, table2, table3)"
    );
}

#[test]
fn test_tables_written_across_multiple_statements() {
    let sql = "
        INSERT INTO table1 VALUES (1);
        UPDATE table2 SET x = 1;
        DELETE FROM table3;
        INSERT INTO table1 VALUES (2);  -- Duplicate
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    // Should deduplicate table1
    assert_eq!(
        report.summary.tables_written, 3,
        "Should count 3 unique tables written (table1, table2, table3)"
    );
}

#[test]
fn test_single_database_not_cross() {
    let sql = "
        SELECT * FROM db1.schema1.table1;
        SELECT * FROM db1.schema2.table2;
        INSERT INTO db1.schema1.table3 VALUES (1);
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    assert!(
        !report.summary.cross_database,
        "Should NOT flag cross-database when all statements use same database"
    );

    assert_eq!(
        report.summary.databases_accessed.len(),
        1,
        "Should track only 1 database"
    );
}

#[test]
fn test_metrics_with_skipped_statements() {
    // This SQL has some unimplemented statement types (CREATE FUNCTION)
    // but metrics should still aggregate correctly from what IS parsed
    let sql = "
        SELECT * FROM db1.public.table1;
        
        CREATE OR REPLACE FUNCTION util_db.public.my_func()
        RETURNS STRING
        AS 'SELECT foo';
        
        SELECT * FROM db2.public.table2;
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    // Even though CREATE FUNCTION might be skipped from AST analysis,
    // cross-database should still be detected from the SELECT statements
    assert!(
        report.summary.cross_database,
        "Should detect cross-database even with some skipped statements"
    );
}

#[test]
fn test_summary_counts_recalculated_correctly() {
    let sql = "
        GRANT USAGE ON DATABASE prod TO ROLE PUBLIC;
        GRANT USAGE ON DATABASE prod TO ROLE PUBLIC;  -- Duplicate
        SELECT * FROM large_table;  -- Cost signal
        UPDATE important_table SET x = 1;  -- Blast radius signal
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    // Validate invariant: sum of severity counts == total signals
    let sum_of_severities = report.summary.critical_count
        + report.summary.high_count
        + report.summary.medium_count
        + report.summary.low_count;

    assert_eq!(
        report.summary.total_reported_signals, sum_of_severities,
        "Sum of severity counts must equal total_signals"
    );

    assert_eq!(
        report.summary.total_reported_signals,
        report.signals.len(),
        "total_signals must match actual signals.len()"
    );
}

#[test]
fn test_ddl_operations_counted() {
    let sql = "
        CREATE TABLE foo (id INT);
        ALTER TABLE foo ADD COLUMN name STRING;
        DROP TABLE bar;
        TRUNCATE TABLE baz;
        SELECT * FROM table1;  -- Not DDL
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    assert!(
        report.summary.ddl_operations >= 4,
        "Should count at least 4 DDL operations (CREATE, ALTER, DROP, TRUNCATE)"
    );
}

#[test]
fn test_case_insensitive_database_names() {
    // Database names should be normalized to uppercase for comparison
    let sql = "
        SELECT * FROM DB1.public.table1;
        SELECT * FROM db1.PUBLIC.table2;  -- Same DB, different case
    ";

    let report = analyze_risk(sql).expect("Should parse and analyze");

    assert!(
        !report.summary.cross_database,
        "Should NOT flag cross-database when database names differ only in case"
    );

    assert_eq!(
        report.summary.databases_accessed.len(),
        1,
        "Should normalize database names to uppercase (DB1 == db1)"
    );
}
