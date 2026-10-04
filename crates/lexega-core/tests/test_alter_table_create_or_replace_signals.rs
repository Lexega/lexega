// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

#[test]
fn test_alter_table_drop_column_emits_tbl_col_drop() {
    let sql = "ALTER TABLE users DROP COLUMN email;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-COL-DROP"),
        "Expected TBL-COL-DROP for ALTER TABLE DROP COLUMN"
    );
}

#[test]
fn test_alter_table_rename_emits_tbl_rename() {
    let sql = "ALTER TABLE users RENAME TO customers;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-RENAME"),
        "Expected TBL-RENAME for ALTER TABLE RENAME"
    );
}

#[test]
fn test_alter_table_add_column_emits_tbl_col_add() {
    let sql = "ALTER TABLE users ADD COLUMN phone VARCHAR;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-COL-ADD"),
        "Expected TBL-COL-ADD for ALTER TABLE ADD COLUMN"
    );
}

#[test]
fn test_create_or_replace_table_emits_tbl_replace() {
    let sql = "CREATE OR REPLACE TABLE users (id INT);";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-REPLACE"),
        "Expected TBL-REPLACE for CREATE OR REPLACE TABLE"
    );
}

#[test]
fn test_create_or_replace_view_emits_view_replace() {
    let sql = "CREATE OR REPLACE VIEW users_v AS SELECT * FROM users;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "VIEW-REPLACE"),
        "Expected VIEW-REPLACE for CREATE OR REPLACE VIEW"
    );
}

#[test]
fn test_create_table_without_or_replace_does_not_emit_tbl_replace() {
    let sql = "CREATE TABLE users (id INT);";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        !has_signal(&report, "TBL-REPLACE"),
        "Did not expect TBL-REPLACE for plain CREATE TABLE"
    );
}

#[test]
fn test_create_view_without_or_replace_does_not_emit_view_replace() {
    let sql = "CREATE VIEW users_v AS SELECT * FROM users;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        !has_signal(&report, "VIEW-REPLACE"),
        "Did not expect VIEW-REPLACE for plain CREATE VIEW"
    );
}

// --- BigQuery-flavored variants (dataset.table naming) ---

#[test]
fn test_bq_alter_table_drop_column_emits_tbl_col_drop() {
    let sql = "ALTER TABLE my_dataset.users DROP COLUMN email;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-COL-DROP"),
        "Expected TBL-COL-DROP for BQ-style ALTER TABLE DROP COLUMN"
    );
}

#[test]
fn test_bq_alter_table_rename_emits_tbl_rename() {
    let sql = "ALTER TABLE my_dataset.users RENAME TO my_dataset.customers;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-RENAME"),
        "Expected TBL-RENAME for BQ-style ALTER TABLE RENAME"
    );
}

#[test]
fn test_bq_alter_table_add_column_emits_tbl_col_add() {
    let sql = "ALTER TABLE my_dataset.users ADD COLUMN phone STRING;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-COL-ADD"),
        "Expected TBL-COL-ADD for BQ-style ALTER TABLE ADD COLUMN"
    );
}

#[test]
fn test_bq_create_or_replace_table_emits_tbl_replace() {
    let sql = "CREATE OR REPLACE TABLE my_dataset.users (id INT64, name STRING);";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "TBL-REPLACE"),
        "Expected TBL-REPLACE for BQ-style CREATE OR REPLACE TABLE"
    );
}

#[test]
fn test_bq_create_or_replace_view_emits_view_replace() {
    let sql = "CREATE OR REPLACE VIEW my_dataset.users_v AS SELECT id, name FROM my_dataset.users;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_signal(&report, "VIEW-REPLACE"),
        "Expected VIEW-REPLACE for BQ-style CREATE OR REPLACE VIEW"
    );
}
