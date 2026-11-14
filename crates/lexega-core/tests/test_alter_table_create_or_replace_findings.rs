// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;

fn has_finding(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .findings
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn has_context(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .context
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

#[test]
fn test_alter_table_drop_column_emits_tbl_col_drop() {
    let sql = "ALTER TABLE users DROP COLUMN email;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "TBL-COL-DROP"),
        "Expected TBL-COL-DROP for ALTER TABLE DROP COLUMN"
    );
}

#[test]
fn test_alter_table_rename_emits_tbl_rename() {
    let sql = "ALTER TABLE users RENAME TO customers;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "TBL-RENAME"),
        "Expected TBL-RENAME for ALTER TABLE RENAME"
    );
}

#[test]
fn test_alter_table_add_column_emits_tbl_col_add() {
    let sql = "ALTER TABLE users ADD COLUMN phone VARCHAR;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_context(&report, "TBL-COL-ADD"),
        "Expected TBL-COL-ADD for ALTER TABLE ADD COLUMN"
    );
}

#[test]
fn test_create_or_replace_table_emits_tbl_replace() {
    let sql = "CREATE OR REPLACE TABLE users (id INT);";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "TBL-REPLACE"),
        "Expected TBL-REPLACE for CREATE OR REPLACE TABLE"
    );
}

#[test]
fn test_create_or_replace_temporary_table_does_not_emit_tbl_replace() {
    let temporary = analyze_risk("CREATE OR REPLACE TEMPORARY TABLE t (id INT);")
        .expect("analysis should succeed");
    assert!(
        !has_finding(&temporary, "TBL-REPLACE") && !has_context(&temporary, "TBL-REPLACE"),
        "Did not expect TBL-REPLACE for CREATE OR REPLACE TEMPORARY TABLE"
    );

    let permanent =
        analyze_risk("CREATE OR REPLACE TABLE t (id INT);").expect("analysis should succeed");
    assert!(
        has_finding(&permanent, "TBL-REPLACE"),
        "Expected TBL-REPLACE for the permanent CREATE OR REPLACE TABLE"
    );
}

#[test]
fn test_tbl_replace_follows_what_the_modifiers_make_the_table() {
    for sql in [
        "CREATE OR REPLACE VOLATILE TABLE t (id INT);",
        "CREATE OR REPLACE LOCAL TEMPORARY TABLE t (id INT);",
        "CREATE OR REPLACE GLOBAL TEMP TABLE t (id INT);",
    ] {
        let report = analyze_risk(sql).expect("analysis should succeed");
        assert!(
            !has_finding(&report, "TBL-REPLACE") && !has_context(&report, "TBL-REPLACE"),
            "a temporary table is not replaced data: {sql}"
        );
    }
    // A transient table persists; replacing it drops its rows.
    let transient = analyze_risk("CREATE OR REPLACE TRANSIENT TABLE t (id INT);")
        .expect("analysis should succeed");
    assert!(has_finding(&transient, "TBL-REPLACE"));
}

// `CREATE OR REFRESH` declares a Databricks pipeline table that the
// pipeline updates: it is no replace, of a live, streaming or temporary
// table alike, and each declaration is read.
#[test]
fn test_databricks_pipeline_table_declarations_are_not_replaces() {
    let analyze = |sql: &str| {
        let config = lexega_core::analyzer::AnalysisConfig {
            dialect: Some(std::sync::Arc::new(lexega_core::DatabricksDialect)),
            ..Default::default()
        };
        lexega_core::api::analyze_risk_with_policy_config(sql, &config)
            .expect("analysis should succeed")
    };
    for sql in [
        "CREATE OR REFRESH LIVE TABLE zz_t AS SELECT id FROM users;",
        "CREATE OR REFRESH STREAMING LIVE TABLE zz_t AS SELECT id FROM users;",
        "CREATE OR REFRESH STREAMING TABLE zz_t AS SELECT id FROM users;",
        "CREATE OR REFRESH TEMPORARY LIVE TABLE zz_t AS SELECT id FROM users;",
    ] {
        let report = analyze(sql);
        assert_eq!(report.summary.statements_skipped, 0, "read: {sql}");
        assert!(
            !has_finding(&report, "TBL-REPLACE") && !has_context(&report, "TBL-REPLACE"),
            "{sql}"
        );
    }
    assert!(has_finding(
        &analyze("CREATE OR REPLACE TABLE zz_t AS SELECT id FROM users;"),
        "TBL-REPLACE"
    ));
}

#[test]
fn test_create_or_replace_view_emits_view_replace() {
    let sql = "CREATE OR REPLACE VIEW users_v AS SELECT * FROM users;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "VIEW-REPLACE"),
        "Expected VIEW-REPLACE for CREATE OR REPLACE VIEW"
    );
}

#[test]
fn test_create_table_without_or_replace_does_not_emit_tbl_replace() {
    let sql = "CREATE TABLE users (id INT);";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        !has_finding(&report, "TBL-REPLACE"),
        "Did not expect TBL-REPLACE for plain CREATE TABLE"
    );
}

#[test]
fn test_create_view_without_or_replace_does_not_emit_view_replace() {
    let sql = "CREATE VIEW users_v AS SELECT * FROM users;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        !has_finding(&report, "VIEW-REPLACE"),
        "Did not expect VIEW-REPLACE for plain CREATE VIEW"
    );
}

// --- BigQuery-flavored variants (dataset.table naming) ---

#[test]
fn test_bq_alter_table_drop_column_emits_tbl_col_drop() {
    let sql = "ALTER TABLE my_dataset.users DROP COLUMN email;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "TBL-COL-DROP"),
        "Expected TBL-COL-DROP for BQ-style ALTER TABLE DROP COLUMN"
    );
}

#[test]
fn test_bq_alter_table_rename_emits_tbl_rename() {
    let sql = "ALTER TABLE my_dataset.users RENAME TO my_dataset.customers;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "TBL-RENAME"),
        "Expected TBL-RENAME for BQ-style ALTER TABLE RENAME"
    );
}

#[test]
fn test_bq_alter_table_add_column_emits_tbl_col_add() {
    let sql = "ALTER TABLE my_dataset.users ADD COLUMN phone STRING;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_context(&report, "TBL-COL-ADD"),
        "Expected TBL-COL-ADD for BQ-style ALTER TABLE ADD COLUMN"
    );
}

#[test]
fn test_bq_create_or_replace_table_emits_tbl_replace() {
    let sql = "CREATE OR REPLACE TABLE my_dataset.users (id INT64, name STRING);";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "TBL-REPLACE"),
        "Expected TBL-REPLACE for BQ-style CREATE OR REPLACE TABLE"
    );
}

#[test]
fn test_bq_create_or_replace_view_emits_view_replace() {
    let sql = "CREATE OR REPLACE VIEW my_dataset.users_v AS SELECT id, name FROM my_dataset.users;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "VIEW-REPLACE"),
        "Expected VIEW-REPLACE for BQ-style CREATE OR REPLACE VIEW"
    );
}
