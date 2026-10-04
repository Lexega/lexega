// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Customer-facing tests for the v1 fact-based pipeline over the
// MSSQL-* rule family. Covers the MSSQL-* rules end-to-end
// across the two substrates the family touches:
//
//   - Query-bearing statements with T-SQL table hints:
//       parse → IR RelPlan → project_table_hints → MssqlTableHintFact
//       → evaluate_rules → Signal
//   - MSSQL DDL statements (Bulk Insert / External Model / Login / User):
//       parse → IR DdlPlan → derive_facts_from_mssql_ddl_plan → Signal
//
// Plus parity assertions vs `analyze_risk_with_policy_config`, so
// customer policy / exception bundles that reference these rule_ids
// fire from either entry point.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::{
    analyze_ddl_facts_with_dialect, analyze_query_facts_with_dialect,
    analyze_risk_with_policy_config,
};
use lexega_core::dialect::MsSqlDialect;

fn mssql_config() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(lexega_core::dialect::mssql()),
        ..Default::default()
    }
}

/// Run the v1 fact-based pipeline twice — once over the query-bearing
/// branch (`analyze_query_facts` populates `query.table_hints` so the
/// MSSQL-HINT-* rules fire), once over the DDL branch
/// (`analyze_ddl_facts` lowers MSSQL DDL and fires MSSQL-DDL rules).
/// Returns the union of rule_ids surfaced. Both calls use the MSSQL
/// dialect so T-SQL syntax (`WITH (NOLOCK)`, `BULK INSERT`, etc.) parses.
fn fact_rule_ids(sql: &str) -> Vec<String> {
    let dialect = MsSqlDialect;
    let mut ids: Vec<String> = analyze_query_facts_with_dialect(sql, &dialect)
        .expect("analyze_query_facts_with_dialect succeeds")
        .into_iter()
        .map(|s| s.rule_id)
        .collect();
    ids.extend(
        analyze_ddl_facts_with_dialect(sql, &dialect)
            .expect("analyze_ddl_facts_with_dialect succeeds")
            .into_iter()
            .map(|s| s.rule_id),
    );
    ids
}

fn risk_rule_ids(sql: &str) -> Vec<String> {
    let report =
        analyze_risk_with_policy_config(sql, &mssql_config()).expect("analyze_risk succeeds");
    report
        .signals
        .iter()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

fn assert_parity(sql: &str, rule_id: &str, expect_fires: bool) {
    let risk_ids = risk_rule_ids(sql);
    let fact_ids = fact_rule_ids(sql);
    let risk_has = risk_ids.contains(&rule_id.to_string());
    let fact_has = fact_ids.contains(&rule_id.to_string());

    if expect_fires {
        assert!(
            risk_has,
            "{}: expected analyze_risk to fire on {:?}; analyze_risk ids={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            fact_has,
            "{}: expected fact pipeline to fire on {:?}; fact ids={:?}",
            rule_id, sql, fact_ids
        );
    } else {
        assert!(
            !risk_has,
            "{}: expected analyze_risk to stay silent on {:?}; analyze_risk ids={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            !fact_has,
            "{}: expected fact pipeline to stay silent on {:?}; fact ids={:?}",
            rule_id, sql, fact_ids
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-DIRTYREAD firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_dirtyread_fires_on_nolock() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (NOLOCK);");
    assert!(
        ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_dirtyread_fires_on_readuncommitted() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (READUNCOMMITTED);");
    assert!(
        ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_dirtyread_silent_for_no_hint() {
    let ids = fact_rule_ids("SELECT * FROM t;");
    assert!(
        !ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_dirtyread_silent_for_serializable_hint() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (SERIALIZABLE);");
    assert!(
        !ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-XLOCK firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_xlock_fires_on_tablockx() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (TABLOCKX);");
    assert!(
        ids.contains(&"MSSQL-HINT-XLOCK".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_xlock_fires_on_xlock() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (XLOCK);");
    assert!(
        ids.contains(&"MSSQL-HINT-XLOCK".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_xlock_silent_for_tablock() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (TABLOCK);");
    assert!(
        !ids.contains(&"MSSQL-HINT-XLOCK".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-INDEX firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_index_fires_on_index_paren_form() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (INDEX(idx_t1));");
    assert!(
        ids.contains(&"MSSQL-HINT-INDEX".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_index_silent_for_no_hint() {
    let ids = fact_rule_ids("SELECT * FROM t;");
    assert!(
        !ids.contains(&"MSSQL-HINT-INDEX".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-FORCESCAN firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_forcescan_fires_on_forcescan() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESCAN);");
    assert!(
        ids.contains(&"MSSQL-HINT-FORCESCAN".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_forcescan_silent_for_forceseek() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESEEK);");
    assert!(
        !ids.contains(&"MSSQL-HINT-FORCESCAN".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-FORCESEEK firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_forceseek_fires_on_forceseek() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESEEK);");
    assert!(
        ids.contains(&"MSSQL-HINT-FORCESEEK".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_forceseek_silent_for_forcescan() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESCAN);");
    assert!(
        !ids.contains(&"MSSQL-HINT-FORCESEEK".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-BULK-INSERT firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_bulk_insert_fires_on_bulk_insert_statement() {
    let ids = fact_rule_ids(
        "BULK INSERT dbo.MyTable FROM 'C:\\data\\file.csv' WITH (FIELDTERMINATOR = ',');",
    );
    assert!(
        ids.contains(&"MSSQL-BULK-INSERT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_bulk_insert_silent_for_regular_insert() {
    let ids = fact_rule_ids("INSERT INTO t VALUES (1);");
    assert!(
        !ids.contains(&"MSSQL-BULK-INSERT".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-EXTMDL-NEW / -RMT / -CHG firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_extmdl_new_fires_on_create_external_model() {
    let sql = "CREATE EXTERNAL MODEL my_model \
               WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');";
    let ids = fact_rule_ids(sql);
    assert!(
        ids.contains(&"MSSQL-EXTMDL-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_extmdl_rmt_fires_on_create_external_model() {
    let sql = "CREATE EXTERNAL MODEL my_model \
               WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');";
    let ids = fact_rule_ids(sql);
    assert!(
        ids.contains(&"MSSQL-EXTMDL-RMT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_extmdl_chg_fires_on_alter_external_model() {
    let sql = "ALTER EXTERNAL MODEL my_model SET (LOCATION = 'https://new.example.com');";
    let ids = fact_rule_ids(sql);
    assert!(
        ids.contains(&"MSSQL-EXTMDL-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_extmdl_new_silent_for_drop_external_model() {
    let ids = fact_rule_ids("DROP EXTERNAL MODEL my_model;");
    assert!(
        !ids.contains(&"MSSQL-EXTMDL-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-LOGIN-NEW firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_login_new_fires_on_create_login_with_password() {
    let ids = fact_rule_ids("CREATE LOGIN bob WITH PASSWORD = 'S3cret!';");
    assert!(
        ids.contains(&"MSSQL-LOGIN-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_new_fires_on_create_login_from_external_provider() {
    let ids = fact_rule_ids("CREATE LOGIN bob FROM EXTERNAL PROVIDER;");
    assert!(
        ids.contains(&"MSSQL-LOGIN-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_new_silent_for_create_user() {
    let ids = fact_rule_ids("CREATE USER alice WITHOUT LOGIN;");
    assert!(
        !ids.contains(&"MSSQL-LOGIN-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-USER-NEW firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_user_new_fires_on_create_user_for_login() {
    let ids = fact_rule_ids("CREATE USER alice FOR LOGIN bob;");
    assert!(ids.contains(&"MSSQL-USER-NEW".to_string()), "ids={:?}", ids);
}

#[test]
fn mssql_user_new_fires_on_create_user_without_login() {
    let ids = fact_rule_ids("CREATE USER alice WITHOUT LOGIN;");
    assert!(ids.contains(&"MSSQL-USER-NEW".to_string()), "ids={:?}", ids);
}

#[test]
fn mssql_user_new_silent_for_create_login() {
    let ids = fact_rule_ids("CREATE LOGIN bob WITH PASSWORD = 'S3cret!';");
    assert!(
        !ids.contains(&"MSSQL-USER-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// Parity tests. Both pipelines must agree per SQL example.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn parity_mssql_hint_dirtyread() {
    assert_parity(
        "SELECT * FROM t WITH (NOLOCK);",
        "MSSQL-HINT-DIRTYREAD",
        true,
    );
    assert_parity(
        "SELECT * FROM t WITH (READUNCOMMITTED);",
        "MSSQL-HINT-DIRTYREAD",
        true,
    );
    assert_parity("SELECT * FROM t;", "MSSQL-HINT-DIRTYREAD", false);
}

#[test]
fn parity_mssql_hint_xlock() {
    assert_parity("SELECT * FROM t WITH (TABLOCKX);", "MSSQL-HINT-XLOCK", true);
    assert_parity("SELECT * FROM t WITH (XLOCK);", "MSSQL-HINT-XLOCK", true);
    assert_parity("SELECT * FROM t WITH (TABLOCK);", "MSSQL-HINT-XLOCK", false);
}

#[test]
fn parity_mssql_hint_index() {
    assert_parity(
        "SELECT * FROM t WITH (INDEX(idx_t1));",
        "MSSQL-HINT-INDEX",
        true,
    );
    assert_parity("SELECT * FROM t;", "MSSQL-HINT-INDEX", false);
}

#[test]
fn parity_mssql_hint_forcescan() {
    assert_parity(
        "SELECT * FROM t WITH (FORCESCAN);",
        "MSSQL-HINT-FORCESCAN",
        true,
    );
    assert_parity(
        "SELECT * FROM t WITH (FORCESEEK);",
        "MSSQL-HINT-FORCESCAN",
        false,
    );
}

#[test]
fn parity_mssql_hint_forceseek() {
    assert_parity(
        "SELECT * FROM t WITH (FORCESEEK);",
        "MSSQL-HINT-FORCESEEK",
        true,
    );
    assert_parity(
        "SELECT * FROM t WITH (FORCESCAN);",
        "MSSQL-HINT-FORCESEEK",
        false,
    );
}

#[test]
fn parity_mssql_bulk_insert() {
    assert_parity(
        "BULK INSERT dbo.MyTable FROM 'C:\\data\\file.csv' WITH (FIELDTERMINATOR = ',');",
        "MSSQL-BULK-INSERT",
        true,
    );
    assert_parity("INSERT INTO t VALUES (1);", "MSSQL-BULK-INSERT", false);
}

#[test]
fn parity_mssql_extmdl_new() {
    assert_parity(
        "CREATE EXTERNAL MODEL my_model \
         WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');",
        "MSSQL-EXTMDL-NEW",
        true,
    );
    assert_parity("DROP EXTERNAL MODEL my_model;", "MSSQL-EXTMDL-NEW", false);
}

#[test]
fn parity_mssql_extmdl_rmt() {
    assert_parity(
        "CREATE EXTERNAL MODEL my_model \
         WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');",
        "MSSQL-EXTMDL-RMT",
        true,
    );
}

#[test]
fn parity_mssql_extmdl_chg() {
    assert_parity(
        "ALTER EXTERNAL MODEL my_model SET (LOCATION = 'https://new.example.com');",
        "MSSQL-EXTMDL-CHG",
        true,
    );
    assert_parity(
        "CREATE EXTERNAL MODEL my_model \
         WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');",
        "MSSQL-EXTMDL-CHG",
        false,
    );
}

#[test]
fn parity_mssql_login_new() {
    assert_parity(
        "CREATE LOGIN bob WITH PASSWORD = 'S3cret!';",
        "MSSQL-LOGIN-NEW",
        true,
    );
    assert_parity(
        "CREATE LOGIN bob FROM EXTERNAL PROVIDER;",
        "MSSQL-LOGIN-NEW",
        true,
    );
    assert_parity("CREATE USER alice WITHOUT LOGIN;", "MSSQL-LOGIN-NEW", false);
}

#[test]
fn parity_mssql_user_new() {
    assert_parity("CREATE USER alice WITHOUT LOGIN;", "MSSQL-USER-NEW", true);
    assert_parity("CREATE USER alice FOR LOGIN bob;", "MSSQL-USER-NEW", true);
    assert_parity(
        "CREATE LOGIN bob WITH PASSWORD = 'S3cret!';",
        "MSSQL-USER-NEW",
        false,
    );
}

// ─────────────────────────────────────────────────────────────────────
// Bucket C — parser-typed-field rules.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_identity_insert_on_fires_on_set_on() {
    let ids = fact_rule_ids("SET IDENTITY_INSERT dbo.MyTable ON;");
    assert!(
        ids.contains(&"MSSQL-IDENTITY-INSERT-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_identity_insert_on_silent_for_off() {
    let ids = fact_rule_ids("SET IDENTITY_INSERT dbo.MyTable OFF;");
    assert!(
        !ids.contains(&"MSSQL-IDENTITY-INSERT-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_identity_insert_on_silent_for_other_option() {
    let ids = fact_rule_ids("SET NOCOUNT ON;");
    assert!(
        !ids.contains(&"MSSQL-IDENTITY-INSERT-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_ext_fires_on_from_external_provider() {
    let ids = fact_rule_ids("CREATE LOGIN bob FROM EXTERNAL PROVIDER;");
    assert!(
        ids.contains(&"MSSQL-LOGIN-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_ext_silent_for_with_password() {
    let ids = fact_rule_ids("CREATE LOGIN bob WITH PASSWORD = 'S3cret!';");
    assert!(
        !ids.contains(&"MSSQL-LOGIN-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_ext_silent_for_create_user_from_external() {
    let ids = fact_rule_ids("CREATE USER alice FROM EXTERNAL PROVIDER;");
    assert!(
        !ids.contains(&"MSSQL-LOGIN-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_user_ext_fires_on_from_external_provider() {
    let ids = fact_rule_ids("CREATE USER alice FROM EXTERNAL PROVIDER;");
    assert!(ids.contains(&"MSSQL-USER-EXT".to_string()), "ids={:?}", ids);
}

#[test]
fn mssql_user_ext_silent_for_for_login() {
    let ids = fact_rule_ids("CREATE USER alice FOR LOGIN bob;");
    assert!(
        !ids.contains(&"MSSQL-USER-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_user_ext_silent_for_without_login() {
    let ids = fact_rule_ids("CREATE USER alice WITHOUT LOGIN;");
    assert!(
        !ids.contains(&"MSSQL-USER-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_user_ext_silent_for_create_login_from_external() {
    let ids = fact_rule_ids("CREATE LOGIN bob FROM EXTERNAL PROVIDER;");
    assert!(
        !ids.contains(&"MSSQL-USER-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_mssql_identity_insert_on() {
    assert_parity(
        "SET IDENTITY_INSERT dbo.MyTable ON;",
        "MSSQL-IDENTITY-INSERT-ON",
        true,
    );
    assert_parity(
        "SET IDENTITY_INSERT dbo.MyTable OFF;",
        "MSSQL-IDENTITY-INSERT-ON",
        false,
    );
    assert_parity("SET NOCOUNT ON;", "MSSQL-IDENTITY-INSERT-ON", false);
}

#[test]
fn parity_mssql_login_ext() {
    assert_parity(
        "CREATE LOGIN bob FROM EXTERNAL PROVIDER;",
        "MSSQL-LOGIN-EXT",
        true,
    );
    assert_parity(
        "CREATE LOGIN bob WITH PASSWORD = 'S3cret!';",
        "MSSQL-LOGIN-EXT",
        false,
    );
}

#[test]
fn parity_mssql_user_ext() {
    assert_parity(
        "CREATE USER alice FROM EXTERNAL PROVIDER;",
        "MSSQL-USER-EXT",
        true,
    );
    assert_parity("CREATE USER alice FOR LOGIN bob;", "MSSQL-USER-EXT", false);
    assert_parity("CREATE USER alice WITHOUT LOGIN;", "MSSQL-USER-EXT", false);
}
