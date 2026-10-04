// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Customer-facing tests for the v1 fact-based pipeline over
// the INFO-* family. Covers 29 rules across three dialect flavors:
//
//   - Snowflake (default dispatch): UNDROP DATABASE / UNDROP SCHEMA /
//     COMMENT ON / DBX-*-COMMENT-CHG / CREATE PIPE / CREATE TABLE
//     CLONE / Q-PRED-TEMPORAL.
//   - PostgreSQL (PgDialect): VACUUM / ANALYZE / CLUSTER / LISTEN /
//     NOTIFY / UNLISTEN / CREATE AGGREGATE / CREATE OPERATOR / CREATE
//     DOMAIN / ALTER DOMAIN / CREATE SEQUENCE / ALTER SEQUENCE /
//     CREATE TYPE / ALTER TYPE.
//   - MSSQL (MsSqlDialect): EXEC procedure / SET option / DROP
//     EXTERNAL MODEL / CREATE VECTOR INDEX / table hint.
//
// Plus parity assertions vs the `analyze_risk` entry points.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::{
    analyze_ddl_facts, analyze_ddl_facts_with_dialect, analyze_query_facts,
    analyze_query_facts_with_dialect, analyze_risk, analyze_risk_with_policy_config,
};
use lexega_core::dialect::{MsSqlDialect, PostgresDialect};

// ─────────────────────────────────────────────────────────────────────
// Dialect-flavored rule_id collectors and parity assertions.
// ─────────────────────────────────────────────────────────────────────

fn fact_rule_ids_snowflake(sql: &str) -> Vec<String> {
    let mut ids: Vec<String> = analyze_ddl_facts(sql)
        .expect("analyze_ddl_facts succeeds")
        .into_iter()
        .map(|s| s.rule_id)
        .collect();
    ids.extend(
        analyze_query_facts(sql)
            .expect("analyze_query_facts succeeds")
            .into_iter()
            .map(|s| s.rule_id),
    );
    ids
}

fn risk_rule_ids_snowflake(sql: &str) -> Vec<String> {
    let report = analyze_risk(sql).expect("analyze_risk succeeds");
    report
        .signals
        .iter()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

fn pg_config() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(lexega_core::dialect::postgres()),
        ..Default::default()
    }
}

fn fact_rule_ids_pg(sql: &str) -> Vec<String> {
    let dialect = PostgresDialect;
    let mut ids: Vec<String> = analyze_ddl_facts_with_dialect(sql, &dialect)
        .expect("analyze_ddl_facts_with_dialect (pg) succeeds")
        .into_iter()
        .map(|s| s.rule_id)
        .collect();
    ids.extend(
        analyze_query_facts_with_dialect(sql, &dialect)
            .expect("analyze_query_facts_with_dialect (pg) succeeds")
            .into_iter()
            .map(|s| s.rule_id),
    );
    ids
}

fn risk_rule_ids_pg(sql: &str) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &pg_config())
        .expect("analyze_risk_with_policy_config (pg) succeeds");
    report
        .signals
        .iter()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

fn mssql_config() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(lexega_core::dialect::mssql()),
        ..Default::default()
    }
}

fn fact_rule_ids_mssql(sql: &str) -> Vec<String> {
    let dialect = MsSqlDialect;
    let mut ids: Vec<String> = analyze_ddl_facts_with_dialect(sql, &dialect)
        .expect("analyze_ddl_facts_with_dialect (mssql) succeeds")
        .into_iter()
        .map(|s| s.rule_id)
        .collect();
    ids.extend(
        analyze_query_facts_with_dialect(sql, &dialect)
            .expect("analyze_query_facts_with_dialect (mssql) succeeds")
            .into_iter()
            .map(|s| s.rule_id),
    );
    ids
}

fn risk_rule_ids_mssql(sql: &str) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &mssql_config())
        .expect("analyze_risk_with_policy_config (mssql) succeeds");
    report
        .signals
        .iter()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

fn assert_parity_snowflake(sql: &str, rule_id: &str, expect_fires: bool) {
    let risk_ids = risk_rule_ids_snowflake(sql);
    let fact_ids = fact_rule_ids_snowflake(sql);
    let risk_has = risk_ids.contains(&rule_id.to_string());
    let fact_has = fact_ids.contains(&rule_id.to_string());
    if expect_fires {
        assert!(
            risk_has,
            "{}: analyze_risk should fire on {:?}; analyze_risk={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            fact_has,
            "{}: facts should fire on {:?}; facts={:?}",
            rule_id, sql, fact_ids
        );
    } else {
        assert!(
            !risk_has,
            "{}: analyze_risk should stay silent on {:?}; analyze_risk={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            !fact_has,
            "{}: facts should stay silent on {:?}; facts={:?}",
            rule_id, sql, fact_ids
        );
    }
}

fn assert_parity_pg(sql: &str, rule_id: &str, expect_fires: bool) {
    let risk_ids = risk_rule_ids_pg(sql);
    let fact_ids = fact_rule_ids_pg(sql);
    let risk_has = risk_ids.contains(&rule_id.to_string());
    let fact_has = fact_ids.contains(&rule_id.to_string());
    if expect_fires {
        assert!(
            risk_has,
            "{}: analyze_risk should fire on {:?}; analyze_risk={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            fact_has,
            "{}: facts should fire on {:?}; facts={:?}",
            rule_id, sql, fact_ids
        );
    } else {
        assert!(
            !risk_has,
            "{}: analyze_risk should stay silent on {:?}; analyze_risk={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            !fact_has,
            "{}: facts should stay silent on {:?}; facts={:?}",
            rule_id, sql, fact_ids
        );
    }
}

fn assert_parity_mssql(sql: &str, rule_id: &str, expect_fires: bool) {
    let risk_ids = risk_rule_ids_mssql(sql);
    let fact_ids = fact_rule_ids_mssql(sql);
    let risk_has = risk_ids.contains(&rule_id.to_string());
    let fact_has = fact_ids.contains(&rule_id.to_string());
    if expect_fires {
        assert!(
            risk_has,
            "{}: analyze_risk should fire on {:?}; analyze_risk={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            fact_has,
            "{}: facts should fire on {:?}; facts={:?}",
            rule_id, sql, fact_ids
        );
    } else {
        assert!(
            !risk_has,
            "{}: analyze_risk should stay silent on {:?}; analyze_risk={:?}",
            rule_id, sql, risk_ids
        );
        assert!(
            !fact_has,
            "{}: facts should stay silent on {:?}; facts={:?}",
            rule_id, sql, fact_ids
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Snowflake stmt-kind-only (UNDROP DATABASE / SCHEMA).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_db_undrop_fires() {
    let ids = fact_rule_ids_snowflake("UNDROP DATABASE prod;");
    assert!(ids.contains(&"INFO-DB-UNDROP".to_string()), "ids={:?}", ids);
}

#[test]
fn info_db_undrop_silent_for_create_database() {
    let ids = fact_rule_ids_snowflake("CREATE DATABASE prod;");
    assert!(
        !ids.contains(&"INFO-DB-UNDROP".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_db_undrop() {
    assert_parity_snowflake("UNDROP DATABASE prod;", "INFO-DB-UNDROP", true);
    assert_parity_snowflake("CREATE DATABASE prod;", "INFO-DB-UNDROP", false);
}

#[test]
fn info_schema_undrop_fires() {
    let ids = fact_rule_ids_snowflake("UNDROP SCHEMA app;");
    assert!(
        ids.contains(&"INFO-SCHEMA-UNDROP".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_schema_undrop_silent_for_create_schema() {
    let ids = fact_rule_ids_snowflake("CREATE SCHEMA app;");
    assert!(
        !ids.contains(&"INFO-SCHEMA-UNDROP".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_schema_undrop() {
    assert_parity_snowflake("UNDROP SCHEMA app;", "INFO-SCHEMA-UNDROP", true);
    assert_parity_snowflake("CREATE SCHEMA app;", "INFO-SCHEMA-UNDROP", false);
}

// ─────────────────────────────────────────────────────────────────────
// PG stmt-kind-only (maintenance + notification + advanced).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_pg_maint_vacuum_fires() {
    let ids = fact_rule_ids_pg("VACUUM users;");
    assert!(
        ids.contains(&"INFO-PG-MAINT-VACUUM".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_maint_vacuum_silent_for_select() {
    let ids = fact_rule_ids_pg("SELECT 1;");
    assert!(
        !ids.contains(&"INFO-PG-MAINT-VACUUM".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_pg_maint_vacuum() {
    assert_parity_pg("VACUUM users;", "INFO-PG-MAINT-VACUUM", true);
}

#[test]
fn info_pg_maint_analyze_fires() {
    let ids = fact_rule_ids_pg("ANALYZE users;");
    assert!(
        ids.contains(&"INFO-PG-MAINT-ANALYZE".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_maint_analyze_silent_for_select() {
    let ids = fact_rule_ids_pg("SELECT 1;");
    assert!(
        !ids.contains(&"INFO-PG-MAINT-ANALYZE".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_pg_maint_analyze() {
    assert_parity_pg("ANALYZE users;", "INFO-PG-MAINT-ANALYZE", true);
}

#[test]
fn info_pg_maint_cluster_fires() {
    let ids = fact_rule_ids_pg("CLUSTER users USING users_pkey;");
    assert!(
        ids.contains(&"INFO-PG-MAINT-CLUSTER".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_maint_cluster_silent_for_select() {
    let ids = fact_rule_ids_pg("SELECT 1;");
    assert!(
        !ids.contains(&"INFO-PG-MAINT-CLUSTER".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_notify_sub_fires() {
    let ids = fact_rule_ids_pg("LISTEN events;");
    assert!(
        ids.contains(&"INFO-PG-NOTIFY-SUB".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_notify_send_fires() {
    let ids = fact_rule_ids_pg("NOTIFY events, 'payload';");
    assert!(
        ids.contains(&"INFO-PG-NOTIFY-SEND".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_notify_unsub_fires() {
    let ids = fact_rule_ids_pg("UNLISTEN events;");
    assert!(
        ids.contains(&"INFO-PG-NOTIFY-UNSUB".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_notify_silent_for_select() {
    let ids = fact_rule_ids_pg("SELECT 1;");
    assert!(
        !ids.contains(&"INFO-PG-NOTIFY-SUB".to_string())
            && !ids.contains(&"INFO-PG-NOTIFY-SEND".to_string())
            && !ids.contains(&"INFO-PG-NOTIFY-UNSUB".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_agg_new_fires() {
    let ids = fact_rule_ids_pg("CREATE AGGREGATE my_sum (int) (sfunc = int_sum, stype = int);");
    assert!(
        ids.contains(&"INFO-PG-AGG-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_op_new_fires() {
    let ids =
        fact_rule_ids_pg("CREATE OPERATOR === (leftarg = int, rightarg = int, function = my_eq);");
    assert!(ids.contains(&"INFO-PG-OP-NEW".to_string()), "ids={:?}", ids);
}

// ─────────────────────────────────────────────────────────────────────
// PG domain / sequence / type lifecycle.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_pg_domain_new_fires() {
    let ids = fact_rule_ids_pg("CREATE DOMAIN positive_int AS int CHECK (VALUE > 0);");
    assert!(
        ids.contains(&"INFO-PG-DOMAIN-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_pg_domain_new() {
    assert_parity_pg(
        "CREATE DOMAIN positive_int AS int CHECK (VALUE > 0);",
        "INFO-PG-DOMAIN-NEW",
        true,
    );
}

#[test]
fn info_pg_domain_constr_add_fires() {
    let ids =
        fact_rule_ids_pg("ALTER DOMAIN positive_int ADD CONSTRAINT chk_pos CHECK (VALUE > 0);");
    assert!(
        ids.contains(&"INFO-PG-DOMAIN-CONSTR-ADD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_domain_constr_add_silent_for_rename() {
    let ids = fact_rule_ids_pg("ALTER DOMAIN positive_int RENAME TO pos_int;");
    assert!(
        !ids.contains(&"INFO-PG-DOMAIN-CONSTR-ADD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_seq_new_fires() {
    let ids = fact_rule_ids_pg("CREATE SEQUENCE order_seq;");
    assert!(ids.contains(&"INFO-SEQ-NEW".to_string()), "ids={:?}", ids);
}

#[test]
fn info_pg_seq_chg_fires() {
    let ids = fact_rule_ids_pg("ALTER SEQUENCE order_seq INCREMENT BY 5;");
    assert!(ids.contains(&"INFO-SEQ-CHG".to_string()), "ids={:?}", ids);
}

#[test]
fn info_pg_type_new_fires() {
    let ids = fact_rule_ids_pg("CREATE TYPE address AS (street text, city text);");
    assert!(
        ids.contains(&"INFO-PG-TYPE-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_pg_type_chg_fires() {
    let ids = fact_rule_ids_pg("ALTER TYPE address OWNER TO postgres;");
    assert!(
        ids.contains(&"INFO-PG-TYPE-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// COMMENT ON (target_kind discriminator).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_comment_chg_fires_on_table_comment() {
    let ids = fact_rule_ids_snowflake("COMMENT ON TABLE users IS 'audit table';");
    assert!(
        ids.contains(&"INFO-COMMENT-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_comment_chg_silent_for_create_table() {
    let ids = fact_rule_ids_snowflake("CREATE TABLE t (a int);");
    assert!(
        !ids.contains(&"INFO-COMMENT-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_comment_chg() {
    assert_parity_snowflake(
        "COMMENT ON TABLE users IS 'audit table';",
        "INFO-COMMENT-CHG",
        true,
    );
}

#[test]
fn info_dbx_cat_comment_chg_fires() {
    let ids = fact_rule_ids_snowflake("COMMENT ON CATALOG main IS 'primary catalog';");
    assert!(
        ids.contains(&"INFO-DBX-CAT-COMMENT-CHG".to_string()),
        "ids={:?}",
        ids
    );
    // INFO-COMMENT-CHG also fires (target-kind variants are *additional*).
    assert!(
        ids.contains(&"INFO-COMMENT-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_dbx_cat_comment_chg_silent_for_table_comment() {
    let ids = fact_rule_ids_snowflake("COMMENT ON TABLE users IS 'x';");
    assert!(
        !ids.contains(&"INFO-DBX-CAT-COMMENT-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_dbx_vol_comment_chg_fires() {
    let ids = fact_rule_ids_snowflake("COMMENT ON VOLUME archive_vol IS 'cold storage';");
    assert!(
        ids.contains(&"INFO-DBX-VOL-COMMENT-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_dbx_conn_comment_chg_fires() {
    let ids = fact_rule_ids_snowflake("COMMENT ON CONNECTION snowflake_conn IS 'prod source';");
    assert!(
        ids.contains(&"INFO-DBX-CONN-COMMENT-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// TABLE CLONE (cross-dialect Standard variant).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_tbl_clone_fires_on_snowflake_clone() {
    let ids = fact_rule_ids_snowflake("CREATE TABLE clone_t CLONE src;");
    assert!(ids.contains(&"INFO-TBL-CLONE".to_string()), "ids={:?}", ids);
}

#[test]
fn info_tbl_clone_silent_for_plain_create() {
    let ids = fact_rule_ids_snowflake("CREATE TABLE t (a int);");
    assert!(
        !ids.contains(&"INFO-TBL-CLONE".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_tbl_clone() {
    assert_parity_snowflake("CREATE TABLE clone_t CLONE src;", "INFO-TBL-CLONE", true);
    assert_parity_snowflake("CREATE TABLE t (a int);", "INFO-TBL-CLONE", false);
}

// ─────────────────────────────────────────────────────────────────────
// SNW-PIPE-ERRINT.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_snw_pipe_errint_fires() {
    let sql = "CREATE PIPE my_pipe ERROR_INTEGRATION = my_notif AS COPY INTO t FROM @s;";
    let ids = fact_rule_ids_snowflake(sql);
    assert!(
        ids.contains(&"INFO-SNW-PIPE-ERRINT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_snw_pipe_errint_silent_without_error_integration() {
    let ids = fact_rule_ids_snowflake("CREATE PIPE my_pipe AS COPY INTO t FROM @s;");
    assert!(
        !ids.contains(&"INFO-SNW-PIPE-ERRINT".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// INFO-Q-PRED-TEMPORAL.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_q_pred_temporal_fires_on_current_date() {
    let ids = fact_rule_ids_snowflake("SELECT * FROM events WHERE created_at = CURRENT_DATE;");
    assert!(
        ids.contains(&"INFO-Q-PRED-TEMPORAL".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_q_pred_temporal_fires_on_current_timestamp() {
    let ids = fact_rule_ids_snowflake("SELECT * FROM events WHERE ts > CURRENT_TIMESTAMP();");
    assert!(
        ids.contains(&"INFO-Q-PRED-TEMPORAL".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_q_pred_temporal_silent_for_static_predicate() {
    let ids = fact_rule_ids_snowflake("SELECT * FROM events WHERE id = 42;");
    assert!(
        !ids.contains(&"INFO-Q-PRED-TEMPORAL".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_q_pred_temporal_silent_for_update() {
    // Fires only for SELECT, not UPDATE/DELETE.
    let ids =
        fact_rule_ids_snowflake("UPDATE events SET status = 'x' WHERE created_at = CURRENT_DATE;");
    assert!(
        !ids.contains(&"INFO-Q-PRED-TEMPORAL".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL stmt-kind-only and option-typed.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_mssql_exec_proc_fires() {
    let ids = fact_rule_ids_mssql("EXEC sp_who;");
    assert!(
        ids.contains(&"INFO-MSSQL-EXEC-PROC".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_exec_proc_silent_for_select() {
    let ids = fact_rule_ids_mssql("SELECT 1;");
    assert!(
        !ids.contains(&"INFO-MSSQL-EXEC-PROC".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_mssql_exec_proc() {
    assert_parity_mssql("EXEC sp_who;", "INFO-MSSQL-EXEC-PROC", true);
}

#[test]
fn info_mssql_set_option_fires_on_nocount_on() {
    let ids = fact_rule_ids_mssql("SET NOCOUNT ON;");
    assert!(
        ids.contains(&"INFO-MSSQL-SET-OPTION".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_set_option_silent_for_select() {
    let ids = fact_rule_ids_mssql("SELECT 1;");
    assert!(
        !ids.contains(&"INFO-MSSQL-SET-OPTION".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_identity_insert_off_fires() {
    let ids = fact_rule_ids_mssql("SET IDENTITY_INSERT dbo.users OFF;");
    assert!(
        ids.contains(&"INFO-MSSQL-IDENTITY-INSERT-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_identity_insert_off_silent_for_on() {
    let ids = fact_rule_ids_mssql("SET IDENTITY_INSERT dbo.users ON;");
    assert!(
        !ids.contains(&"INFO-MSSQL-IDENTITY-INSERT-OFF".to_string()),
        "ids={:?}",
        ids
    );
    // Sibling on-variant must still fire to confirm the typed
    // option-value discriminator is wired correctly.
    assert!(
        ids.contains(&"MSSQL-IDENTITY-INSERT-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_extmdl_drop_fires() {
    let ids = fact_rule_ids_mssql("DROP EXTERNAL MODEL my_model;");
    assert!(
        ids.contains(&"INFO-MSSQL-EXTMDL-DROP".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_vecidx_new_fires() {
    let ids =
        fact_rule_ids_mssql("CREATE VECTOR INDEX vidx ON docs (embedding) WITH (METRIC = COSINE);");
    assert!(
        ids.contains(&"INFO-MSSQL-VECIDX-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// INFO-MSSQL-HINT (query.table_hints presence).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_mssql_hint_fires_on_nolock() {
    let ids = fact_rule_ids_mssql("SELECT * FROM t WITH (NOLOCK);");
    assert!(
        ids.contains(&"INFO-MSSQL-HINT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_hint_fires_on_forcescan() {
    let ids = fact_rule_ids_mssql("SELECT * FROM t WITH (FORCESCAN);");
    assert!(
        ids.contains(&"INFO-MSSQL-HINT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_mssql_hint_silent_without_hint() {
    let ids = fact_rule_ids_mssql("SELECT * FROM t;");
    assert!(
        !ids.contains(&"INFO-MSSQL-HINT".to_string()),
        "ids={:?}",
        ids
    );
}
