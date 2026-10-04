// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Customer-facing tests for the v1 fact-based pipeline over Databricks /
// Delta / SparkSQL table-maintenance statements. Covers the
// DBX-TBL-OPT, DBX-VACUUM-*, INFO-DBX-TBL-*, DBX-TBL-RESTORE,
// DBX-TBL-CACHE / INFO-DBX-TBL-CACHE-LAZY, DBX-TBL-UNCACHE,
// INFO-DBX-TBL-CLUSTER-CFG rule family end-to-end:
//
//   parse → IR TableMaintenancePlan → derive_facts → evaluate_rules → Signal
//
// Plus parity assertions vs `analyze_risk`, so customer policy /
// exception bundles that reference these rule_ids fire from either
// entry point.

use lexega_core::api::analyze_ddl_facts;
use lexega_core::api::analyze_risk;

fn fact_rule_ids(sql: &str) -> Vec<String> {
    analyze_ddl_facts(sql)
        .expect("analyze_ddl_facts succeeds")
        .into_iter()
        .map(|s| s.rule_id)
        .collect()
}

fn risk_rule_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk(sql).expect("analyze_risk succeeds");
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
// DBX-TBL-OPT: fires unconditionally on OPTIMIZE.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dbx_tbl_opt_fires_on_optimize() {
    let ids = fact_rule_ids("OPTIMIZE events;");
    assert!(ids.contains(&"DBX-TBL-OPT".to_string()), "ids={:?}", ids);
}

#[test]
fn dbx_tbl_opt_silent_on_unrelated_statement() {
    let ids = fact_rule_ids("SELECT 1;");
    assert!(!ids.contains(&"DBX-TBL-OPT".to_string()), "ids={:?}", ids);
}

#[test]
fn parity_dbx_tbl_opt() {
    assert_parity("OPTIMIZE events;", "DBX-TBL-OPT", true);
    assert_parity("OPTIMIZE events ZORDER BY (user_id);", "DBX-TBL-OPT", true);
}

// ─────────────────────────────────────────────────────────────────────
// DBX-VACUUM-ZERO + DBX-VACUUM-LOWRET: both fire when retain_hours == 0;
// only LOWRET fires for 0 < retain < 168; both silent at >= 168.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dbx_vacuum_zero_fires_on_retain_zero_hours() {
    let ids = fact_rule_ids("VACUUM events RETAIN 0 HOURS;");
    assert!(
        ids.contains(&"DBX-VACUUM-ZERO".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_vacuum_zero_silent_when_retain_omitted() {
    let ids = fact_rule_ids("VACUUM events;");
    assert!(
        !ids.contains(&"DBX-VACUUM-ZERO".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_vacuum_zero_silent_when_retain_above_zero() {
    let ids = fact_rule_ids("VACUUM events RETAIN 24 HOURS;");
    assert!(
        !ids.contains(&"DBX-VACUUM-ZERO".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_vacuum_lowret_fires_below_168() {
    let ids = fact_rule_ids("VACUUM events RETAIN 24 HOURS;");
    assert!(
        ids.contains(&"DBX-VACUUM-LOWRET".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_vacuum_lowret_also_fires_at_zero() {
    // BOTH ZERO and LOWRET fire on retain_hours == 0;
    // LOWRET predicate is `retain_hours < 168` which subsumes ZERO.
    let ids = fact_rule_ids("VACUUM events RETAIN 0 HOURS;");
    assert!(
        ids.contains(&"DBX-VACUUM-LOWRET".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_vacuum_lowret_silent_at_threshold() {
    let ids = fact_rule_ids("VACUUM events RETAIN 168 HOURS;");
    assert!(
        !ids.contains(&"DBX-VACUUM-LOWRET".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_vacuum_lowret_silent_above_threshold() {
    let ids = fact_rule_ids("VACUUM events RETAIN 200 HOURS;");
    assert!(
        !ids.contains(&"DBX-VACUUM-LOWRET".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_dbx_vacuum_zero() {
    assert_parity("VACUUM events RETAIN 0 HOURS;", "DBX-VACUUM-ZERO", true);
    assert_parity("VACUUM events RETAIN 24 HOURS;", "DBX-VACUUM-ZERO", false);
    assert_parity("VACUUM events;", "DBX-VACUUM-ZERO", false);
}

#[test]
fn parity_dbx_vacuum_lowret() {
    assert_parity("VACUUM events RETAIN 0 HOURS;", "DBX-VACUUM-LOWRET", true);
    assert_parity("VACUUM events RETAIN 24 HOURS;", "DBX-VACUUM-LOWRET", true);
    assert_parity(
        "VACUUM events RETAIN 168 HOURS;",
        "DBX-VACUUM-LOWRET",
        false,
    );
}

// ─────────────────────────────────────────────────────────────────────
// INFO-DBX-TBL-HIST: fires unconditionally on DESCRIBE HISTORY.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_dbx_tbl_hist_fires_on_describe_history() {
    let ids = fact_rule_ids("DESCRIBE HISTORY events;");
    assert!(
        ids.contains(&"INFO-DBX-TBL-HIST".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_dbx_tbl_hist() {
    assert_parity("DESCRIBE HISTORY events;", "INFO-DBX-TBL-HIST", true);
}

// ─────────────────────────────────────────────────────────────────────
// INFO-DBX-TBL-REPAIR: fires unconditionally on REPAIR TABLE (and MSCK
// REPAIR TABLE) regardless of partition mode.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_dbx_tbl_repair_fires_on_repair_table() {
    let ids = fact_rule_ids("REPAIR TABLE events;");
    assert!(
        ids.contains(&"INFO-DBX-TBL-REPAIR".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_dbx_tbl_repair_fires_on_msck_repair_table() {
    let ids = fact_rule_ids("MSCK REPAIR TABLE events;");
    assert!(
        ids.contains(&"INFO-DBX-TBL-REPAIR".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_dbx_tbl_repair_fires_with_add_partitions() {
    let ids = fact_rule_ids("REPAIR TABLE events ADD PARTITIONS;");
    assert!(
        ids.contains(&"INFO-DBX-TBL-REPAIR".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_info_dbx_tbl_repair() {
    assert_parity("REPAIR TABLE events;", "INFO-DBX-TBL-REPAIR", true);
    assert_parity("MSCK REPAIR TABLE events;", "INFO-DBX-TBL-REPAIR", true);
    assert_parity(
        "REPAIR TABLE events SYNC PARTITIONS;",
        "INFO-DBX-TBL-REPAIR",
        true,
    );
}

// ─────────────────────────────────────────────────────────────────────
// INFO-DBX-TBL-CLUSTER-CFG: ALTER TABLE ... CLUSTER BY (cols) (not NONE).
// Mirror of DBX-TBL-CLUSTER-OFF — same substrate, opposite `disabled`.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn info_dbx_tbl_cluster_cfg_fires_on_alter_cluster_by_columns() {
    let ids = fact_rule_ids("ALTER TABLE events CLUSTER BY (user_id);");
    assert!(
        ids.contains(&"INFO-DBX-TBL-CLUSTER-CFG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_dbx_tbl_cluster_cfg_silent_on_cluster_by_none() {
    let ids = fact_rule_ids("ALTER TABLE events CLUSTER BY NONE;");
    assert!(
        !ids.contains(&"INFO-DBX-TBL-CLUSTER-CFG".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// DBX-TBL-RESTORE: fires unconditionally on RESTORE.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dbx_tbl_restore_fires_on_restore_version_as_of() {
    let ids = fact_rule_ids("RESTORE TABLE events TO VERSION AS OF 3;");
    assert!(
        ids.contains(&"DBX-TBL-RESTORE".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_tbl_restore_fires_on_restore_timestamp_as_of() {
    let ids = fact_rule_ids("RESTORE events TO TIMESTAMP AS OF '2025-01-01';");
    assert!(
        ids.contains(&"DBX-TBL-RESTORE".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_dbx_tbl_restore() {
    assert_parity(
        "RESTORE TABLE events TO VERSION AS OF 3;",
        "DBX-TBL-RESTORE",
        true,
    );
    assert_parity(
        "RESTORE events TO TIMESTAMP AS OF '2025-01-01';",
        "DBX-TBL-RESTORE",
        true,
    );
}

// ─────────────────────────────────────────────────────────────────────
// DBX-TBL-CACHE vs INFO-DBX-TBL-CACHE-LAZY: discriminator on `lazy`.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dbx_tbl_cache_fires_on_eager_cache() {
    let ids = fact_rule_ids("CACHE TABLE events;");
    assert!(ids.contains(&"DBX-TBL-CACHE".to_string()), "ids={:?}", ids);
    assert!(
        !ids.contains(&"INFO-DBX-TBL-CACHE-LAZY".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn info_dbx_tbl_cache_lazy_fires_on_lazy_cache() {
    let ids = fact_rule_ids("CACHE LAZY TABLE events;");
    assert!(
        ids.contains(&"INFO-DBX-TBL-CACHE-LAZY".to_string()),
        "ids={:?}",
        ids
    );
    assert!(!ids.contains(&"DBX-TBL-CACHE".to_string()), "ids={:?}", ids);
}

#[test]
fn parity_dbx_tbl_cache_split() {
    assert_parity("CACHE TABLE events;", "DBX-TBL-CACHE", true);
    assert_parity("CACHE LAZY TABLE events;", "DBX-TBL-CACHE", false);
    assert_parity("CACHE LAZY TABLE events;", "INFO-DBX-TBL-CACHE-LAZY", true);
    assert_parity("CACHE TABLE events;", "INFO-DBX-TBL-CACHE-LAZY", false);
}

// ─────────────────────────────────────────────────────────────────────
// DBX-TBL-UNCACHE: fires unconditionally on UNCACHE TABLE.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dbx_tbl_uncache_fires_on_uncache_table() {
    let ids = fact_rule_ids("UNCACHE TABLE events;");
    assert!(
        ids.contains(&"DBX-TBL-UNCACHE".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_tbl_uncache_fires_with_if_exists() {
    let ids = fact_rule_ids("UNCACHE TABLE IF EXISTS events;");
    assert!(
        ids.contains(&"DBX-TBL-UNCACHE".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_dbx_tbl_uncache() {
    assert_parity("UNCACHE TABLE events;", "DBX-TBL-UNCACHE", true);
    assert_parity("UNCACHE TABLE IF EXISTS events;", "DBX-TBL-UNCACHE", true);
}
