// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Customer-facing tests for the v1 fact-based pipeline over view DDL
// statements (`analyze_ddl_facts` → `ViewDdlKind` dispatch). Pipeline:
//
//   parse → IR DdlPlan via `lower_ddl_stmt` → derive_facts_from_view_ddl_plan
//     → evaluate_rules → Signal
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
// VIEW-REPLACE
// ─────────────────────────────────────────────────────────────────────

#[test]
fn view_replace_fires_on_or_replace_view() {
    let ids = fact_rule_ids("CREATE OR REPLACE VIEW v AS SELECT 1 AS c;");
    assert!(ids.contains(&"VIEW-REPLACE".to_string()), "ids={:?}", ids);
}

#[test]
fn view_replace_silent_on_plain_create_view() {
    let ids = fact_rule_ids("CREATE VIEW v AS SELECT 1 AS c;");
    assert!(!ids.contains(&"VIEW-REPLACE".to_string()), "ids={:?}", ids);
}

#[test]
fn parity_view_replace() {
    assert_parity(
        "CREATE OR REPLACE VIEW v AS SELECT 1 AS c;",
        "VIEW-REPLACE",
        true,
    );
    assert_parity("CREATE VIEW v AS SELECT 1 AS c;", "VIEW-REPLACE", false);
}

// ─────────────────────────────────────────────────────────────────────
// VIEW-CHG
// ─────────────────────────────────────────────────────────────────────

#[test]
fn view_chg_fires_on_alter_view_rename() {
    let ids = fact_rule_ids("ALTER VIEW v RENAME TO v2;");
    assert!(ids.contains(&"VIEW-CHG".to_string()), "ids={:?}", ids);
}

#[test]
fn view_chg_silent_on_create_view() {
    let ids = fact_rule_ids("CREATE VIEW v AS SELECT 1 AS c;");
    assert!(!ids.contains(&"VIEW-CHG".to_string()), "ids={:?}", ids);
}

#[test]
fn parity_view_chg() {
    assert_parity("ALTER VIEW v RENAME TO v2;", "VIEW-CHG", true);
    assert_parity("CREATE VIEW v AS SELECT 1 AS c;", "VIEW-CHG", false);
}

// ─────────────────────────────────────────────────────────────────────
// VIEW-DROP
// ─────────────────────────────────────────────────────────────────────

#[test]
fn view_drop_fires_on_drop_view() {
    let ids = fact_rule_ids("DROP VIEW v;");
    assert!(ids.contains(&"VIEW-DROP".to_string()), "ids={:?}", ids);
}

#[test]
fn view_drop_silent_on_drop_table() {
    let ids = fact_rule_ids("DROP TABLE t;");
    assert!(!ids.contains(&"VIEW-DROP".to_string()), "ids={:?}", ids);
}

#[test]
fn parity_view_drop() {
    assert_parity("DROP VIEW v;", "VIEW-DROP", true);
    assert_parity("DROP TABLE t;", "VIEW-DROP", false);
}

// ─────────────────────────────────────────────────────────────────────
// VIEW-CASCADE-DROP
// ─────────────────────────────────────────────────────────────────────

#[test]
fn view_cascade_drop_fires_on_cascade() {
    let ids = fact_rule_ids("DROP VIEW v CASCADE;");
    assert!(
        ids.contains(&"VIEW-CASCADE-DROP".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn view_cascade_drop_silent_without_cascade() {
    let ids = fact_rule_ids("DROP VIEW v;");
    assert!(
        !ids.contains(&"VIEW-CASCADE-DROP".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_view_cascade_drop() {
    assert_parity("DROP VIEW v CASCADE;", "VIEW-CASCADE-DROP", true);
    assert_parity("DROP VIEW v;", "VIEW-CASCADE-DROP", false);
}
