// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Customer-facing tests for the v1 fact-based pipeline over view DDL
// statements (`analyze_ddl_facts` → `ViewDdlKind` dispatch). Pipeline:
//
//   parse → IR DdlPlan via `lower_ddl_stmt` → derive_facts_from_view_ddl_plan
//     → evaluate_rules → Finding
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
        .findings
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
    assert_parity("ALTER MATERIALIZED VIEW mv SET SECURE;", "VIEW-CHG", true);
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

// ─────────────────────────────────────────────────────────────────────
// Policy attach / detach on a view (VIEW-RAP-*, VIEW-MASK-*, VIEW-AGGPOL-RMV)
// ─────────────────────────────────────────────────────────────────────

/// Findings and context entries of the whole analysis, by rule id.
fn entry_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk(sql).expect("analyze_risk succeeds");
    report
        .findings
        .iter()
        .chain(report.context.iter())
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

const VIEW_POLICY_RULES: [&str; 8] = [
    "VIEW-RAP-ADD",
    "VIEW-RAP-RMV",
    "VIEW-RAP-RMV-ALL",
    "VIEW-MASK-ADD",
    "VIEW-MASK-RMV",
    "VIEW-AGGPOL-RMV",
    "TBL-RAP-RMV",
    "TBL-MASK-RMV",
];

fn assert_policy_rules(sql: &str, expected: &[&str]) {
    let ids = entry_ids(sql);
    for rule in VIEW_POLICY_RULES {
        assert_eq!(
            ids.contains(&rule.to_string()),
            expected.contains(&rule),
            "{rule} on {sql:?}; ids={ids:?}"
        );
    }
}

#[test]
fn view_detach_forms_fire_their_rule() {
    assert_policy_rules("ALTER VIEW v DROP ROW ACCESS POLICY p;", &["VIEW-RAP-RMV"]);
    assert_policy_rules(
        "ALTER VIEW v DROP ALL ROW ACCESS POLICIES;",
        &["VIEW-RAP-RMV-ALL"],
    );
    for sql in [
        "ALTER VIEW v ALTER COLUMN c UNSET MASKING POLICY;",
        "ALTER VIEW v MODIFY COLUMN c UNSET MASKING POLICY;",
        "ALTER VIEW v ALTER c UNSET MASKING POLICY;",
        "ALTER VIEW v ALTER COLUMN c UNSET PROJECTION POLICY;",
    ] {
        assert_policy_rules(sql, &["VIEW-MASK-RMV"]);
    }
    for sql in [
        "ALTER VIEW v UNSET AGGREGATION POLICY;",
        "ALTER VIEW v UNSET JOIN POLICY;",
    ] {
        assert_policy_rules(sql, &["VIEW-AGGPOL-RMV"]);
    }
}

#[test]
fn view_attach_forms_do_not_fire_a_detach_rule() {
    assert_policy_rules(
        "ALTER VIEW v ADD ROW ACCESS POLICY p ON (c);",
        &["VIEW-RAP-ADD"],
    );
    assert_policy_rules(
        "ALTER VIEW v ALTER COLUMN c SET MASKING POLICY m;",
        &["VIEW-MASK-ADD"],
    );
    assert_policy_rules(
        "ALTER VIEW v ALTER COLUMN c SET PROJECTION POLICY m;",
        &["VIEW-MASK-ADD"],
    );
    for sql in [
        "ALTER VIEW v RENAME TO v2;",
        "ALTER VIEW v SET SECURE;",
        "ALTER VIEW v ALTER COLUMN c UNSET TAG t;",
        "ALTER VIEW v ALTER COLUMN c DROP DEFAULT;",
        "ALTER VIEW v SET AGGREGATION POLICY p;",
    ] {
        assert_policy_rules(sql, &[]);
    }
}

#[test]
fn materialized_view_policy_forms_read_as_view_forms() {
    assert_policy_rules(
        "ALTER MATERIALIZED VIEW mv DROP ROW ACCESS POLICY p;",
        &["VIEW-RAP-RMV"],
    );
    assert_policy_rules(
        "ALTER MATERIALIZED VIEW mv DROP ALL ROW ACCESS POLICIES;",
        &["VIEW-RAP-RMV-ALL"],
    );
    assert_policy_rules(
        "ALTER MATERIALIZED VIEW mv ADD ROW ACCESS POLICY p ON (c);",
        &["VIEW-RAP-ADD"],
    );
    for sql in [
        "ALTER MATERIALIZED VIEW mv ALTER COLUMN c UNSET MASKING POLICY;",
        "ALTER MATERIALIZED VIEW db.sch.\"My MV\" MODIFY COLUMN c UNSET PROJECTION POLICY;",
    ] {
        assert_policy_rules(sql, &["VIEW-MASK-RMV"]);
    }
    assert_policy_rules(
        "ALTER MATERIALIZED VIEW mv ALTER COLUMN c SET MASKING POLICY m;",
        &["VIEW-MASK-ADD"],
    );
    for sql in [
        "ALTER MATERIALIZED VIEW mv RENAME TO mv2;",
        "ALTER MATERIALIZED VIEW mv SUSPEND;",
        "ALTER MATERIALIZED VIEW mv ALTER COLUMN c UNSET TAG t;",
    ] {
        assert_policy_rules(sql, &[]);
    }
}

#[test]
fn view_detach_keeps_the_generic_change_finding() {
    let ids = entry_ids("ALTER VIEW v DROP ROW ACCESS POLICY p;");
    assert!(ids.contains(&"VIEW-CHG".to_string()), "ids={ids:?}");
}

#[test]
fn view_detach_names_qualified_and_quoted_views() {
    assert_policy_rules(
        "ALTER VIEW db.sch.v DROP ROW ACCESS POLICY p;",
        &["VIEW-RAP-RMV"],
    );
    assert_policy_rules(
        "ALTER VIEW IF EXISTS \"My DB\".\"my schema\".\"My View\" ALTER COLUMN \"Col\" UNSET MASKING POLICY;",
        &["VIEW-MASK-RMV"],
    );
}

#[test]
fn table_policy_detach_is_unchanged() {
    assert_policy_rules("ALTER TABLE t DROP ROW ACCESS POLICY p;", &["TBL-RAP-RMV"]);
    assert_policy_rules(
        "ALTER TABLE t ALTER COLUMN c UNSET MASKING POLICY;",
        &["TBL-MASK-RMV"],
    );
}

// ─────────────────────────────────────────────────────────────────────
// ddl.view.action: the action an ALTER [MATERIALIZED] VIEW performs
// ─────────────────────────────────────────────────────────────────────

fn view_action(sql: &str) -> Option<lexega_core::facts::ddl::ViewAlterActionKind> {
    let config = lexega_core::analyzer::AnalysisConfig {
        trace_mode: true,
        ..Default::default()
    };
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("analyze_risk succeeds");
    report
        .statement_traces
        .iter()
        .filter_map(|trace| trace.facts.as_ref())
        .find_map(|facts| facts.ddl.as_ref()?.view.as_ref()?.action)
}

#[test]
fn every_alter_view_action_reaches_the_view_facts() {
    use lexega_core::facts::ddl::ViewAlterActionKind as A;
    for (sql, expected) in [
        (
            "ALTER VIEW v SET OPTIONS (description = 'x');",
            A::SetOptions,
        ),
        ("ALTER VIEW v SET (security_barrier = true);", A::SetOptions),
        (
            "ALTER VIEW v ALTER COLUMN c SET OPTIONS (description = 'x');",
            A::SetColumnOptions,
        ),
        ("ALTER VIEW v RENAME TO v2;", A::Rename),
        ("ALTER VIEW v RENAME COLUMN a TO b;", A::RenameColumn),
        ("ALTER VIEW v SET SECURE;", A::SetSecure),
        ("ALTER VIEW v UNSET SECURE;", A::UnsetSecure),
        ("ALTER VIEW v SET COMMENT = 'a';", A::SetComment),
        ("ALTER VIEW v UNSET COMMENT;", A::UnsetComment),
        (
            "ALTER VIEW v SET CHANGE_TRACKING = TRUE;",
            A::SetChangeTracking,
        ),
        ("ALTER VIEW v SET TAG t1 = 'a';", A::SetTag),
        ("ALTER VIEW v UNSET TAG t1;", A::UnsetTag),
        (
            "ALTER VIEW v ADD ROW ACCESS POLICY p ON (c);",
            A::AddRowAccessPolicy,
        ),
        (
            "ALTER VIEW v DROP ROW ACCESS POLICY p;",
            A::DropRowAccessPolicy,
        ),
        (
            "ALTER VIEW v DROP ALL ROW ACCESS POLICIES;",
            A::DropAllRowAccessPolicies,
        ),
        (
            "ALTER VIEW v SET AGGREGATION POLICY p;",
            A::SetAggregationPolicy,
        ),
        (
            "ALTER VIEW v UNSET AGGREGATION POLICY;",
            A::UnsetAggregationPolicy,
        ),
        ("ALTER VIEW v SET JOIN POLICY p;", A::SetJoinPolicy),
        ("ALTER VIEW v UNSET JOIN POLICY;", A::UnsetJoinPolicy),
        (
            "ALTER VIEW v ALTER COLUMN c SET MASKING POLICY m;",
            A::AlterColumn,
        ),
        ("ALTER VIEW v ADD COLUMN c INT;", A::AddColumn),
        (
            "ALTER VIEW v SET DATA_METRIC_SCHEDULE = '5 MINUTE';",
            A::DataMetricFunction,
        ),
        ("ALTER VIEW v OWNER TO bob;", A::Unknown),
        (
            "ALTER MATERIALIZED VIEW mv SET OPTIONS (enable_refresh = true);",
            A::SetOptions,
        ),
        ("ALTER MATERIALIZED VIEW mv RENAME TO mv2;", A::Rename),
        (
            "ALTER MATERIALIZED VIEW mv RENAME COLUMN a TO b;",
            A::RenameColumn,
        ),
        ("ALTER MATERIALIZED VIEW mv SET SECURE;", A::SetSecure),
        ("ALTER MATERIALIZED VIEW mv UNSET SECURE;", A::UnsetSecure),
        (
            "ALTER MATERIALIZED VIEW mv SET COMMENT = 'a';",
            A::SetComment,
        ),
        ("ALTER MATERIALIZED VIEW mv UNSET COMMENT;", A::UnsetComment),
        ("ALTER MATERIALIZED VIEW mv SET TAG t1 = 'a';", A::SetTag),
        ("ALTER MATERIALIZED VIEW mv UNSET TAG t1;", A::UnsetTag),
        (
            "ALTER MATERIALIZED VIEW mv ADD ROW ACCESS POLICY p ON (c);",
            A::AddRowAccessPolicy,
        ),
        (
            "ALTER MATERIALIZED VIEW mv DROP ROW ACCESS POLICY p;",
            A::DropRowAccessPolicy,
        ),
        (
            "ALTER MATERIALIZED VIEW mv DROP ALL ROW ACCESS POLICIES;",
            A::DropAllRowAccessPolicies,
        ),
        (
            "ALTER MATERIALIZED VIEW mv ALTER COLUMN c UNSET MASKING POLICY;",
            A::AlterColumn,
        ),
        ("ALTER MATERIALIZED VIEW mv SUSPEND;", A::Unknown),
    ] {
        assert_eq!(view_action(sql), Some(expected), "{sql}");
    }
}

#[test]
fn view_secure_rmv_fires_where_secure_is_removed() {
    for sql in [
        "ALTER VIEW v UNSET SECURE;",
        "ALTER VIEW IF EXISTS db.sch.\"My View\" UNSET SECURE;",
        "ALTER MATERIALIZED VIEW mv UNSET SECURE;",
    ] {
        assert_parity(sql, "VIEW-SECURE-RMV", true);
    }
    for sql in [
        "ALTER VIEW v SET SECURE;",
        "ALTER VIEW v UNSET COMMENT;",
        "ALTER MATERIALIZED VIEW mv SET SECURE;",
        "CREATE OR REPLACE VIEW v AS SELECT 1 AS c;",
    ] {
        assert_parity(sql, "VIEW-SECURE-RMV", false);
    }
}
