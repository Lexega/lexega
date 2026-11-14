// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Table read and write facts, as custom rules and the report summary
//! see them.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::facts::query::TableAccessKind;
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};

fn rule_ids_from(sql: &str, rules_yaml: &str) -> Vec<String> {
    let loaded = load_v1_rules(rules_yaml).expect("load_v1_rules");
    let rules = build_v1_rule_corpus(loaded, false)
        .expect("YAML carries only full rules — no partial-override resolution needed");
    let config = AnalysisConfig {
        custom_rules: Some(rules.into()),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .findings
        .iter()
        .map(|r| match r {
            RuleMatch::Analysis(a) => a.matched_rule.clone(),
        })
        .collect()
}

#[test]
fn test_unfiltered_scan_with_table_allowlist() {
    // YAML rules using `reads_table.none.table.name.normalized: { matches: ... }`
    // implement an "allowlist of known-small tables" semantic.

    let sql = "SELECT * FROM dim_dates";

    // No allowlist — rule fires on every single-table unfiltered scan.
    let yaml_all_tables = r#"
rules:
  - id: TEST-UNFILTERED-ALL
    risk_level: medium
    message: "Unfiltered scan on table"
    triggers:
      all_of:
        - kind: { in: [select, set_select] }
        - any_of:
            - query.has_where: false
            - query.has_tautology_where: true
        - query.has_limit: false
        - query.reads_table:
            count: { eq: 1 }
"#;
    assert_eq!(
        rule_ids_from(sql, yaml_all_tables),
        vec!["TEST-UNFILTERED-ALL"],
        "Rule without allowlist should warn on dim_dates"
    );

    // Allowlist excludes DIM_DATES — rule must NOT fire.
    let yaml_with_allowlist = r#"
rules:
  - id: TEST-UNFILTERED-ALLOWLIST
    risk_level: medium
    message: "Unfiltered scan on large table"
    triggers:
      all_of:
        - kind: { in: [select, set_select] }
        - any_of:
            - query.has_where: false
            - query.has_tautology_where: true
        - query.has_limit: false
        - query.reads_table:
            count: { eq: 1 }
        - query.reads_table:
            none:
              table.name.normalized:
                matches: DIM_DATES
"#;
    assert!(
        rule_ids_from(sql, yaml_with_allowlist).is_empty(),
        "Rule with DIM_DATES in allowlist should NOT warn"
    );

    // Allowlist covers a different table — rule still fires on dim_dates.
    let yaml_other_allowlist = r#"
rules:
  - id: TEST-UNFILTERED-OTHER
    risk_level: medium
    message: "Unfiltered scan on large table"
    triggers:
      all_of:
        - kind: { in: [select, set_select] }
        - any_of:
            - query.has_where: false
            - query.has_tautology_where: true
        - query.has_limit: false
        - query.reads_table:
            count: { eq: 1 }
        - query.reads_table:
            none:
              table.name.normalized:
                matches: OTHER_TABLE
"#;
    assert_eq!(
        rule_ids_from(sql, yaml_other_allowlist),
        vec!["TEST-UNFILTERED-OTHER"],
        "Rule with other_table in allowlist should warn on dim_dates"
    );
}

#[test]
fn test_merge_handling() {
    // MERGE INTO target_table contributes exactly one DML write
    // target and tags it with `TableAccessKind::ReadAndWritten` —
    // the read-on-target semantic is encoded on the write entry
    // rather than double-listed in `reads_table`. The USING side
    // lives in `reads_table`. The aggregate count surfaces in
    // `report.summary.tables_written`.
    let bounded_merge = r#"
            MERGE INTO target_table t
            USING source_table s
            ON t.id = s.id
            WHEN MATCHED THEN UPDATE SET t.value = s.value
            WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)
        "#;
    let config = AnalysisConfig {
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(bounded_merge, &config).expect("analyze");
    assert_eq!(
        report.summary.tables_written, 1,
        "MERGE should contribute 1 DML write target"
    );

    let merge_facts = report
        .statement_traces
        .iter()
        .find_map(|s| s.facts.as_ref())
        .expect("trace mode should populate per-statement facts");
    let query = merge_facts
        .query
        .as_ref()
        .expect("MERGE should carry QueryFacts");

    let target_write = query
        .writes_table
        .iter()
        .find(|te| {
            te.table
                .name
                .normalized
                .eq_ignore_ascii_case("TARGET_TABLE")
        })
        .unwrap_or_else(|| {
            panic!(
                "writes_table should record target_table; got {:?}",
                query
                    .writes_table
                    .iter()
                    .map(|te| te.table.name.raw.clone())
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        target_write.access_kind,
        TableAccessKind::ReadAndWritten,
        "MERGE target_table must be tagged ReadAndWritten — the \
         read-on-target semantic is encoded on the write entry"
    );

    assert!(
        query.reads_table.iter().any(|te| te
            .table
            .name
            .normalized
            .eq_ignore_ascii_case("SOURCE_TABLE")),
        "reads_table should record the USING source_table; got {:?}",
        query
            .reads_table
            .iter()
            .map(|te| te.table.name.raw.clone())
            .collect::<Vec<_>>()
    );
}

/// `ANALYTICS.PUBLIC`: `USERS (ID, EMAIL, NAME)`, `ORDERS (ID, USER_ID,
/// QUARTER, AMOUNT)` and `ARCHIVE (ID, NAME)`.
fn update_catalog() -> lexega_core::catalog::CatalogIndex {
    let snapshot: lexega_core::catalog::CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [
                {"name": "USERS", "kind": "Table", "columns": [{"name": "ID"}, {"name": "EMAIL"}, {"name": "NAME"}]},
                {"name": "ORDERS", "kind": "Table", "columns": [{"name": "ID"}, {"name": "USER_ID"}, {"name": "QUARTER"}, {"name": "AMOUNT"}]},
                {"name": "ARCHIVE", "kind": "Table", "columns": [{"name": "ID"}, {"name": "NAME"}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    lexega_core::catalog::CatalogIndex::from_snapshot(snapshot).expect("index")
}

/// What MySQL `sql`, one statement, publishes with [`update_catalog`]:
/// the tables it writes, each column reference as `TABLE.NAME` (`?NAME`
/// for a column of no table), the rules that fire and the tables the
/// catalog lacks.
fn mysql_update(sql: &str) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let config = AnalysisConfig {
        dialect: Some(lexega_core::dialect::mysql()),
        trace_mode: true,
        ..Default::default()
    };
    let report = lexega_core::api::analyze_risk_with_policy_config_and_catalog_index(
        sql,
        &config,
        &update_catalog(),
    )
    .expect("analyze");
    let query = report
        .statement_traces
        .iter()
        .find_map(|s| s.facts.as_ref()?.query.as_ref())
        .expect("trace mode populates the statement's query facts");
    let written = query
        .writes_table
        .iter()
        .map(|te| te.table.name.normalized.clone())
        .collect();
    let referenced = query
        .references_column
        .iter()
        .map(|event| match &event.column.table {
            Some(table) => format!("{}.{}", table.name.normalized, event.column.name.normalized),
            None => format!("?{}", event.column.name.normalized),
        })
        .collect();
    let rules = report
        .findings
        .iter()
        .map(|r| match r {
            RuleMatch::Analysis(a) => a.matched_rule.clone(),
        })
        .collect();
    (
        written,
        referenced,
        rules,
        report.catalog_info.missing_tables,
    )
}

#[test]
fn a_multi_table_update_writes_the_table_its_assignment_names() {
    let (written, referenced, _, _) = mysql_update(
        "UPDATE analytics.public.orders o JOIN analytics.public.users u ON u.id = o.user_id \
         SET u.name = o.quarter WHERE o.amount > 1",
    );
    assert_eq!(written, ["USERS"]);
    assert!(
        referenced.contains(&"USERS.NAME".to_string()),
        "{referenced:?}"
    );
    assert!(
        !referenced.contains(&"ORDERS.NAME".to_string()),
        "{referenced:?}"
    );
    // A bare name only the joined table has is that table's.
    let (written, referenced, rules, _) = mysql_update(
        "UPDATE analytics.public.orders o JOIN analytics.public.users u ON u.id = o.user_id \
         SET email = 'x' WHERE o.amount > 1",
    );
    assert_eq!(written, ["USERS"]);
    assert!(
        referenced.contains(&"USERS.EMAIL".to_string()),
        "{referenced:?}"
    );
    assert!(
        !rules.iter().any(|rule| rule.starts_with("CAT-COL")),
        "{rules:?}"
    );
    // Each table an assignment names is written, the target among them.
    let (written, _, _, _) = mysql_update(
        "UPDATE analytics.public.orders o, analytics.public.users u \
         SET o.quarter = 'q1', u.name = 'x' WHERE u.id = o.user_id",
    );
    assert_eq!(written, ["ORDERS", "USERS"]);
}

#[test]
fn a_multi_table_assignment_raises_what_a_read_of_its_name_raises() {
    // Both tables have the name: MySQL refuses it as ambiguous.
    let (_, _, rules, _) = mysql_update(
        "UPDATE analytics.public.users u JOIN analytics.public.archive a ON a.id = u.id \
         SET name = 'x' WHERE u.id = 1",
    );
    assert!(
        rules.contains(&"CAT-COL-AMBIGUOUS".to_string()),
        "{rules:?}"
    );
    let (_, _, rules, _) = mysql_update(
        "UPDATE analytics.public.users u JOIN analytics.public.archive a ON a.id = u.id \
         SET u.nosuch = 1 WHERE u.id = 1",
    );
    assert!(rules.contains(&"CAT-COL-UNKNOWN".to_string()), "{rules:?}");
}

#[test]
fn a_derived_table_listed_first_is_no_target_and_no_table() {
    let (written, _, _, missing) = mysql_update(
        "UPDATE (SELECT id, email FROM analytics.public.users) d \
         JOIN analytics.public.orders o ON o.user_id = d.id SET o.quarter = d.email",
    );
    assert_eq!(written, ["ORDERS"]);
    assert!(missing.is_empty(), "{missing:?}");
}

// The query of a definition reads its tables: the summary counts them as it
// counts a SELECT's.
#[test]
fn the_tables_a_definition_reads_are_counted() {
    for (sql, read) in [
        (
            "CREATE TABLE reporting.daily AS SELECT id FROM sales.orders WHERE total > 0;",
            1,
        ),
        (
            "CREATE VIEW v AS SELECT a.id FROM a JOIN b ON a.id = b.id;",
            2,
        ),
        ("CREATE TABLE t (id INT);", 0),
        ("DROP TABLE t;", 0),
    ] {
        let report = lexega_core::api::analyze_risk(sql).expect("should analyze");
        assert_eq!(report.summary.tables_read, read, "{sql}");
    }
}
