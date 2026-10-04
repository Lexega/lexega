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
        custom_rules: Some(rules),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .signals
        .iter()
        .filter_map(|r| match r {
            RuleMatch::Analysis(a) => Some(a.matched_rule.clone()),
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
        .statement_signals
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
