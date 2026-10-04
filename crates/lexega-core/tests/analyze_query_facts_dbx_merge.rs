// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Customer-facing test for DBX-MERGE-SCHEMA-EVO via the v1 fact-based
// pipeline. MERGE statements lower through `RelPlan::Merge`, which
// carries the `with_schema_evolution` flag; `QueryFacts.merge` projects
// it for the rule predicate.

use lexega_core::api::analyze_query_facts;
use lexega_core::api::analyze_risk;

fn fact_rule_ids(sql: &str) -> Vec<String> {
    analyze_query_facts(sql)
        .expect("analyze_query_facts succeeds")
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

const MERGE_WITH_EVO: &str = "MERGE WITH SCHEMA EVOLUTION INTO target t \
                              USING source s ON t.id = s.id \
                              WHEN MATCHED THEN UPDATE SET t.v = s.v;";

const MERGE_PLAIN: &str = "MERGE INTO target t USING source s ON t.id = s.id \
                           WHEN MATCHED THEN UPDATE SET t.v = s.v;";

#[test]
fn dbx_merge_schema_evo_fires_with_clause() {
    let ids = fact_rule_ids(MERGE_WITH_EVO);
    assert!(
        ids.contains(&"DBX-MERGE-SCHEMA-EVO".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn dbx_merge_schema_evo_silent_without_clause() {
    let ids = fact_rule_ids(MERGE_PLAIN);
    assert!(
        !ids.contains(&"DBX-MERGE-SCHEMA-EVO".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_dbx_merge_schema_evo() {
    let risk_pos = risk_rule_ids(MERGE_WITH_EVO);
    let fact_pos = fact_rule_ids(MERGE_WITH_EVO);
    assert!(
        risk_pos.contains(&"DBX-MERGE-SCHEMA-EVO".to_string()),
        "analyze_risk must fire on WITH SCHEMA EVOLUTION; analyze_risk ids={:?}",
        risk_pos
    );
    assert!(
        fact_pos.contains(&"DBX-MERGE-SCHEMA-EVO".to_string()),
        "fact pipeline must fire on WITH SCHEMA EVOLUTION; new_ids={:?}",
        fact_pos
    );

    let risk_neg = risk_rule_ids(MERGE_PLAIN);
    let fact_neg = fact_rule_ids(MERGE_PLAIN);
    assert!(
        !risk_neg.contains(&"DBX-MERGE-SCHEMA-EVO".to_string()),
        "analyze_risk must stay silent on plain MERGE; analyze_risk ids={:?}",
        risk_neg
    );
    assert!(
        !fact_neg.contains(&"DBX-MERGE-SCHEMA-EVO".to_string()),
        "fact pipeline must stay silent on plain MERGE; new_ids={:?}",
        fact_neg
    );
}
