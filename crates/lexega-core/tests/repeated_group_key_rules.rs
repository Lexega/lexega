// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A select item that `GROUP BY` names by position, alias or `ALL` is the
//! item as written: the rules that read its projection fire on it whichever
//! way the key names it. So is a key's expression written out again.

use lexega_core::api::{analyze_query_facts, analyze_query_facts_with_catalog};
use lexega_core::catalog::{
    CatalogColumn, CatalogDatabase, CatalogIdent, CatalogSchema, CatalogSnapshot, CatalogTable,
    CatalogTableKind, CatalogTag, CATALOG_SCHEMA_VERSION,
};
use lexega_core::rules::Finding;
use lexega_core::CatalogIndex;

/// The three ways `GROUP BY` names the first item, aliased `m`.
const NAMINGS: [&str; 3] = ["1", "m", "ALL"];

fn rule_ids(findings: &[Finding]) -> Vec<&str> {
    let mut ids: Vec<&str> = findings.iter().map(|s| s.rule_id.as_str()).collect();
    ids.sort_unstable();
    ids
}

fn count(ids: &[&str], rule: &str) -> usize {
    ids.iter().filter(|id| **id == rule).count()
}

#[test]
fn a_scalar_subquery_item_named_by_a_group_key_is_reported_once() {
    for by in NAMINGS {
        let sql = format!(
            "SELECT (SELECT MAX(o.amount) FROM orders o WHERE o.user_id = u.id) AS m, \
             COUNT(*) AS n FROM users u GROUP BY {by}"
        );
        let findings = analyze_query_facts(&sql).expect("analyzes");
        let ids = rule_ids(&findings);
        // A correlated subquery is Q-SUBQ-CORR-SEL's alone.
        assert_eq!(count(&ids, "Q-SUBQ-SCALAR"), 0, "GROUP BY {by}: {ids:?}");
        assert_eq!(count(&ids, "Q-SUBQ-CORR-SEL"), 1, "GROUP BY {by}: {ids:?}");
    }
}

#[test]
fn an_alias_of_a_subquery_item_named_by_a_group_key_is_no_second_subquery() {
    for by in ["1", "m", "ALL", "1, 2", "2"] {
        let sql = format!(
            "SELECT (SELECT MAX(o.amount) FROM orders o WHERE o.user_id = u.id) AS m, \
             m AS m2, COUNT(*) AS n FROM users u GROUP BY {by}"
        );
        let findings = analyze_query_facts(&sql).expect("analyzes");
        let ids = rule_ids(&findings);
        // A correlated subquery is Q-SUBQ-CORR-SEL's alone.
        assert_eq!(count(&ids, "Q-SUBQ-SCALAR"), 0, "GROUP BY {by}: {ids:?}");
        assert_eq!(count(&ids, "Q-SUBQ-CORR-SEL"), 1, "GROUP BY {by}: {ids:?}");
    }
}

#[test]
fn a_subquery_item_named_in_several_grouping_sets_is_reported_once() {
    for by in [
        "ROLLUP(1, 2)",
        "CUBE(1, 2)",
        "GROUPING SETS ((1), (1, 2))",
        "1, ROLLUP(2)",
    ] {
        let sql = format!(
            "SELECT (SELECT MAX(o.amount) FROM orders o WHERE o.user_id = u.id) AS m, \
             m AS m2, COUNT(*) AS n FROM users u GROUP BY {by}"
        );
        let findings = analyze_query_facts(&sql).expect("analyzes");
        let ids = rule_ids(&findings);
        // A correlated subquery is Q-SUBQ-CORR-SEL's alone.
        assert_eq!(count(&ids, "Q-SUBQ-SCALAR"), 0, "GROUP BY {by}: {ids:?}");
        assert_eq!(count(&ids, "Q-SUBQ-CORR-SEL"), 1, "GROUP BY {by}: {ids:?}");
    }
}

#[test]
fn a_volatile_subquery_item_named_by_a_group_key_is_non_deterministic() {
    for by in NAMINGS {
        let sql = format!(
            "SELECT (SELECT MAX(RANDOM()) FROM orders o) AS m, COUNT(*) AS n \
             FROM users u GROUP BY {by}"
        );
        let findings = analyze_query_facts(&sql).expect("analyzes");
        let ids = rule_ids(&findings);
        assert!(ids.contains(&"Q-NONDET"), "GROUP BY {by}: {ids:?}");
        assert!(ids.contains(&"Q-SUBQ-SCALAR"), "GROUP BY {by}: {ids:?}");
    }
}

fn column(name: &str, tags: Vec<CatalogTag>) -> CatalogColumn {
    CatalogColumn {
        name: CatalogIdent {
            name: name.to_string(),
        },
        data_type: Some("VARCHAR".to_string()),
        nullable: Some(true),
        tags,
    }
}

/// `ANALYTICS.PUBLIC.CUSTOMERS(ID, SSN)`, `SSN` tagged `PII=SSN`.
fn catalog_with_tagged_ssn() -> CatalogIndex {
    let snapshot = CatalogSnapshot {
        schema_version: CATALOG_SCHEMA_VERSION,
        listing: lexega_core::catalog::CatalogListing::Inventory,
        generated_at: None,
        source: Some("unit-test".to_string()),
        policies: vec![],
        policy_references: vec![],
        grants: None,
        provider: None,
        databases: vec![CatalogDatabase {
            name: CatalogIdent {
                name: "ANALYTICS".to_string(),
            },
            schemas: vec![CatalogSchema {
                name: CatalogIdent {
                    name: "PUBLIC".to_string(),
                },
                tables: vec![CatalogTable {
                    name: CatalogIdent {
                        name: "CUSTOMERS".to_string(),
                    },
                    kind: CatalogTableKind::Table,
                    columns: vec![
                        column("ID", vec![]),
                        column(
                            "SSN",
                            vec![CatalogTag {
                                tag_database: Some("GOVERNANCE".to_string()),
                                tag_schema: Some("TAGS".to_string()),
                                tag_name: "PII".to_string(),
                                tag_value: Some("SSN".to_string()),
                            }],
                        ),
                    ],
                    row_count_estimate: None,
                    row_count_estimate_as_of: None,
                    bytes_estimate: None,
                    bytes_estimate_as_of: None,
                    constraints: vec![],
                    comment: None,
                    tags: vec![],
                }],
            }],
        }],
    };
    CatalogIndex::from_snapshot(snapshot).expect("valid snapshot")
}

#[test]
fn a_tagged_column_in_an_item_named_by_a_group_key_keeps_its_labels() {
    let catalog = catalog_with_tagged_ssn();
    let written = analyze_query_facts_with_catalog(
        "SELECT LOWER(ssn) AS m FROM analytics.public.customers",
        &catalog,
    )
    .expect("analyzes");
    assert!(
        rule_ids(&written).contains(&"Q-FLOW-TAINT"),
        "the ungrouped item must carry the label: {:?}",
        rule_ids(&written)
    );
    for by in NAMINGS {
        let sql = format!(
            "SELECT LOWER(ssn) AS m, COUNT(*) AS n FROM analytics.public.customers GROUP BY {by}"
        );
        let findings = analyze_query_facts_with_catalog(&sql, &catalog).expect("analyzes");
        let ids = rule_ids(&findings);
        assert!(ids.contains(&"Q-FLOW-TAINT"), "GROUP BY {by}: {ids:?}");
    }
}

#[test]
fn a_tagged_column_in_a_key_written_out_again_keeps_its_labels() {
    // The item reads the key; each place the query wrote the key's
    // expression is still that expression, alone or inside another.
    let catalog = catalog_with_tagged_ssn();
    for (items, by, tainted) in [
        ("LOWER(ssn) AS m", "LOWER(ssn)", 1),
        ("CONCAT(LOWER(ssn), 'x') AS m", "LOWER(ssn)", 1),
        ("LOWER(ssn) AS m, LOWER(ssn) AS m2", "LOWER(ssn)", 2),
        ("LOWER(ssn) AS m, CONCAT(LOWER(ssn), 'x') AS m2", "1", 2),
        (
            "COALESCE(LOWER(ssn), 'Total') AS m",
            "ROLLUP(LOWER(ssn))",
            1,
        ),
    ] {
        let sql =
            format!("SELECT {items}, COUNT(*) AS n FROM analytics.public.customers GROUP BY {by}");
        let findings = analyze_query_facts_with_catalog(&sql, &catalog).expect("analyzes");
        let ids = rule_ids(&findings);
        assert_eq!(count(&ids, "Q-FLOW-TAINT"), tainted, "{sql}: {ids:?}");
    }
}

#[test]
fn six_fields_of_one_date_are_six_grouping_dimensions() {
    // Each EXTRACT is its own key: the field tells them apart.
    let findings = analyze_query_facts(
        "SELECT COUNT(*) AS n FROM t GROUP BY ROLLUP(EXTRACT(YEAR FROM d), \
         EXTRACT(QUARTER FROM d), EXTRACT(MONTH FROM d), EXTRACT(WEEK FROM d), \
         EXTRACT(DAY FROM d), EXTRACT(HOUR FROM d))",
    )
    .expect("analyzes");
    let ids = rule_ids(&findings);
    assert_eq!(count(&ids, "Q-AGG-MANYDIM"), 1, "{ids:?}");
}

/// The span of each call to `function` the statement's facts publish
/// under `clause` of its outermost scope, as `(start, end)`, in the order
/// published.
fn published_call_spans(sql: &str, clause: &str, function: &str) -> Vec<(u64, u64)> {
    fn collect(value: &serde_json::Value, function: &str, out: &mut Vec<(u64, u64)>) {
        match value {
            serde_json::Value::Object(fields) => {
                let named = fields
                    .get("name")
                    .and_then(|name| name.get("normalized"))
                    .and_then(serde_json::Value::as_str);
                let span = fields.get("source_span").and_then(|span| {
                    Some((span.get("start")?.as_u64()?, span.get("end")?.as_u64()?))
                });
                if let (Some(name), Some(span)) = (named, span) {
                    if name.eq_ignore_ascii_case(function) {
                        out.push(span);
                    }
                }
                for field in fields.values() {
                    collect(field, function, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect(item, function, out);
                }
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }

    let config = lexega_core::analyzer::AnalysisConfig {
        trace_mode: true,
        ..Default::default()
    };
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config).expect("analyzes");
    let query = report
        .statement_traces
        .iter()
        .find_map(|statement| statement.facts.as_ref()?.query.as_ref())
        .expect("query facts");
    let scope = serde_json::to_value(&query.scopes[0]).expect("serializes");
    let mut spans = Vec::new();
    collect(&scope[clause], function, &mut spans);
    spans
}

#[test]
fn a_key_written_out_again_is_published_where_it_was_written() {
    // 7..18 is the select item, 59..70 the GROUP BY key.
    let sql = "SELECT LOWER(name) AS k, COUNT(*) AS n FROM users GROUP BY LOWER(name);";
    assert_eq!(published_call_spans(sql, "projections", "LOWER"), [(7, 18)]);
    assert_eq!(published_call_spans(sql, "group_by", "LOWER"), [(59, 70)]);

    // 22..33 inside the item, 97..108 in HAVING, 125..136 in ORDER BY,
    // 77..88 the key.
    let sql = "SELECT COALESCE(UPPER(LOWER(name)), 'Total') AS k FROM users \
               GROUP BY ROLLUP(LOWER(name)) HAVING LOWER(name) <> 'x' ORDER BY LOWER(name);";
    for at in [22, 77, 97, 125] {
        assert_eq!(&sql[at..at + 11], "LOWER(name)");
    }
    assert_eq!(
        published_call_spans(sql, "projections", "LOWER"),
        [(22, 33)]
    );
    assert_eq!(published_call_spans(sql, "group_by", "LOWER"), [(77, 88)]);
    assert_eq!(
        published_call_spans(sql, "having_predicates", "LOWER"),
        [(97, 108)]
    );
    assert_eq!(published_call_spans(sql, "order_by", "LOWER"), [(125, 136)]);
}
