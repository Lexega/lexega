// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! v1 custom-rule predicates over catalog tags. The rule corpus is loaded
//! from v1 YAML and evaluated against a tagged catalog; each test verifies
//! that a `catalog_tags`-keyed predicate matches when the read table
//! carries the tag, and stays silent otherwise.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::{
    analyze_risk_with_policy_config, analyze_risk_with_policy_config_and_catalog_index,
};
use lexega_core::catalog::{
    CatalogColumn, CatalogDatabase, CatalogIdent, CatalogSchema, CatalogSnapshot, CatalogTable,
    CatalogTag, CATALOG_SCHEMA_VERSION,
};
use lexega_core::rules::load_v1_rules;
use lexega_core::CatalogIndex;

fn make_catalog_with_pii_tags() -> CatalogIndex {
    let snapshot = CatalogSnapshot {
        schema_version: CATALOG_SCHEMA_VERSION,
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
                tables: vec![
                    // Tagged: DATA_CLASSIFICATION=CONFIDENTIAL on the table, PII on EMAIL/SSN.
                    CatalogTable {
                        name: CatalogIdent {
                            name: "CUSTOMERS".to_string(),
                        },
                        kind: lexega_core::catalog::CatalogTableKind::Table,
                        columns: vec![
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "ID".to_string(),
                                },
                                data_type: Some("NUMBER".to_string()),
                                nullable: Some(false),
                                tags: vec![],
                            },
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "EMAIL".to_string(),
                                },
                                data_type: Some("VARCHAR".to_string()),
                                nullable: Some(true),
                                tags: vec![CatalogTag {
                                    tag_database: Some("GOVERNANCE".to_string()),
                                    tag_schema: Some("TAGS".to_string()),
                                    tag_name: "PII".to_string(),
                                    tag_value: Some("EMAIL".to_string()),
                                }],
                            },
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "SSN".to_string(),
                                },
                                data_type: Some("VARCHAR".to_string()),
                                nullable: Some(true),
                                tags: vec![CatalogTag {
                                    tag_database: Some("GOVERNANCE".to_string()),
                                    tag_schema: Some("TAGS".to_string()),
                                    tag_name: "PII".to_string(),
                                    tag_value: Some("SSN".to_string()),
                                }],
                            },
                        ],
                        row_count_estimate: None,
                        row_count_estimate_as_of: None,
                        bytes_estimate: None,
                        bytes_estimate_as_of: None,
                        constraints: vec![],
                        comment: None,
                        tags: vec![CatalogTag {
                            tag_database: Some("GOVERNANCE".to_string()),
                            tag_schema: Some("TAGS".to_string()),
                            tag_name: "DATA_CLASSIFICATION".to_string(),
                            tag_value: Some("CONFIDENTIAL".to_string()),
                        }],
                    },
                    // Untagged.
                    CatalogTable {
                        name: CatalogIdent {
                            name: "PRODUCTS".to_string(),
                        },
                        kind: lexega_core::catalog::CatalogTableKind::Table,
                        columns: vec![
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "ID".to_string(),
                                },
                                data_type: Some("NUMBER".to_string()),
                                nullable: Some(false),
                                tags: vec![],
                            },
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "NAME".to_string(),
                                },
                                data_type: Some("VARCHAR".to_string()),
                                nullable: Some(true),
                                tags: vec![],
                            },
                        ],
                        row_count_estimate: None,
                        row_count_estimate_as_of: None,
                        bytes_estimate: None,
                        bytes_estimate_as_of: None,
                        constraints: vec![],
                        comment: None,
                        tags: vec![],
                    },
                ],
            }],
        }],
    };
    CatalogIndex::from_snapshot(snapshot).expect("valid snapshot")
}

fn config_from_yaml(yaml: &str) -> AnalysisConfig {
    let loaded = load_v1_rules(yaml).expect("load v1 rules");
    let rules = lexega_core::rules::build_v1_rule_corpus(loaded, false)
        .expect("test YAMLs carry only full rules");
    let mut config = AnalysisConfig::default();
    config.custom_rules = Some(rules);
    config
}

fn fired_with_catalog(sql: &str, yaml: &str, catalog: &CatalogIndex) -> Vec<String> {
    let config = config_from_yaml(yaml);
    let report =
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, catalog).expect("analyze");
    report
        .signals
        .iter()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

fn fired_no_catalog(sql: &str, yaml: &str) -> Vec<String> {
    let config = config_from_yaml(yaml);
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .signals
        .iter()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

#[test]
fn test_catalog_tag_rule_matches_tagged_table() {
    let catalog = make_catalog_with_pii_tags();
    let yaml = r#"
rules:
  - id: TEST-TAG-001
    risk_level: high
    message: "Query accesses confidential data table"
    triggers:
      all_of:
        - kind: select
        - query.reads_table:
            exists:
              catalog_tags:
                exists:
                  all_of:
                    - key.normalized: { matches: GOVERNANCE.TAGS.DATA_CLASSIFICATION }
                    - value: { matches: CONFIDENTIAL }
"#;
    let sql = "SELECT id, email FROM analytics.public.customers;";
    let fired = fired_with_catalog(sql, yaml, &catalog);
    assert!(
        fired.contains(&"TEST-TAG-001".to_string()),
        "TEST-TAG-001 must fire on a CUSTOMERS table tagged CONFIDENTIAL. Got: {:?}",
        fired
    );
}

#[test]
fn test_catalog_tag_rule_does_not_match_untagged_table() {
    let catalog = make_catalog_with_pii_tags();
    let yaml = r#"
rules:
  - id: TEST-TAG-002
    risk_level: high
    message: "Query accesses confidential data table"
    triggers:
      all_of:
        - kind: select
        - query.reads_table:
            exists:
              catalog_tags:
                exists:
                  all_of:
                    - key.normalized: { matches: GOVERNANCE.TAGS.DATA_CLASSIFICATION }
                    - value: { matches: CONFIDENTIAL }
"#;
    let sql = "SELECT id, name FROM analytics.public.products;";
    let fired = fired_with_catalog(sql, yaml, &catalog);
    assert!(
        !fired.contains(&"TEST-TAG-002".to_string()),
        "TEST-TAG-002 must NOT fire on untagged PRODUCTS table. Got: {:?}",
        fired
    );
}

#[test]
fn test_catalog_tag_rule_no_catalog_does_not_match() {
    // Without a catalog, catalog_tags is always empty, so the exists
    // quantifier never matches.
    let yaml = r#"
rules:
  - id: TEST-TAG-003
    risk_level: high
    message: "Query accesses confidential data table"
    triggers:
      all_of:
        - kind: select
        - query.reads_table:
            exists:
              catalog_tags:
                exists:
                  key.normalized: { matches: GOVERNANCE.TAGS.DATA_CLASSIFICATION }
"#;
    let sql = "SELECT * FROM customers;";
    let fired = fired_no_catalog(sql, yaml);
    assert!(
        !fired.contains(&"TEST-TAG-003".to_string()),
        "TEST-TAG-003 must NOT fire when no catalog is attached. Got: {:?}",
        fired
    );
}

#[test]
fn test_catalog_tag_rule_matches_tag_name_only() {
    let catalog = make_catalog_with_pii_tags();
    // Match the tag name with no value filter — any value satisfies.
    let yaml = r#"
rules:
  - id: TEST-TAG-004
    risk_level: medium
    message: "Query accesses classified data"
    triggers:
      all_of:
        - kind: select
        - query.reads_table:
            exists:
              catalog_tags:
                exists:
                  key.normalized: { matches: GOVERNANCE.TAGS.DATA_CLASSIFICATION }
"#;
    let sql = "SELECT * FROM analytics.public.customers;";
    let fired = fired_with_catalog(sql, yaml, &catalog);
    assert!(
        fired.contains(&"TEST-TAG-004".to_string()),
        "TEST-TAG-004 must fire on tag name alone. Got: {:?}",
        fired
    );
}

// SELECT and UNION SELECT together are expressed via
// `kind: { in: [select, set_select] }`.
#[test]
fn test_kind_in_select_or_set_select_matches_both() {
    let catalog = make_catalog_with_pii_tags();
    let yaml = r#"
rules:
  - id: TEST-ALIAS-001
    risk_level: medium
    message: "Query accesses classified table"
    triggers:
      all_of:
        - kind: { in: [select, set_select] }
        - query.reads_table:
            exists:
              catalog_tags:
                exists:
                  key.normalized: { matches: GOVERNANCE.TAGS.DATA_CLASSIFICATION }
"#;

    // Plain SELECT must match.
    let sql_select = "SELECT * FROM analytics.public.customers;";
    let fired_select = fired_with_catalog(sql_select, yaml, &catalog);
    assert!(
        fired_select.contains(&"TEST-ALIAS-001".to_string()),
        "select must match. Got: {:?}",
        fired_select
    );

    // UNION must also match (set_select kind).
    let sql_union =
        "SELECT id FROM analytics.public.customers UNION SELECT id FROM analytics.public.products;";
    let fired_union = fired_with_catalog(sql_union, yaml, &catalog);
    assert!(
        fired_union.contains(&"TEST-ALIAS-001".to_string()),
        "set_select must match. Got: {:?}",
        fired_union
    );
}

// INSERT, UPDATE, DELETE together are expressed via
// `kind: { in: [insert, update, delete] }`.
#[test]
fn test_kind_in_dml_write_matches_insert_update_delete_but_not_select() {
    let yaml = r#"
rules:
  - id: TEST-ALIAS-002
    risk_level: low
    message: "DML write operation"
    triggers:
      all_of:
        - kind: { in: [insert, update, delete] }
"#;

    assert!(
        fired_no_catalog("INSERT INTO t VALUES (1);", yaml).contains(&"TEST-ALIAS-002".to_string()),
        "INSERT must match"
    );
    assert!(
        fired_no_catalog("UPDATE t SET x = 1;", yaml).contains(&"TEST-ALIAS-002".to_string()),
        "UPDATE must match"
    );
    assert!(
        fired_no_catalog("DELETE FROM t;", yaml).contains(&"TEST-ALIAS-002".to_string()),
        "DELETE must match"
    );
    assert!(
        !fired_no_catalog("SELECT * FROM t;", yaml).contains(&"TEST-ALIAS-002".to_string()),
        "SELECT must NOT match"
    );
}
