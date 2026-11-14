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

    AnalysisConfig {
        custom_rules: Some(rules.into()),
        ..Default::default()
    }
}

fn fired_with_catalog(sql: &str, yaml: &str, catalog: &CatalogIndex) -> Vec<String> {
    let config = config_from_yaml(yaml);
    let report =
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, catalog).expect("analyze");
    report
        .entries()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

fn fired_no_catalog(sql: &str, yaml: &str) -> Vec<String> {
    let config = config_from_yaml(yaml);
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .entries()
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
fn a_table_named_by_identifier_of_a_string_is_the_table_the_string_names() {
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
    for sql in [
        "SELECT id, email FROM IDENTIFIER('analytics.public.customers');",
        "SELECT id, email FROM IDENTIFIER('\"ANALYTICS\".public.customers');",
        "SELECT p.id FROM analytics.public.products p \
         JOIN IDENTIFIER('analytics.public.customers') c ON c.id = p.id;",
    ] {
        let fired = fired_with_catalog(sql, yaml, &catalog);
        assert!(
            fired.contains(&"TEST-TAG-001".to_string()),
            "{sql}: {fired:?}"
        );
        let missing = missing_tables(sql, lexega_core::dialect::snowflake());
        assert!(missing.is_empty(), "{sql}: {missing:?}");
    }
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

/// The tables a report lists as absent from the catalog.
fn missing_tables(sql: &str, dialect: lexega_core::dialect::DialectRef) -> Vec<String> {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    analyze_risk_with_policy_config_and_catalog_index(sql, &config, &make_catalog_with_pii_tags())
        .expect("analyze")
        .catalog_info
        .missing_tables
}

#[test]
fn a_table_the_catalog_has_is_not_listed_as_missing_under_a_lower_folding_dialect() {
    let sql =
        "SELECT id FROM analytics.public.customers; SELECT id FROM analytics.public.elsewhere;";
    for dialect in [
        lexega_core::dialect::snowflake(),
        lexega_core::dialect::postgres(),
    ] {
        let name = dialect.name().to_string();
        let missing = missing_tables(sql, dialect);
        assert_eq!(missing.len(), 1, "{name}: {missing:?}");
        assert!(
            missing[0].eq_ignore_ascii_case("analytics.public.elsewhere"),
            "{name}: {missing:?}"
        );
    }
}

/// The tables a Snowflake report lists as absent from the catalog of
/// [`quoted_name_snapshot`].
fn missing_from_quoted_names(sql: &str) -> Vec<String> {
    let catalog = CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot");
    analyze_risk_with_policy_config_and_catalog_index(sql, &AnalysisConfig::default(), &catalog)
        .expect("analyze")
        .catalog_info
        .missing_tables
}

fn assert_missing(sql: &str, expected: &[&str]) {
    let missing = missing_from_quoted_names(sql);
    assert!(
        missing.len() == expected.len()
            && missing
                .iter()
                .zip(expected)
                .all(|(listed, written)| listed.eq_ignore_ascii_case(written)),
        "{sql}: {missing:?}"
    );
}

#[test]
fn a_missing_table_is_listed_once_where_the_script_first_names_it() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing(
        "SELECT id FROM zz_a; SELECT id FROM zz_a; DELETE FROM zz_a",
        &["zz_a"],
    );
    assert_missing(
        "SELECT a.id FROM zz_b a JOIN zz_a b ON a.id = b.id JOIN zz_c c ON c.id = a.id",
        &["zz_b", "zz_a", "zz_c"],
    );
    assert_missing("INSERT INTO zz_w SELECT id FROM zz_r", &["zz_w", "zz_r"]);
    assert_missing(
        "SELECT id FROM zz_late; SELECT l.id FROM zz_early e JOIN zz_late l ON l.id = e.id",
        &["zz_late", "zz_early"],
    );
}

#[test]
fn a_routine_is_not_listed_as_a_missing_table() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing(
        "CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS \
         $$ BEGIN DELETE FROM zz_in_body; END $$; SELECT id FROM zz_after",
        &["zz_in_body", "zz_after"],
    );
    assert_missing(
        "CREATE FUNCTION f() RETURNS INT AS 'SELECT 1'; SELECT f() FROM zz_read",
        &["zz_read"],
    );
}

#[test]
fn a_table_is_missing_by_its_whole_reference() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing("SELECT id FROM analytics.public.\"my.tbl\"", &[]);
    assert_missing("SELECT id FROM analytics.public.\"MyTable\"", &[]);
    assert_missing(
        "SELECT id FROM analytics.other.\"MyTable\"",
        &["analytics.other.\"MyTable\""],
    );
    assert_missing(
        "SELECT id FROM elsewhere.public.\"MyTable\"",
        &["elsewhere.public.\"MyTable\""],
    );
}

/// The tables a report under `dialect` lists as absent from `catalog`.
fn assert_missing_from(
    catalog: &CatalogIndex,
    dialect: Option<lexega_core::dialect::DialectRef>,
    sql: &str,
    expected: &[&str],
) {
    let config = AnalysisConfig {
        dialect,
        ..Default::default()
    };
    let missing = analyze_risk_with_policy_config_and_catalog_index(sql, &config, catalog)
        .expect("analyze")
        .catalog_info
        .missing_tables;
    assert!(
        missing.len() == expected.len()
            && missing
                .iter()
                .zip(expected)
                .all(|(listed, written)| listed.eq_ignore_ascii_case(written)),
        "{sql}: {missing:?}"
    );
}

#[test]
fn a_bulk_load_target_is_listed_as_a_missing_table() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing("COPY INTO zz_copy FROM @zz_stage", &["zz_copy"]);
    assert_missing(
        "COPY INTO zz_copy FROM (SELECT $1 FROM @zz_stage)",
        &["zz_copy"],
    );
    // A column list after the target is no part of its name.
    assert_missing("COPY INTO zz_copy (a, b) FROM @zz_stage", &["zz_copy"]);
    assert_missing(
        "COPY INTO analytics.public.zz_copy (a) FROM @zz_stage",
        &["analytics.public.zz_copy"],
    );
    // An index is read under the dialect it was built under.
    let databricks_catalog = {
        let _folding = lexega_core::set_normalization_dialect("databricks");
        CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot")
    };
    assert_missing_from(
        &databricks_catalog,
        Some(lexega_core::dialect::databricks()),
        "COPY INTO zz_dbx FROM '/mnt/x' FILEFORMAT = CSV",
        &["zz_dbx"],
    );
    let mssql_catalog = {
        let _folding = lexega_core::set_normalization_dialect("mssql");
        CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot")
    };
    assert_missing_from(
        &mssql_catalog,
        Some(lexega_core::dialect::mssql()),
        "BULK INSERT dbo.zz_bulk FROM 'c:\\x.csv'",
        &["dbo.zz_bulk"],
    );
    // An object that is no table is not asked for.
    assert_missing("CREATE SEQUENCE zz_seq", &[]);
    assert_missing("CREATE DATABASE zz_db", &[]);
    assert_missing("CREATE STAGE zz_stage URL = 's3://b/p'", &[]);
}

#[test]
fn the_tables_a_defining_query_reads_are_listed() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing("CREATE VIEW zz_v AS SELECT id FROM zz_src", &["zz_src"]);
    assert_missing("CREATE TABLE zz_ct AS SELECT id FROM zz_src", &["zz_src"]);
    assert_missing(
        "CREATE MATERIALIZED VIEW zz_mv AS SELECT id FROM zz_src",
        &["zz_src"],
    );
    assert_missing(
        "CREATE DYNAMIC TABLE zz_dt TARGET_LAG = '1 minute' WAREHOUSE = wh AS \
         SELECT a.id FROM zz_first a JOIN zz_second b ON a.id = b.id",
        &["zz_first", "zz_second"],
    );
    assert_missing(
        "CREATE VIEW zz_v AS SELECT id FROM analytics.public.\"MyTable\"",
        &[],
    );
}

#[test]
fn a_table_the_script_created_is_not_listed_as_missing() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing(
        "CREATE TABLE zz_new (id INT); SELECT id FROM zz_new; \
         INSERT INTO zz_new (id) VALUES (1); ALTER TABLE zz_new ADD COLUMN x INT",
        &[],
    );
    assert_missing(
        "CREATE VIEW zz_vw AS SELECT 1 AS id; SELECT id FROM ZZ_VW",
        &[],
    );
    assert_missing(
        "USE DATABASE otherdb; USE SCHEMA other; CREATE TABLE zz_s (id INT); \
         SELECT id FROM zz_s; SELECT id FROM otherdb.other.zz_s",
        &[],
    );
    // A read before the statement that creates the table, and a table of
    // the same name in another schema, are still missing.
    assert_missing(
        "SELECT id FROM zz_late; CREATE TABLE zz_late (id INT)",
        &["zz_late"],
    );
    assert_missing(
        "CREATE TABLE s1.zz_q (id INT); SELECT id FROM s2.zz_q",
        &["s2.zz_q"],
    );
}

#[test]
fn a_ddl_target_is_asked_of_the_catalog_and_listed_as_it_is_written() {
    let listed = |dialect: lexega_core::dialect::DialectRef, sql: &str| -> Vec<String> {
        let _folding = lexega_core::set_normalization_dialect(dialect.name());
        let catalog = CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot");
        let config = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyze")
            .catalog_info
            .missing_tables
    };
    let snowflake = lexega_core::dialect::snowflake;
    // A quoted target the catalog has is found as a quoted read of it is.
    for sql in [
        "DROP VIEW analytics.public.\"MyTable\"",
        "COPY INTO analytics.public.\"MyTable\" FROM @zz_stage",
        "SELECT id FROM analytics.public.\"MyTable\"",
    ] {
        assert_eq!(listed(snowflake(), sql), Vec::<String>::new(), "{sql}");
    }
    assert_eq!(
        listed(
            lexega_core::dialect::postgres(),
            "DROP VIEW analytics.public.\"MyTable\""
        ),
        Vec::<String>::new()
    );
    // Quoting keeps the case: `"MYTABLE"` is another table.
    assert_eq!(
        listed(snowflake(), "DROP VIEW analytics.public.\"MYTABLE\""),
        ["analytics.public.\"MYTABLE\""]
    );
    // A view the script created under a quoted name is not missing.
    assert_eq!(
        listed(
            snowflake(),
            "CREATE VIEW \"MyView\" AS SELECT id FROM analytics.public.\"MyTable\"; \
             SELECT id FROM \"MyView\""
        ),
        Vec::<String>::new()
    );
    // Targets and reads are listed as written.
    assert_eq!(
        listed(
            snowflake(),
            "COPY INTO zz_copy FROM @zz_stage; DROP VIEW zz_dv; SELECT id FROM zz_read"
        ),
        ["zz_copy", "zz_dv", "zz_read"]
    );
    assert_eq!(
        listed(
            lexega_core::dialect::mssql(),
            "BULK INSERT dbo.zz_bulk FROM 'f.csv'; DROP VIEW zz_dv; SELECT id FROM dbo.zz_read"
        ),
        ["dbo.zz_bulk", "zz_dv", "dbo.zz_read"]
    );
    // Each entry is the reference it is told apart by, the session's
    // defaults filling what it omits.
    assert_eq!(
        listed(
            snowflake(),
            "USE DATABASE d; USE SCHEMA s1; DROP TABLE zz_t; USE SCHEMA s2; DROP TABLE zz_t"
        ),
        ["d.s1.zz_t", "d.s2.zz_t"]
    );
    assert_eq!(
        listed(
            snowflake(),
            "USE DATABASE d; USE SCHEMA s1; SELECT id FROM zz_t; USE SCHEMA s2; SELECT id FROM zz_t"
        ),
        ["d.s1.zz_t", "d.s2.zz_t"]
    );
}

#[test]
fn a_name_a_template_writes_part_of_is_one_table_never_asked_of_the_catalog() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    let catalog = CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot");
    // (statement, the tables the report lists as missing)
    let cases: &[(&str, &[&str])] = &[
        ("SELECT id FROM t_{{ s }} WHERE id = 1", &[]),
        ("SELECT id FROM {{ s }}_t WHERE id = 1", &[]),
        ("SELECT id FROM {{ db }}.{{ s }}_t WHERE id = 1", &[]),
        (
            "SELECT id FROM analytics.public.t_{{ s }} WHERE id = 1",
            &[],
        ),
        ("SELECT id FROM {{ s }} WHERE id = 1", &[]),
        (
            "SELECT a.id FROM zz_other a JOIN t_{{ s }} b ON a.id = b.id",
            &["zz_other"],
        ),
        ("DELETE FROM t_{{ s }} WHERE id = 1", &[]),
        ("UPDATE t_{{ s }} SET id = 2 WHERE id = 1", &[]),
        (
            "INSERT INTO t_{{ s }} SELECT id FROM zz_other",
            &["zz_other"],
        ),
        // A derived table so aliased, its columns read through the alias.
        (
            "SELECT a_{{ s }}.id FROM (SELECT id FROM zz_other) AS a_{{ s }} WHERE a_{{ s }}.id = 1",
            &["zz_other"],
        ),
        // A table-valued function so named is one call.
        ("SELECT * FROM {{ schema }}.fn(1) AS f WHERE f.c = 1", &[]),
        ("SELECT * FROM t_{{ s }}(1) WHERE c = 1", &[]),
        ("SELECT * FROM {{ my_tvf }}(1) WHERE c = 1", &[]),
        (
            "SELECT * FROM zz_other r JOIN {{ schema }}.fn(1) f ON r.id = f.id",
            &["zz_other"],
        ),
        (
            "DELETE FROM t_{{ s }} WHERE id IN (SELECT id FROM {{ schema }}.fn(1))",
            &[],
        ),
    ];
    for (sql, missing) in cases {
        let report = analyze_risk_with_policy_config_and_catalog_index(
            sql,
            &AnalysisConfig::default(),
            &catalog,
        )
        .expect("analyze");
        let summary = &report.summary;
        assert_eq!(
            (
                summary.statements_parsed,
                summary.statements_analyzed,
                summary.statements_skipped
            ),
            (1, 1, 0),
            "{sql}"
        );
        let unknown = report.entries().any(|m| match m {
            lexega_core::analyzer::RuleMatch::Analysis(g) => g.matched_rule == "CAT-TBL-UNKNOWN",
        });
        assert_eq!(unknown, !missing.is_empty(), "{sql}");
        assert_missing(sql, missing);
    }
}

#[test]
fn a_statement_that_reads_the_table_it_creates_lists_it() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing(
        "CREATE OR REPLACE TABLE zz_h AS SELECT id FROM zz_h WHERE id > 0",
        &["zz_h"],
    );
    assert_missing(
        "CREATE OR REPLACE TABLE zz_h AS \
         SELECT a.id FROM zz_h a JOIN zz_other b ON a.id = b.id",
        &["zz_h", "zz_other"],
    );
    // Read only inside an expression's subquery.
    assert_missing(
        "CREATE OR REPLACE TABLE zz_h AS SELECT (SELECT MAX(id) FROM zz_h) AS m",
        &["zz_h"],
    );
    assert_missing(
        "CREATE OR REPLACE TABLE zz_h AS SELECT 1 AS id WHERE EXISTS (SELECT 1 FROM zz_h)",
        &["zz_h"],
    );
    assert_missing(
        "CREATE OR REPLACE TABLE zz_h AS SELECT 1 AS id WHERE 1 IN (SELECT id FROM zz_h)",
        &["zz_h"],
    );
    assert_missing(
        "CREATE OR REPLACE TABLE zz_h AS \
         SELECT CASE WHEN (SELECT COUNT(*) FROM zz_h) > 0 THEN 1 ELSE 0 END AS n",
        &["zz_h"],
    );
    assert_missing("CREATE VIEW zz_v AS SELECT id FROM zz_v", &["zz_v"]);
}

#[test]
fn a_created_table_is_not_missing_for_the_statements_after_it() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    assert_missing(
        "CREATE VIEW zz_v AS SELECT id FROM zz_v2; SELECT id FROM zz_v",
        &["zz_v2"],
    );
    assert_missing(
        "CREATE TABLE zz_t (id INT); CREATE OR REPLACE TABLE zz_t AS SELECT id FROM zz_t",
        &[],
    );
    // The next statement starts where the creating one ends.
    assert_missing("CREATE TABLE zz_n (id INT);DROP TABLE zz_n", &[]);
    assert_missing(
        "CREATE TABLE zz_n AS SELECT 1 AS id;INSERT INTO zz_n (id) VALUES (1)",
        &[],
    );
    // The index is keyed under the folding the statements are read under.
    let _mssql = lexega_core::set_normalization_dialect("mssql");
    let catalog = CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot");
    assert_missing_from(
        &catalog,
        Some(lexega_core::dialect::mssql()),
        "CREATE TABLE dbo.zz_n (id INT)DROP TABLE dbo.zz_n",
        &[],
    );
}

#[test]
fn a_ddl_target_is_asked_for_with_the_sessions_defaults() {
    let catalog = CatalogIndex::from_snapshot(snapshot_of(&[
        ("PUBLIC", &["CUSTOMERS"]),
        ("OTHER", &["CUSTOMERS"]),
    ]))
    .expect("valid snapshot");
    let alter = "ALTER TABLE customers ADD COLUMN x INT";
    for (session, expected) in [
        ("USE DATABASE analytics; USE SCHEMA public; ", vec![]),
        ("USE DATABASE analytics; USE SCHEMA other; ", vec![]),
        (
            "USE DATABASE analytics; USE SCHEMA nosuch; ",
            vec!["analytics.nosuch.customers"],
        ),
        // Two schemas hold the name and nothing says which is meant.
        ("", vec!["customers"]),
    ] {
        assert_missing_from(&catalog, None, &format!("{session}{alter}"), &expected);
    }
}

/// A catalog whose tables are declared with quoted names: one mixed-case,
/// one holding a dot.
fn quoted_name_snapshot() -> CatalogSnapshot {
    snapshot_of(&[("PUBLIC", &["\"MyTable\"", "\"my.tbl\""])])
}

/// A catalog of one database, `ANALYTICS`, with the given schemas and their
/// tables, each of one column.
fn snapshot_of(schemas: &[(&str, &[&str])]) -> CatalogSnapshot {
    let ident = |name: &str| CatalogIdent {
        name: name.to_string(),
    };
    let table = |name: &str| CatalogTable {
        name: ident(name),
        kind: lexega_core::catalog::CatalogTableKind::Table,
        columns: vec![CatalogColumn {
            name: ident("ID"),
            data_type: Some("NUMBER".to_string()),
            nullable: Some(false),
            tags: vec![],
        }],
        row_count_estimate: None,
        row_count_estimate_as_of: None,
        bytes_estimate: None,
        bytes_estimate_as_of: None,
        constraints: vec![],
        comment: None,
        tags: vec![],
    };
    CatalogSnapshot {
        schema_version: CATALOG_SCHEMA_VERSION,
        listing: lexega_core::catalog::CatalogListing::Inventory,
        generated_at: None,
        source: Some("unit-test".to_string()),
        policies: vec![],
        policy_references: vec![],
        grants: None,
        provider: None,
        databases: vec![CatalogDatabase {
            name: ident("ANALYTICS"),
            schemas: schemas
                .iter()
                .map(|(schema, tables)| CatalogSchema {
                    name: ident(schema),
                    tables: tables.iter().map(|name| table(name)).collect(),
                })
                .collect(),
        }],
    }
}

/// What a Snowflake analysis reports against a catalog index built on a
/// thread of its own after that thread analysed a statement under `earlier`.
fn report_against_index_built_after(earlier: Option<lexega_core::dialect::DialectRef>) -> String {
    std::thread::spawn(move || {
        if let Some(dialect) = earlier {
            let config = AnalysisConfig {
                dialect: Some(dialect),
                ..Default::default()
            };
            analyze_risk_with_policy_config("SELECT 1", &config)
                .expect("the earlier statement is analysed");
        }
        // Built under the folding the analysis reads it in.
        let catalog = {
            let _folding = lexega_core::set_normalization_dialect("snowflake");
            CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot")
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(
            "SELECT id FROM analytics.public.\"MyTable\"",
            &AnalysisConfig::default(),
            &catalog,
        )
        .expect("analyze");
        let mut rules: Vec<String> = report
            .entries()
            .map(|lexega_core::analyzer::RuleMatch::Analysis(finding)| finding.matched_rule.clone())
            .collect();
        rules.sort();
        format!(
            "missing {:?} rules {rules:?}",
            report.catalog_info.missing_tables
        )
    })
    .join()
    .expect("the thread finishes")
}

#[test]
fn a_catalog_index_is_the_same_whatever_its_thread_analysed_before() {
    let alone = report_against_index_built_after(None);
    assert!(alone.starts_with("missing []"), "{alone}");
    for earlier in [
        lexega_core::dialect::postgres(),
        lexega_core::dialect::databricks(),
        lexega_core::dialect::mssql(),
    ] {
        let name = earlier.name().to_string();
        assert_eq!(
            report_against_index_built_after(Some(earlier)),
            alone,
            "after {name}"
        );
    }
}

#[test]
fn missing_tables_are_listed_in_statement_order() {
    let tables: Vec<String> = (0..40).map(|n| format!("ABSENT_{n:02}")).collect();
    let sql: String = tables
        .iter()
        .map(|table| format!("SELECT id FROM {table};\n"))
        .collect();
    let missing = missing_tables(&sql, lexega_core::dialect::snowflake());
    assert_eq!(missing.len(), tables.len(), "{missing:?}");
    for (listed, written) in missing.iter().zip(&tables) {
        assert!(listed.eq_ignore_ascii_case(written), "{missing:?}");
    }
}

/// The tag `pii` on the column `email` of `analytics.app.users`.
fn email_tag() -> Vec<lexega_core::catalog::ColumnTagOverlay> {
    vec![lexega_core::catalog::ColumnTagOverlay {
        full_ref: "analytics.app.users".to_string(),
        column: "email".to_string(),
        tag_names: vec!["pii".to_string()],
    }]
}

/// The `CAT-TBL-UNKNOWN` and `CAT-COL-UNKNOWN` findings of `sql` against
/// `catalog`, and the tables its report lists as missing.
fn unknowns(sql: &str, catalog: &CatalogIndex) -> (Vec<String>, Vec<String>) {
    let report =
        analyze_risk_with_policy_config_and_catalog_index(sql, &AnalysisConfig::default(), catalog)
            .expect("analyze");
    let rules = report
        .entries()
        .filter_map(|finding| finding.rule_id())
        .filter(|rule| matches!(*rule, "CAT-TBL-UNKNOWN" | "CAT-COL-UNKNOWN"))
        .map(String::from)
        .collect();
    (rules, report.catalog_info.missing_tables)
}

#[test]
fn a_catalog_of_tagged_columns_says_nothing_of_what_it_does_not_list() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    let snapshot = CatalogSnapshot::from_source_column_tags(
        &email_tag(),
        None,
        &*lexega_core::default_catalog_provider(),
    );
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("valid snapshot");
    for sql in [
        "SELECT id FROM analytics.noschema.customers",
        "SELECT id FROM orders",
        "SELECT id, email FROM analytics.app.users",
        "SELECT u.id FROM analytics.app.users AS u",
        "SELECT * FROM analytics.app.users",
        "SELECT c.id, u.email FROM analytics.noschema.customers AS c \
         JOIN analytics.app.users AS u ON c.id = u.id",
        "INSERT INTO analytics.app.users (id, email) SELECT id, email FROM analytics.app.staged",
        "UPDATE analytics.app.users SET name = 'x' WHERE id = 1",
        "ALTER TABLE analytics.noschema.customers ADD COLUMN x INT",
    ] {
        assert_eq!(unknowns(sql, &catalog), (vec![], vec![]), "{sql}");
    }
}

#[test]
fn a_catalog_file_with_tags_added_still_reports_what_it_does_not_list() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    let provider = lexega_core::default_catalog_provider();
    let mut snapshot = snapshot_of(&[("APP", &["USERS"])]);
    snapshot.enrich_column_tags(&email_tag(), &*provider);
    assert_eq!(
        snapshot.listing,
        lexega_core::catalog::CatalogListing::Inventory
    );
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("valid snapshot");
    assert_eq!(
        unknowns("SELECT id FROM analytics.noschema.customers", &catalog),
        (
            vec!["CAT-TBL-UNKNOWN".to_string()],
            vec!["analytics.noschema.customers".to_string()]
        )
    );
    assert_eq!(
        unknowns("SELECT id, email FROM analytics.app.users", &catalog),
        (vec!["CAT-COL-UNKNOWN".to_string()], vec![])
    );
    assert_eq!(
        unknowns(
            "ALTER TABLE analytics.noschema.customers ADD COLUMN x INT",
            &catalog
        ),
        (vec![], vec!["analytics.noschema.customers".to_string()])
    );
}

#[test]
fn a_star_over_a_table_of_tagged_columns_holds_any_name() {
    let _folding = lexega_core::set_normalization_dialect("snowflake");
    let snapshot = CatalogSnapshot::from_source_column_tags(
        &email_tag(),
        None,
        &*lexega_core::default_catalog_provider(),
    );
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("valid snapshot");
    for sql in [
        "SELECT *, nosuch FROM analytics.app.users",
        "SELECT id FROM (SELECT * FROM analytics.app.users) AS s",
        "WITH c AS (SELECT * FROM analytics.app.users) SELECT id, email FROM c",
        "SELECT id FROM (SELECT * EXCLUDE (email) FROM analytics.app.users) AS s",
        "SELECT uid, id FROM (SELECT * RENAME (id AS uid) FROM analytics.app.users) AS s",
        "SELECT s.id FROM (SELECT * REPLACE (1 AS id) FROM analytics.app.users) AS s",
        "INSERT INTO analytics.app.users SELECT * FROM analytics.app.users",
    ] {
        assert_eq!(unknowns(sql, &catalog), (vec![], vec![]), "{sql}");
    }
}

/// The catalog of [`quoted_name_snapshot`], indexed under `dialect`'s folding.
fn quoted_names_under(dialect: &lexega_core::dialect::DialectRef) -> CatalogIndex {
    let _folding = lexega_core::set_normalization_dialect(dialect.name());
    CatalogIndex::from_snapshot(quoted_name_snapshot()).expect("valid snapshot")
}

#[test]
fn a_table_created_under_any_spelling_of_its_name_is_not_listed_as_missing() {
    for dialect in [
        lexega_core::dialect::snowflake(),
        lexega_core::dialect::postgres(),
        lexega_core::dialect::mysql(),
        lexega_core::dialect::databricks(),
        lexega_core::dialect::bigquery(),
    ] {
        let catalog = quoted_names_under(&dialect);
        for sql in [
            "CREATE TABLE IF NOT EXISTS zz_g (id INT); SELECT id FROM zz_g",
            "CREATE TABLE IF NOT EXISTS s1.zz_g (id INT); SELECT id FROM s1.zz_g",
            "CREATE TABLE IF NOT EXISTS zz_g AS SELECT 1 AS id; SELECT id FROM zz_g",
            "CREATE TABLE IF NOT EXISTS /* c */ zz_g (id INT); SELECT id FROM zz_g",
        ] {
            assert_missing_from(&catalog, Some(dialect.clone()), sql, &[]);
        }
    }
    let snowflake = lexega_core::dialect::snowflake();
    let catalog = quoted_names_under(&snowflake);
    for sql in [
        "CREATE TEMPORARY TABLE IF NOT EXISTS zz_g (id INT); SELECT id FROM zz_g",
        "CREATE TABLE \"my.new\" (id INT); SELECT id FROM \"my.new\"",
        "CREATE TABLE \"my.new\" AS SELECT 1 AS id; SELECT id FROM \"my.new\"",
        "CREATE EXTERNAL TABLE zz_ge (id INT AS (value:c1::INT)) LOCATION = @zz_stage \
         FILE_FORMAT = (TYPE = CSV); SELECT id FROM zz_ge",
    ] {
        assert_missing_from(&catalog, Some(snowflake.clone()), sql, &[]);
    }
    let postgres = lexega_core::dialect::postgres();
    let catalog = quoted_names_under(&postgres);
    for sql in [
        "CREATE TEMP TABLE IF NOT EXISTS zz_g (id INT); SELECT id FROM zz_g",
        "CREATE UNLOGGED TABLE zz_g (id INT); SELECT id FROM zz_g",
        "CREATE TABLE \"my.new\" (id INT); SELECT id FROM \"my.new\"",
    ] {
        assert_missing_from(&catalog, Some(postgres.clone()), sql, &[]);
    }
    let databricks = lexega_core::dialect::databricks();
    assert_missing_from(
        &quoted_names_under(&databricks),
        Some(databricks.clone()),
        "CREATE EXTERNAL TABLE zz_ge (id INT) LOCATION 's3://b/p'; SELECT id FROM zz_ge",
        &[],
    );
    // A written table keeps every part it was written with.
    assert_missing_from(
        &catalog,
        Some(postgres),
        "INSERT INTO \"a.b\" (id) VALUES (1)",
        &["\"a.b\""],
    );
}

/// The rule ids a report under `dialect` raises against `catalog`, with
/// the custom rules of `yaml` (the built-in rules where it is empty).
fn rules_raised(
    sql: &str,
    dialect: lexega_core::dialect::DialectRef,
    catalog: &CatalogIndex,
    yaml: &str,
) -> Vec<String> {
    let mut config = if yaml.is_empty() {
        AnalysisConfig::default()
    } else {
        config_from_yaml(yaml)
    };
    config.dialect = Some(dialect);
    let mut rules: Vec<String> =
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, catalog)
            .expect("analyze")
            .entries()
            .map(|lexega_core::analyzer::RuleMatch::Analysis(finding)| finding.matched_rule.clone())
            .collect();
    rules.sort();
    rules
}

#[test]
fn a_session_local_table_or_a_stage_is_never_asked_of_the_catalog() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let cases: [(&str, &[&str]); 11] = [
        ("SELECT id FROM #t", &[]),
        ("SELECT id FROM ##g", &[]),
        ("DECLARE @tv TABLE (id INT); SELECT id FROM @tv", &[]),
        (
            "SELECT a.id FROM #t a JOIN dbo.zz_real b ON a.id = b.id",
            &["dbo.zz_real"],
        ),
        ("INSERT INTO #t SELECT id FROM zz_src", &["zz_src"]),
        ("INSERT INTO ##g (id) SELECT id FROM zz_src", &["zz_src"]),
        (
            "INSERT INTO tempdb..#t (id) SELECT id FROM zz_src",
            &["zz_src"],
        ),
        (
            "DECLARE @tv TABLE (id INT); INSERT INTO @tv (id) VALUES (1); UPDATE @tv SET id = 2",
            &[],
        ),
        ("UPDATE #t SET id = 1; DELETE FROM ##g", &[]),
        (
            "MERGE INTO #t AS t USING zz_src AS s ON t.id = s.id \
             WHEN MATCHED THEN UPDATE SET id = s.id;",
            &["zz_src"],
        ),
        (
            "SELECT id INTO #x FROM zz_src; SELECT id FROM #x",
            &["zz_src"],
        ),
    ];
    for (sql, missing) in cases {
        assert_missing_from(&catalog, Some(mssql.clone()), sql, missing);
        let rules = rules_raised(sql, mssql.clone(), &catalog, "");
        let unknown = rules.iter().filter(|r| *r == "CAT-TBL-UNKNOWN").count();
        // Only the catalogue's own tables are asked for, once a statement.
        assert_eq!(
            unknown,
            usize::from(!missing.is_empty()),
            "{sql}: {rules:?}"
        );
    }
    let snowflake = lexega_core::dialect::snowflake();
    let catalog = quoted_names_under(&snowflake);
    for sql in [
        "SELECT $1 FROM @zz_stage",
        "SELECT t.$1 FROM @zz_stage t",
        "SELECT $1 FROM @analytics.public.zz_stage/path",
    ] {
        assert_missing_from(&catalog, Some(snowflake.clone()), sql, &[]);
        let rules = rules_raised(sql, snowflake.clone(), &catalog, "");
        assert!(
            !rules.contains(&"CAT-TBL-UNKNOWN".to_string()),
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_written_temporary_table_is_published_with_its_mark() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let yaml = r##"
rules:
  - id: TEST-WRITES-TEMP
    risk_level: low
    message: "Writes the session's temporary table"
    triggers:
      all_of:
        - query.writes_table:
            exists:
              table.name.raw: { matches: "#t" }
"##;
    for sql in [
        "INSERT INTO #t SELECT id FROM zz_src",
        "MERGE INTO #t AS t USING zz_src AS s ON t.id = s.id \
         WHEN MATCHED THEN UPDATE SET id = s.id;",
        "MERGE INTO #t WITH (HOLDLOCK) USING zz_src AS s ON #t.id = s.id \
         WHEN MATCHED THEN UPDATE SET id = s.id;",
    ] {
        let rules = rules_raised(sql, mssql.clone(), &catalog, yaml);
        assert!(
            rules.contains(&"TEST-WRITES-TEMP".to_string()),
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_session_local_table_a_ddl_statement_names_is_never_asked_of_the_catalog() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let cases: [(&str, &[&str]); 12] = [
        ("DROP TABLE #t", &[]),
        ("DROP TABLE ##g", &[]),
        ("DROP TABLE IF EXISTS #t", &[]),
        ("DROP TABLE tempdb..#t", &[]),
        ("IF OBJECT_ID('tempdb..#t') IS NOT NULL DROP TABLE #t", &[]),
        ("TRUNCATE TABLE #t", &[]),
        ("TRUNCATE TABLE ##g", &[]),
        ("ALTER TABLE #t ADD c INT", &[]),
        ("ALTER TABLE ##g ADD c INT", &[]),
        ("DROP TABLE dbo.zz_gone", &["dbo.zz_gone"]),
        ("TRUNCATE TABLE dbo.zz_gone", &["dbo.zz_gone"]),
        ("ALTER TABLE dbo.zz_gone ADD c INT", &["dbo.zz_gone"]),
    ];
    for (sql, missing) in cases {
        assert_missing_from(&catalog, Some(mssql.clone()), sql, missing);
    }
    let yaml = r##"
rules:
  - id: TEST-DDL-TEMP
    risk_level: low
    message: "Names the session's temporary table"
    triggers:
      all_of:
        - ddl.target.name.name.raw: { matches: "#t" }
"##;
    for sql in [
        "DROP TABLE #t",
        "TRUNCATE TABLE #t",
        "ALTER TABLE #t ADD c INT",
    ] {
        let rules = rules_raised(sql, mssql.clone(), &catalog, yaml);
        assert!(
            rules.contains(&"TEST-DDL-TEMP".to_string()),
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_ddl_statement_names_its_table_by_the_parts_it_was_written_with() {
    let snowflake = lexega_core::dialect::snowflake();
    let catalog = quoted_names_under(&snowflake);
    for sql in [
        "DROP TABLE \"my.tbl\"",
        "TRUNCATE TABLE \"my.tbl\"",
        "ALTER TABLE \"my.tbl\" ADD COLUMN c INT",
        "DROP TABLE analytics./* c */public.\"MyTable\"",
        "TRUNCATE TABLE analytics.public /* c */ .\"MyTable\"",
    ] {
        assert_missing_from(&catalog, Some(snowflake.clone()), sql, &[]);
    }
}

#[test]
fn a_tsql_drop_or_truncate_without_a_semicolon_leaves_the_next_statement_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    for (sql, missing, rule) in [
        (
            "DROP TABLE dbo.zz_t\nSELECT id INTO dbo.zz_t FROM dbo.zz_t2",
            &["dbo.zz_t", "dbo.zz_t2"][..],
            "TBL-DROP",
        ),
        (
            "IF OBJECT_ID('dbo.zz_t') IS NOT NULL DROP TABLE dbo.zz_t\n\
             SELECT id FROM dbo.zz_src",
            &["dbo.zz_t", "dbo.zz_src"],
            "TBL-DROP",
        ),
        (
            "DROP TABLE IF EXISTS dbo.zz_t\nCREATE TABLE dbo.zz_t (id INT)\n\
             SELECT id FROM dbo.zz_src",
            &["dbo.zz_t", "dbo.zz_src"],
            "TBL-DROP",
        ),
        (
            "IF OBJECT_ID('dbo.zz_t') IS NOT NULL\n    DROP TABLE dbo.zz_t\nGO\n\
             CREATE TABLE dbo.zz_t (id INT)\nGO\nINSERT INTO dbo.zz_t SELECT id FROM dbo.zz_src",
            &["dbo.zz_t", "dbo.zz_src"],
            "TBL-DROP",
        ),
        (
            "TRUNCATE TABLE dbo.zz_t\nSELECT id FROM dbo.zz_src",
            &["dbo.zz_t", "dbo.zz_src"],
            "TBL-TRUNCATE",
        ),
        (
            "DROP VIEW dbo.zz_v\nSELECT id FROM dbo.zz_src",
            &["dbo.zz_v", "dbo.zz_src"],
            "VIEW-DROP",
        ),
        (
            "DROP PROCEDURE dbo.zz_p\nSELECT id FROM dbo.zz_src",
            &["dbo.zz_src"],
            "PROC-DROP",
        ),
        (
            "ALTER TABLE dbo.zz_t ADD c INT\nSELECT id FROM dbo.zz_src",
            &["dbo.zz_t", "dbo.zz_src"],
            "TBL-COL-ADD",
        ),
        (
            "DECLARE @n INT\nSELECT id FROM dbo.zz_src WHERE id = 1",
            &["dbo.zz_src"],
            "CAT-TBL-UNKNOWN",
        ),
    ] {
        assert_missing_from(&catalog, Some(mssql.clone()), sql, missing);
        let rules = rules_raised(sql, mssql.clone(), &catalog, "");
        assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
        assert!(
            rules.contains(&"CAT-TBL-UNKNOWN".to_string()),
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_tsql_security_or_maintenance_statement_without_a_semicolon_leaves_the_next_statements_analysed(
) {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    for (statement, rule) in [
        ("CREATE USER zz_u FOR LOGIN zz_l", "MSSQL-USER-NEW"),
        (
            "CREATE LOGIN zz_l WITH PASSWORD = 'x', CHECK_POLICY = OFF",
            "MSSQL-LOGIN-NEW",
        ),
        ("CREATE ROLE zz_r AUTHORIZATION dbo", "ROLE-NEW"),
        ("ALTER ROLE zz_r ADD MEMBER zz_u", "MSSQL-ROLE-MEMBER-ADD"),
        ("CREATE SCHEMA zz_s AUTHORIZATION dbo", "INFO-SCHEMA-NEW"),
        ("ALTER SCHEMA zz_s TRANSFER dbo.zz_t", "SCHEMA-PROPS-CHG"),
        ("ALTER DATABASE zz_db SET RECOVERY SIMPLE", "DB-PROPS-CHG"),
        ("ALTER DATABASE zz_db MODIFY NAME = zz_db2", "DB-PROPS-CHG"),
        (
            "BACKUP DATABASE zz_db TO DISK = 'c:\\x.bak' WITH INIT",
            "INFO-MSSQL-BACKUP",
        ),
        (
            "RESTORE DATABASE zz_db FROM DISK = 'c:\\x.bak' WITH REPLACE",
            "MSSQL-RESTORE-REPLACE",
        ),
        ("DBCC CHECKDB (zz_db) WITH NO_INFOMSGS", "INFO-MSSQL-DBCC"),
        (
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'x'",
            "INFO-MSSQL-CRYPTO-NEW",
        ),
        (
            "CREATE SYMMETRIC KEY k WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE c",
            "INFO-MSSQL-CRYPTO-NEW",
        ),
        (
            "OPEN SYMMETRIC KEY k DECRYPTION BY CERTIFICATE c",
            "INFO-MSSQL-KEY-MANAGEMENT",
        ),
        ("SETUSER 'zz_u'", "INFO-MSSQL-SETUSER"),
    ] {
        let sql = format!(
            "{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src"
        );
        assert_missing_from(
            &catalog,
            Some(mssql.clone()),
            &sql,
            &["dbo.zz_src", "dbo.zz_dst"],
        );
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
    }
}

#[test]
fn a_tsql_alter_table_without_a_semicolon_leaves_the_next_statements_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let fk = "ALTER TABLE dbo.zz_t ADD CONSTRAINT fk_c FOREIGN KEY (a) REFERENCES dbo.zz_p (id)";
    let next = "\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src";
    for (sql, rule) in [
        (
            format!(
                "ALTER TABLE [dbo].[zz_t]  WITH CHECK ADD  CONSTRAINT [fk_c] FOREIGN KEY([a])\n\
                 REFERENCES [dbo].[zz_p] ([id])\nGO\n\
                 ALTER TABLE [dbo].[zz_t] CHECK CONSTRAINT [fk_c]\nGO{next}"
            ),
            None,
        ),
        (format!("{fk} ON DELETE CASCADE{next}"), None),
        (
            format!("{fk} ON DELETE SET NULL ON UPDATE SET DEFAULT{next}"),
            None,
        ),
        (format!("{fk} ON UPDATE CASCADE{next}"), None),
        (format!("{fk} ON DELETE NO ACTION{next}"), None),
        (
            format!(
                "{fk} ON DELETE CASCADE;{};",
                next.replace("\nINSERT", ";\nINSERT")
            ),
            None,
        ),
        (
            format!(
                "ALTER TABLE dbo.zz_t ADD p_id INT NULL CONSTRAINT fk_p REFERENCES dbo.zz_p (id) \
                 ON DELETE CASCADE{next}"
            ),
            Some("TBL-COL-ADD"),
        ),
        (
            format!(
                "ALTER TABLE [dbo].[zz_t]  WITH CHECK ADD  CONSTRAINT [fk_c] FOREIGN KEY([a])\n\
                 REFERENCES [dbo].[zz_p] ([id])\nON DELETE CASCADE\nGO\n\
                 ALTER TABLE [dbo].[zz_t] CHECK CONSTRAINT [fk_c]\nGO{next}"
            ),
            None,
        ),
        (
            format!(
                "ALTER TABLE [dbo].[zz_t] NOCHECK CONSTRAINT [fk_c]\nGO\nDROP TABLE dbo.zz_gone\nGO{next}"
            ),
            Some("TBL-DROP"),
        ),
        (
            format!("ALTER TABLE dbo.zz_t NOCHECK CONSTRAINT ALL{next}"),
            None,
        ),
        (format!("ALTER TABLE dbo.zz_t SWITCH TO dbo.zz_p{next}"), None),
        (
            format!("ALTER TABLE dbo.zz_t REBUILD WITH (DATA_COMPRESSION = PAGE){next}"),
            None,
        ),
    ] {
        let config = AnalysisConfig {
            dialect: Some(mssql.clone()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let missing = &report.catalog_info.missing_tables;
        for read in ["dbo.zz_src", "dbo.zz_dst"] {
            assert!(
                missing.iter().any(|m| m.eq_ignore_ascii_case(read)),
                "{sql}: {missing:?}"
            );
        }
        assert!(
            missing.iter().all(|m| !m.contains(char::is_whitespace)),
            "{sql}: {missing:?}"
        );
        if let Some(rule) = rule {
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
        }
    }
}

#[test]
fn a_tsql_statement_start_word_its_grammar_holds_leaves_the_statement_whole() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    for (alter, rule) in [
        (
            "ALTER TABLE dbo.zz_t DROP COLUMN IF EXISTS c",
            Some("TBL-COL-DROP"),
        ),
        (
            "ALTER TABLE dbo.zz_t DROP COLUMN IF EXISTS c, d",
            Some("TBL-COL-DROP"),
        ),
        (
            "ALTER TABLE dbo.zz_t DROP CONSTRAINT IF EXISTS df_c, COLUMN IF EXISTS c",
            Some("TBL-COL-DROP"),
        ),
        (
            "ALTER TABLE dbo.zz_t ALTER COLUMN c DROP NOT FOR REPLICATION",
            None,
        ),
        ("DROP ASSEMBLY zz_a WITH NO DEPENDENTS", None),
        (
            "DECLARE zz_cur CURSOR LOCAL FAST_FORWARD FOR SELECT id FROM dbo.zz_src",
            None,
        ),
    ] {
        for sql in [
            format!("{alter}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src"),
            format!("{alter};\nSELECT id FROM dbo.zz_src;\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src;"),
            format!("{alter}\nGO\nSELECT id FROM dbo.zz_src\nGO\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src\nGO"),
            format!(
                "IF COL_LENGTH('dbo.zz_t', 'c') IS NOT NULL\nBEGIN\n    {alter}\nEND\nGO\n\
                 SELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src\nGO"
            ),
            format!(
                "IF COL_LENGTH('dbo.zz_t', 'c') IS NOT NULL\nBEGIN\n    {alter};\n    \
                 SELECT id FROM dbo.zz_src;\nEND\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src"
            ),
        ] {
            let config = AnalysisConfig {
                dialect: Some(mssql.clone()),
                ..Default::default()
            };
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let missing = &report.catalog_info.missing_tables;
            for read in ["dbo.zz_src", "dbo.zz_dst"] {
                assert!(
                    missing.iter().any(|m| m.eq_ignore_ascii_case(read)),
                    "{sql}: {missing:?}"
                );
            }
            if let Some(rule) = rule {
                let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
                assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
            }
        }
    }
}

#[test]
fn a_tsql_maintenance_statement_in_a_block_leaves_the_next_statements_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    for (statement, rule) in [
        (
            "BACKUP DATABASE zz_db TO DISK = 'a.bak' WITH INIT",
            "INFO-MSSQL-BACKUP",
        ),
        (
            "RESTORE DATABASE zz_db FROM DISK = 'a.bak' WITH REPLACE",
            "MSSQL-RESTORE-REPLACE",
        ),
        ("DBCC CHECKDB (zz_db) WITH NO_INFOMSGS", "INFO-MSSQL-DBCC"),
        ("SETUSER 'zz_u'", "INFO-MSSQL-SETUSER"),
        (
            "BACKUP CERTIFICATE c TO FILE = 'c.cer'",
            "INFO-MSSQL-KEY-BACKUP",
        ),
    ] {
        let next = "SELECT id FROM dbo.zz_src\n    DELETE FROM dbo.zz_dst";
        for sql in [
            format!("IF 1 = 1\nBEGIN\n    {statement}\n    {next}\nEND"),
            format!("CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n    {statement}\n    {next}\nEND"),
            format!("BEGIN TRY\n    {statement}\n    {next}\nEND TRY\nBEGIN CATCH\n    SELECT 1\nEND CATCH"),
        ] {
            let config = AnalysisConfig {
                dialect: Some(mssql.clone()),
                ..Default::default()
            };
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            for raised in [rule, "DML-WRITE-UNBOUNDED"] {
                assert!(rules.contains(&raised.to_string()), "{sql}: {rules:?}");
            }
        }
    }
}

#[test]
fn a_tsql_statement_in_a_block_never_takes_in_the_statements_after_it() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let delete = "DELETE FROM dbo.zz_dst";
    for statement in [
        "DEALLOCATE zz_cur",
        "DISABLE TRIGGER zz_tr ON dbo.zz_t",
        "ENABLE TRIGGER zz_tr ON dbo.zz_t",
        "CHECKPOINT",
        "CHECKPOINT 10",
        "RECONFIGURE",
        "RECONFIGURE WITH OVERRIDE",
        "REVERT",
        "REVERT WITH COOKIE = @cookie",
        "KILL 52",
        "KILL 52 WITH STATUSONLY",
        "SHUTDOWN",
        "SHUTDOWN WITH NOWAIT",
        "SEND ON CONVERSATION @h MESSAGE TYPE [//zz/m] (@body)",
        "RESTORE FILELISTONLY FROM DISK = 'a.bak'",
        "RESTORE HEADERONLY FROM DISK = 'a.bak' WITH FILE = 1",
        "RESTORE VERIFYONLY FROM DISK = 'a.bak' WITH CHECKSUM",
        "RESTORE LABELONLY FROM DISK = 'a.bak'",
        "ADD SIGNATURE TO dbo.zz_p BY CERTIFICATE zz_c",
        "SAVE TRANSACTION zz_sp",
        "BEGIN TRAN",
        "BEGIN DISTRIBUTED TRANSACTION",
        "BEGIN DIALOG CONVERSATION @h FROM SERVICE s TO SERVICE 't'",
        "COMMIT TRAN",
        "MOVE CONVERSATION @h TO @g",
        "RECEIVE TOP (1) * FROM zz_q",
        "READTEXT dbo.zz_t.c @ptr 0 10",
    ] {
        let top = format!("{statement}\n{delete}");
        let top_skipped =
            analyze_risk_with_policy_config_and_catalog_index(&top, &config, &catalog)
                .expect("analyze")
                .summary
                .statements_skipped;
        for sql in [
            format!("IF 1 = 1\nBEGIN\n    {statement}\n    {delete}\nEND"),
            format!("CREATE PROCEDURE dbo.zz_p2 AS\nBEGIN\n    {statement}\n    {delete}\nEND"),
            format!("BEGIN TRY\n    {statement}\n    {delete}\nEND TRY\nBEGIN CATCH\n    SELECT 1\nEND CATCH"),
        ] {
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, top_skipped, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            assert!(
                rules.contains(&"DML-WRITE-UNBOUNDED".to_string()),
                "{sql}: {rules:?}"
            );
            if statement.starts_with("ADD SIGNATURE") {
                assert!(
                    rules.contains(&"MSSQL-MODULE-SIGNATURE-ADDED".to_string()),
                    "{sql}: {rules:?}"
                );
            }
        }
    }
}

#[test]
fn a_tsql_transaction_statement_is_analysed_whole() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let delete = "DELETE FROM dbo.zz_dst";
    for statement in [
        "BEGIN TRAN",
        "BEGIN TRANSACTION zz_tx WITH MARK 'nightly load'",
        "BEGIN DISTRIBUTED TRANSACTION",
        "COMMIT TRAN",
        "COMMIT TRANSACTION zz_tx",
        "ROLLBACK TRAN zz_sp",
    ] {
        for sql in [
            format!("{statement}\n{delete}"),
            format!("{statement}\nGO\n{delete}\nGO"),
            format!("CREATE PROCEDURE dbo.zz_p2 AS\nBEGIN\n    {statement}\n    {delete}\nEND"),
            format!("BEGIN TRY\n    {statement}\n    {delete}\nEND TRY\nBEGIN CATCH\n    SELECT 1\nEND CATCH"),
        ] {
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            assert!(
                rules.contains(&"DML-WRITE-UNBOUNDED".to_string()),
                "{sql}: {rules:?}"
            );
        }
    }
}

#[test]
fn a_tsql_transaction_without_tran_leaves_the_next_statement_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    for sql in [
        "COMMIT\ndone:\nTRUNCATE TABLE dbo.zz_dst",
        "BEGIN TRANSACTION\ndone:\nTRUNCATE TABLE dbo.zz_dst",
        "ROLLBACK\nREVERT\nTRUNCATE TABLE dbo.zz_dst",
    ] {
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let rules = rules_raised(sql, mssql.clone(), &catalog, "");
        assert!(
            rules.contains(&"TBL-TRUNCATE".to_string()),
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_tsql_schema_and_its_batch_separator_leave_the_next_batch_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    for schema in ["CREATE SCHEMA zz_s", "CREATE SCHEMA [zz_stg]"] {
        let sql = format!("{schema}\nGO\nDELETE FROM dbo.zz_dst\nGO");
        let config = AnalysisConfig {
            dialect: Some(mssql.clone()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        for raised in ["INFO-SCHEMA-NEW", "DML-WRITE-UNBOUNDED"] {
            assert!(rules.contains(&raised.to_string()), "{sql}: {rules:?}");
        }
    }
}

#[test]
fn a_tsql_inline_function_leaves_the_next_batch_analysed() {
    assert_next_tsql_batch_analysed(&[
        (
            "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS TABLE AS RETURN SELECT id FROM dbo.zz_src",
            "UDF-NEW",
        ),
        (
            "CREATE OR ALTER FUNCTION dbo.zz_f (@x INT)\nRETURNS TABLE\nAS\nRETURN (SELECT id FROM dbo.zz_src)",
            "UDF-NEW",
        ),
    ]);
}

#[test]
fn a_tsql_function_with_execute_as_leaves_the_next_batch_analysed() {
    assert_next_tsql_batch_analysed(&[
        (
            "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH EXECUTE AS CALLER \
             AS BEGIN RETURN @x END",
            "UDF-NEW",
        ),
        (
            "CREATE FUNCTION dbo.zz_f () RETURNS @t TABLE (id INT) WITH EXECUTE AS 'zz_u' \
             BEGIN INSERT INTO @t SELECT id FROM dbo.zz_src RETURN END",
            "UDF-NEW",
        ),
    ]);
    // An ALTER creates nothing: no `UDF-NEW`, the next batch analysed.
    let altered =
        "ALTER FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH SCHEMABINDING, EXECUTE AS OWNER \
                   AS BEGIN RETURN @x END";
    assert_next_tsql_batch_analysed(&[(altered, "DML-WRITE-UNBOUNDED")]);
    let mssql = lexega_core::dialect::mssql();
    let rules = rules_raised(
        &format!("{altered}\nGO\nDELETE FROM dbo.zz_dst\nGO"),
        mssql.clone(),
        &quoted_names_under(&mssql),
        "",
    );
    assert!(!rules.contains(&"UDF-NEW".to_string()), "{rules:?}");
}

#[test]
fn a_tsql_altered_view_leaves_the_next_batch_analysed() {
    assert_next_tsql_batch_analysed(&[
        (
            "ALTER VIEW dbo.zz_v AS SELECT id FROM dbo.zz_src",
            "VIEW-CHG",
        ),
        (
            "ALTER VIEW dbo.zz_v WITH SCHEMABINDING AS SELECT id FROM dbo.zz_src WITH CHECK OPTION",
            "VIEW-CHG",
        ),
    ]);
}

#[test]
fn a_tsql_audit_signature_or_availability_group_statement_leaves_the_next_batch_analysed() {
    assert_next_tsql_batch_analysed(&[
        (
            "CREATE SERVER AUDIT zz_a TO FILE (FILEPATH = 'C:\\a\\') WHERE object_name = 'x'",
            "INFO-MSSQL-AUDIT-NEW",
        ),
        (
            "ALTER SERVER AUDIT zz_a WITH (STATE = ON)",
            "MSSQL-AUDIT-CHG",
        ),
        ("DROP SERVER AUDIT SPECIFICATION zz_s", "MSSQL-AUDIT-DROP"),
        (
            "ALTER DATABASE AUDIT SPECIFICATION zz_d FOR SERVER AUDIT zz_a \
             DROP (DELETE ON SCHEMA::dbo BY dbo) WITH (STATE = OFF)",
            "MSSQL-AUDIT-DISABLE",
        ),
        (
            "ADD SIGNATURE TO dbo.zz_p BY CERTIFICATE zz_c WITH PASSWORD = 'x'",
            "MSSQL-MODULE-SIGNATURE-ADDED",
        ),
        ("DROP AVAILABILITY GROUP zz_ag", "DML-WRITE-UNBOUNDED"),
    ]);
}

#[test]
fn a_tsql_revert_with_cookie_or_get_conversation_group_leaves_the_next_batch_analysed() {
    assert_next_tsql_batch_analysed(&[
        ("REVERT WITH COOKIE = @cookie", "DML-WRITE-UNBOUNDED"),
        ("GET CONVERSATION GROUP @g FROM zz_q", "DML-WRITE-UNBOUNDED"),
    ]);
}

#[test]
fn a_tsql_execute_as_with_no_revert_or_a_cookie_leaves_the_next_statement_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    for (statement, raised, not_raised) in [
        (
            "EXECUTE AS USER = 'zz_u' WITH NO REVERT",
            vec!["MSSQL-EXECAS-USER", "MSSQL-EXECAS-NO-REVERT"],
            None,
        ),
        (
            "EXECUTE AS LOGIN = 'zz_l' WITH COOKIE INTO @c",
            vec!["MSSQL-EXECAS-LOGIN"],
            Some("MSSQL-EXECAS-NO-REVERT"),
        ),
        (
            "DECLARE @c VARBINARY(100)\nEXECUTE AS LOGIN = 'zz_l' WITH COOKIE INTO @c",
            vec!["MSSQL-EXECAS-LOGIN"],
            Some("MSSQL-EXECAS-NO-REVERT"),
        ),
    ] {
        for separator in ["\n", "\nGO\n", ";\n", ";\nGO\n"] {
            let sql = format!("{statement}{separator}TRUNCATE TABLE dbo.zz_dst");
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            for rule in raised.iter().copied().chain(["TBL-TRUNCATE"]) {
                assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
            }
            if let Some(rule) = not_raised {
                assert!(!rules.contains(&rule.to_string()), "{sql}: {rules:?}");
            }
        }
    }
}

/// Each statement followed by a `GO` batch holding an unbounded `DELETE`:
/// nothing is skipped, and both the statement's rule and the `DELETE`'s are
/// raised.
fn assert_next_tsql_batch_analysed(statements: &[(&str, &str)]) {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    for &(statement, rule) in statements {
        let sql = format!("{statement}\nGO\nDELETE FROM dbo.zz_dst\nGO");
        let config = AnalysisConfig {
            dialect: Some(mssql.clone()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        for raised in [rule, "DML-WRITE-UNBOUNDED"] {
            assert!(rules.contains(&raised.to_string()), "{sql}: {rules:?}");
        }
    }
}

#[test]
fn a_tsql_procedure_body_without_a_block_is_analysed_as_a_block_body_is() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let skipped = |sql: &str| {
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyze")
            .summary
            .statements_skipped
    };
    let dynamic =
        "DECLARE @sql NVARCHAR(MAX) = N'SELECT id FROM dbo.zz_src WHERE c = ' + @x\nEXEC (@sql)";
    let literal = "DECLARE @sql NVARCHAR(MAX) = N'SELECT id FROM dbo.zz_src'\nEXEC (@sql)";
    let cases: [(&str, &str, &[&str]); 8] = [
        ("", "UPDATE dbo.zz_src SET c = 1", &["DML-WRITE-UNBOUNDED"]),
        (
            "",
            "SET NOCOUNT ON\nSELECT id FROM dbo.zz_src\nUPDATE dbo.zz_src SET c = 1",
            &["DML-WRITE-UNBOUNDED"],
        ),
        (
            "WITH EXECUTE AS OWNER ",
            "IF @x = 'a'\n  UPDATE dbo.zz_src SET c = 1 WHERE id = 1\nELSE\n  DELETE FROM dbo.zz_src",
            &["DML-WRITE-UNBOUNDED", "PROC-EXECAS-OWNER"],
        ),
        ("", dynamic, &[]),
        ("", literal, &[]),
        (
            "",
            "BEGIN TRY\n  UPDATE dbo.zz_src SET c = 1\nEND TRY\nBEGIN CATCH\n  SELECT 1\nEND CATCH",
            &["DML-WRITE-UNBOUNDED"],
        ),
        (
            "",
            "DECLARE cur CURSOR FOR SELECT id FROM dbo.zz_src\nOPEN cur\nCLOSE cur\nDEALLOCATE cur\n\
             UPDATE dbo.zz_src SET c = 1",
            &["DML-WRITE-UNBOUNDED"],
        ),
        ("", "CHECKPOINT\nUPDATE dbo.zz_src SET c = 1", &["DML-WRITE-UNBOUNDED"]),
    ];
    for (options, body, raised) in cases {
        let head = format!("CREATE PROCEDURE dbo.zz_p @x NVARCHAR(10) {options}AS");
        let after = "GO\nTRUNCATE TABLE dbo.zz_dst\nGO";
        let bare = format!("{head}\n{body}\n{after}");
        let block = format!("{head}\nBEGIN\n{body}\nEND\n{after}");
        let rules = rules_raised(&bare, mssql.clone(), &catalog, "");
        assert_eq!(
            rules,
            rules_raised(&block, mssql.clone(), &catalog, ""),
            "{bare}"
        );
        assert_eq!(skipped(&bare), skipped(&block), "{bare}");
        for rule in raised.iter().chain(&["PROC-NEW", "TBL-TRUNCATE"]) {
            assert!(rules.contains(&rule.to_string()), "{bare}: {rules:?}");
        }
        if body == dynamic {
            assert!(raises_dynamic_sql(&rules), "{bare}: {rules:?}");
        }
    }
    // Without `GO` the body runs to the end of input.
    let sql =
        "CREATE PROCEDURE dbo.zz_p AS\nSELECT id FROM dbo.zz_src;\nTRUNCATE TABLE dbo.zz_dst;";
    let rules = rules_raised(sql, mssql.clone(), &catalog, "");
    assert!(
        rules.contains(&"TBL-TRUNCATE".to_string()),
        "{sql}: {rules:?}"
    );
    assert_eq!(skipped(sql), 0, "{sql}");
}

#[test]
fn a_tsql_create_proc_or_altered_module_is_analysed_as_its_create() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let dynamic =
        "DECLARE @sql NVARCHAR(MAX) = N'SELECT id FROM dbo.zz_src WHERE c = ' + @x\nEXEC (@sql)";
    // (module, its CREATE, the rule only the CREATE raises: an ALTER
    // creates nothing)
    let cases = [
        (
            "CREATE PROC dbo.zz_p @x INT AS\nUPDATE dbo.zz_src SET c = @x".to_string(),
            "CREATE PROCEDURE dbo.zz_p @x INT AS\nUPDATE dbo.zz_src SET c = @x".to_string(),
            None,
        ),
        (
            format!("ALTER PROCEDURE dbo.zz_p @x NVARCHAR(10) WITH EXECUTE AS OWNER AS\n{dynamic}"),
            format!(
                "CREATE PROCEDURE dbo.zz_p @x NVARCHAR(10) WITH EXECUTE AS OWNER AS\n{dynamic}"
            ),
            Some("PROC-NEW"),
        ),
        (
            "ALTER PROC dbo.zz_p AS\nBEGIN\n  UPDATE dbo.zz_src SET c = 1\nEND".to_string(),
            "CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n  UPDATE dbo.zz_src SET c = 1\nEND".to_string(),
            Some("PROC-NEW"),
        ),
        (
            "ALTER FUNCTION dbo.zz_f () RETURNS @t TABLE (id INT) AS\nBEGIN\n  \
             INSERT INTO @t SELECT id FROM dbo.zz_src\n  RETURN\nEND"
                .to_string(),
            "CREATE FUNCTION dbo.zz_f () RETURNS @t TABLE (id INT) AS\nBEGIN\n  \
             INSERT INTO @t SELECT id FROM dbo.zz_src\n  RETURN\nEND"
                .to_string(),
            Some("UDF-NEW"),
        ),
        (
            "ALTER TRIGGER dbo.zz_tr ON dbo.zz_src AFTER INSERT AS\nUPDATE dbo.zz_src SET c = 1"
                .to_string(),
            "CREATE TRIGGER dbo.zz_tr ON dbo.zz_src AFTER INSERT AS\nUPDATE dbo.zz_src SET c = 1"
                .to_string(),
            Some("TRIG-NEW"),
        ),
    ];
    for (module, created, created_only) in cases {
        let after = "GO\nTRUNCATE TABLE dbo.zz_dst\nGO";
        let sql = format!("{module}\n{after}");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        let mut expected =
            rules_raised(&format!("{created}\n{after}"), mssql.clone(), &catalog, "");
        if let Some(created_only) = created_only {
            assert!(
                expected.contains(&created_only.to_string()),
                "{created}: {expected:?}"
            );
            expected.retain(|rule| rule != created_only);
        }
        assert_eq!(rules, expected, "{sql}");
        assert!(
            rules.contains(&"TBL-TRUNCATE".to_string()),
            "{sql}: {rules:?}"
        );
        let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
    }
}

#[test]
fn a_tsql_declaration_list_is_analysed_as_its_declarations_one_by_one() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let dynamic = "N'SELECT id FROM dbo.zz_src WHERE c = ' + @x";
    // (one statement, the same variables declared one by one)
    let cases = [
        (
            "DECLARE @x INT = 1, @y INT = 2".to_string(),
            "DECLARE @x INT = 1\nDECLARE @y INT = 2".to_string(),
        ),
        (
            "DECLARE @x INT, @y INT = (SELECT MAX(id) FROM dbo.zz_src), @z VARCHAR(10)".to_string(),
            "DECLARE @x INT\nDECLARE @y INT = (SELECT MAX(id) FROM dbo.zz_src)\nDECLARE @z VARCHAR(10)"
                .to_string(),
        ),
        (
            format!("DECLARE @x NVARCHAR(10) = N'a', @sql NVARCHAR(MAX) = {dynamic}\nEXEC (@sql)"),
            format!(
                "DECLARE @x NVARCHAR(10) = N'a'\nDECLARE @sql NVARCHAR(MAX) = {dynamic}\nEXEC (@sql)"
            ),
        ),
        (
            "DECLARE @c CURSOR, @x INT = 1".to_string(),
            "DECLARE @c CURSOR\nDECLARE @x INT = 1".to_string(),
        ),
    ];
    for (list, one_by_one) in cases {
        for after in [
            "\nDELETE FROM dbo.zz_dst",
            ";\nDELETE FROM dbo.zz_dst;",
            "\nGO\nDELETE FROM dbo.zz_dst\nGO",
        ] {
            let sql = format!("{list}{after}");
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            let expected =
                rules_raised(&format!("{one_by_one}{after}"), mssql.clone(), &catalog, "");
            assert_eq!(rules, expected, "{sql}");
            assert!(
                rules.contains(&"DML-WRITE-UNBOUNDED".to_string()),
                "{sql}: {rules:?}"
            );
        }
    }
}

#[test]
fn a_tsql_insert_from_exec_is_analysed_as_its_exec() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let dynamic = "DECLARE @x NVARCHAR(10) = N'a'\n\
                   DECLARE @sql NVARCHAR(MAX) = N'SELECT id FROM dbo.zz_src WHERE c = ' + @x\n";
    // (what precedes it, the EXEC)
    let cases = [
        ("", "EXEC dbo.zz_p"),
        ("", "EXECUTE dbo.zz_p @a = 1"),
        (dynamic, "EXEC (@sql)"),
        (dynamic, "EXEC sp_executesql @sql"),
        ("", "EXECUTE ('SELECT id FROM dbo.zz_src')"),
    ];
    for (before, exec) in cases {
        for after in [
            "\nDELETE FROM dbo.zz_dst",
            ";\nDELETE FROM dbo.zz_dst;",
            "\nGO\nDELETE FROM dbo.zz_dst\nGO",
        ] {
            let sql = format!("{before}INSERT INTO #t (id) {exec}{after}");
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            let standalone = rules_raised(
                &format!("{before}{exec}{after}"),
                mssql.clone(),
                &catalog,
                "",
            );
            assert_eq!(rules, standalone, "{sql}");
            for rule in ["INFO-MSSQL-EXEC-PROC", "DML-WRITE-UNBOUNDED"] {
                assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
            }
        }
    }
    // The plan writes the target from a source whose columns it does not
    // know: the EXEC, a statement that is no query.
    let sql = "INSERT INTO #t (id) EXEC dbo.zz_p";
    let script = lexega_core::parse_sql_with_dialect(sql, &*mssql).expect("parse");
    let engine = lexega_core::Engine::recognition();
    let _scope = engine.apply_dialect(&Some(mssql.clone()));
    let plan = lexega_core::ir::lower_query(
        &script.stmts[0],
        sql,
        lexega_core::ir::StrictMode::Permissive,
    )
    .expect("lowers");
    let lexega_core::ir::RelPlan::Insert { source, .. } = plan else {
        panic!("not an insert: {plan:?}");
    };
    assert!(
        matches!(
            source,
            lexega_core::ir::InsertSource::Query(ref query)
                if matches!(
                    **query,
                    lexega_core::ir::RelPlan::Opaque {
                        reason: lexega_core::ir::OpaqueReason::NonSelectTopLevel,
                        ..
                    }
                )
        ),
        "{source:?}"
    );
}

#[test]
fn a_tsql_cursor_script_is_analysed_whole() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    for fetch in [
        "FETCH c INTO @a, @b",
        "FETCH NEXT FROM c INTO @a, @b",
        "FETCH ABSOLUTE 5 FROM GLOBAL c INTO @a",
        "FETCH RELATIVE @n FROM c INTO @a",
        "FETCH NEXT FROM c",
    ] {
        for (sep, go) in [("\n", "\n"), (";\n", ";\n"), ("\n", "\nGO\n")] {
            let sql = format!(
                "DECLARE c CURSOR FOR SELECT id, c FROM dbo.zz_src{sep}OPEN c{go}{fetch}{go}\
                 DELETE FROM dbo.zz_dst{sep}CLOSE c{sep}DEALLOCATE c{sep}"
            );
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            assert!(
                rules.contains(&"DML-WRITE-UNBOUNDED".to_string()),
                "{sql}: {rules:?}"
            );
        }
    }
}

#[test]
fn a_savepoint_statement_is_analysed() {
    for (sql, dialect) in [
        (
            "BEGIN TRAN\nSAVE TRAN sp1\nDELETE FROM dbo.zz_dst\nROLLBACK TRAN sp1\nCOMMIT",
            lexega_core::dialect::mssql(),
        ),
        (
            "BEGIN TRAN\nSAVE TRANSACTION @sp\nGO\nDELETE FROM dbo.zz_dst\nGO",
            lexega_core::dialect::mssql(),
        ),
        (
            "BEGIN;\nSAVEPOINT sp1;\nDELETE FROM zz_dst;\nROLLBACK TO SAVEPOINT sp1;\n\
             RELEASE SAVEPOINT sp1;\nCOMMIT;",
            lexega_core::dialect::postgres(),
        ),
    ] {
        let catalog = quoted_names_under(&dialect);
        let config = AnalysisConfig {
            dialect: Some(dialect.clone()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let rules = rules_raised(sql, dialect.clone(), &catalog, "");
        assert!(
            rules.contains(&"DML-WRITE-UNBOUNDED".to_string()),
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_tsql_module_publishes_the_kind_of_the_statement_defining_it() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    // One rule per published kind, action and `or_alter`.
    let yaml = r#"
rules:
  - id: T-CREATE-PROC
    risk_level: info
    message: "x"
    triggers:
      all_of:
        - kind: create_procedure
        - ddl.action: create
  - id: T-ALTER-PROC
    risk_level: info
    message: "x"
    triggers:
      all_of:
        - kind: alter_procedure
        - ddl.action: alter
  - id: T-CREATE-FUNC
    risk_level: info
    message: "x"
    triggers:
      all_of:
        - kind: create_function
        - ddl.action: create
  - id: T-ALTER-FUNC
    risk_level: info
    message: "x"
    triggers:
      all_of:
        - kind: alter_function
        - ddl.action: alter
  - id: T-OR-ALTER
    risk_level: info
    message: "x"
    triggers:
      ddl.options.or_alter: true
"#;
    let cases: [(&str, &[&str]); 8] = [
        ("CREATE PROCEDURE dbo.zz_p AS SELECT 1", &["T-CREATE-PROC"]),
        ("ALTER PROCEDURE dbo.zz_p AS SELECT 1", &["T-ALTER-PROC"]),
        (
            "ALTER PROC dbo.zz_p AS BEGIN SELECT 1 END",
            &["T-ALTER-PROC"],
        ),
        (
            "CREATE OR ALTER PROCEDURE dbo.zz_p AS SELECT 1",
            &["T-CREATE-PROC", "T-OR-ALTER"],
        ),
        (
            "CREATE FUNCTION dbo.zz_f () RETURNS INT AS BEGIN RETURN 1 END",
            &["T-CREATE-FUNC"],
        ),
        (
            "ALTER FUNCTION dbo.zz_f () RETURNS INT AS BEGIN RETURN 1 END",
            &["T-ALTER-FUNC"],
        ),
        (
            "ALTER FUNCTION dbo.zz_f (@x INT) RETURNS TABLE AS RETURN (SELECT 1 AS a)",
            &["T-ALTER-FUNC"],
        ),
        (
            "CREATE OR ALTER FUNCTION dbo.zz_f () RETURNS INT AS BEGIN RETURN 1 END",
            &["T-CREATE-FUNC", "T-OR-ALTER"],
        ),
    ];
    for (sql, expected) in cases {
        let mut fired: Vec<String> = rules_raised(sql, mssql.clone(), &catalog, yaml)
            .into_iter()
            .filter(|id| id.starts_with("T-"))
            .collect();
        fired.sort();
        fired.dedup();
        assert_eq!(fired, expected.to_vec(), "{sql}");
        // `*-NEW` says "created": never on an ALTER.
        let rules = rules_raised(sql, mssql.clone(), &catalog, "");
        let created = !sql.starts_with("ALTER");
        assert_eq!(
            rules.iter().any(|r| r == "PROC-NEW" || r == "UDF-NEW"),
            created,
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_tsql_trigger_publishes_the_kind_of_the_statement_defining_it() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    // One rule per published kind, action and `or_alter`; the trigger is
    // the statement's target.
    let yaml = r#"
rules:
  - id: T-CREATE-TRIG
    risk_level: info
    message: "x"
    triggers:
      all_of:
        - kind: create_trigger
        - ddl.action: create
        - ddl.object_kind: trigger
        - ddl.target.kind: trigger
        - ddl.target.name.name.normalized: ZZ_TR
  - id: T-ALTER-TRIG
    risk_level: info
    message: "x"
    triggers:
      all_of:
        - kind: alter_trigger
        - ddl.action: alter
        - ddl.object_kind: trigger
        - ddl.target.kind: trigger
        - ddl.target.name.name.normalized: ZZ_TR
  - id: T-OR-ALTER
    risk_level: info
    message: "x"
    triggers:
      ddl.options.or_alter: true
"#;
    let body = "AS BEGIN SET NOCOUNT ON; END";
    let cases: [(&str, &[&str]); 9] = [
        (
            "CREATE TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT",
            &["T-CREATE-TRIG"],
        ),
        (
            "CREATE TRIGGER dbo.zz_tr ON dbo.zz_t FOR INSERT, UPDATE",
            &["T-CREATE-TRIG"],
        ),
        (
            "CREATE TRIGGER dbo.zz_tr ON dbo.zz_v INSTEAD OF DELETE",
            &["T-CREATE-TRIG"],
        ),
        (
            "ALTER TRIGGER dbo.zz_tr ON dbo.zz_t AFTER UPDATE",
            &["T-ALTER-TRIG"],
        ),
        (
            "CREATE OR ALTER TRIGGER dbo.zz_tr ON dbo.zz_t AFTER DELETE",
            &["T-CREATE-TRIG", "T-OR-ALTER"],
        ),
        (
            "CREATE TRIGGER zz_tr ON DATABASE FOR CREATE_TABLE, DROP_TABLE",
            &["T-CREATE-TRIG"],
        ),
        (
            "ALTER TRIGGER zz_tr ON DATABASE AFTER DROP_TABLE",
            &["T-ALTER-TRIG"],
        ),
        (
            "CREATE TRIGGER zz_tr ON ALL SERVER FOR LOGON",
            &["T-CREATE-TRIG"],
        ),
        (
            "CREATE OR ALTER TRIGGER zz_tr ON ALL SERVER FOR CREATE_LOGIN",
            &["T-CREATE-TRIG", "T-OR-ALTER"],
        ),
    ];
    for (head, expected) in cases {
        let sql = format!("{head} {body}\nGO");
        let mut fired: Vec<String> = rules_raised(&sql, mssql.clone(), &catalog, yaml)
            .into_iter()
            .filter(|id| id.starts_with("T-"))
            .collect();
        fired.sort();
        fired.dedup();
        assert_eq!(fired, expected.to_vec(), "{sql}");
    }
}

#[test]
fn a_tsql_trigger_publishes_its_body_as_a_procedure_publishes_its_own() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let yaml = r#"
rules:
  - id: T-BODY
    risk_level: info
    message: "x"
    triggers:
      ddl.trigger_body.statements_count:
        gte: 1
  - id: T-THREE
    risk_level: info
    message: "x"
    triggers:
      ddl.trigger_body.statements_count: 3
  - id: T-CONCAT
    risk_level: info
    message: "x"
    triggers:
      ddl.trigger_body.dynamic_sql_calls:
        exists:
          all_of:
            - surface: mssql_exec_dynamic
            - argument: concat
            - parameterization: not_applicable
  - id: T-NAMED
    risk_level: info
    message: "x"
    triggers:
      ddl.trigger_body.dynamic_sql_calls:
        exists:
          all_of:
            - surface: mssql_sp_executesql
            - parameterization: named_params
  - id: T-EXECAS
    risk_level: info
    message: "x"
    triggers:
      ddl.trigger_body.execute_as_mode:
        in: [owner, caller, restricted_caller]
"#;
    let concat = "AS BEGIN DECLARE @n NVARCHAR(50); SELECT @n = name FROM inserted; \
                  EXEC ('DELETE FROM dbo.zz_u WHERE c = ' + @n) END";
    let named = "AS BEGIN DECLARE @n NVARCHAR(50); SELECT @n = name FROM inserted; \
                 EXEC sp_executesql N'SELECT c FROM dbo.zz_u WHERE c = @c', \
                 N'@c NVARCHAR(50)', @c = @n END";
    let cases: [(String, &[&str]); 11] = [
        (
            format!("CREATE TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT {concat}"),
            &["T-BODY", "T-CONCAT", "T-THREE"],
        ),
        // The trigger's `WITH EXECUTE AS` mode is its body's.
        (
            format!("CREATE TRIGGER dbo.zz_tr ON dbo.zz_t WITH EXECUTE AS OWNER AFTER INSERT {concat}"),
            &["T-BODY", "T-CONCAT", "T-EXECAS", "T-THREE"],
        ),
        // A named user names a principal no mode states.
        (
            "CREATE TRIGGER dbo.zz_tr ON dbo.zz_t WITH EXECUTE AS 'bob' AFTER INSERT AS UPDATE dbo.zz_u SET c = 1"
                .to_string(),
            &["T-BODY"],
        ),
        (
            format!("ALTER TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT {concat}"),
            &["T-BODY", "T-CONCAT", "T-THREE"],
        ),
        (
            format!("CREATE OR ALTER TRIGGER dbo.zz_tr ON dbo.zz_t INSTEAD OF DELETE {named}"),
            &["T-BODY", "T-NAMED", "T-THREE"],
        ),
        (
            format!("CREATE TRIGGER zz_tr ON DATABASE FOR CREATE_TABLE {named}"),
            &["T-BODY", "T-NAMED", "T-THREE"],
        ),
        (
            "CREATE TRIGGER zz_tr ON ALL SERVER FOR LOGON AS BEGIN IF 1 = 1 \
             BEGIN SET NOCOUNT ON; PRINT 'x' END END"
                .to_string(),
            &["T-BODY"],
        ),
        (
            "CREATE TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT AS UPDATE dbo.zz_u SET c = 1"
                .to_string(),
            &["T-BODY"],
        ),
        // A procedure's body is its own, never a trigger's.
        (format!("CREATE PROCEDURE dbo.zz_p {concat}"), &[]),
        (format!("ALTER PROCEDURE dbo.zz_p {named}"), &[]),
        ("DROP TRIGGER dbo.zz_tr".to_string(), &[]),
    ];
    for (head, expected) in cases {
        let sql = format!("{head}\nGO");
        let mut fired: Vec<String> = rules_raised(&sql, mssql.clone(), &catalog, yaml)
            .into_iter()
            .filter(|id| id.starts_with("T-"))
            .collect();
        fired.sort();
        fired.dedup();
        assert_eq!(fired, expected.to_vec(), "{sql}");
    }
}

#[test]
fn a_tsql_trigger_created_raises_trig_new_and_an_altered_one_does_not() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let body = "AS BEGIN SET NOCOUNT ON; END";
    let cases: [(&str, bool); 8] = [
        ("CREATE TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT", true),
        (
            "CREATE TRIGGER dbo.zz_tr ON dbo.zz_v INSTEAD OF DELETE",
            true,
        ),
        (
            "CREATE OR ALTER TRIGGER dbo.zz_tr ON dbo.zz_t FOR UPDATE",
            true,
        ),
        ("CREATE TRIGGER zz_tr ON DATABASE FOR CREATE_TABLE", true),
        (
            "CREATE OR ALTER TRIGGER zz_tr ON ALL SERVER FOR LOGON",
            true,
        ),
        ("ALTER TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT", false),
        ("ALTER TRIGGER zz_tr ON DATABASE FOR DROP_TABLE", false),
        ("ALTER TRIGGER zz_tr ON ALL SERVER FOR LOGON", false),
    ];
    for (head, raised) in cases {
        let sql = format!("{head} {body}\nGO");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        assert_eq!(
            rules.iter().any(|id| id == "TRIG-NEW"),
            raised,
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_procedure_created_to_execute_as_restricted_caller_is_flagged() {
    let snowflake = lexega_core::dialect::snowflake();
    let catalog = quoted_names_under(&snowflake);
    let config = AnalysisConfig {
        dialect: Some(snowflake.clone()),
        ..Default::default()
    };
    let sql = "CREATE OR REPLACE PROCEDURE zz_p() RETURNS VARCHAR LANGUAGE SQL \
               EXECUTE AS RESTRICTED CALLER AS $$ BEGIN RETURN 'x'; END $$;\nTRUNCATE TABLE zz_dst;";
    let report =
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog).expect("analyze");
    assert_eq!(report.summary.statements_skipped, 0, "{sql}");
    let rules = rules_raised(sql, snowflake.clone(), &catalog, "");
    for raised in ["PROC-EXECAS-RESTRICT", "PROC-NEW", "TBL-TRUNCATE"] {
        assert!(rules.contains(&raised.to_string()), "{sql}: {rules:?}");
    }
}

#[test]
fn a_tsql_exec_without_arguments_leaves_the_next_statement_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let block = "IF 1 = 1\nBEGIN\n  PRINT 'x'\nEND";
    for (sql, rule) in [
        ("EXEC dbo.zz_p\nTRUNCATE TABLE dbo.zz_dst".to_string(), "TBL-TRUNCATE"),
        (format!("{block}\nEXEC dbo.zz_p\nTRUNCATE TABLE dbo.zz_dst"), "TBL-TRUNCATE"),
        (format!("{block}\nEXEC dbo.zz_p\nDROP TABLE dbo.zz_dst"), "TBL-DROP"),
        (
            "CREATE PROCEDURE dbo.zz_p2 AS\nBEGIN\n  EXEC dbo.zz_p\n  TRUNCATE TABLE dbo.zz_dst\nEND"
                .to_string(),
            "TBL-TRUNCATE",
        ),
    ] {
        let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        for raised in [rule, "INFO-MSSQL-EXEC-PROC"] {
            assert!(rules.contains(&raised.to_string()), "{sql}: {rules:?}");
        }
    }
}

#[test]
fn a_tsql_procedure_executing_as_a_named_user_is_analysed_as_executing_as_self() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let after = "GO\nTRUNCATE TABLE dbo.zz_dst\nGO";
    for (named, as_self) in [
        (
            "CREATE PROCEDURE dbo.zz_p WITH EXECUTE AS 'zz_u' AS\nUPDATE dbo.zz_src SET c = 1",
            "CREATE PROCEDURE dbo.zz_p WITH EXECUTE AS SELF AS\nUPDATE dbo.zz_src SET c = 1",
        ),
        (
            "ALTER PROCEDURE dbo.zz_p WITH RECOMPILE, EXECUTE AS N'zz_u' AS\nBEGIN\n  \
             UPDATE dbo.zz_src SET c = 1\nEND",
            "ALTER PROCEDURE dbo.zz_p WITH RECOMPILE, EXECUTE AS SELF AS\nBEGIN\n  \
             UPDATE dbo.zz_src SET c = 1\nEND",
        ),
    ] {
        let sql = format!("{named}\n{after}");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        let expected = rules_raised(&format!("{as_self}\n{after}"), mssql.clone(), &catalog, "");
        assert_eq!(rules, expected, "{sql}");
        for raised in ["DML-WRITE-UNBOUNDED", "TBL-TRUNCATE"] {
            assert!(rules.contains(&raised.to_string()), "{sql}: {rules:?}");
        }
        // `PROC-NEW` on the CREATE only: an ALTER creates nothing.
        assert_eq!(
            rules.contains(&"PROC-NEW".to_string()),
            named.starts_with("CREATE"),
            "{sql}: {rules:?}"
        );
        let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
    }
}

#[test]
fn a_function_body_block_without_as_leaves_the_next_statement_analysed() {
    let cases = [
        (
            lexega_core::dialect::mssql(),
            "CREATE FUNCTION dbo.zz_f () RETURNS INT\nBEGIN\n  RETURN 1\nEND\nGO\nTRUNCATE TABLE dbo.zz_dst\nGO",
        ),
        (
            lexega_core::dialect::mssql(),
            "ALTER FUNCTION dbo.zz_f () RETURNS @t TABLE (id INT)\nBEGIN\n  \
             INSERT INTO @t SELECT id FROM dbo.zz_src\n  RETURN\nEND\nTRUNCATE TABLE dbo.zz_dst",
        ),
        (
            lexega_core::dialect::mysql(),
            "CREATE FUNCTION zz_f() RETURNS INT DETERMINISTIC\nBEGIN\n  RETURN 1;\nEND;\nTRUNCATE TABLE zz_dst;",
        ),
        (
            lexega_core::dialect::databricks(),
            "CREATE FUNCTION zz_f() RETURNS INT LANGUAGE SQL BEGIN RETURN 1; END;\nTRUNCATE TABLE zz_dst;",
        ),
    ];
    for (dialect, sql) in cases {
        let catalog = quoted_names_under(&dialect);
        let config = AnalysisConfig {
            dialect: Some(dialect.clone()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let rules = rules_raised(sql, dialect.clone(), &catalog, "");
        assert!(
            rules.contains(&"TBL-TRUNCATE".to_string()),
            "{sql}: {rules:?}"
        );
        // `UDF-NEW` on the CREATE only: an ALTER creates nothing.
        assert_eq!(
            rules.contains(&"UDF-NEW".to_string()),
            sql.starts_with("CREATE"),
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_tsql_statement_after_a_block_end_is_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let sql = "DECLARE @sql NVARCHAR(MAX) = N'SELECT id FROM dbo.zz_src WHERE c = ' + @x\n\
               IF @x IS NOT NULL\nBEGIN\n  PRINT 'run'\nEND\nEXEC (@sql)";
    let report =
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog).expect("analyze");
    assert_eq!(report.summary.statements_skipped, 0, "{sql}");
    let rules = rules_raised(sql, mssql.clone(), &catalog, "");
    assert!(raises_dynamic_sql(&rules), "{sql}: {rules:?}");
}

/// Whether `rules` report the concatenated `EXEC (@sql)`: where `@sql` reads
/// as a variable, as `DYNSQL` (or `PROC-DYNSQL` in a procedure body); where
/// analysis resolves it to the concatenation it holds, as `DYNSQL-CONCAT`.
fn raises_dynamic_sql(rules: &[String]) -> bool {
    rules
        .iter()
        .any(|rule| rule == "DYNSQL" || rule == "PROC-DYNSQL" || rule == "DYNSQL-CONCAT")
}

#[test]
fn a_tsql_break_or_continue_inside_a_while_is_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let skipped = |sql: &str| {
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyze")
            .summary
            .statements_skipped
    };
    let loop_body =
        "WHILE @i < 3\nBEGIN\n  SET @i = @i + 1\n  IF @i = 2\n  BEGIN\n    BREAK\n  END\n  \
                     CONTINUE\nEND";
    for sql in [
        format!("{loop_body}\nDELETE FROM dbo.zz_dst"),
        format!("CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n{loop_body}\nEND\nGO\nDELETE FROM dbo.zz_dst\nGO"),
        format!("CREATE PROCEDURE dbo.zz_p AS\n{loop_body}\nGO\nDELETE FROM dbo.zz_dst\nGO"),
        format!("BEGIN TRY\n{loop_body}\nEND TRY\nBEGIN CATCH\n  SELECT 1\nEND CATCH\nDELETE FROM dbo.zz_dst"),
    ] {
        assert_eq!(skipped(&sql), 0, "{sql}");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        assert!(rules.contains(&"DML-WRITE-UNBOUNDED".to_string()), "{sql}: {rules:?}");
    }
    // Outside a loop it is still not read.
    assert_eq!(skipped("IF 1 = 1\nBEGIN\n  BREAK\nEND"), 1);
}

#[test]
fn a_tsql_enable_or_disable_trigger_raises_the_trigger_state_rules_and_ends_with_its_scope() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let truncate = "TRUNCATE TABLE dbo.zz_dst";
    for (statement, raised, not_raised) in [
        (
            "DISABLE TRIGGER dbo.zz_tr ON dbo.zz_dst",
            "PG-TRIG-OFF",
            "INFO-PG-TRIG-ON",
        ),
        (
            "DISABLE TRIGGER zz_a, [zz b] ON [dbo].[zz_dst]",
            "PG-TRIG-OFF",
            "INFO-PG-TRIG-ON",
        ),
        (
            "DISABLE TRIGGER ALL ON DATABASE",
            "PG-TRIG-OFF",
            "INFO-PG-TRIG-ON",
        ),
        (
            "disable trigger all on all server",
            "PG-TRIG-OFF",
            "INFO-PG-TRIG-ON",
        ),
        (
            "ENABLE TRIGGER zz_tr ON dbo.zz_dst",
            "INFO-PG-TRIG-ON",
            "PG-TRIG-OFF",
        ),
        (
            "ENABLE TRIGGER zz_a, zz_b ON DATABASE",
            "INFO-PG-TRIG-ON",
            "PG-TRIG-OFF",
        ),
        (
            "ENABLE TRIGGER ALL ON ALL SERVER",
            "INFO-PG-TRIG-ON",
            "PG-TRIG-OFF",
        ),
    ] {
        for sql in [
            format!("{statement}\n{truncate}"),
            format!("{statement};\n{truncate};"),
            format!("{statement}\nGO\n{truncate}\nGO"),
            format!("IF 1 = 1\nBEGIN\n  {statement}\n  {truncate}\nEND"),
            format!("CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n  {statement};\n  {truncate};\nEND\nGO"),
            format!("CREATE PROCEDURE dbo.zz_p AS\n{statement}\n{truncate}\nGO"),
        ] {
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            for rule in [raised, "TBL-TRUNCATE"] {
                assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
            }
            assert!(!rules.contains(&not_raised.to_string()), "{sql}: {rules:?}");
        }
    }
}

#[test]
fn a_tsql_trigger_state_statement_targets_the_table_its_triggers_are_on() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let yaml = r#"
rules:
  - id: ZZ-TRIGGER-STATE-TARGET
    risk_level: low
    message: "trigger state on a table"
    triggers:
      all_of:
        - kind: mssql_trigger_state
        - ddl.object_kind: trigger
        - ddl.target.kind: generic
        - ddl.target.name.name.normalized: ZZ_DST
"#;
    for (sql, fires) in [
        ("DISABLE TRIGGER dbo.zz_tr ON dbo.zz_dst", true),
        ("ENABLE TRIGGER zz_a, zz_b ON [dbo].[ZZ_DST]", true),
        ("DISABLE TRIGGER zz_dst ON DATABASE", false),
        ("ENABLE TRIGGER ALL ON ALL SERVER", false),
    ] {
        let rules = rules_raised(sql, mssql.clone(), &catalog, yaml);
        assert_eq!(
            rules.contains(&"ZZ-TRIGGER-STATE-TARGET".to_string()),
            fires,
            "{sql}: {rules:?}"
        );
    }
}

#[test]
fn a_tsql_statement_led_by_a_reserved_statement_word_leaves_the_statements_around_it_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    for statement in [
        "RAISERROR('zz', 0, 1) WITH NOWAIT",
        "WAITFOR DELAY '00:00:01'",
        "DBCC CHECKDB",
        "BACKUP DATABASE zz TO DISK = 'zz.bak'",
    ] {
        for (before, raised) in [
            ("EXEC dbo.zz_p", "INFO-MSSQL-EXEC-PROC"),
            ("SELECT * FROM dbo.zz_src", "TBL-TRUNCATE"),
            ("DELETE FROM dbo.zz_src", "DML-WRITE-UNBOUNDED"),
        ] {
            let sql = format!("{before}\n{statement}\nTRUNCATE TABLE dbo.zz_dst");
            let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
                .expect("analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            assert_eq!(report.summary.statements_analyzed, 3, "{sql}");
            let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
            for rule in [raised, "TBL-TRUNCATE"] {
                assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
            }
        }
    }
}

#[test]
fn a_tsql_bulk_insert_after_a_statement_without_a_semicolon_is_analysed() {
    let mssql = lexega_core::dialect::mssql();
    let catalog = quoted_names_under(&mssql);
    let config = AnalysisConfig {
        dialect: Some(mssql.clone()),
        ..Default::default()
    };
    let bulk = "BULK INSERT dbo.zz_dst FROM 'c:\\zz.csv' WITH (FIELDTERMINATOR = ',')";
    let mut scripts: Vec<String> = [
        "EXEC dbo.zz_p",
        "SELECT * FROM dbo.zz_src",
        "DELETE FROM dbo.zz_src",
        "INSERT INTO dbo.zz_dst SELECT * FROM dbo.zz_src",
    ]
    .iter()
    .map(|before| format!("{before}\n{bulk}\nTRUNCATE TABLE dbo.zz_dst"))
    .collect();
    scripts.push(format!(
        "CREATE PROCEDURE dbo.zz_p2 AS\nDELETE FROM dbo.zz_src\n{bulk}\nGO\nTRUNCATE TABLE dbo.zz_dst\nGO"
    ));
    scripts.push(format!(
        "CREATE PROCEDURE dbo.zz_p2 AS\nBEGIN\n  DELETE FROM dbo.zz_src\n  {bulk}\nEND\nGO\nTRUNCATE TABLE dbo.zz_dst\nGO"
    ));
    for sql in scripts {
        let report = analyze_risk_with_policy_config_and_catalog_index(&sql, &config, &catalog)
            .expect("analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let rules = rules_raised(&sql, mssql.clone(), &catalog, "");
        for rule in ["MSSQL-BULK-INSERT", "TBL-TRUNCATE"] {
            assert!(rules.contains(&rule.to_string()), "{sql}: {rules:?}");
        }
    }
}

#[test]
fn a_row_count_is_never_a_column_of_its_own_query() {
    let catalog = make_catalog_with_pii_tags();
    let postgres = lexega_core::dialect::postgres;
    let mssql = lexega_core::dialect::mssql;
    let mysql = lexega_core::dialect::mysql;
    let query = "SELECT email FROM analytics.public.customers";
    let cases: Vec<(lexega_core::dialect::DialectRef, String)> = vec![
        (postgres(), format!("CREATE FUNCTION f(n int) RETURNS SETOF text LANGUAGE plpgsql AS $$ BEGIN RETURN QUERY {query} ORDER BY id FETCH FIRST n ROWS ONLY; END $$;")),
        (postgres(), format!("CREATE FUNCTION f(n int) RETURNS SETOF text LANGUAGE plpgsql AS $$ BEGIN RETURN QUERY {query} ORDER BY id FETCH FIRST n + 1 ROWS ONLY; END $$;")),
        (postgres(), format!("CREATE FUNCTION f(n int) RETURNS SETOF text LANGUAGE plpgsql AS $$ BEGIN RETURN QUERY {query} ORDER BY id LIMIT n OFFSET n; END $$;")),
        (postgres(), format!("CREATE FUNCTION f(n int) RETURNS SETOF text LANGUAGE sql AS $$ {query} ORDER BY id FETCH FIRST n ROWS ONLY $$;")),
        (postgres(), format!("{query} UNION ALL {query} LIMIT n;")),
        (mssql(), format!("CREATE PROCEDURE dbo.p @n INT AS BEGIN {query} ORDER BY id OFFSET 0 ROWS FETCH NEXT @n ROWS ONLY; END")),
        (mssql(), "CREATE PROCEDURE dbo.p @n INT AS BEGIN SELECT TOP (@n) email FROM analytics.public.customers ORDER BY id; END".to_string()),
        (mssql(), format!("DECLARE @n INT = 5\n{query} ORDER BY id OFFSET @n ROWS FETCH NEXT @n ROWS ONLY")),
        (mssql(), "DECLARE @n INT = 5\nDELETE TOP (@n) FROM analytics.public.customers WHERE id = 1".to_string()),
        (mysql(), format!("CREATE PROCEDURE p(IN n INT) BEGIN {query} ORDER BY id LIMIT n; END")),
    ];
    for (dialect, sql) in cases {
        let rules = rules_raised(&sql, dialect, &catalog, "");
        assert!(
            !rules.contains(&"CAT-COL-UNKNOWN".to_string()),
            "{sql}: {rules:?}"
        );
    }
    // A name the query reads is still asked of the catalog.
    let sql = format!("{query} WHERE nope = 1 ORDER BY id LIMIT 5");
    let rules = rules_raised(&sql, postgres(), &catalog, "");
    assert!(
        rules.contains(&"CAT-COL-UNKNOWN".to_string()),
        "{sql}: {rules:?}"
    );
}

/// What a report under `dialect` says of `sql` against a catalog of
/// `ANALYTICS.PUBLIC.ZZ_KNOWN`: its missing tables, its statements parsed
/// and skipped, and the rule ids it raises.
fn created_table_report(
    dialect: lexega_core::dialect::DialectRef,
    sql: &str,
) -> (Vec<String>, usize, usize, Vec<String>) {
    let catalog = {
        let _folding = lexega_core::set_normalization_dialect(dialect.name());
        CatalogIndex::from_snapshot(snapshot_of(&[("PUBLIC", &["ZZ_KNOWN"])]))
            .expect("valid snapshot")
    };
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report =
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog).expect("analyze");
    let mut rules: Vec<String> = report
        .entries()
        .map(|lexega_core::analyzer::RuleMatch::Analysis(finding)| finding.matched_rule.clone())
        .collect();
    rules.sort();
    (
        report.catalog_info.missing_tables,
        report.summary.statements_parsed,
        report.summary.statements_skipped,
        rules,
    )
}

#[test]
fn a_create_in_any_of_its_leads_is_one_statement_whose_table_is_not_missing() {
    use lexega_core::dialect::{bigquery, databricks, postgres, snowflake};
    let cases: [(lexega_core::dialect::DialectRef, &str, &[&str]); 13] = [
        (
            snowflake(),
            "CREATE OR ALTER TABLE zz_t (id INT); SELECT id FROM zz_t",
            &[],
        ),
        (
            snowflake(),
            "CREATE OR ALTER TABLE s1.zz_t (id INT, email VARCHAR); SELECT id FROM s1.zz_t",
            &[],
        ),
        (
            databricks(),
            "REPLACE TABLE zz_t AS SELECT id FROM zz_src; SELECT id FROM zz_t",
            &["zz_src"],
        ),
        (
            databricks(),
            "REPLACE TABLE zz_t (id INT) USING DELTA; SELECT id FROM zz_t",
            &[],
        ),
        (
            databricks(),
            "CREATE OR REFRESH STREAMING TABLE zz_t AS SELECT id FROM zz_src; SELECT id FROM zz_t",
            &["zz_src"],
        ),
        (
            databricks(),
            "CREATE STREAMING TABLE zz_t AS SELECT id FROM zz_src; SELECT id FROM zz_t",
            &["zz_src"],
        ),
        (
            postgres(),
            "CREATE FOREIGN TABLE zz_t (id INT) SERVER zz_srv; SELECT id FROM zz_t",
            &[],
        ),
        (
            postgres(),
            "CREATE FOREIGN TABLE IF NOT EXISTS s1.zz_t (id INT) SERVER zz_srv; \
             SELECT id FROM s1.zz_t",
            &[],
        ),
        (
            bigquery(),
            "CREATE SNAPSHOT TABLE zz_t CLONE zz_known; SELECT id FROM zz_t",
            &[],
        ),
        (
            bigquery(),
            "CREATE SNAPSHOT TABLE IF NOT EXISTS d1.zz_t CLONE zz_known \
             FOR SYSTEM_TIME AS OF CURRENT_TIMESTAMP(); SELECT id FROM d1.zz_t",
            &[],
        ),
        (
            snowflake(),
            "CREATE TABLE IDENTIFIER('zz_t') (id INT); SELECT id FROM zz_t",
            &[],
        ),
        (
            snowflake(),
            "CREATE TABLE IDENTIFIER('s1.zz_t') (id INT); SELECT id FROM s1.zz_t",
            &[],
        ),
        (
            snowflake(),
            "CREATE OR REPLACE TABLE IDENTIFIER('zz_t') AS SELECT id FROM zz_src; \
             SELECT id FROM zz_t",
            &["zz_src"],
        ),
    ];
    let mut wrong: Vec<String> = cases
        .into_iter()
        .filter_map(|(dialect, sql, missing)| {
            let (listed, parsed, skipped, _) = created_table_report(dialect, sql);
            let expected: Vec<String> = missing.iter().map(|m| m.to_string()).collect();
            ((listed.clone(), parsed, skipped) != (expected, 2, 0))
                .then(|| format!("{sql}: missing {listed:?}, parsed {parsed}, skipped {skipped}"))
        })
        .collect();
    // `REPLACE TABLE` replaces the table; `CREATE OR ALTER TABLE` alters it.
    let (_, _, _, rules) = created_table_report(databricks(), "REPLACE TABLE zz_t (id INT)");
    if !rules.contains(&"TBL-REPLACE".to_string()) {
        wrong.push(format!("REPLACE TABLE: {rules:?}"));
    }
    let (_, _, _, rules) = created_table_report(snowflake(), "CREATE OR ALTER TABLE zz_t (id INT)");
    if rules.contains(&"TBL-REPLACE".to_string()) {
        wrong.push(format!("CREATE OR ALTER TABLE: {rules:?}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_snapshot_or_foreign_table_read_as_fully_as_it_was_created_is_not_missing() {
    use lexega_core::dialect::{bigquery, postgres};
    let cases: [(lexega_core::dialect::DialectRef, &str); 10] = [
        (
            bigquery(),
            "CREATE SNAPSHOT TABLE `zz_p.zz_d.zz_t` CLONE zz_known; \
             SELECT id FROM `zz_p.zz_d.zz_t`",
        ),
        (
            bigquery(),
            "CREATE SNAPSHOT TABLE `zz_p`.`zz_d`.`zz_t` CLONE zz_known; \
             SELECT id FROM `zz_p`.`zz_d`.`zz_t`",
        ),
        (
            bigquery(),
            "CREATE SNAPSHOT TABLE zz_d.`ZzMixed` CLONE zz_known; SELECT id FROM zz_d.`ZzMixed`",
        ),
        (
            bigquery(),
            "CREATE SNAPSHOT TABLE zz_d . /* c */ zz_t CLONE zz_known; SELECT id FROM zz_d.zz_t",
        ),
        (
            bigquery(),
            "CREATE SNAPSHOT TABLE zz_d.zz_t CLONE zz_known; SELECT id FROM zz_d.zz_t",
        ),
        (
            postgres(),
            "CREATE FOREIGN TABLE \"my.new\" (id INT) SERVER zz_srv; SELECT id FROM \"my.new\"",
        ),
        (
            postgres(),
            "CREATE FOREIGN TABLE zz_s.\"My.T\" (id INT) SERVER zz_srv; \
             SELECT id FROM zz_s.\"My.T\"",
        ),
        (
            postgres(),
            "CREATE FOREIGN TABLE zz_s.zz_t (id INT) SERVER zz_db.zz_srv; \
             SELECT id FROM zz_s.zz_t",
        ),
        (
            postgres(),
            "CREATE FOREIGN TABLE zz_s.zz_p PARTITION OF zz_s.zz_parent FOR VALUES IN (1) \
             SERVER zz_srv; SELECT id FROM zz_s.zz_p",
        ),
        (
            postgres(),
            "CREATE FOREIGN TABLE zz_s . /* c */ zz_t (id INT) SERVER zz_srv; \
             SELECT id FROM zz_s.zz_t",
        ),
    ];
    let wrong: Vec<String> = cases
        .into_iter()
        .filter_map(|(dialect, sql)| {
            let (listed, parsed, skipped, _) = created_table_report(dialect, sql);
            (!listed.is_empty() || parsed != 2 || skipped != 0)
                .then(|| format!("{sql}: missing {listed:?}, parsed {parsed}, skipped {skipped}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_create_table_query_written_without_as_reads_its_tables() {
    use lexega_core::dialect::{mssql, mysql};
    let cases: [(lexega_core::dialect::DialectRef, &str, &[&str], usize); 7] = [
        (
            mysql(),
            "CREATE TABLE zz_t SELECT id FROM zz_src; SELECT id FROM zz_t",
            &["zz_src"],
            2,
        ),
        (
            mysql(),
            "CREATE TABLE t2 (a INT, b VARCHAR(10)) SELECT id, email FROM zz_src",
            &["zz_src"],
            1,
        ),
        (
            mysql(),
            "CREATE TABLE zz_t (a INT) SELECT id FROM zz_src; SELECT a FROM zz_t",
            &["zz_src"],
            2,
        ),
        (
            mysql(),
            "CREATE TABLE IF NOT EXISTS zz_t SELECT id FROM zz_src; SELECT id FROM zz_t",
            &["zz_src"],
            2,
        ),
        (
            mysql(),
            "CREATE TABLE zz_t IGNORE SELECT id FROM zz_src; SELECT id FROM zz_t",
            &["zz_src"],
            2,
        ),
        (
            mysql(),
            "CREATE TABLE zz_t ENGINE=InnoDB SELECT id FROM zz_src; SELECT id FROM zz_t",
            &["zz_src"],
            2,
        ),
        // A T-SQL `SELECT` after a create is the next statement.
        (
            mssql(),
            "CREATE TABLE dbo.zz_t (id INT)\nSELECT id FROM dbo.zz_src",
            &["dbo.zz_src"],
            2,
        ),
    ];
    let mut wrong: Vec<String> = cases
        .into_iter()
        .filter_map(|(dialect, sql, missing, statements)| {
            let (listed, parsed, skipped, _) = created_table_report(dialect, sql);
            let expected: Vec<String> = missing.iter().map(|m| m.to_string()).collect();
            ((listed.clone(), parsed, skipped) != (expected, statements, 0))
                .then(|| format!("{sql}: missing {listed:?}, parsed {parsed}, skipped {skipped}"))
        })
        .collect();
    // The query's table the catalog lacks is reported.
    let (_, _, _, rules) = created_table_report(mysql(), "CREATE TABLE zz_t SELECT id FROM zz_src");
    if !rules.contains(&"CAT-TBL-UNKNOWN".to_string()) {
        wrong.push(format!("CREATE TABLE zz_t SELECT: {rules:?}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Whether `CAT-COL-UNKNOWN` is raised for `sql` under `dialect_name`,
/// against a catalog whose `analytics.public.accounts` holds `id` and
/// `owner`, and whose `analytics.public.stamped` holds `id` and a column
/// named for the current date.
fn column_unknown_under(sql: &str, dialect_name: &str) -> bool {
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [{"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [
            {"name": "ACCOUNTS", "kind": "Table", "columns": [{"name": "ID"}, {"name": "OWNER"}]},
            {"name": "STAMPED", "kind": "Table", "columns": [{"name": "ID"}, {"name": "CURRENT_DATE"}]}
        ]}]}]}"#,
    )
    .expect("snapshot");
    let dialect = lexega_core::dialect::dialect_from_name(dialect_name).expect("a known dialect");
    let _folding = lexega_core::set_normalization_dialect(dialect.name());
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("valid snapshot");
    rules_raised(sql, dialect, &catalog, "").contains(&"CAT-COL-UNKNOWN".to_string())
}

#[test]
fn a_bare_word_is_a_column_of_the_catalog_unless_the_dialect_documents_it_as_a_function() {
    let accounts = "analytics.public.accounts";
    let stamped = "analytics.public.stamped";
    let mut wrong = Vec::new();
    for (dialect, sql, raised) in [
        // The documented bare functions are not columns to look for.
        (
            "snowflake",
            format!("SELECT id FROM {accounts} WHERE owner = current_user"),
            false,
        ),
        (
            "mysql",
            format!("SELECT id FROM {accounts} WHERE owner = current_user"),
            false,
        ),
        (
            "databricks",
            format!("SELECT id FROM {accounts} WHERE owner = current_user"),
            false,
        ),
        (
            "mssql",
            format!("SELECT id FROM {accounts} WHERE owner = system_user"),
            false,
        ),
        (
            "postgresql",
            format!("SELECT id FROM {accounts} WHERE owner = session_user"),
            false,
        ),
        // A function written only with parentheses is a column bare.
        ("snowflake", format!("SELECT sysdate FROM {accounts}"), true),
        ("postgresql", format!("SELECT now FROM {accounts}"), true),
        ("mssql", format!("SELECT getdate FROM {accounts}"), true),
        ("mssql", format!("SELECT localtime FROM {accounts}"), true),
        (
            "databricks",
            format!("SELECT current_time FROM {accounts}"),
            true,
        ),
        ("mysql", format!("SELECT year FROM {accounts}"), true),
        (
            "snowflake",
            format!("SELECT id FROM {accounts} WHERE day = 1"),
            true,
        ),
        // A quoted name is a column.
        (
            "snowflake",
            format!("SELECT \"CURRENT_DATE\" FROM {accounts}"),
            true,
        ),
        (
            "mysql",
            format!("SELECT `CURRENT_DATE` FROM {accounts}"),
            true,
        ),
        // Where the dialect does not reserve the word, a column of a table
        // in scope is what it names.
        (
            "bigquery",
            format!("SELECT current_date FROM {stamped}"),
            false,
        ),
        (
            "databricks",
            format!("SELECT current_date FROM {stamped}"),
            false,
        ),
        (
            "databricks",
            format!("SELECT current_date FROM {accounts}"),
            false,
        ),
    ] {
        if column_unknown_under(&sql, dialect) != raised {
            wrong.push(format!("{dialect}: {sql}: expected raised={raised}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The catalog findings a report under `dialect` raises against the tagged
/// catalog, each once and in order, and the tables it lists as missing.
fn catalog_findings(
    dialect: lexega_core::dialect::DialectRef,
    sql: &str,
) -> (Vec<String>, Vec<String>) {
    let catalog = {
        let _folding = lexega_core::set_normalization_dialect(dialect.name());
        make_catalog_with_pii_tags()
    };
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report =
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog).expect("analyze");
    let mut rules: Vec<String> = report
        .entries()
        .filter_map(|s| s.rule_id())
        .filter(|id| id.starts_with("CAT-"))
        .map(String::from)
        .collect();
    rules.sort();
    rules.dedup();
    (rules, report.catalog_info.missing_tables)
}

/// `rules` raised and `missing` listed, as [`catalog_findings`] gives them.
fn findings(rules: &[&str], missing: &[&str]) -> (Vec<String>, Vec<String>) {
    let owned = |names: &[&str]| names.iter().map(|n| n.to_string()).collect();
    (owned(rules), owned(missing))
}

#[test]
fn a_relation_an_earlier_statement_creates_is_known_to_a_later_read() {
    let snowflake = lexega_core::dialect::snowflake;
    let mssql = lexega_core::dialect::mssql;
    for (dialect, sql) in [
        (
            snowflake(),
            "CREATE TABLE s.zz_new (id INT); SELECT id FROM s.zz_new",
        ),
        (
            snowflake(),
            "CREATE TABLE s.zz_ct AS SELECT id FROM analytics.public.customers; \
             SELECT id FROM s.zz_ct",
        ),
        (
            snowflake(),
            "CREATE VIEW s.zz_v AS SELECT id FROM analytics.public.customers; \
             SELECT id FROM s.zz_v",
        ),
        (
            snowflake(),
            "CREATE TABLE s.zz_new (id INT); ALTER TABLE s.zz_new RENAME TO s.zz_renamed; \
             SELECT id FROM s.zz_renamed",
        ),
        (
            mssql(),
            "CREATE TABLE s.zz_new (id INT);\nGO\nSELECT id FROM s.zz_new;",
        ),
        (
            mssql(),
            "CREATE TABLE s.zz_new (id INT); SELECT id FROM s.zz_new;",
        ),
        (
            mssql(),
            "SELECT id INTO s.zz_into FROM analytics.public.customers; \
             SELECT id FROM s.zz_into;",
        ),
        // A table the catalog has, renamed, is known by its new name.
        (
            snowflake(),
            "ALTER TABLE analytics.public.customers RENAME TO analytics.public.clients; \
             SELECT email FROM analytics.public.clients",
        ),
    ] {
        assert_eq!(catalog_findings(dialect, sql), findings(&[], &[]), "{sql}");
    }
}

#[test]
fn a_read_before_the_create_or_after_the_drop_is_still_of_an_unknown_table() {
    let snowflake = lexega_core::dialect::snowflake;
    let mssql = lexega_core::dialect::mssql;
    for (dialect, sql, missing) in [
        (
            snowflake(),
            "SELECT id FROM s.zz_late; CREATE TABLE s.zz_late (id INT)",
            "s.zz_late",
        ),
        (
            mssql(),
            "SELECT id FROM s.zz_late; CREATE TABLE s.zz_late (id INT);",
            "s.zz_late",
        ),
        (
            snowflake(),
            "CREATE TABLE s.zz_gone (id INT); DROP TABLE s.zz_gone; SELECT id FROM s.zz_gone",
            "s.zz_gone",
        ),
        (
            mssql(),
            "CREATE TABLE s.zz_gone (id INT); DROP TABLE s.zz_gone; SELECT id FROM s.zz_gone;",
            "s.zz_gone",
        ),
        // The name a table is renamed from names none after the rename.
        (
            snowflake(),
            "CREATE TABLE s.zz_old (id INT); ALTER TABLE s.zz_old RENAME TO s.zz_r; \
             SELECT id FROM s.zz_old",
            "s.zz_old",
        ),
        // Another schema's table of the name is another table.
        (
            snowflake(),
            "CREATE TABLE s1.zz_q (id INT); SELECT id FROM s2.zz_q",
            "s2.zz_q",
        ),
    ] {
        assert_eq!(
            catalog_findings(dialect, sql),
            findings(&["CAT-TBL-UNKNOWN"], &[missing]),
            "{sql}"
        );
    }
}

#[test]
fn the_columns_a_created_relation_declares_are_its_columns() {
    let snowflake = lexega_core::dialect::snowflake;
    for (dialect, sql, rules) in [
        (
            snowflake(),
            "CREATE TABLE s.zz_new (id INT, name TEXT); SELECT id, name FROM s.zz_new",
            &[][..],
        ),
        (
            snowflake(),
            "CREATE TABLE s.zz_new (id INT); SELECT nope FROM s.zz_new",
            &["CAT-COL-UNKNOWN"][..],
        ),
        (
            snowflake(),
            "CREATE VIEW s.zz_v (a, b) AS SELECT id, email FROM analytics.public.customers; \
             SELECT a, nope FROM s.zz_v",
            &["CAT-COL-UNKNOWN"][..],
        ),
        // A rename keeps the columns.
        (
            snowflake(),
            "CREATE TABLE s.zz_new (id INT); ALTER TABLE s.zz_new RENAME TO s.zz_r; \
             SELECT nope FROM s.zz_r",
            &["CAT-COL-UNKNOWN"][..],
        ),
        // A `CREATE … AS SELECT` has the columns its select list names.
        (
            snowflake(),
            "CREATE TABLE s.zz_ct AS SELECT id FROM analytics.public.customers; \
             SELECT nope FROM s.zz_ct",
            &["CAT-COL-UNKNOWN"][..],
        ),
        (
            snowflake(),
            "CREATE TABLE s.zz_ct AS SELECT id AS a, c.email FROM analytics.public.customers c; \
             SELECT a, email FROM s.zz_ct",
            &[][..],
        ),
        // A star gives the columns of the tables it reads, where they are known.
        (
            snowflake(),
            "CREATE TABLE s.zz_ct AS SELECT * FROM analytics.public.customers; \
             SELECT nope FROM s.zz_ct",
            &["CAT-COL-UNKNOWN"][..],
        ),
        (
            snowflake(),
            "CREATE TABLE s.zz_ct AS SELECT c.* FROM analytics.public.customers c; \
             SELECT email FROM s.zz_ct",
            &[][..],
        ),
        // In each dialect, as it writes names.
        (
            lexega_core::dialect::mysql(),
            "CREATE TABLE s.zz_ct SELECT id, `Email` AS e2 FROM analytics.public.customers; \
             SELECT id, E2 FROM s.zz_ct",
            &[][..],
        ),
        (
            lexega_core::dialect::databricks(),
            "CREATE OR REPLACE TABLE s.zz_ct AS SELECT id, email FROM analytics.public.customers; \
             SELECT ID, email FROM s.zz_ct",
            &[][..],
        ),
        (
            lexega_core::dialect::postgres(),
            "CREATE TABLE s.zz_ct AS SELECT id AS \"Mixed\" FROM analytics.public.customers; \
             SELECT \"Mixed\" FROM s.zz_ct",
            &[][..],
        ),
        // An alias written as a string names no column as written.
        (
            snowflake(),
            "CREATE TABLE s.zz_ct AS SELECT id AS 'a b' FROM analytics.public.customers; \
             SELECT nope FROM s.zz_ct",
            &[][..],
        ),
        // An item with no name written is a column no other name matches.
        (
            snowflake(),
            "CREATE TABLE s.zz_src AS SELECT id + 1 FROM analytics.public.customers; \
             CREATE TABLE s.zz_ct AS SELECT * FROM s.zz_src; SELECT nope FROM s.zz_ct",
            &["CAT-COL-UNKNOWN"][..],
        ),
        (
            snowflake(),
            "CREATE TABLE s.zz_ct AS SELECT id + 1 FROM analytics.public.customers; \
             SELECT nope FROM s.zz_ct",
            &["CAT-COL-UNKNOWN"][..],
        ),
        // A table made like another has its columns.
        (
            snowflake(),
            "CREATE TABLE s.zz_src LIKE analytics.public.customers; \
             CREATE TABLE s.zz_ct AS SELECT * FROM s.zz_src; SELECT nope FROM s.zz_ct",
            &["CAT-COL-UNKNOWN"][..],
        ),
        // A column a later statement adds is the table's.
        (
            snowflake(),
            "CREATE TABLE s.zz_new (id INT); ALTER TABLE s.zz_new ADD COLUMN extra INT; \
             SELECT extra FROM s.zz_new",
            &[][..],
        ),
        // MySQL adds the listed columns beside the query's.
        (
            lexega_core::dialect::mysql(),
            "CREATE TABLE s.zz_t (extra INT) SELECT 1 AS id; SELECT id, extra FROM s.zz_t",
            &[][..],
        ),
    ] {
        assert_eq!(
            catalog_findings(dialect, sql),
            findings(rules, &[]),
            "{sql}"
        );
    }
}

/// A CTE whose body reads a CTE of its own name in a nested scope is
/// followed to the table it reads, and the analysis ends.
#[test]
fn a_cte_reading_a_nested_cte_of_its_own_name_is_analysed() {
    let snowflake = lexega_core::dialect::snowflake;
    let sql = "WITH source AS (SELECT * FROM (WITH source AS \
               (SELECT * FROM analytics.public.customers) SELECT * FROM source) up) \
               SELECT * FROM analytics.public.customers o CROSS JOIN source";
    assert_eq!(
        catalog_findings(snowflake(), sql),
        findings(&[], &[]),
        "{sql}"
    );
}

#[test]
fn a_relation_a_routine_creates_is_known_in_its_body_only() {
    let snowflake = lexega_core::dialect::snowflake;
    let routine = "CREATE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ BEGIN \
                   CREATE TABLE s.zz_in (id INT); SELECT id FROM s.zz_in; RETURN 1; END $$;";
    assert_eq!(
        catalog_findings(snowflake(), routine),
        findings(&[], &[]),
        "{routine}"
    );
    let read_after = format!("{routine} SELECT id FROM s.zz_in");
    assert_eq!(
        catalog_findings(snowflake(), &read_after),
        findings(&["CAT-TBL-UNKNOWN"], &["s.zz_in"]),
        "{read_after}"
    );
}
