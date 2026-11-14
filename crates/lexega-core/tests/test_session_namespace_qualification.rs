// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! In-script `USE DATABASE` / `USE SCHEMA` sets the default namespace
//! that later *bare* table references resolve under, folded per
//! statement position (the same `ScriptContextFold` that tracks the
//! active role).
//!
//! The observable is `DML-WRITE-XSCHEMA`, which fires only when a write
//! and a read span two distinct schemas. The same `INSERT ... FROM s`
//! (bare `s`) flips between firing and silent purely by the preceding
//! `USE SCHEMA` target — isolating the qualification effect.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};

use lexega_core::api::{
    analyze_risk, analyze_risk_with_policy_config,
    analyze_risk_with_policy_config_and_catalog_index,
};
use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
use std::collections::HashSet;

const XSCHEMA: &str = "DML-WRITE-XSCHEMA";

fn rule_ids(entries: &[RuleMatch]) -> HashSet<String> {
    entries
        .iter()
        .map(|m| match m {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
        })
        .collect()
}

/// The ids of the context entries, where the info-level cross-schema rule lands.
fn context_ids(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    rule_ids(&report.context)
}

/// The ids of the findings and the context entries.
fn entry_ids(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    let mut ids = rule_ids(&report.findings);
    ids.extend(rule_ids(&report.context));
    ids
}

#[test]
fn use_schema_qualifies_bare_read_into_cross_schema() {
    // `USE SCHEMA core` qualifies the bare `s` to core.s; the write
    // target sandbox.t is a different schema → cross-schema fires.
    let ids = context_ids("USE SCHEMA core;\nINSERT INTO sandbox.t (a) SELECT a FROM s;");
    assert!(
        ids.contains(XSCHEMA),
        "expected cross-schema fire; ids={:?}",
        ids
    );
}

#[test]
fn use_schema_qualifies_bare_read_into_same_schema() {
    // Same INSERT, but `USE SCHEMA sandbox` qualifies `s` to sandbox.s —
    // identical schema to the write → silent. Only the USE SCHEMA target
    // differs from the firing case, isolating the qualification.
    let ids = entry_ids("USE SCHEMA sandbox;\nINSERT INTO sandbox.t (a) SELECT a FROM s;");
    assert!(
        !ids.contains(XSCHEMA),
        "expected silence under same-schema qualification; ids={:?}",
        ids
    );
}

#[test]
fn use_database_and_schema_compose_for_qualification() {
    // `USE DATABASE d1; USE SCHEMA core` — the db side fills both refs and
    // the schema side qualifies the bare `s` to core; the write sandbox.t
    // is a different schema → cross-schema fires. Exercises the db + schema
    // timeline composing through one fold.
    let ids = context_ids(
        "USE DATABASE d1;\nUSE SCHEMA core;\nINSERT INTO sandbox.t (a) SELECT a FROM s;",
    );
    assert!(
        ids.contains(XSCHEMA),
        "expected cross-schema fire; ids={:?}",
        ids
    );
}

#[test]
fn use_catalog_sets_the_catalog_a_name_without_one_resolves_in() {
    // Two catalogs hold a `public.zz_p`.
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [{"name": "ZZ_P", "kind": "Table", "columns": [{"name": "ID"}]}]}]},
            {"name": "OTHERDB", "schemas": [{"name": "PUBLIC", "tables": [{"name": "ZZ_P", "kind": "Table", "columns": [{"name": "ID"}]}]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    let config = AnalysisConfig {
        dialect: Some(lexega_core::dialect::databricks()),
        ..Default::default()
    };
    // Whether `CAT-TBL-UNKNOWN` fires, and the tables listed missing.
    let answer = |sql: &str| {
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyzes");
        let unknown = report.findings.iter().any(|m| match m {
            RuleMatch::Analysis(g) => g.matched_rule == "CAT-TBL-UNKNOWN",
        });
        (unknown, report.catalog_info.missing_tables)
    };
    let missing = |names: &[&str]| -> Vec<String> { names.iter().map(|n| n.to_string()).collect() };
    assert_eq!(
        answer("SELECT id FROM public.zz_p"),
        (true, missing(&["public.zz_p"]))
    );
    assert_eq!(
        answer("USE CATALOG analytics; SELECT id FROM public.zz_p"),
        (false, missing(&[]))
    );
    assert_eq!(
        answer("USE CATALOG analytics; USE SCHEMA public; SELECT id FROM zz_absent"),
        (true, missing(&["analytics.public.zz_absent"]))
    );
}

/// Whether `CAT-TBL-UNKNOWN` fires on `sql` under `dialect` against a
/// catalog holding `ANALYTICS.DB1.ZZ_Q`, and the tables listed missing.
fn against_db1(dialect: lexega_core::dialect::DialectRef, sql: &str) -> (bool, Vec<String>) {
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ANALYTICS", "schemas": [{"name": "DB1", "tables": [{"name": "ZZ_Q", "kind": "Table", "columns": [{"name": "ID"}]}]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = {
        let _folding = lexega_core::set_normalization_dialect(dialect.name());
        CatalogIndex::from_snapshot(snapshot).expect("index")
    };
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
        .expect("analyzes");
    let unknown = report.findings.iter().any(|m| match m {
        RuleMatch::Analysis(g) => g.matched_rule == "CAT-TBL-UNKNOWN",
    });
    (unknown, report.catalog_info.missing_tables)
}

/// `names`, as the tables a report lists missing.
fn listed(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

#[test]
fn a_mysql_use_sets_the_schema_a_name_without_one_resolves_in() {
    // A MySQL database is the schema of a catalog's three-part name.
    let mysql = lexega_core::dialect::mysql;
    assert_eq!(
        against_db1(mysql(), "USE db1; SELECT id FROM zz_q"),
        (false, listed(&[]))
    );
    assert_eq!(
        against_db1(mysql(), "USE db1; SELECT id FROM db1.zz_q"),
        (false, listed(&[]))
    );
    assert_eq!(
        against_db1(mysql(), "USE db1; SELECT id FROM zz_absent"),
        (true, listed(&["db1.zz_absent"]))
    );
    // A Snowflake database holds schemas: `USE db1` is no schema.
    assert!(
        against_db1(
            lexega_core::dialect::snowflake(),
            "USE db1; SELECT id FROM zz_q"
        )
        .0
    );
}

#[test]
fn a_databricks_use_or_use_database_sets_the_schema() {
    // A Databricks database is a schema: `DATABASE` is `SCHEMA`.
    let databricks = lexega_core::dialect::databricks;
    for sql in [
        "USE db1; SELECT id FROM zz_q",
        "USE DATABASE db1; SELECT id FROM zz_q",
        "USE SCHEMA db1; SELECT id FROM zz_q",
        "USE CATALOG analytics; USE DATABASE db1; SELECT id FROM zz_q",
    ] {
        assert_eq!(
            against_db1(databricks(), sql),
            (false, listed(&[])),
            "{sql}"
        );
    }
    assert_eq!(
        against_db1(databricks(), "USE DATABASE db1; SELECT id FROM zz_absent"),
        (true, listed(&["db1.zz_absent"]))
    );
    // `USE CATALOG` still sets the catalog: another catalog's `db1` is not it.
    assert_eq!(
        against_db1(
            databricks(),
            "USE CATALOG analytics; SELECT id FROM db1.zz_q"
        ),
        (false, listed(&[]))
    );
    assert!(against_db1(databricks(), "USE CATALOG other; SELECT id FROM db1.zz_q").0);
}

/// The configuration of a run whose session starts in `db` and `schema`.
fn session(db: Option<&str>, schema: Option<&str>) -> AnalysisConfig {
    AnalysisConfig {
        session_db: db.map(str::to_string),
        session_schema: schema.map(str::to_string),
        ..Default::default()
    }
}

#[test]
fn the_schema_a_session_starts_in_qualifies_a_bare_read_until_a_use() {
    let insert = "INSERT INTO sandbox.t (a) SELECT a FROM s;";
    let ids = |sql: &str, schema: &str| -> (HashSet<String>, HashSet<String>) {
        let report =
            analyze_risk_with_policy_config(sql, &session(None, Some(schema))).expect("analyzes");
        (rule_ids(&report.findings), rule_ids(&report.context))
    };
    let silent = |sql: &str, schema: &str| {
        let (findings, context) = ids(sql, schema);
        !findings.contains(XSCHEMA) && !context.contains(XSCHEMA)
    };
    assert!(ids(insert, "core").1.contains(XSCHEMA));
    assert!(silent(insert, "sandbox"));
    // A `USE` of the script replaces it for the statements after it.
    let used = format!("USE SCHEMA sandbox;\n{insert}");
    assert!(silent(&used, "core"));
}

#[test]
fn the_database_and_schema_a_session_starts_in_answer_the_catalog() {
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [{"name": "ANALYTICS", "schemas": [
            {"name": "PUBLIC", "tables": [{"name": "USERS", "kind": "Table", "columns": [{"name": "ID"}, {"name": "EMAIL"}]}]},
            {"name": "STAGING", "tables": [{"name": "USERS", "kind": "Table", "columns": [{"name": "ID"}, {"name": "NAME"}]}, {"name": "ONLY_STG", "kind": "Table", "columns": [{"name": "ID"}]}]}
        ]}]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    // The rules about the catalog, and the tables listed missing.
    let answer = |sql: &str, config: &AnalysisConfig| {
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, config, &catalog)
            .expect("analyzes");
        let mut ids: Vec<String> = report
            .findings
            .iter()
            .map(|m| match m {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .filter(|id| id.starts_with("CAT-"))
            .collect();
        ids.sort();
        (ids, report.catalog_info.missing_tables)
    };
    let users = "SELECT email FROM users";
    // Two schemas hold a `USERS`: with no session the name is not one table.
    assert_eq!(
        answer(users, &session(None, None)),
        (
            vec!["CAT-TBL-UNKNOWN".to_string()],
            vec!["users".to_string()]
        )
    );
    assert_eq!(
        answer(users, &session(Some("analytics"), Some("public"))),
        (Vec::new(), Vec::new())
    );
    // Under `staging` the table is found, and it has no `email`.
    assert_eq!(
        answer(users, &session(Some("analytics"), Some("staging"))),
        (vec!["CAT-COL-UNKNOWN".to_string()], Vec::new())
    );
    // A name only another schema holds is not the session schema's table.
    let only_stg = "SELECT id FROM only_stg";
    assert_eq!(
        answer(only_stg, &session(None, None)),
        (Vec::new(), Vec::new())
    );
    assert_eq!(
        answer(only_stg, &session(Some("analytics"), Some("public"))),
        (
            vec!["CAT-TBL-UNKNOWN".to_string()],
            vec!["analytics.public.only_stg".to_string()]
        )
    );
}

#[test]
fn a_database_named_without_its_schema_is_in_its_default_schema_never_a_named_one() {
    // The rule is info-level, so it is reported as context; it is also
    // never among the findings.
    let fires = |dialect: lexega_core::dialect::DialectRef, sql: &str| -> bool {
        let config = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &config).expect("analyzes");
        assert!(
            !rule_ids(&report.findings).contains(XSCHEMA),
            "{XSCHEMA} is context, not a finding: {sql}"
        );
        rule_ids(&report.context).contains(XSCHEMA)
    };
    let mssql = lexega_core::dialect::mssql;
    let snowflake = lexega_core::dialect::snowflake;
    for (dialect, sql, expected) in [
        (
            mssql(),
            "MERGE INTO d1..orders AS t USING crm.stage AS s ON t.id = s.id WHEN MATCHED THEN DELETE;",
            true,
        ),
        (
            mssql(),
            "MERGE INTO d1..orders AS t USING d1.dbo.stage AS s ON t.id = s.id WHEN MATCHED THEN DELETE;",
            true,
        ),
        (
            mssql(),
            "INSERT INTO d1..orders (id) SELECT id FROM crm.stage;",
            true,
        ),
        (
            mssql(),
            "MERGE INTO d1..orders AS t USING d1..stage AS s ON t.id = s.id WHEN MATCHED THEN DELETE;",
            false,
        ),
        (
            snowflake(),
            "USE DATABASE d1;\nINSERT INTO sandbox.t (a) SELECT a FROM s;",
            true,
        ),
        (mssql(), "USE d1;\nINSERT INTO crm.t (a) SELECT a FROM s;", true),
        (snowflake(), "INSERT INTO sandbox.t (a) SELECT a FROM s;", false),
    ] {
        assert_eq!(fires(dialect, sql), expected, "{sql}");
    }
}
