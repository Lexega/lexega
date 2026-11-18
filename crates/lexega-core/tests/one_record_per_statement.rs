// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Each statement is one fact record: the rules read it once, an absence
//! test reads the statement's own facts, and the trace lists it once.

use lexega_core::analyzer::{AnalysisConfig, AnalysisReport, RiskEvidence, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::{mssql, mysql, postgres, snowflake, DialectRef};
use lexega_core::facts::{StatementFacts, StatementKind};
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};

const CUSTOM_RULES: &str = r#"
rules:
  - id: CUSTOM-CREATE-TABLE
    risk_level: medium
    message: "A table is created."
    triggers:
      kind: create_table
  - id: CUSTOM-UNQUALIFIED-TABLE
    risk_level: medium
    message: "A table is created without a database."
    triggers:
      all_of:
        - kind: create_table
        - ddl.target.name.database:
            exists: false
"#;

fn custom_report(sql: &str) -> AnalysisReport {
    let custom = load_v1_rules(CUSTOM_RULES).expect("custom rules parse");
    let config = AnalysisConfig {
        custom_rules: Some(
            build_v1_rule_corpus(custom, false)
                .expect("corpus builds")
                .into(),
        ),
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analyzes")
}

/// The messages of the entries `rule` raises on `sql`.
fn messages(sql: &str, rule: &str) -> Vec<String> {
    custom_report(sql)
        .entries()
        .filter(|m| m.rule_id() == Some(rule))
        .map(|m| m.message().to_string())
        .collect()
}

#[test]
fn a_kind_rule_matches_a_create_table_once() {
    assert_eq!(
        messages("CREATE TABLE t (a int);", "CUSTOM-CREATE-TABLE"),
        ["A table is created."]
    );
}

#[test]
fn an_absence_test_reads_the_statements_own_facts() {
    assert_eq!(
        messages("CREATE TABLE t (a int);", "CUSTOM-UNQUALIFIED-TABLE"),
        ["A table is created without a database."]
    );
    assert!(messages("CREATE TABLE d.s.t (a int);", "CUSTOM-UNQUALIFIED-TABLE").is_empty());
}

/// Each fact record the trace lists for `sql`, in source order.
fn records(sql: &str, dialect: DialectRef) -> Vec<StatementFacts> {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyzes");
    let mut records: Vec<StatementFacts> = report
        .statement_traces
        .into_iter()
        .filter_map(|trace| trace.facts)
        .collect();
    records.sort_by_key(|f| f.source_span.map(|s| (s.start, s.end)));
    records
}

fn kinds(records: &[StatementFacts]) -> Vec<StatementKind> {
    records.iter().map(|f| f.kind).collect()
}

#[test]
fn a_ddl_or_grant_statement_is_one_record() {
    let grant = records("GRANT SELECT ON TABLE t TO ROLE r;", snowflake());
    assert_eq!(kinds(&grant), [StatementKind::Grant]);
    assert!(grant[0].privilege.is_some() && grant[0].query.is_none());

    let drop = records("DROP TABLE x;", snowflake());
    assert_eq!(kinds(&drop), [StatementKind::DropTable]);
    assert!(drop[0].ddl.is_some() && drop[0].query.is_none());

    let create = records("CREATE TABLE t (a int);", snowflake());
    assert_eq!(kinds(&create), [StatementKind::CreateTable]);
    assert!(create[0].ddl.is_some());

    let exec = records("EXEC p @a = 1;", mssql());
    assert_eq!(kinds(&exec), [StatementKind::MssqlExec]);
    assert!(exec[0].mssql_exec.is_some() && exec[0].query.is_none());

    // A call is one whether or not a sink its callee reaches is known.
    let call = records(
        "CREATE PROCEDURE run_sql(q VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS \
         BEGIN EXECUTE IMMEDIATE :q; RETURN 'ok'; END; CALL run_sql('x' || 'y'); CALL other(1);",
        snowflake(),
    );
    let calls: Vec<&StatementFacts> = call
        .iter()
        .filter(|f| f.kind == StatementKind::Call)
        .collect();
    assert_eq!(calls.len(), 2, "{:?}", kinds(&call));
    assert!(calls.iter().all(|f| f.query.is_none()));
}

/// The names a record's `targets` holds, as written.
fn written(targets: &[lexega_core::facts::ObjectRef]) -> Vec<&str> {
    targets.iter().map(|t| t.name.written.as_str()).collect()
}

#[test]
fn a_list_statement_is_one_record_naming_each_object() {
    for sql in [
        "DROP TABLE prod.orders, prod.payroll;",
        "TRUNCATE TABLE prod.orders, prod.payroll;",
    ] {
        let record = records(sql, postgres());
        assert_eq!(record.len(), 1, "{sql}");
        let ddl = record[0].ddl.as_ref().expect("ddl facts");
        assert_eq!(
            written(&ddl.targets),
            ["prod.orders", "prod.payroll"],
            "{sql}"
        );
        assert_eq!(ddl.target.as_ref(), ddl.targets.first(), "{sql}");
    }
    let optimize = records("OPTIMIZE TABLE prod.orders, prod.payroll;", mysql());
    assert_eq!(kinds(&optimize), [StatementKind::OptimizeTable]);
    let ddl = optimize[0].ddl.as_ref().expect("ddl facts");
    assert_eq!(written(&ddl.targets), ["prod.orders", "prod.payroll"]);

    let grant = records(
        "GRANT SELECT ON TABLE prod.orders, prod.payroll TO analyst;",
        postgres(),
    );
    assert_eq!(grant.len(), 1);
    let privilege = grant[0].privilege.as_ref().expect("privilege facts");
    assert_eq!(written(&privilege.targets), ["prod.orders", "prod.payroll"]);
    assert_eq!(privilege.target.as_ref(), privilege.targets.first());

    // A lone object is the one target listed.
    let drop = records("DROP TABLE x;", snowflake());
    let ddl = drop[0].ddl.as_ref().expect("ddl facts");
    assert_eq!(written(&ddl.targets), ["x"]);
}

#[test]
fn a_create_as_query_is_one_record_with_its_query() {
    for (sql, kind) in [
        (
            "CREATE TABLE t AS SELECT a FROM u;",
            StatementKind::CreateTable,
        ),
        (
            "CREATE VIEW v AS SELECT a FROM u WHERE b = 1;",
            StatementKind::CreateView,
        ),
    ] {
        let record = records(sql, snowflake());
        assert_eq!(kinds(&record), [kind], "{sql}");
        let read: Vec<&str> = record[0]
            .query
            .iter()
            .flat_map(|q| &q.reads_table)
            .map(|r| r.table.canonical.as_str())
            .collect();
        assert!(record[0].ddl.is_some(), "{sql}");
        assert_eq!(read, ["U"], "{sql}");
    }
    let insert = records("INSERT INTO t SELECT a FROM u;", snowflake());
    assert_eq!(kinds(&insert), [StatementKind::Insert]);
}

#[test]
fn each_body_statement_and_each_script_statement_is_one_record() {
    let procedure = records(
        "CREATE PROCEDURE p AS BEGIN INSERT INTO t SELECT * FROM u; DELETE FROM t WHERE a = 1; END",
        mssql(),
    );
    assert_eq!(
        kinds(&procedure),
        [
            StatementKind::CreateProcedure,
            StatementKind::Block,
            StatementKind::Insert,
            StatementKind::Delete,
        ]
    );
    let script = records(
        "DECLARE @x int; SET @x = 1; GRANT SELECT ON t TO r;",
        mssql(),
    );
    assert_eq!(
        kinds(&script),
        [
            StatementKind::Declare,
            StatementKind::Set,
            StatementKind::Grant,
        ]
    );
}

#[test]
fn each_statement_of_a_pipe_chain_is_a_record_of_its_own() {
    let chain = records("SHOW TABLES ->> DELETE FROM prod.core.orders;", snowflake());
    let kinds = kinds(&chain);
    assert!(kinds.contains(&StatementKind::Show), "{kinds:?}");
    assert!(kinds.contains(&StatementKind::Delete), "{kinds:?}");
    let report = analyze_risk_with_policy_config(
        "SELECT 1 ->> DELETE FROM prod.core.orders;",
        &AnalysisConfig {
            dialect: Some(snowflake()),
            ..Default::default()
        },
    )
    .expect("analyzes");
    assert!(report
        .entries()
        .any(|entry| entry.rule_id() == Some("DML-WRITE-UNBOUNDED")));
}

/// Where each entry `rule` raises on `sql` points.
fn positions(sql: &str, dialect: DialectRef, rule: &str) -> Vec<(usize, usize)> {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyzes");
    let mut out = Vec::new();
    for entry in report.entries() {
        let RuleMatch::Analysis(analysis) = entry;
        if analysis.matched_rule != rule {
            continue;
        }
        for evidence in &analysis.evidence {
            if let RiskEvidence::RuleMatch {
                line_number: Some(line),
                column_number: Some(column),
                ..
            } = evidence
            {
                out.push((*line, *column));
            }
        }
    }
    out
}

#[test]
fn the_statement_a_prepare_holds_is_a_statement_of_its_own() {
    assert_eq!(
        kinds(&records("PREPARE s AS DELETE FROM zz_t;", postgres())),
        [StatementKind::PgPrepare, StatementKind::Delete]
    );
    for (sql, at) in [
        ("PREPARE s AS DELETE FROM zz_t;", vec![(1, 14)]),
        ("PREPARE s AS DELETE FROM orders; EXECUTE s;", vec![(1, 14)]),
        (
            "PREPARE s (int) AS UPDATE orders SET amount = $1;",
            vec![(1, 20)],
        ),
        (
            "PREPARE s (int) AS UPDATE orders SET amount = $1 WHERE id = $1;",
            vec![],
        ),
        ("EXECUTE s;", vec![]),
        (
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN \
             PREPARE s AS DELETE FROM zz_t; EXECUTE s; END $$;",
            vec![(1, 76)],
        ),
        (
            "DO $$ BEGIN PREPARE s AS DELETE FROM zz_t; END $$;",
            vec![(1, 26)],
        ),
    ] {
        assert_eq!(
            positions(sql, postgres(), "DML-WRITE-UNBOUNDED"),
            at,
            "{sql}"
        );
    }
}
