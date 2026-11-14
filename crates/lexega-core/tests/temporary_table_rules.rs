// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dropping, truncating or emptying a temporary table deletes nothing that
//! outlives the session: a table named as a temporary one (T-SQL `#t`,
//! `##t`) or a table variable (`@t`), or one an earlier statement of the
//! script created temporary.

use std::collections::BTreeSet;

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::DialectRef;

fn rule_ids(sql: &str, dialect: DialectRef) -> BTreeSet<String> {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    report
        .entries()
        .map(|finding| {
            let RuleMatch::Analysis(analysis) = finding;
            analysis.matched_rule.clone()
        })
        .collect()
}

fn assert_silent(sql: &str, dialect: DialectRef) {
    let ids = rule_ids(sql, dialect);
    for rule in ["TBL-DROP", "TBL-TRUNCATE"] {
        assert!(!ids.contains(rule), "{sql}: {ids:?}");
    }
}

#[test]
fn a_tsql_temporary_table_name_is_never_a_permanent_drop() {
    for sql in [
        "DROP TABLE #work;",
        "DROP TABLE IF EXISTS #work2;",
        "DROP TABLE ##shared;",
        "TRUNCATE TABLE #work;",
        "CREATE TABLE #work (Id INT); INSERT INTO #work (Id) SELECT Id FROM dbo.Src WHERE Id > 0; DROP TABLE #work;",
        "SELECT Id INTO #picked FROM dbo.Src WHERE Id > 0; DROP TABLE #picked;",
        "DROP TABLE [#work];",
        "DROP TABLE [##shared];",
    ] {
        assert_silent(sql, lexega_core::dialect::mssql());
    }
}

#[test]
fn a_table_the_script_created_temporary_is_never_a_permanent_drop() {
    for (sql, dialect) in [
        (
            "CREATE TEMPORARY TABLE work (id INT); DROP TABLE work;",
            lexega_core::dialect::snowflake(),
        ),
        (
            "CREATE TEMP TABLE work (id INT); TRUNCATE TABLE work;",
            lexega_core::dialect::snowflake(),
        ),
        (
            "CREATE TEMP TABLE work (id INT); DROP TABLE IF EXISTS work;",
            lexega_core::dialect::postgres(),
        ),
        (
            "CREATE TEMPORARY TABLE work AS SELECT 1 AS id; DROP TABLE work;",
            lexega_core::dialect::postgres(),
        ),
    ] {
        assert_silent(sql, dialect);
    }
}

#[test]
fn each_table_a_truncate_lists_is_truncated_as_one_alone() {
    let postgres = lexega_core::dialect::postgres;
    assert_silent(
        "CREATE TEMP TABLE wa (id INT); CREATE TEMP TABLE wb (id INT); TRUNCATE wa, wb;",
        postgres(),
    );
    for sql in [
        "CREATE TEMP TABLE wa (id INT); TRUNCATE wa, orders;",
        "CREATE TEMP TABLE wa (id INT); TRUNCATE orders, ONLY wa;",
        "TRUNCATE orders, customers;",
    ] {
        let ids = rule_ids(sql, postgres());
        assert!(ids.contains("TBL-TRUNCATE"), "{sql}: {ids:?}");
    }
}

#[test]
fn a_permanent_table_drop_stays_critical() {
    for (sql, rule, dialect) in [
        (
            "DROP TABLE dbo.Orders;",
            "TBL-DROP",
            lexega_core::dialect::mssql(),
        ),
        (
            "TRUNCATE TABLE dbo.Orders;",
            "TBL-TRUNCATE",
            lexega_core::dialect::mssql(),
        ),
        (
            "DROP TABLE work;",
            "TBL-DROP",
            lexega_core::dialect::snowflake(),
        ),
        (
            "CREATE TABLE work (id INT); DROP TABLE work;",
            "TBL-DROP",
            lexega_core::dialect::snowflake(),
        ),
        // A temporary table elsewhere does not make another table of the
        // name temporary.
        (
            "CREATE TEMPORARY TABLE work (id INT); DROP TABLE other.work;",
            "TBL-DROP",
            lexega_core::dialect::snowflake(),
        ),
        // Once dropped, the name reaches the permanent table again.
        (
            "CREATE TEMP TABLE work (id INT); DROP TABLE work; DROP TABLE work;",
            "TBL-DROP",
            lexega_core::dialect::postgres(),
        ),
    ] {
        let ids = rule_ids(sql, dialect);
        assert!(ids.contains(rule), "{sql}: {ids:?}");
    }
}

#[test]
fn a_table_made_temporary_on_some_paths_only_is_not_temporary() {
    for sql in [
        // When `x <> 1` the name reaches the permanent table.
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wd (id INT); END IF; DROP TABLE wd; END;",
        // The ELSE branch makes a permanent table of the name.
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wc (id INT); ELSE CREATE TABLE wc (id INT); END IF; DROP TABLE wc; END;",
        // A temporary table dropped on some paths leaves the permanent one.
        "BEGIN CREATE TEMP TABLE wf (id INT); IF (x = 1) THEN DROP TABLE wf; END IF; DROP TABLE wf; END;",
    ] {
        let ids = rule_ids(sql, lexega_core::dialect::snowflake());
        assert!(ids.contains("TBL-DROP"), "{sql}: {ids:?}");
    }
    for sql in [
        // Made temporary in the branch the DROP is in.
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE we (id INT); DROP TABLE we; END IF; END;",
        // Made temporary before the branch, and altered in it.
        "BEGIN CREATE TEMP TABLE wg (id INT); IF (x = 1) THEN ALTER TABLE wg ADD COLUMN c INT; END IF; DROP TABLE wg; END;",
    ] {
        assert_silent(sql, lexega_core::dialect::snowflake());
    }
}

#[test]
fn a_table_made_temporary_on_every_path_is_temporary() {
    for sql in [
        // Every branch, the ELSE included, makes it temporary.
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wh (id INT); ELSE CREATE TEMP TABLE wh (id INT); END IF; DROP TABLE wh; END;",
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wi (id INT); ELSEIF (x = 2) THEN CREATE TEMP TABLE wi (id INT); ELSE CREATE TEMP TABLE wi (id INT); END IF; TRUNCATE TABLE wi; END;",
        "BEGIN IF (x = 1) THEN IF (y = 1) THEN CREATE TEMP TABLE wj (id INT); ELSE CREATE TEMP TABLE wj (id INT); END IF; ELSE CREATE TEMP TABLE wj (id INT); END IF; DROP TABLE wj; END;",
        "BEGIN CASE WHEN x = 1 THEN CREATE TEMP TABLE wk (id INT); ELSE CREATE TEMP TABLE wk (id INT); END CASE; DROP TABLE wk; END;",
        // A branch that leaves the earlier temporary table as it was.
        "BEGIN CREATE TEMP TABLE wl (id INT); IF (x = 1) THEN CREATE OR REPLACE TEMP TABLE wl (id INT); ELSE INSERT INTO wl VALUES (1); END IF; DROP TABLE wl; END;",
    ] {
        assert_silent(sql, lexega_core::dialect::snowflake());
    }
    for sql in [
        // No ELSE: the path past every branch reaches the permanent table.
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wm (id INT); ELSEIF (x = 2) THEN CREATE TEMP TABLE wm (id INT); END IF; DROP TABLE wm; END;",
        "BEGIN IF (x = 1) THEN IF (y = 1) THEN CREATE TEMP TABLE wn (id INT); END IF; ELSE CREATE TEMP TABLE wn (id INT); END IF; DROP TABLE wn; END;",
        "BEGIN CASE WHEN x = 1 THEN CREATE TEMP TABLE wq (id INT); WHEN x = 2 THEN CREATE TEMP TABLE wq (id INT); END CASE; DROP TABLE wq; END;",
        // One branch drops it.
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wo (id INT); ELSE CREATE TEMP TABLE wo (id INT); DROP TABLE wo; END IF; DROP TABLE wo; END;",
        // The DROP is in the ELSE, which the THEN's table never reaches.
        "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wp (id INT); ELSE DROP TABLE wp; END IF; END;",
    ] {
        let ids = rule_ids(sql, lexega_core::dialect::snowflake());
        assert!(ids.contains("TBL-DROP"), "{sql}: {ids:?}");
    }
}

#[test]
fn a_create_states_its_own_temporariness() {
    let config = AnalysisConfig {
        dialect: Some(lexega_core::dialect::snowflake()),
        trace_mode: true,
        ..Default::default()
    };
    let sql = "BEGIN IF (x = 1) THEN CREATE TEMP TABLE wc (id INT); ELSE CREATE TABLE wc (id INT); END IF; END;";
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    let temporary: Vec<bool> = report
        .statement_traces
        .iter()
        .filter_map(|trace| trace.facts.as_ref()?.ddl.as_ref()?.table.as_ref())
        .map(|table| table.temporary)
        .collect();
    assert_eq!(temporary, [true, false]);
}

// Deleting or updating every row of a temporary table or a table variable
// changes nothing that outlives the session; a write to a table of the
// catalog is still unbounded.
#[test]
fn an_unbounded_write_to_a_session_table_is_no_unbounded_write() {
    for (sql, dialect) in [
        (
            "CREATE TABLE #t (id INT); DELETE FROM #t; UPDATE #t SET id = 0;",
            lexega_core::dialect::mssql(),
        ),
        (
            "DELETE FROM #work; DELETE FROM ##shared;",
            lexega_core::dialect::mssql(),
        ),
        (
            "DECLARE @v TABLE (id INT); DELETE FROM @v;",
            lexega_core::dialect::mssql(),
        ),
        (
            "CREATE TEMP TABLE s (id INT); DELETE FROM s; UPDATE s SET id = 1;",
            lexega_core::dialect::postgres(),
        ),
    ] {
        let ids = rule_ids(sql, dialect);
        assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{sql}: {ids:?}");
    }
    for (sql, dialect) in [
        ("DELETE FROM dbo.orders;", lexega_core::dialect::mssql()),
        (
            "CREATE TABLE s (id INT); DELETE FROM s;",
            lexega_core::dialect::postgres(),
        ),
    ] {
        let ids = rule_ids(sql, dialect);
        assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{sql}: {ids:?}");
    }
}
