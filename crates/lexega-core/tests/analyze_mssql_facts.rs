// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Customer-facing tests for the v1 fact-based pipeline over the
// MSSQL-* rule family. Covers the MSSQL-* rules end-to-end
// across the two substrates the family touches:
//
//   - Query-bearing statements with T-SQL table hints:
//       parse → IR RelPlan → project_table_hints → MssqlTableHintFact
//       → evaluate_rules → Finding
//   - MSSQL DDL statements (Bulk Insert / External Model / Login / User):
//       parse → IR DdlPlan → derive_facts_from_mssql_ddl_plan → Finding
//
// Plus parity assertions vs `analyze_risk_with_policy_config`, so
// customer policy / exception bundles that reference these rule_ids
// fire from either entry point.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::{
    analyze_ddl_facts_with_dialect, analyze_query_facts_with_dialect,
    analyze_risk_with_policy_config,
};
use lexega_core::dialect::MsSqlDialect;

fn mssql_config() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(lexega_core::dialect::mssql()),
        ..Default::default()
    }
}

/// Run the v1 fact-based pipeline twice — once over the query-bearing
/// branch (`analyze_query_facts` populates `query.table_hints` so the
/// MSSQL-HINT-* rules fire), once over the DDL branch
/// (`analyze_ddl_facts` lowers MSSQL DDL and fires MSSQL-DDL rules).
/// Returns the union of rule_ids surfaced. Both calls use the MSSQL
/// dialect so T-SQL syntax (`WITH (NOLOCK)`, `BULK INSERT`, etc.) parses.
fn fact_rule_ids(sql: &str) -> Vec<String> {
    let dialect = MsSqlDialect;
    let mut ids: Vec<String> = analyze_query_facts_with_dialect(sql, &dialect)
        .expect("analyze_query_facts_with_dialect succeeds")
        .into_iter()
        .map(|s| s.rule_id)
        .collect();
    ids.extend(
        analyze_ddl_facts_with_dialect(sql, &dialect)
            .expect("analyze_ddl_facts_with_dialect succeeds")
            .into_iter()
            .map(|s| s.rule_id),
    );
    ids
}

fn risk_rule_ids(sql: &str) -> Vec<String> {
    let report =
        analyze_risk_with_policy_config(sql, &mssql_config()).expect("analyze_risk succeeds");
    report
        .entries()
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
// MSSQL-HINT-DIRTYREAD firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_dirtyread_fires_on_nolock() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (NOLOCK);");
    assert!(
        ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn a_hint_list_written_without_with_is_read_as_the_tables_hints() {
    for sql in [
        "SELECT * FROM zz.dbo.zz_real (NOLOCK) WHERE c = 1;",
        "SELECT * FROM zz.dbo.zz_real r (NOLOCK) WHERE r.c = 1;",
        "SELECT * FROM a AS x (NOLOCK) JOIN b (NOLOCK) ON x.id = b.id;",
    ] {
        let ids = risk_rule_ids(sql);
        assert!(
            ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
            "{sql}: {ids:?}"
        );
        assert!(
            ids.contains(&"INFO-MSSQL-HINT".to_string()),
            "{sql}: {ids:?}"
        );
    }
    let cfg = AnalysisConfig {
        trace_mode: true,
        ..mssql_config()
    };
    let report = analyze_risk_with_policy_config(
        "SELECT * FROM zz.dbo.zz_real (TABLOCK) WHERE c = 1;",
        &cfg,
    )
    .expect("analyze_risk succeeds");
    let report = serde_json::to_value(&report).expect("report serializes");
    let read = &report["statement_traces"][0]["facts"]["query"]["reads_table"][0]["table"];
    assert_eq!(read["canonical"], "ZZ.DBO.ZZ_REAL", "{read}");
    // A function call keeps its argument.
    let ids = risk_rule_ids("SELECT * FROM dbo.fn(1) f WHERE f.c = 1;");
    assert!(!ids.contains(&"INFO-MSSQL-HINT".to_string()), "{ids:?}");
}

#[test]
fn an_update_target_named_by_a_from_alias_is_the_aliased_table() {
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [
                {"name": "ZZ_REAL", "kind": "Table", "columns": [{"name": "ID"}, {"name": "C"}]},
                {"name": "ZZ_SRC", "kind": "Table", "columns": [{"name": "ID"}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    let config = AnalysisConfig {
        trace_mode: true,
        ..mssql_config()
    };
    for (sql, table, alias) in [
        (
            "UPDATE r SET r.c = s.id FROM dbo.zz_real AS r JOIN dbo.zz_src AS s ON s.id = r.id",
            "ZZ_REAL",
            "r",
        ),
        (
            "UPDATE r SET r.c = 1 FROM zz.dbo.zz_real r WHERE r.id = 1",
            "ZZ_REAL",
            "r",
        ),
        (
            "UPDATE t SET t.id = s.id FROM #t AS t JOIN dbo.zz_src AS s ON s.id = t.id",
            "#T",
            "t",
        ),
    ] {
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyzes");
        let missing = &report.catalog_info.missing_tables;
        assert!(!missing.iter().any(|m| m == alias), "{sql}: {missing:?}");
        let written: Vec<String> = report
            .statement_traces
            .iter()
            .filter_map(|s| s.facts.as_ref()?.query.as_ref())
            .flat_map(|query| &query.writes_table)
            .map(|te| te.table.name.normalized.clone())
            .collect();
        assert_eq!(written, [table], "{sql}");
    }
}

#[test]
fn a_table_function_in_from_is_never_asked_of_the_catalog() {
    use lexega_core::analyzer::RuleMatch;
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [{"name": "ZZ_REAL", "kind": "Table", "columns": [{"name": "ID"}, {"name": "C"}]}]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    for sql in [
        "SELECT * FROM dbo.fn(1) f",
        "SELECT * FROM zz.dbo.zz_real r CROSS APPLY dbo.fn(r.id) f WHERE r.id = 1",
        "SELECT f.nope FROM zz.dbo.zz_real(1) f",
    ] {
        let report =
            analyze_risk_with_policy_config_and_catalog_index(sql, &mssql_config(), &catalog)
                .expect("analyzes");
        let catalog_rules: Vec<&str> = report
            .entries()
            .map(|m| match m {
                RuleMatch::Analysis(g) => g.matched_rule.as_str(),
            })
            .filter(|id| id.starts_with("CAT-"))
            .collect();
        assert!(catalog_rules.is_empty(), "{sql}: {catalog_rules:?}");
        assert!(
            report.catalog_info.missing_tables.is_empty(),
            "{sql}: {:?}",
            report.catalog_info.missing_tables
        );
    }
}

/// The orders catalog the writes through a query below read.
fn orders_catalog() -> lexega_core::catalog::CatalogIndex {
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "SALES", "schemas": [{"name": "DBO", "tables": [
                {"name": "ORDERS", "kind": "Table", "columns": [{"name": "ID"}, {"name": "STATUS"}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    CatalogIndex::from_snapshot(snapshot).expect("index")
}

/// The tables `sql` writes, the tables the catalog lacks, and its rule ids.
fn write_through_query(sql: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    let config = AnalysisConfig {
        trace_mode: true,
        ..mssql_config()
    };
    let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &orders_catalog())
        .expect("analyzes");
    let written = report
        .statement_traces
        .iter()
        .filter_map(|s| s.facts.as_ref()?.query.as_ref())
        .flat_map(|query| &query.writes_table)
        .map(|te| te.table.name.normalized.clone())
        .collect();
    let ids = report
        .entries()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect();
    (written, report.catalog_info.missing_tables.clone(), ids)
}

#[test]
fn a_write_through_a_cte_or_derived_table_writes_its_table_within_its_bound() {
    for sql in [
        "WITH c AS (SELECT TOP 10 * FROM dbo.Orders ORDER BY Id) UPDATE c SET Status = 1",
        "UPDATE x SET Status = 1 FROM (SELECT TOP 10 * FROM dbo.Orders ORDER BY Id) x",
        "WITH c AS (SELECT * FROM dbo.Orders WHERE Status = 0) UPDATE c SET Status = 1",
        "WITH c AS (SELECT TOP 10 * FROM dbo.Orders ORDER BY Id) DELETE FROM c",
        "DELETE x FROM (SELECT TOP 10 * FROM dbo.Orders ORDER BY Id) x",
        "WITH c AS (SELECT *, ROW_NUMBER() OVER (PARTITION BY Id ORDER BY Id) AS rn FROM dbo.Orders) DELETE FROM c WHERE rn > 1",
    ] {
        let (written, missing, ids) = write_through_query(sql);
        assert_eq!(written, ["ORDERS"], "{sql}");
        assert!(missing.is_empty(), "{sql}: {missing:?}");
        assert!(
            !ids.iter().any(|id| id == "DML-WRITE-UNBOUNDED"),
            "{sql}: {ids:?}"
        );
    }
}

#[test]
fn a_write_through_an_unbounded_query_is_unbounded() {
    for sql in [
        "WITH c AS (SELECT * FROM dbo.Orders) UPDATE c SET Status = 1",
        "UPDATE x SET Status = 1 FROM (SELECT Id, Status FROM dbo.Orders) x",
        "WITH c AS (SELECT * FROM dbo.Orders WHERE 1 = 1) DELETE FROM c",
        "WITH c AS (SELECT *, ROW_NUMBER() OVER (PARTITION BY Id ORDER BY Id) AS rn FROM dbo.Orders) DELETE FROM c",
    ] {
        let (written, missing, ids) = write_through_query(sql);
        assert_eq!(written, ["ORDERS"], "{sql}");
        assert!(missing.is_empty(), "{sql}: {missing:?}");
        assert!(
            ids.iter().any(|id| id == "DML-WRITE-UNBOUNDED"),
            "{sql}: {ids:?}"
        );
    }
}

#[test]
fn only_tsql_writes_through_a_cte_of_the_targets_name() {
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    // PostgreSQL writes the table `c`, whatever a CTE of the name holds.
    let config = AnalysisConfig {
        dialect: Some(lexega_core::dialect::postgres()),
        trace_mode: true,
        ..Default::default()
    };
    let sql = "WITH c AS (SELECT * FROM dbo.orders) UPDATE c SET status = 1 WHERE id = 1";
    let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &orders_catalog())
        .expect("analyzes");
    let written: Vec<String> = report
        .statement_traces
        .iter()
        .filter_map(|s| s.facts.as_ref()?.query.as_ref())
        .flat_map(|query| &query.writes_table)
        .map(|te| te.table.name.normalized.clone())
        .collect();
    assert_eq!(written, ["c"], "{sql}");
}

#[test]
fn a_databricks_stream_or_table_argument_is_a_read_of_its_table() {
    use lexega_core::analyzer::RuleMatch;
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [{"name": "ZZ_REAL", "kind": "Table", "columns": [{"name": "ID"}, {"name": "C"}]}]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    let config = AnalysisConfig {
        dialect: Some(lexega_core::dialect::databricks()),
        trace_mode: true,
        ..Default::default()
    };
    let rules = |sql: &str| -> (Vec<String>, Vec<String>) {
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyzes");
        let reads = report.statement_traces[0]
            .facts
            .as_ref()
            .and_then(|f| f.query.as_ref())
            .map(|q| {
                q.reads_table
                    .iter()
                    .map(|r| r.table.canonical.clone())
                    .collect()
            })
            .unwrap_or_default();
        let rules = report
            .entries()
            .map(|m| match m {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect();
        (reads, rules)
    };
    let (reads, found) = rules("SELECT e.nope FROM STREAM(zz.dbo.zz_real) e WHERE e.id = 1");
    assert_eq!(reads, ["zz.dbo.zz_real"]);
    assert!(found.contains(&"CAT-COL-UNKNOWN".to_string()), "{found:?}");
    let (reads, found) = rules("SELECT * FROM STREAM zz.dbo.nosuch WHERE id = 1");
    assert_eq!(reads, ["zz.dbo.nosuch"]);
    assert!(found.contains(&"CAT-TBL-UNKNOWN".to_string()), "{found:?}");
    // A table argument is a read of its table; its PARTITION BY reads the
    // table's columns.
    let (reads, found) = rules("SELECT * FROM my_udtf(TABLE(zz.dbo.zz_real) PARTITION BY nope)");
    assert_eq!(reads, ["zz.dbo.zz_real"]);
    assert!(found.contains(&"CAT-COL-UNKNOWN".to_string()), "{found:?}");
    let (_, found) = rules("SELECT * FROM my_udtf(TABLE(zz.dbo.zz_real) ORDER BY nope)");
    assert!(found.contains(&"CAT-COL-UNKNOWN".to_string()), "{found:?}");
    // The lists partition and order the rows the function is given: no
    // scope of the statement is ordered by them.
    let sql = "SELECT * FROM my_udtf(TABLE(zz.dbo.zz_real) PARTITION BY id ORDER BY c DESC)";
    let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
        .expect("analyzes");
    let query = report.statement_traces[0]
        .facts
        .as_ref()
        .and_then(|f| f.query.as_ref())
        .expect("query facts");
    assert!(
        query.scopes.iter().all(|s| s.order_by.is_empty()),
        "{:?}",
        query.scopes
    );
    let (_, found) = rules(sql);
    assert!(!found.contains(&"CAT-COL-UNKNOWN".to_string()), "{found:?}");
    let (reads, found) = rules("SELECT * FROM my_udtf(TABLE(zz.dbo.nosuch))");
    assert_eq!(reads, ["zz.dbo.nosuch"]);
    assert!(found.contains(&"CAT-TBL-UNKNOWN".to_string()), "{found:?}");
}

// The type argument of `CONVERT` / `TRY_CONVERT` names a type, at any
// depth of the query; an unknown column in the value argument is still
// one.
#[test]
fn a_conversion_type_argument_reads_no_column() {
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [
                {"name": "U", "kind": "Table", "columns": [{"name": "ID"}, {"name": "NAME"}]},
                {"name": "O", "kind": "Table", "columns": [{"name": "ID"}, {"name": "USER_ID"}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    // The columns CAT-COL-UNKNOWN names in `sql`, read in `dialect`.
    let unknown = |sql: &str, dialect: lexega_core::dialect::DialectRef| -> Vec<String> {
        let config = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyzes");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let report = serde_json::to_value(&report).expect("report serializes");
        let mut columns: Vec<String> = report["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .filter(|finding| finding["matched_rule"] == "CAT-COL-UNKNOWN")
            .flat_map(|finding| finding["evidence"].as_array().cloned().unwrap_or_default())
            .filter_map(|evidence| evidence["statement_preview"].as_str().map(String::from))
            .collect();
        columns.sort();
        columns
    };
    let places = [
        "SELECT {c} AS n FROM zz.dbo.u",
        "SELECT id FROM zz.dbo.u WHERE {c} = 1",
        "SELECT id FROM zz.dbo.o WHERE user_id NOT IN (SELECT {c} FROM zz.dbo.u)",
        "SELECT id FROM zz.dbo.o o WHERE EXISTS (SELECT 1 FROM zz.dbo.u WHERE {c} = o.user_id)",
        "WITH c AS (SELECT {c} AS n FROM zz.dbo.u) SELECT n FROM c",
        "SELECT n FROM (SELECT {c} AS n FROM zz.dbo.u) d",
    ];
    let calls = [
        (lexega_core::dialect::mssql(), "CONVERT(INT, {v})"),
        (lexega_core::dialect::mssql(), "convert(int, {v})"),
        (
            lexega_core::dialect::mssql(),
            "CONVERT(VARCHAR(10), {v}, 120)",
        ),
        (lexega_core::dialect::mssql(), "CONVERT(NVARCHAR(MAX), {v})"),
        (lexega_core::dialect::mssql(), "CONVERT(DATE, {v}, 23)"),
        (lexega_core::dialect::mssql(), "TRY_CONVERT(INT, {v})"),
        (
            lexega_core::dialect::mssql(),
            "TRY_CONVERT(DECIMAL(10, 2), {v})",
        ),
        (lexega_core::dialect::redshift(), "CONVERT(INTEGER, {v})"),
        (lexega_core::dialect::mysql(), "CONVERT({v}, SIGNED)"),
        (lexega_core::dialect::mysql(), "CONVERT({v}, CHAR)"),
        (lexega_core::dialect::mysql(), "CONVERT({v}, DATE)"),
        (
            lexega_core::dialect::mysql(),
            "CONVERT({v}, DECIMAL(10, 2))",
        ),
    ];
    for (dialect, call) in calls {
        for place in places {
            let sql = place.replace("{c}", &call.replace("{v}", "name"));
            assert_eq!(
                unknown(&sql, dialect.clone()),
                Vec::<String>::new(),
                "{sql}"
            );
            let sql = place.replace("{c}", &call.replace("{v}", "nosuch"));
            assert_eq!(unknown(&sql, dialect.clone()), ["nosuch"], "{sql}");
        }
    }
}

// A date or time part, a normalization form, and a type the dialect's
// table names read no column, at any depth of the query; an unknown
// column in a value argument is still one.
#[test]
fn a_date_part_or_keyword_argument_reads_no_column() {
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    use lexega_core::dialect::{bigquery, databricks, mssql, mysql, postgres, redshift, snowflake};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [
                {"name": "U", "kind": "Table", "columns": [{"name": "ID"}, {"name": "NAME"}]},
                {"name": "O", "kind": "Table", "columns": [{"name": "ID"}, {"name": "USER_ID"}, {"name": "QUARTER"}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    // The rules `sql` raises and the columns CAT-COL-UNKNOWN names, read in
    // `dialect`.
    let analysed = |sql: &str, dialect: lexega_core::dialect::DialectRef| {
        let config = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyzes");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let report = serde_json::to_value(&report).expect("report serializes");
        let findings = report["findings"].as_array().cloned().unwrap_or_default();
        let rules: Vec<String> = findings
            .iter()
            .filter_map(|finding| finding["matched_rule"].as_str().map(String::from))
            .collect();
        let mut unknown: Vec<String> = findings
            .iter()
            .filter(|finding| finding["matched_rule"] == "CAT-COL-UNKNOWN")
            .flat_map(|finding| finding["evidence"].as_array().cloned().unwrap_or_default())
            .filter_map(|evidence| evidence["statement_preview"].as_str().map(String::from))
            .collect();
        unknown.sort();
        (rules, unknown)
    };
    let places = [
        "SELECT {c} AS n FROM zz.dbo.u",
        "SELECT id FROM zz.dbo.u WHERE {c} = 1",
        "SELECT id FROM zz.dbo.o WHERE user_id NOT IN (SELECT {c} FROM zz.dbo.u)",
        "WITH c AS (SELECT {c} AS n FROM zz.dbo.u) SELECT n FROM c",
        "SELECT {c} AS k, COUNT(*) AS n FROM zz.dbo.u GROUP BY {c}",
    ];
    let calls = [
        (snowflake(), "DATEADD(week, 1, {v})"),
        (snowflake(), "DATEADD(yy, 1, {v})"),
        (snowflake(), "DATEDIFF(quarter, {v}, name)"),
        (snowflake(), "TIMESTAMPDIFF(dd, {v}, name)"),
        (snowflake(), "DATE_TRUNC(week, {v})"),
        (snowflake(), "DATE_PART(dow, {v})"),
        (snowflake(), "LAST_DAY({v}, week)"),
        (snowflake(), "TRUNC({v}, week)"),
        (bigquery(), "DATE_DIFF({v}, name, WEEK(MONDAY))"),
        (bigquery(), "DATE_TRUNC({v}, ISOWEEK)"),
        (bigquery(), "DATETIME_DIFF({v}, name, QUARTER)"),
        (bigquery(), "LAST_DAY({v}, WEEK)"),
        (bigquery(), "NORMALIZE({v}, NFKC)"),
        (bigquery(), "NORMALIZE_AND_CASEFOLD({v}, NFKC)"),
        (postgres(), "normalize({v}, NFC)"),
        (databricks(), "DATE_ADD(WEEK, 1, {v})"),
        (databricks(), "TIMESTAMPDIFF(QUARTER, {v}, name)"),
        (mysql(), "TIMESTAMPADD(SQL_TSI_DAY, 1, {v})"),
        (mysql(), "TIMESTAMPDIFF(WEEK, {v}, name)"),
        (mssql(), "DATEADD(dd, 1, {v})"),
        (mssql(), "DATEADD(m, 1, {v})"),
        (mssql(), "DATEADD(wk, 1, {v})"),
        (mssql(), "DATEDIFF(mi, {v}, name)"),
        (mssql(), "DATEDIFF_BIG(ss, {v}, name)"),
        (mssql(), "DATEPART(dw, {v})"),
        (mssql(), "DATEPART(iso_week, {v})"),
        (mssql(), "DATETRUNC(quarter, {v})"),
        (mssql(), "DATE_BUCKET(week, 1, {v})"),
        (mssql(), "{fn TIMESTAMPADD(SQL_TSI_DAY, 1, {v})}"),
        (mssql(), "{fn CONVERT({v}, SQL_VARCHAR)}"),
        (redshift(), "DATEADD(w, 1, {v})"),
        (redshift(), "DATEDIFF(qtr, {v}, name)"),
        (redshift(), "DATE_PART(dow, {v})"),
    ];
    for (dialect, call) in calls {
        for place in places {
            // An ODBC escape is a call of its own grammar, not a key.
            if call.starts_with('{') && place.contains("GROUP BY") {
                continue;
            }
            let sql = place.replace("{c}", &call.replace("{v}", "name"));
            let (rules, unknown) = analysed(&sql, dialect.clone());
            assert_eq!(unknown, Vec::<String>::new(), "{sql}");
            // A word read as a column of the outer query would correlate
            // the subquery.
            assert!(
                !rules.iter().any(|rule| rule == "Q-SUBQ-CORR-WHERE"),
                "{sql}: {rules:?}"
            );
            let sql = place.replace("{c}", &call.replace("{v}", "nosuch"));
            assert!(
                analysed(&sql, dialect.clone())
                    .1
                    .contains(&"nosuch".to_string()),
                "{sql}"
            );
        }
    }
    // A row is the dialect's: a word where its dialect has no row is a
    // column.
    let (_, unknown) = analysed(
        "SELECT GET_FORMAT(DATE, 'USA') AS f, IDENTITY(INT, 1, 1) AS i FROM zz.dbo.u",
        mssql(),
    );
    assert_eq!(unknown, ["DATE"]);
    let (_, unknown) = analysed("SELECT GET_FORMAT(DATE, 'USA') AS f FROM zz.dbo.u", mysql());
    assert_eq!(unknown, Vec::<String>::new());
}

// A bare name is a column unless its dialect writes the function without
// parentheses: `month` is a column (PostgreSQL's date_trunc takes its
// field as text, so a word there is one too), and so is Snowflake's
// `sysdate`, which needs its parentheses; `current_date` is not.
#[test]
fn a_bare_name_of_a_date_function_is_a_column() {
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    use lexega_core::dialect::{postgres, snowflake};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [
                {"name": "U", "kind": "Table", "columns": [{"name": "ID"}, {"name": "NAME"}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    let unknown = |sql: &str, dialect: lexega_core::dialect::DialectRef| -> Vec<String> {
        let config = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog)
            .expect("analyzes");
        let report = serde_json::to_value(&report).expect("report serializes");
        let mut columns: Vec<String> = report["findings"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|finding| finding["matched_rule"] == "CAT-COL-UNKNOWN")
            .flat_map(|finding| finding["evidence"].as_array().cloned().unwrap_or_default())
            .filter_map(|evidence| evidence["statement_preview"].as_str().map(String::from))
            .collect();
        columns.sort();
        columns
    };
    assert_eq!(
        unknown(
            "SELECT date_trunc(month, name) AS n FROM zz.dbo.u",
            postgres()
        ),
        ["month"]
    );
    assert_eq!(
        unknown("SELECT month, year FROM zz.dbo.u", snowflake()),
        ["month", "year"]
    );
    assert_eq!(
        unknown(
            "SELECT current_date AS d, sysdate AS s FROM zz.dbo.u",
            snowflake()
        ),
        ["sysdate"]
    );
    assert_eq!(
        unknown(
            "SELECT current_date AS d, sysdate() AS s FROM zz.dbo.u",
            snowflake()
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_join_to_a_table_function_is_a_join_with_the_function_on_that_side() {
    use lexega_core::analyzer::RuleMatch;
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [
            {"name": "ZZ", "schemas": [{"name": "DBO", "tables": [
                {"name": "ZZ_REAL", "kind": "Table", "columns": [{"name": "ID", "data_type": "INT", "nullable": true}, {"name": "C", "data_type": "INT", "nullable": true}]},
                {"name": "ZZ_T", "kind": "Table", "columns": [{"name": "ID", "data_type": "INT", "nullable": true}]}
            ]}]}
        ]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    let config = AnalysisConfig {
        trace_mode: true,
        ..mssql_config()
    };
    let analyse = |sql: &str| {
        analyze_risk_with_policy_config_and_catalog_index(sql, &config, &catalog).expect("analyzes")
    };
    // The call is the join's right side, named by its function, and the
    // join after it is kept.
    let sql = "SELECT * FROM zz.dbo.zz_real r JOIN dbo.fn(1) f ON r.id = f.id \
               JOIN zz.dbo.zz_t t ON t.id = r.id WHERE r.c = 1";
    let report = analyse(sql);
    let query = report.statement_traces[0]
        .facts
        .as_ref()
        .and_then(|f| f.query.as_ref())
        .expect("query facts");
    let joins: Vec<(String, String)> = query.scopes[0]
        .joins
        .iter()
        .map(|j| (j.left.canonical.clone(), j.right.canonical.clone()))
        .collect();
    assert_eq!(
        joins,
        [
            ("ZZ.DBO.ZZ_REAL".to_string(), "DBO.FN".to_string()),
            ("DBO.FN".to_string(), "ZZ.DBO.ZZ_T".to_string()),
        ],
        "{sql}"
    );
    let rules: Vec<&str> = report
        .entries()
        .map(|m| match m {
            RuleMatch::Analysis(g) => g.matched_rule.as_str(),
        })
        .collect();
    assert!(rules.contains(&"Q-JOIN-NULL-CENH"), "{sql}: {rules:?}");
    // Two calls joined: no catalog says whether either column is a key.
    let report = analyse("SELECT * FROM dbo.fn(1) f JOIN dbo.gn(2) g ON f.id = g.id");
    let query = report.statement_traces[0]
        .facts
        .as_ref()
        .and_then(|f| f.query.as_ref())
        .expect("query facts");
    let join = &query.scopes[0].joins[0];
    assert_eq!(join.right.canonical, "DBO.GN");
    assert!(!join.on_columns[0].unique_key_backing_known, "{join:?}");
}

#[test]
fn a_join_says_whether_its_right_side_is_a_call_that_reads_the_left_side() {
    use lexega_core::analyzer::RuleMatch;
    use lexega_core::facts::JoinSource;
    use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};
    let sources = |sql: &str, config: &AnalysisConfig| -> (Vec<JoinSource>, Vec<String>) {
        let report = analyze_risk_with_policy_config(sql, config).expect("analyzes");
        let joins = report.statement_traces[0]
            .facts
            .as_ref()
            .and_then(|f| f.query.as_ref())
            .map(|q| q.scopes[0].joins.iter().map(|j| j.right_source).collect())
            .unwrap_or_default();
        let rules = report
            .entries()
            .map(|m| match m {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect();
        (joins, rules)
    };
    let traced = |dialect| AnalysisConfig {
        trace_mode: true,
        dialect: Some(dialect),
        ..Default::default()
    };
    let mssql = traced(lexega_core::dialect::mssql());
    // Each case: the joins' right sides, and whether DISTINCT may mask a
    // fan-out. DISTINCT over the values a built-in call made per left row
    // yields lists those values; over the second of two such calls, whose
    // values it does not list, it masks that call's fan-out.
    let cases: [(&str, &AnalysisConfig, &[JoinSource], bool); 5] = [
        (
            "SELECT DISTINCT s.value FROM t r CROSS APPLY STRING_SPLIT(r.c, ',') s",
            &mssql,
            &[JoinSource::CorrelatedTableFunction],
            false,
        ),
        (
            "SELECT DISTINCT r.id FROM t r CROSS APPLY dbo.fn(1) f",
            &mssql,
            &[JoinSource::TableFunction],
            true,
        ),
        (
            "SELECT DISTINCT r.id FROM t r JOIN u ON r.id = u.id",
            &mssql,
            &[JoinSource::Table],
            true,
        ),
        (
            "SELECT DISTINCT f.value FROM t r, LATERAL FLATTEN(input => r.c) f, \
             LATERAL FLATTEN(input => f.value) g",
            &traced(lexega_core::dialect::snowflake()),
            &[
                JoinSource::CorrelatedTableFunction,
                JoinSource::CorrelatedTableFunction,
            ],
            true,
        ),
        (
            "SELECT DISTINCT tag FROM t r, UNNEST(r.c) AS tag",
            &traced(lexega_core::dialect::bigquery()),
            &[JoinSource::CorrelatedTableFunction],
            false,
        ),
    ];
    for (sql, config, expected, masks) in cases {
        let (joins, rules) = sources(sql, config);
        assert_eq!(joins, expected, "{sql}");
        assert_eq!(
            rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
            masks,
            "{sql}: {rules:?}"
        );
    }
    // The verdict is the rule's: counting every join raises it again.
    let custom = load_v1_rules(
        r#"
rules:
  - id: Q-JOIN-DISTINCT-MASK
    risk_level: medium
    message: "DISTINCT over a join."
    triggers:
      query.scopes:
        each:
          all_of:
            - has_distinct: true
            - joins:
                count: { gt: 0 }
            - group_by:
                count: { eq: 0 }
"#,
    )
    .expect("rules parse");
    let flipped = AnalysisConfig {
        custom_rules: Some(build_v1_rule_corpus(custom, true).expect("corpus").into()),
        ..mssql.clone()
    };
    let (_, rules) = sources(
        "SELECT DISTINCT s.value FROM t r CROSS APPLY STRING_SPLIT(r.c, ',') s",
        &flipped,
    );
    assert!(
        rules.iter().any(|r| r == "Q-JOIN-DISTINCT-MASK"),
        "{rules:?}"
    );
}

#[test]
fn mssql_hint_dirtyread_fires_on_readuncommitted() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (READUNCOMMITTED);");
    assert!(
        ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_dirtyread_silent_for_no_hint() {
    let ids = fact_rule_ids("SELECT * FROM t;");
    assert!(
        !ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_dirtyread_silent_for_serializable_hint() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (SERIALIZABLE);");
    assert!(
        !ids.contains(&"MSSQL-HINT-DIRTYREAD".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-XLOCK firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_xlock_fires_on_tablockx() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (TABLOCKX);");
    assert!(
        ids.contains(&"MSSQL-HINT-XLOCK".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_xlock_fires_on_xlock() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (XLOCK);");
    assert!(
        ids.contains(&"MSSQL-HINT-XLOCK".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_xlock_silent_for_tablock() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (TABLOCK);");
    assert!(
        !ids.contains(&"MSSQL-HINT-XLOCK".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-INDEX firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_index_fires_on_index_paren_form() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (INDEX(idx_t1));");
    assert!(
        ids.contains(&"MSSQL-HINT-INDEX".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_index_silent_for_no_hint() {
    let ids = fact_rule_ids("SELECT * FROM t;");
    assert!(
        !ids.contains(&"MSSQL-HINT-INDEX".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-FORCESCAN firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_forcescan_fires_on_forcescan() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESCAN);");
    assert!(
        ids.contains(&"MSSQL-HINT-FORCESCAN".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_forcescan_silent_for_forceseek() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESEEK);");
    assert!(
        !ids.contains(&"MSSQL-HINT-FORCESCAN".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-HINT-FORCESEEK firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_hint_forceseek_fires_on_forceseek() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESEEK);");
    assert!(
        ids.contains(&"MSSQL-HINT-FORCESEEK".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_hint_forceseek_silent_for_forcescan() {
    let ids = fact_rule_ids("SELECT * FROM t WITH (FORCESCAN);");
    assert!(
        !ids.contains(&"MSSQL-HINT-FORCESEEK".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-BULK-INSERT firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_bulk_insert_fires_on_bulk_insert_statement() {
    let ids = fact_rule_ids(
        "BULK INSERT dbo.MyTable FROM 'C:\\data\\file.csv' WITH (FIELDTERMINATOR = ',');",
    );
    assert!(
        ids.contains(&"MSSQL-BULK-INSERT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_bulk_insert_silent_for_regular_insert() {
    let ids = fact_rule_ids("INSERT INTO t VALUES (1);");
    assert!(
        !ids.contains(&"MSSQL-BULK-INSERT".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-EXTMDL-NEW / -CHG firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_extmdl_new_fires_on_create_external_model() {
    let sql = "CREATE EXTERNAL MODEL my_model \
               WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');";
    let ids = fact_rule_ids(sql);
    assert!(
        ids.contains(&"MSSQL-EXTMDL-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_extmdl_new_fires_once_on_create_external_model() {
    let sql = "CREATE EXTERNAL MODEL my_model \
               WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');";
    let ids = fact_rule_ids(sql);
    assert_eq!(
        ids.iter().filter(|id| *id == "MSSQL-EXTMDL-NEW").count(),
        1,
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_extmdl_rmt_resolves_to_extmdl_new() {
    assert_eq!(
        lexega_core::rules::canonical_rule_id("MSSQL-EXTMDL-RMT"),
        "MSSQL-EXTMDL-NEW"
    );
}

#[test]
fn mssql_extmdl_chg_fires_on_alter_external_model() {
    let sql = "ALTER EXTERNAL MODEL my_model SET (LOCATION = 'https://new.example.com');";
    let ids = fact_rule_ids(sql);
    assert!(
        ids.contains(&"MSSQL-EXTMDL-CHG".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_extmdl_new_silent_for_drop_external_model() {
    let ids = fact_rule_ids("DROP EXTERNAL MODEL my_model;");
    assert!(
        !ids.contains(&"MSSQL-EXTMDL-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-LOGIN-NEW firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_login_new_fires_on_create_login_with_password() {
    let ids = fact_rule_ids("CREATE LOGIN bob WITH PASSWORD = 'S3cret!';");
    assert!(
        ids.contains(&"MSSQL-LOGIN-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_new_fires_on_create_login_from_external_provider() {
    let ids = fact_rule_ids("CREATE LOGIN bob FROM EXTERNAL PROVIDER;");
    assert!(
        ids.contains(&"MSSQL-LOGIN-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_new_silent_for_create_user() {
    let ids = fact_rule_ids("CREATE USER alice WITHOUT LOGIN;");
    assert!(
        !ids.contains(&"MSSQL-LOGIN-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// MSSQL-USER-NEW firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_user_new_fires_on_create_user_for_login() {
    let ids = fact_rule_ids("CREATE USER alice FOR LOGIN bob;");
    assert!(ids.contains(&"MSSQL-USER-NEW".to_string()), "ids={:?}", ids);
}

#[test]
fn mssql_user_new_fires_on_create_user_without_login() {
    let ids = fact_rule_ids("CREATE USER alice WITHOUT LOGIN;");
    assert!(ids.contains(&"MSSQL-USER-NEW".to_string()), "ids={:?}", ids);
}

#[test]
fn mssql_user_new_silent_for_create_login() {
    let ids = fact_rule_ids("CREATE LOGIN bob WITH PASSWORD = 'S3cret!';");
    assert!(
        !ids.contains(&"MSSQL-USER-NEW".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// Parity tests. Both pipelines must agree per SQL example.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn parity_mssql_hint_dirtyread() {
    assert_parity(
        "SELECT * FROM t WITH (NOLOCK);",
        "MSSQL-HINT-DIRTYREAD",
        true,
    );
    assert_parity(
        "SELECT * FROM t WITH (READUNCOMMITTED);",
        "MSSQL-HINT-DIRTYREAD",
        true,
    );
    assert_parity("SELECT * FROM t;", "MSSQL-HINT-DIRTYREAD", false);
}

#[test]
fn parity_mssql_hint_xlock() {
    assert_parity("SELECT * FROM t WITH (TABLOCKX);", "MSSQL-HINT-XLOCK", true);
    assert_parity("SELECT * FROM t WITH (XLOCK);", "MSSQL-HINT-XLOCK", true);
    assert_parity("SELECT * FROM t WITH (TABLOCK);", "MSSQL-HINT-XLOCK", false);
}

#[test]
fn parity_mssql_hint_index() {
    assert_parity(
        "SELECT * FROM t WITH (INDEX(idx_t1));",
        "MSSQL-HINT-INDEX",
        true,
    );
    assert_parity("SELECT * FROM t;", "MSSQL-HINT-INDEX", false);
}

#[test]
fn parity_mssql_hint_forcescan() {
    assert_parity(
        "SELECT * FROM t WITH (FORCESCAN);",
        "MSSQL-HINT-FORCESCAN",
        true,
    );
    assert_parity(
        "SELECT * FROM t WITH (FORCESEEK);",
        "MSSQL-HINT-FORCESCAN",
        false,
    );
}

#[test]
fn parity_mssql_hint_forceseek() {
    assert_parity(
        "SELECT * FROM t WITH (FORCESEEK);",
        "MSSQL-HINT-FORCESEEK",
        true,
    );
    assert_parity(
        "SELECT * FROM t WITH (FORCESCAN);",
        "MSSQL-HINT-FORCESEEK",
        false,
    );
}

#[test]
fn parity_mssql_bulk_insert() {
    assert_parity(
        "BULK INSERT dbo.MyTable FROM 'C:\\data\\file.csv' WITH (FIELDTERMINATOR = ',');",
        "MSSQL-BULK-INSERT",
        true,
    );
    assert_parity("INSERT INTO t VALUES (1);", "MSSQL-BULK-INSERT", false);
}

#[test]
fn parity_mssql_extmdl_new() {
    assert_parity(
        "CREATE EXTERNAL MODEL my_model \
         WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');",
        "MSSQL-EXTMDL-NEW",
        true,
    );
    assert_parity("DROP EXTERNAL MODEL my_model;", "MSSQL-EXTMDL-NEW", false);
}

#[test]
fn parity_mssql_extmdl_chg() {
    assert_parity(
        "ALTER EXTERNAL MODEL my_model SET (LOCATION = 'https://new.example.com');",
        "MSSQL-EXTMDL-CHG",
        true,
    );
    assert_parity(
        "CREATE EXTERNAL MODEL my_model \
         WITH (LOCATION = 'https://openai.example.com', API_FORMAT = 'OpenAI');",
        "MSSQL-EXTMDL-CHG",
        false,
    );
}

#[test]
fn parity_mssql_login_new() {
    assert_parity(
        "CREATE LOGIN bob WITH PASSWORD = 'S3cret!';",
        "MSSQL-LOGIN-NEW",
        true,
    );
    assert_parity(
        "CREATE LOGIN bob FROM EXTERNAL PROVIDER;",
        "MSSQL-LOGIN-NEW",
        true,
    );
    assert_parity("CREATE USER alice WITHOUT LOGIN;", "MSSQL-LOGIN-NEW", false);
}

#[test]
fn parity_mssql_user_new() {
    assert_parity("CREATE USER alice WITHOUT LOGIN;", "MSSQL-USER-NEW", true);
    assert_parity("CREATE USER alice FOR LOGIN bob;", "MSSQL-USER-NEW", true);
    assert_parity(
        "CREATE LOGIN bob WITH PASSWORD = 'S3cret!';",
        "MSSQL-USER-NEW",
        false,
    );
}

// ─────────────────────────────────────────────────────────────────────
// Bucket C — parser-typed-field rules.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mssql_identity_insert_on_fires_on_set_on() {
    let ids = fact_rule_ids("SET IDENTITY_INSERT dbo.MyTable ON;");
    assert!(
        ids.contains(&"MSSQL-IDENTITY-INSERT-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_identity_insert_on_silent_for_off() {
    let ids = fact_rule_ids("SET IDENTITY_INSERT dbo.MyTable OFF;");
    assert!(
        !ids.contains(&"MSSQL-IDENTITY-INSERT-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_identity_insert_on_silent_for_other_option() {
    let ids = fact_rule_ids("SET NOCOUNT ON;");
    assert!(
        !ids.contains(&"MSSQL-IDENTITY-INSERT-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_ext_fires_on_from_external_provider() {
    let ids = fact_rule_ids("CREATE LOGIN bob FROM EXTERNAL PROVIDER;");
    assert!(
        ids.contains(&"MSSQL-LOGIN-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_ext_silent_for_with_password() {
    let ids = fact_rule_ids("CREATE LOGIN bob WITH PASSWORD = 'S3cret!';");
    assert!(
        !ids.contains(&"MSSQL-LOGIN-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_login_ext_silent_for_create_user_from_external() {
    let ids = fact_rule_ids("CREATE USER alice FROM EXTERNAL PROVIDER;");
    assert!(
        !ids.contains(&"MSSQL-LOGIN-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_user_ext_fires_on_from_external_provider() {
    let ids = fact_rule_ids("CREATE USER alice FROM EXTERNAL PROVIDER;");
    assert!(ids.contains(&"MSSQL-USER-EXT".to_string()), "ids={:?}", ids);
}

#[test]
fn mssql_user_ext_silent_for_for_login() {
    let ids = fact_rule_ids("CREATE USER alice FOR LOGIN bob;");
    assert!(
        !ids.contains(&"MSSQL-USER-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_user_ext_silent_for_without_login() {
    let ids = fact_rule_ids("CREATE USER alice WITHOUT LOGIN;");
    assert!(
        !ids.contains(&"MSSQL-USER-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn mssql_user_ext_silent_for_create_login_from_external() {
    let ids = fact_rule_ids("CREATE LOGIN bob FROM EXTERNAL PROVIDER;");
    assert!(
        !ids.contains(&"MSSQL-USER-EXT".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn parity_mssql_identity_insert_on() {
    assert_parity(
        "SET IDENTITY_INSERT dbo.MyTable ON;",
        "MSSQL-IDENTITY-INSERT-ON",
        true,
    );
    assert_parity(
        "SET IDENTITY_INSERT dbo.MyTable OFF;",
        "MSSQL-IDENTITY-INSERT-ON",
        false,
    );
    assert_parity("SET NOCOUNT ON;", "MSSQL-IDENTITY-INSERT-ON", false);
}

#[test]
fn parity_mssql_login_ext() {
    assert_parity(
        "CREATE LOGIN bob FROM EXTERNAL PROVIDER;",
        "MSSQL-LOGIN-EXT",
        true,
    );
    assert_parity(
        "CREATE LOGIN bob WITH PASSWORD = 'S3cret!';",
        "MSSQL-LOGIN-EXT",
        false,
    );
}

#[test]
fn parity_mssql_user_ext() {
    assert_parity(
        "CREATE USER alice FROM EXTERNAL PROVIDER;",
        "MSSQL-USER-EXT",
        true,
    );
    assert_parity("CREATE USER alice FOR LOGIN bob;", "MSSQL-USER-EXT", false);
    assert_parity("CREATE USER alice WITHOUT LOGIN;", "MSSQL-USER-EXT", false);
}

/// The name of every column the statements of `sql` reference, as the
/// facts publish them.
fn referenced_columns(sql: &str) -> Vec<String> {
    let config = AnalysisConfig {
        trace_mode: true,
        ..mssql_config()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    report
        .statement_traces
        .iter()
        .filter_map(|statement| statement.facts.as_ref()?.query.as_ref())
        .flat_map(|query| &query.references_column)
        .map(|reference| reference.column.name.normalized.to_ascii_lowercase())
        .collect()
}

#[test]
fn a_money_literal_is_no_column_reference() {
    assert_eq!(
        referenced_columns("SELECT name FROM items WHERE price > $100;"),
        ["name", "price"]
    );
    for (sql, expected) in [
        ("UPDATE items SET price = $5 WHERE id = 1;", vec!["id"]),
        ("INSERT INTO items (price) VALUES ($100);", vec![]),
        (
            "SELECT name FROM items WHERE price > $1.50 AND cost < -$2;",
            vec!["name", "price", "cost"],
        ),
    ] {
        assert_eq!(referenced_columns(sql), expected, "{sql}");
    }
}

/// A fact entry point of the public API.
#[derive(Clone, Copy, Debug)]
enum FactEntry {
    TsqlQuery,
    TsqlDdl,
    Query,
    QueryWithCatalog,
    Ddl,
    Privilege,
    PrivilegeWithCatalog,
    PolicyAttachment,
}

/// What a thread holds of another dialect when a fact entry point is called.
#[derive(Clone, Copy, Debug)]
enum Before {
    Nothing,
    /// The thread analysed a statement under the dialect, and the analysis
    /// returned.
    Analysed(&'static str),
    /// The thread folds names as the dialect does while the entry point
    /// runs.
    Set(&'static str),
}

fn customers_catalog() -> lexega_core::CatalogIndex {
    use lexega_core::catalog::{
        CatalogColumn, CatalogDatabase, CatalogIdent, CatalogSchema, CatalogSnapshot, CatalogTable,
        CatalogTableKind, CATALOG_SCHEMA_VERSION,
    };
    let ident = |name: &str| CatalogIdent {
        name: name.to_string(),
    };
    lexega_core::CatalogIndex::from_snapshot(CatalogSnapshot {
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
            schemas: vec![CatalogSchema {
                name: ident("PUBLIC"),
                tables: vec![CatalogTable {
                    name: ident("CUSTOMERS"),
                    kind: CatalogTableKind::Table,
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
                }],
            }],
        }],
    })
    .expect("valid snapshot")
}

/// A Snowflake procedure whose dynamic statement is the result of FORMAT.
const FORMAT_PROCEDURE: &str = "CREATE PROCEDURE p(x STRING) RETURNS STRING LANGUAGE SQL AS \
     $$ BEGIN EXECUTE IMMEDIATE FORMAT('DROP TABLE %s', x); END $$";

/// What a fact entry point reports for `sql` on a thread of its own that
/// holds `before` of another dialect.
fn rule_findings(before: Before, entry: FactEntry, sql: &'static str) -> String {
    std::thread::spawn(move || {
        // Built first, so the entry point's own dialect is all that varies.
        let catalog = customers_catalog();
        // Held while the entry point runs: one that adopts nothing folds
        // under it.
        let _set = match before {
            Before::Nothing => None,
            Before::Analysed(name) => {
                let config = AnalysisConfig {
                    dialect: lexega_core::dialect::dialect_from_name(name),
                    ..Default::default()
                };
                assert!(config.dialect.is_some(), "{name}");
                analyze_risk_with_policy_config("SELECT 1", &config)
                    .expect("the earlier statement is analysed");
                None
            }
            Before::Set(name) => Some(lexega_core::set_normalization_dialect(name)),
        };
        let findings = match entry {
            FactEntry::TsqlQuery => analyze_query_facts_with_dialect(sql, &MsSqlDialect),
            FactEntry::TsqlDdl => analyze_ddl_facts_with_dialect(sql, &MsSqlDialect),
            FactEntry::Query => lexega_core::api::analyze_query_facts(sql),
            FactEntry::QueryWithCatalog => {
                lexega_core::api::analyze_query_facts_with_catalog(sql, &catalog)
            }
            FactEntry::Ddl => lexega_core::api::analyze_ddl_facts(sql),
            FactEntry::Privilege => lexega_core::api::analyze_privilege_facts(sql),
            FactEntry::PrivilegeWithCatalog => {
                lexega_core::api::analyze_privilege_facts_with_catalog(sql, &catalog)
            }
            FactEntry::PolicyAttachment => lexega_core::api::analyze_policy_attachment_facts(sql),
        };
        format!("{:#?}", findings.expect("the statement parses"))
    })
    .join()
    .expect("the thread finishes")
}

// A fact entry point names its dialect (or is Snowflake's): what it reports,
// the names in its evidence included, follows neither the dialect of the
// statement its thread analysed last nor one the thread was left set to.
// The T-SQL, query and privilege statements carry a folded name in their
// evidence, so each of those entry points reports something else when it
// does not adopt its own dialect. The Snowflake DDL entry point's adoption
// shows in the FORMAT test below. No statement shows the policy-attachment
// entry point's: its rules read the verb and the kind of policy, and no
// finding it returns carries a name (eleven statements tried).
#[test]
fn a_fact_entry_point_reports_the_same_whatever_its_thread_analysed_before() {
    let mut differing = Vec::new();
    for (entry, sql) in [
        (FactEntry::TsqlQuery, "SELECT * FROM t WITH (NOLOCK)"),
        (
            FactEntry::TsqlDdl,
            "CREATE EXTERNAL TABLE dbo.ext (id INT) \
             WITH (LOCATION = '/x', DATA_SOURCE = MyDs, FILE_FORMAT = ff)",
        ),
        (
            FactEntry::Query,
            "SELECT a FROM t WHERE a NOT IN (SELECT b FROM s)",
        ),
        (
            FactEntry::QueryWithCatalog,
            "SELECT nosuch FROM analytics.public.customers",
        ),
        (FactEntry::Ddl, FORMAT_PROCEDURE),
        (
            FactEntry::Privilege,
            "GRANT SELECT ON TABLE db.s.t TO ROLE public",
        ),
        (
            FactEntry::PrivilegeWithCatalog,
            "GRANT SELECT ON TABLE db.s.t TO ROLE public",
        ),
        (
            FactEntry::PolicyAttachment,
            "ALTER USER \"Bob\" SET AUTHENTICATION POLICY \"MyPol\"",
        ),
    ] {
        let alone = rule_findings(Before::Nothing, entry, sql);
        assert!(
            alone.contains("rule_id"),
            "{entry:?} reports nothing: {sql}"
        );
        if matches!(entry, FactEntry::TsqlQuery) {
            assert!(alone.contains("\"normalized\": String(\"T\")"), "{alone}");
        }
        for before in [
            Before::Analysed("postgresql"),
            Before::Analysed("databricks"),
            Before::Analysed("mssql"),
            Before::Set("postgresql"),
            Before::Set("databricks"),
        ] {
            if rule_findings(before, entry, sql) != alone {
                differing.push(format!("{entry:?} with {before:?}: {sql}"));
            }
        }
    }
    assert!(differing.is_empty(), "{differing:#?}");
}

fn rule_ids(findings: &[lexega_core::rules::Finding]) -> Vec<&str> {
    findings.iter().map(|s| s.rule_id.as_str()).collect()
}

// Snowflake's FORMAT builds no SQL text, so the Snowflake DDL entry point
// does not report the procedure's dynamic statement as built by
// concatenation: the call's text comes from the parameter it is passed.
#[test]
fn the_snowflake_ddl_entry_point_reads_format_as_snowflake_does() {
    let findings =
        lexega_core::api::analyze_ddl_facts(FORMAT_PROCEDURE).expect("the statement parses");
    let ids = rule_ids(&findings);
    let dynamic: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| id.contains("DYNSQL"))
        .collect();
    assert_eq!(dynamic, ["DYNSQL-PARAM-TEXT"], "{ids:?}");
}

// A bracketed name is the name inside the brackets to the T-SQL DDL entry
// point.
#[test]
fn the_tsql_ddl_entry_point_reads_a_bracketed_role_name() {
    let findings = analyze_ddl_facts_with_dialect(
        "ALTER SERVER ROLE [sysadmin] ADD MEMBER [app]",
        &MsSqlDialect,
    )
    .expect("the statement parses");
    let ids = rule_ids(&findings);
    assert!(ids.contains(&"MSSQL-SRVROLE-SYSADMIN"), "{ids:?}");
}

// A role named in brackets, in any case, is the role the rules name.
#[test]
fn the_tsql_ddl_entry_point_reads_a_bracketed_database_role_name_in_any_case() {
    for sql in [
        "ALTER ROLE [db_owner] ADD MEMBER [bob]",
        "ALTER ROLE [DB_Owner] ADD MEMBER [bob]",
    ] {
        let findings =
            analyze_ddl_facts_with_dialect(sql, &MsSqlDialect).expect("the statement parses");
        let ids = rule_ids(&findings);
        assert!(ids.contains(&"MSSQL-DBROLE-ADMIN-ADD"), "{sql}: {ids:?}");
    }
    let findings = analyze_ddl_facts_with_dialect(
        "ALTER SERVER ROLE [SysAdmin] ADD MEMBER [app]",
        &MsSqlDialect,
    )
    .expect("the statement parses");
    let ids = rule_ids(&findings);
    assert!(ids.contains(&"MSSQL-SRVROLE-SYSADMIN"), "{ids:?}");
}

// `OPENROWSET(BULK '<file>', …)` reads a file; the provider form sends its
// query to another server.
#[test]
fn openrowset_reading_a_file_runs_no_sql() {
    for sql in [
        "SELECT BulkColumn FROM OPENROWSET(BULK 'C:\\data\\x.json', SINGLE_CLOB) AS j;",
        "SELECT * FROM OPENROWSET(BULK 'C:\\f.dat', FORMATFILE = 'C:\\f.fmt') AS b;",
    ] {
        let ids = risk_rule_ids(sql);
        assert!(
            !ids.iter().any(|id| id.starts_with("DYNSQL")),
            "{sql}: {ids:?}"
        );
    }
    let ids = risk_rule_ids(
        "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=x;Trusted_Connection=yes;', 'SELECT 1') AS r;",
    );
    assert!(ids.contains(&"DYNSQL-CROSS-SERVER".to_string()), "{ids:?}");
}
