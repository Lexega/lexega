// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A row-selecting predicate that keeps every row leaves a write
//! unbounded, however the predicate is spelled.

use std::collections::BTreeSet;

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;

fn rule_ids(sql: &str) -> BTreeSet<String> {
    let report = analyze_risk(sql).expect("analysis succeeds");
    report
        .entries()
        .map(|finding| {
            let RuleMatch::Analysis(analysis) = finding;
            analysis.matched_rule.clone()
        })
        .collect()
}

#[test]
fn a_constant_comparison_leaves_a_delete_unbounded() {
    let ids = rule_ids("DELETE FROM orders WHERE 1 = 1;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_true_literal_leaves_an_update_unbounded() {
    let ids = rule_ids("UPDATE orders SET status = 'x' WHERE TRUE;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_disjunction_covering_null_and_non_null_is_every_row() {
    let ids = rule_ids("DELETE FROM orders WHERE batch_id IS NULL OR batch_id IS NOT NULL;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_disjunction_compares_its_values_as_the_dialect_does() {
    // `1` and `1.0` are one number: every row is written.
    let ids = rule_ids("UPDATE orders SET a = 1 WHERE x = 1 OR x <> 1.0 OR x IS NULL;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
    // Under a case-sensitive collation a row holding 'a' matches neither
    // side.
    let ids = rule_ids("UPDATE orders SET a = 1 WHERE s = 'A' OR s <> 'a' OR s IS NULL;");
    assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
    let ids = rule_ids("UPDATE orders SET a = 1 WHERE s = 'a' OR s <> 'a' OR s IS NULL;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_column_a_template_names_after_its_qualifier_keeps_the_write_unbounded() {
    for sql in [
        "DELETE FROM orders WHERE orders.{{ c }} = 1 OR 1 = 1;",
        "UPDATE orders SET status = 'x' WHERE orders.{{ c }} = 1 OR TRUE;",
    ] {
        let ids = rule_ids(sql);
        assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{sql}: {ids:?}");
    }
}

#[test]
fn merge_on_true_is_an_unbounded_write() {
    let ids = rule_ids("MERGE INTO orders t USING staging s ON TRUE WHEN MATCHED THEN DELETE;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
    assert!(!ids.contains("DML-MERGE-DELETE"), "{ids:?}");
}

/// As [`rule_ids`], with `sql` read as MySQL.
fn mysql_rule_ids(sql: &str) -> BTreeSet<String> {
    let config = lexega_core::analyzer::AnalysisConfig {
        dialect: Some(lexega_core::dialect::mysql()),
        ..Default::default()
    };
    let report =
        lexega_core::api::analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    report
        .entries()
        .map(|finding| {
            let RuleMatch::Analysis(analysis) = finding;
            analysis.matched_rule.clone()
        })
        .collect()
}

#[test]
fn an_exclusive_or_of_a_true_and_a_false_side_leaves_a_delete_unbounded() {
    for sql in [
        "DELETE FROM orders WHERE 1 = 1 XOR 1 = 2;",
        "DELETE FROM orders WHERE TRUE XOR FALSE;",
    ] {
        let ids = mysql_rule_ids(sql);
        assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{sql}: {ids:?}");
    }
    // One side depends on the row; and both sides true is no row at all.
    for sql in [
        "DELETE FROM orders WHERE 1 = 1 XOR region = 'EU';",
        "DELETE FROM orders WHERE 1 = 1 XOR 1 = 1;",
    ] {
        let ids = mysql_rule_ids(sql);
        assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{sql}: {ids:?}");
    }
}

#[test]
fn a_mysql_conjunction_of_constants_leaves_a_delete_unbounded() {
    let ids = mysql_rule_ids("DELETE FROM orders WHERE 1 = 1 && 2 = 2;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
    let ids = mysql_rule_ids("DELETE FROM orders WHERE 1 = 1 && region = 'EU';");
    assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

/// The five dialects whose bitwise operators these tests read.
fn bitwise_dialects() -> [lexega_core::dialect::DialectRef; 5] {
    use lexega_core::dialect;
    [
        dialect::mysql(),
        dialect::mssql(),
        dialect::postgres(),
        dialect::bigquery(),
        dialect::databricks(),
    ]
}

/// The report of `sql` read as `dialect`, with the facts of its statements.
fn trace_report(
    sql: &str,
    dialect: &lexega_core::dialect::DialectRef,
) -> lexega_core::analyzer::AnalysisReport {
    let config = lexega_core::analyzer::AnalysisConfig {
        dialect: Some(dialect.clone()),
        trace_mode: true,
        ..Default::default()
    };
    lexega_core::api::analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds")
}

#[test]
fn a_bitwise_or_in_an_assignment_does_not_cut_the_update_from_its_where() {
    let sql = "UPDATE t SET flags = flags | 4 WHERE id = 1";
    for dialect in bitwise_dialects() {
        let report = trace_report(sql, &dialect);
        let ids: BTreeSet<&str> = report
            .entries()
            .map(|finding| {
                let RuleMatch::Analysis(analysis) = finding;
                analysis.matched_rule.as_str()
            })
            .collect();
        assert!(
            !ids.contains("DML-WRITE-UNBOUNDED"),
            "{}: {ids:?}",
            dialect.name()
        );
    }
}

#[test]
fn a_predicate_after_a_bitwise_and_is_read() {
    let sql = "DELETE FROM t WHERE flags & 4 = 4 AND tenant_id = 1";
    for dialect in bitwise_dialects() {
        let report = trace_report(sql, &dialect);
        let query = report
            .statement_traces
            .iter()
            .find_map(|statement| statement.facts.as_ref()?.query.as_ref())
            .expect("query facts");
        let scope = serde_json::to_string(&query.scopes[0]).expect("serializes");
        assert!(
            scope.to_ascii_lowercase().contains("tenant_id"),
            "{}: {scope}",
            dialect.name()
        );
    }
}

#[test]
fn a_real_filter_stays_bounded() {
    let ids = rule_ids("DELETE FROM orders WHERE region = 'EU';");
    assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn is_not_null_alone_is_not_every_row() {
    // Rows where the column is NULL survive unless it is proven non-null.
    let ids = rule_ids("DELETE FROM orders WHERE deleted_at IS NOT NULL;");
    assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_comparison_that_spares_only_null_rows_leaves_a_write_unbounded() {
    for sql in [
        "DELETE FROM orders WHERE id = id;",
        "UPDATE orders SET status = 'x' WHERE id >= id;",
        "DELETE FROM orders WHERE orders.id <= orders.id;",
        "DELETE FROM orders WHERE x = 1 OR x <> 1;",
        "DELETE FROM orders WHERE id = id OR region = 'EU';",
        "MERGE INTO orders USING s ON orders.id = orders.id WHEN MATCHED THEN DELETE;",
    ] {
        let ids = rule_ids(sql);
        assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{sql}: {ids:?}");
    }
    for sql in [
        "DELETE FROM orders WHERE id = id AND region = 'EU';",
        "DELETE FROM orders WHERE id <> id;",
        "DELETE FROM orders WHERE id < id;",
        "DELETE FROM orders WHERE id = parent_id;",
        "DELETE FROM orders WHERE NOT (deleted_at IS NULL);",
    ] {
        let ids = rule_ids(sql);
        assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{sql}: {ids:?}");
    }
}

#[test]
fn a_predicate_on_the_current_date_is_reported() {
    let ids = rule_ids("SELECT id FROM orders WHERE created_at > CURRENT_DATE;");
    assert!(ids.contains("INFO-Q-PRED-TEMPORAL"), "{ids:?}");
}

#[test]
fn a_write_setting_a_radix_or_suffixed_number_is_bounded_by_its_where() {
    let cases = [
        ("mssql", "UPDATE orders SET c = 0x4142 WHERE id = 1"),
        ("mssql", "UPDATE orders SET c = 0X41 WHERE id = 1;"),
        ("mysql", "UPDATE orders SET c = 0x4142 WHERE id = 1;"),
        ("mysql", "UPDATE orders SET c = 0b0101 WHERE id = 1"),
        ("postgres", "UPDATE orders SET c = 0o17 WHERE id = 1;"),
        ("postgres", "UPDATE orders SET c = 1_000 WHERE id = 1;"),
        ("bigquery", "UPDATE orders SET c = 0x4142 WHERE id = 1;"),
        ("databricks", "UPDATE orders SET c = 10L WHERE id = 1;"),
    ];
    for (dialect, sql) in cases {
        let config = lexega_core::analyzer::AnalysisConfig {
            dialect: lexega_core::dialect::dialect_from_name(dialect),
            ..Default::default()
        };
        let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
            .expect("analysis succeeds");
        let summary = &report.summary;
        assert_eq!(
            (summary.statements_parsed, summary.statements_skipped),
            (1, 0),
            "{dialect}: {sql}"
        );
        let unbounded = report.entries().any(|finding| {
            let RuleMatch::Analysis(analysis) = finding;
            analysis.matched_rule == "DML-WRITE-UNBOUNDED"
        });
        assert!(!unbounded, "{dialect}: {sql}");
    }
}

/// The operators of PostgreSQL, MySQL, T-SQL and BigQuery a write was read
/// up to and no further, each with its dialect.
const OPERATOR_VALUES: &[(&str, &str)] = &[
    ("postgres", "name @@ to_tsquery('x')"),
    ("postgres", "doc @@ '$.a == 1'"),
    ("postgres", "tags ?| array['a','b']"),
    ("postgres", "tags ?& array['a','b']"),
    ("postgres", "tags ? 'a'"),
    ("postgres", "doc @? '$.a'"),
    ("postgres", "id OPERATOR(pg_catalog.=) 2"),
    ("postgres", "(d1, d2) OVERLAPS (d3, d4)"),
    ("postgres", "doc IS JSON"),
    ("postgres", "name ^@ 'x'"),
    ("postgres", "|/ id > 2"),
    ("postgres", "@ id > 2"),
    ("postgres", "name IS NORMALIZED"),
    ("mysql", "name SOUNDS LIKE 'x'"),
    ("mysql", "3 MEMBER OF (doc)"),
    ("mysql", "name = BINARY 'x'"),
    ("mysql", "a IS UNKNOWN"),
    ("mysql", "! a"),
    ("mssql", "id !< 1"),
    ("mssql", "id !> 1"),
    ("bigquery", "a IS TRUE"),
];

/// The report of `sql` read as `dialect`: whether it raises
/// `DML-WRITE-UNBOUNDED`, and how many statements were partial and skipped.
fn unbounded_partial_skipped(dialect: &str, sql: &str) -> (bool, usize, usize) {
    let config = lexega_core::analyzer::AnalysisConfig {
        dialect: lexega_core::dialect::dialect_from_name(dialect),
        ..Default::default()
    };
    let report =
        lexega_core::api::analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    let unbounded = report.entries().any(|finding| {
        let RuleMatch::Analysis(analysis) = finding;
        analysis.matched_rule == "DML-WRITE-UNBOUNDED"
    });
    (
        unbounded,
        report.summary.statements_partial,
        report.summary.statements_skipped,
    )
}

#[test]
fn a_write_holding_one_of_these_operators_is_read_whole_and_bounded() {
    for (dialect, value) in OPERATOR_VALUES {
        for sql in [
            format!("UPDATE users SET flag = {value} WHERE id = 1"),
            format!("UPDATE users SET flag = 1 WHERE {value} AND id = 1"),
        ] {
            assert_eq!(
                unbounded_partial_skipped(dialect, &sql),
                (false, 0, 0),
                "{dialect}: {sql}"
            );
        }
    }
}

#[test]
fn a_write_in_a_body_holding_one_of_these_operators_is_bounded() {
    for (dialect, sql) in [
        (
            "mysql",
            "CREATE FUNCTION f() RETURNS INT DETERMINISTIC BEGIN UPDATE t SET flag = name SOUNDS LIKE 'x' WHERE id = 1; RETURN 1; END",
        ),
        (
            "postgres",
            "DO $$ BEGIN UPDATE users SET flag = 1 WHERE id = 1; EXCEPTION WHEN others THEN UPDATE users SET flag = tags ?| array['a'] WHERE id = 1; END $$",
        ),
        (
            "mssql",
            "CREATE PROCEDURE p AS BEGIN UPDATE users SET flag = id !< 1 WHERE id = 1; END",
        ),
    ] {
        assert_eq!(
            unbounded_partial_skipped(dialect, sql),
            (false, 0, 0),
            "{dialect}: {sql}"
        );
    }
}

#[test]
fn a_write_holding_one_of_these_operators_and_no_where_is_unbounded() {
    for (dialect, value) in OPERATOR_VALUES {
        let sql = format!("UPDATE users SET flag = {value}");
        assert_eq!(
            unbounded_partial_skipped(dialect, &sql),
            (true, 0, 0),
            "{dialect}: {sql}"
        );
    }
}
