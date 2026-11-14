// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A write whose FROM list joins the target's rows to keep only those a
//! join matches is bounded by that join; one whose joins keep every row of
//! the target, or that reads the target beside its FROM list, is not.

use std::collections::BTreeSet;

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::DialectRef;

const RULE: &str = "DML-WRITE-UNBOUNDED";

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

fn assert_bounded(sql: &str, dialect: DialectRef) {
    let ids = rule_ids(sql, dialect);
    assert!(!ids.contains(RULE), "{sql}: {ids:?}");
}

fn assert_unbounded(sql: &str, dialect: DialectRef) {
    let ids = rule_ids(sql, dialect);
    assert!(ids.contains(RULE), "{sql}: {ids:?}");
}

#[test]
fn an_inner_join_bounds_a_tsql_update_or_delete() {
    for sql in [
        "UPDATE dbo.EmailList SET Addr = s.Email FROM dbo.EmailList e JOIN stg.CustomerImport s ON s.CustomerImportId = e.Id;",
        "UPDATE e SET e.Addr = s.Email FROM dbo.EmailList e INNER JOIN stg.CustomerImport s ON s.CustomerImportId = e.Id;",
        "DELETE e FROM dbo.EmailList e JOIN stg.Blocked b ON b.Id = e.Id;",
    ] {
        assert_bounded(sql, lexega_core::dialect::mssql());
    }
}

#[test]
fn an_inner_join_bounds_a_mysql_multi_table_write() {
    for sql in [
        "UPDATE a JOIN b ON a.id = b.id SET a.x = 1;",
        "DELETE a FROM a JOIN b ON a.id = b.id;",
    ] {
        assert_bounded(sql, lexega_core::dialect::mysql());
    }
}

#[test]
fn a_postgres_from_list_bounds_only_through_where() {
    assert_bounded(
        "UPDATE t SET a = s.a FROM s WHERE t.id = s.id;",
        lexega_core::dialect::postgres(),
    );
    // `t` is no FROM source: every row of `t` is written.
    assert_unbounded(
        "UPDATE t SET a = s.a FROM s;",
        lexega_core::dialect::postgres(),
    );
    assert_unbounded("DELETE FROM t USING s;", lexega_core::dialect::postgres());
}

#[test]
fn a_join_that_keeps_every_target_row_bounds_nothing() {
    for sql in [
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e, stg.Blocked b;",
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e CROSS JOIN stg.Blocked b;",
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e LEFT JOIN stg.Blocked b ON b.Id = e.Id;",
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e FULL JOIN stg.Blocked b ON b.Id = e.Id;",
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e JOIN stg.Blocked b ON 1 = 1;",
        "DELETE e FROM dbo.EmailList e JOIN stg.Blocked b ON 1 = 1;",
        "UPDATE e SET e.Addr = 'x' FROM stg.Blocked b RIGHT JOIN dbo.EmailList e ON e.Id = b.Id;",
    ] {
        assert_unbounded(sql, lexega_core::dialect::mssql());
    }
}

#[test]
fn the_padded_side_of_an_outer_join_is_bounded() {
    for sql in [
        "UPDATE e SET e.Addr = 'x' FROM stg.Blocked b LEFT JOIN dbo.EmailList e ON e.Id = b.Id;",
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e RIGHT JOIN stg.Blocked b ON b.Id = e.Id;",
    ] {
        assert_bounded(sql, lexega_core::dialect::mssql());
    }
}

#[test]
fn a_write_with_neither_where_nor_join_stays_unbounded() {
    assert_unbounded(
        "UPDATE dbo.EmailList SET Addr = 'x';",
        lexega_core::dialect::mssql(),
    );
    assert_unbounded("DELETE FROM dbo.EmailList;", lexega_core::dialect::mssql());
    // A join elsewhere does not bound a target read beside it.
    assert_unbounded(
        "UPDATE dbo.EmailList SET Addr = 'x' FROM stg.Blocked b JOIN stg.CustomerImport s ON s.CustomerImportId = b.Id;",
        lexega_core::dialect::mssql(),
    );
}

#[test]
fn top_bounds_a_tsql_write() {
    assert_bounded(
        "UPDATE TOP (10) dbo.Orders SET Status = 1;",
        lexega_core::dialect::mssql(),
    );
    assert_bounded(
        "DELETE TOP (10) FROM dbo.Orders;",
        lexega_core::dialect::mssql(),
    );
}

/// The tables `sql`, one statement, writes.
fn written_tables(sql: &str, dialect: DialectRef) -> BTreeSet<String> {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    report
        .statement_traces
        .iter()
        .filter_map(|trace| trace.facts.as_ref()?.query.as_ref())
        .flat_map(|query| &query.writes_table)
        .map(|written| written.table.name.normalized.clone())
        .collect()
}

#[test]
fn a_multi_table_write_is_bounded_only_where_every_table_it_writes_is() {
    let mysql = lexega_core::dialect::mysql;
    for sql in [
        // `a` is the preserved side, or cross-joined: every row of it.
        "UPDATE b RIGHT JOIN a ON a.id = b.id SET a.x = 1;",
        "UPDATE b JOIN c ON b.id = c.id, a SET a.x = 1;",
        "DELETE b, a FROM b RIGHT JOIN a ON a.id = b.id;",
        "DELETE b, a FROM a LEFT JOIN b ON a.id = b.id;",
        // `b` is matched, `a` preserved.
        "UPDATE a LEFT JOIN b ON a.id = b.id SET a.x = 1, b.x = 1;",
    ] {
        assert_unbounded(sql, mysql());
    }
    for sql in [
        // Only the padded side's matched rows are written.
        "UPDATE a LEFT JOIN b ON a.id = b.id SET b.x = 1;",
        "UPDATE b JOIN a ON a.id = b.id SET a.x = 1;",
        "DELETE a, b FROM a JOIN b ON a.id = b.id;",
    ] {
        assert_bounded(sql, mysql());
    }
}

#[test]
fn each_table_a_multi_table_delete_names_is_written() {
    assert_eq!(
        written_tables(
            "DELETE b, a FROM b RIGHT JOIN a ON a.id = b.id;",
            lexega_core::dialect::mysql()
        ),
        BTreeSet::from(["A".to_string(), "B".to_string()])
    );
    assert_eq!(
        written_tables(
            "DELETE a FROM b JOIN a ON a.id = b.id;",
            lexega_core::dialect::mysql()
        ),
        BTreeSet::from(["A".to_string()])
    );
}

#[test]
fn a_self_join_bounds_nothing_where_the_target_stands_beside_the_from_list() {
    for (sql, dialect) in [
        (
            "UPDATE t SET a = 1 FROM t t2 JOIN s ON t2.id = s.id;",
            lexega_core::dialect::postgres(),
        ),
        (
            "DELETE FROM t USING t t2 JOIN s ON t2.id = s.id;",
            lexega_core::dialect::postgres(),
        ),
        (
            "UPDATE t SET a = 1 FROM t t2 JOIN s ON t2.id = s.id;",
            lexega_core::dialect::redshift(),
        ),
        (
            "UPDATE t SET a = 1 FROM t t2 JOIN s ON t2.id = s.id;",
            lexega_core::dialect::snowflake(),
        ),
        (
            "DELETE FROM t USING t t2 JOIN s ON t2.id = s.id;",
            lexega_core::dialect::snowflake(),
        ),
        (
            "UPDATE db.sch.t SET a = 1 FROM db.sch.t AS t2 INNER JOIN s ON t2.id = s.id;",
            lexega_core::dialect::snowflake(),
        ),
        (
            "UPDATE ds.t SET a = 1 FROM ds.t t2 JOIN ds.s ON t2.id = s.id WHERE TRUE;",
            lexega_core::dialect::bigquery(),
        ),
    ] {
        assert_unbounded(sql, dialect);
    }
    // T-SQL names the target by the FROM source of its table.
    assert_bounded(
        "UPDATE dbo.t SET a = 1 FROM dbo.t t2 JOIN dbo.s ON t2.id = s.id;",
        lexega_core::dialect::mssql(),
    );
}

#[test]
fn a_tsql_delete_target_no_from_item_names_is_written_beside_the_list() {
    let mssql = lexega_core::dialect::mssql;
    for sql in [
        "DELETE dbo.EmailList FROM stg.S s JOIN stg.T t ON t.Id = s.Id;",
        "DELETE dbo.EmailList FROM stg.S s;",
    ] {
        assert_unbounded(sql, mssql());
        assert_eq!(
            written_tables(sql, mssql()),
            BTreeSet::from(["EMAILLIST".to_string()]),
            "{sql}"
        );
    }
    assert_eq!(
        written_tables(
            "DELETE t FROM stg.S s JOIN dbo.EmailList t ON t.Id = s.Id;",
            mssql()
        ),
        BTreeSet::from(["EMAILLIST".to_string()])
    );
}

#[test]
fn a_cap_that_keeps_every_row_bounds_nothing() {
    let mssql = lexega_core::dialect::mssql;
    for sql in [
        "UPDATE TOP (100) PERCENT dbo.EmailList SET Addr = 'x';",
        "WITH c AS (SELECT TOP 100 PERCENT * FROM dbo.Orders ORDER BY Id) UPDATE c SET Status = 1;",
        "WITH c AS (SELECT * FROM dbo.Orders ORDER BY Id OFFSET 10 ROWS) UPDATE c SET Status = 1;",
    ] {
        assert_unbounded(sql, mssql());
    }
    for sql in [
        "UPDATE TOP (50) PERCENT dbo.EmailList SET Addr = 'x';",
        "UPDATE TOP (@n) dbo.EmailList SET Addr = 'x';",
        "DELETE TOP (1000) FROM dbo.EmailList;",
        "WITH c AS (SELECT * FROM dbo.Orders ORDER BY Id OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY) UPDATE c SET Status = 1;",
    ] {
        assert_bounded(sql, mssql());
    }
}

#[test]
fn a_mysql_limit_bounds_a_write_as_top_does() {
    for sql in ["DELETE FROM a LIMIT 10;", "UPDATE a SET x = 1 LIMIT 10;"] {
        assert_bounded(sql, lexega_core::dialect::mysql());
    }
}

#[test]
fn a_correlated_cross_apply_keeps_only_the_rows_it_matches() {
    let mssql = lexega_core::dialect::mssql;
    for sql in [
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e CROSS APPLY (SELECT TOP 1 * FROM stg.S s WHERE s.Id = e.Id) s;",
        "UPDATE e SET Cnt = v.c FROM dbo.EmailList e CROSS APPLY (SELECT COUNT(*) AS c FROM stg.S s WHERE s.Id = e.Id HAVING COUNT(*) > 1) v;",
        "UPDATE e SET Cnt = v.c FROM dbo.EmailList e CROSS APPLY (SELECT s.Id, COUNT(*) AS c FROM stg.S s WHERE s.Id = e.Id GROUP BY s.Id) v;",
        "DELETE e FROM dbo.EmailList e CROSS APPLY (SELECT TOP 0 e.Id AS x) v;",
    ] {
        assert_bounded(sql, mssql());
    }
    for sql in [
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e OUTER APPLY (SELECT TOP 1 * FROM stg.S s WHERE s.Id = e.Id) s;",
        // A right side that yields a row for every row to its left.
        "UPDATE e SET Addr = v.Clean FROM dbo.EmailList e CROSS APPLY (SELECT LTRIM(RTRIM(e.Addr)) AS Clean) v;",
        "DELETE e FROM dbo.EmailList e CROSS APPLY (SELECT e.Id AS x) v;",
        "UPDATE e SET Cnt = v.c FROM dbo.EmailList e CROSS APPLY (SELECT COUNT(*) AS c FROM stg.S s WHERE s.Id = e.Id) v;",
        "UPDATE e SET Addr = v.a FROM dbo.EmailList e CROSS APPLY (VALUES (e.Addr)) v(a);",
        // Nothing shows whether these yield a row.
        "UPDATE e SET Addr = v.value FROM dbo.EmailList e CROSS APPLY STRING_SPLIT(e.Addr, ',') v;",
        "UPDATE e SET e.Addr = 'x' FROM dbo.EmailList e CROSS APPLY (SELECT TOP 1 * FROM stg.S s ORDER BY s.Id) s;",
        // What can drop a row reads no row to its left: every row or none.
        "UPDATE e SET e.Rate = c.Rate FROM dbo.Emp e CROSS APPLY (SELECT TOP 1 Rate FROM dbo.Config WHERE Name = 'rate') c;",
        "DELETE e FROM dbo.Emp e CROSS APPLY (SELECT TOP 1 1 AS x FROM dbo.Config WHERE Name = 'purge' AND Value = 'on') c;",
        "UPDATE e SET e.Rate = c.Rate FROM dbo.Emp e CROSS APPLY (SELECT Rate FROM dbo.Config WHERE Name = 'rate') c;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT * FROM dbo.S s WHERE s.Flag = 1) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT TOP 1 * FROM dbo.S s WHERE s.Flag = 1) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT c FROM dbo.S s ORDER BY c OFFSET @k ROWS) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT * FROM dbo.S WHERE Flag = @p) v;",
        // Correlated only in its select list.
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT e.Id AS k, s.c FROM dbo.S s WHERE s.Flag = 1) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT TOP 1 e.Id AS k, s.c FROM dbo.S s WHERE s.Flag = 1 ORDER BY s.c) v;",
        "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER JOIN dbo.T t ON t.Id = s.Id) v;",
    ] {
        assert_unbounded(sql, mssql());
    }
    // What can drop a row reads the row to its left.
    for sql in [
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT TOP 1 s.c FROM dbo.S s WHERE s.Id = e.Id ORDER BY s.d) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s WHERE s.Id = e.Id) v;",
        "UPDATE e SET x = v.x FROM dbo.E e CROSS APPLY (SELECT e.Id AS x WHERE e.Active = 1) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT TOP (@n) s.c FROM dbo.S s WHERE s.Id = e.Id) v;",
        "UPDATE e SET x = v.x FROM dbo.E e CROSS APPLY (SELECT e.Id AS x EXCEPT SELECT s.Id FROM dbo.S s) v;",
        "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT 1 AS x WHERE EXISTS (SELECT 1 FROM dbo.S s WHERE s.Id = e.Id)) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT c FROM dbo.S s WHERE s.Id = e.Id ORDER BY c OFFSET 0 ROWS) v;",
        "DELETE e FROM dbo.E e CROSS APPLY (SELECT TOP 1 s.c FROM dbo.S s WHERE s.Id = e.Id) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s WHERE s.Id = e.Id) v CROSS APPLY (SELECT 1 AS one) w;",
        "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER JOIN dbo.T t ON t.Id = s.Id WHERE s.Id = e.Id) v;",
        "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER JOIN dbo.T t ON t.Id = e.Id) v;",
        "UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s WHERE s.Flag = 1 AND e.Id > 0) v;",
        // A cap of no rows writes nothing.
        "DELETE e FROM dbo.E e CROSS APPLY (SELECT TOP 0 * FROM dbo.S s) v;",
    ] {
        assert_bounded(sql, mssql());
    }
}

#[test]
fn a_right_side_is_judged_alike_however_the_join_is_spelled() {
    let mssql = lexega_core::dialect::mssql;
    let mysql = lexega_core::dialect::mysql;
    for (sql, dialect) in [
        ("UPDATE e SET e.Rate = c.Rate FROM dbo.Emp e CROSS JOIN (SELECT TOP 1 Rate FROM dbo.Config WHERE Name = 'rate') c;", mssql()),
        ("UPDATE e SET e.Rate = c.Rate FROM dbo.Emp e CROSS APPLY (SELECT TOP 1 Rate FROM dbo.Config WHERE Name = 'rate') c;", mssql()),
        ("DELETE e FROM dbo.Emp e CROSS JOIN (SELECT TOP 1 1 AS x FROM dbo.Config WHERE Name = 'purge') c;", mssql()),
        ("DELETE e FROM dbo.Emp e CROSS APPLY (SELECT TOP 1 1 AS x FROM dbo.Config WHERE Name = 'purge') c;", mssql()),
        ("UPDATE a CROSS JOIN (SELECT b.y FROM b WHERE b.flag = 1 LIMIT 1) l SET a.x = l.y;", mysql()),
        ("UPDATE a CROSS JOIN LATERAL (SELECT b.y FROM b WHERE b.flag = 1 LIMIT 1) l SET a.x = l.y;", mysql()),
        ("UPDATE a JOIN LATERAL (SELECT b.y FROM b WHERE b.flag = 1 LIMIT 1) l ON TRUE SET a.x = l.y;", mysql()),
        ("UPDATE a JOIN LATERAL (SELECT b.y FROM b WHERE b.flag = 1) l ON TRUE SET a.x = l.y;", mysql()),
        ("DELETE a FROM a JOIN LATERAL (SELECT b.y FROM b WHERE b.flag = 1) l ON TRUE;", mysql()),
    ] {
        assert_unbounded(sql, dialect);
    }
    for (sql, dialect) in [
        ("UPDATE e SET x = v.c FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s WHERE s.Id = e.Id) v;", mssql()),
        ("UPDATE a CROSS JOIN LATERAL (SELECT b.y FROM b WHERE b.id = a.id) l SET a.x = l.y;", mysql()),
        ("UPDATE a JOIN LATERAL (SELECT b.y FROM b WHERE b.id = a.id) l ON TRUE SET a.x = l.y;", mysql()),
        ("UPDATE a, LATERAL (SELECT b.y FROM b WHERE b.id = a.id) l SET a.x = l.y;", mysql()),
        ("DELETE a FROM a JOIN LATERAL (SELECT b.y FROM b WHERE b.id = a.id LIMIT 1) l ON TRUE;", mysql()),
    ] {
        assert_bounded(sql, dialect);
    }
}

#[test]
fn a_lateral_join_bounds_a_write_only_where_its_right_side_can_yield_no_row() {
    let mysql = lexega_core::dialect::mysql;
    for sql in [
        "UPDATE a JOIN LATERAL (SELECT a.x + 1 AS y) l SET a.x = l.y;",
        "UPDATE a CROSS JOIN LATERAL (SELECT a.x + 1 AS y) l SET a.x = l.y;",
        "UPDATE a JOIN LATERAL (SELECT COUNT(*) AS y FROM b WHERE b.id = a.id) l SET a.x = l.y;",
    ] {
        assert_unbounded(sql, mysql());
    }
    for sql in [
        "UPDATE a JOIN LATERAL (SELECT b.y FROM b WHERE b.id = a.id LIMIT 1) l SET a.x = l.y;",
        "UPDATE a CROSS JOIN LATERAL (SELECT b.y FROM b WHERE b.id = a.id) l SET a.x = l.y;",
    ] {
        assert_bounded(sql, mysql());
    }
}

#[test]
fn a_tsql_delete_target_after_from_is_the_item_of_the_second_from_list_it_names() {
    let mssql = lexega_core::dialect::mssql;
    for sql in [
        "DELETE FROM o FROM dbo.Orders o JOIN stg.S s ON s.Id = o.Id;",
        "DELETE FROM o FROM dbo.Orders o;",
        "DELETE FROM Orders FROM dbo.Orders JOIN stg.S s ON s.Id = Orders.Id;",
    ] {
        assert_eq!(
            written_tables(sql, mssql()),
            BTreeSet::from(["ORDERS".to_string()]),
            "{sql}"
        );
    }
    assert_bounded(
        "DELETE FROM o FROM dbo.Orders o JOIN stg.S s ON s.Id = o.Id;",
        mssql(),
    );
    assert_unbounded("DELETE FROM o FROM dbo.Orders o;", mssql());
    // The target names its FROM item, and writes the schema it is written in.
    let sql = "DELETE dbo.EmailList FROM EmailList JOIN stg.S s ON s.Id = EmailList.Id;";
    let ids = rule_ids(sql, mssql());
    assert!(
        ids.contains("DML-WRITE-XSCHEMA") && !ids.contains(RULE),
        "{sql}: {ids:?}"
    );
}

/// The canonical names of the tables `sql`, one statement, writes.
fn written_canonical(sql: &str, dialect: DialectRef) -> BTreeSet<String> {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    report
        .statement_traces
        .iter()
        .filter_map(|trace| trace.facts.as_ref()?.query.as_ref())
        .flat_map(|query| &query.writes_table)
        .map(|written| written.table.canonical.clone())
        .collect()
}

#[test]
fn a_tsql_target_naming_another_schema_than_its_from_item_is_a_table_of_its_own() {
    let mssql = lexega_core::dialect::mssql;
    for (sql, written) in [
        (
            "DELETE dbo.Orders FROM stg.Orders JOIN stg.S s ON s.Id = Orders.Id;",
            "DBO.ORDERS",
        ),
        (
            "DELETE FROM dbo.Orders FROM stg.Orders JOIN stg.S s ON s.Id = Orders.Id;",
            "DBO.ORDERS",
        ),
        (
            "DELETE stg.Orders FROM dbo.Orders JOIN dbo.S s ON s.Id = Orders.Id;",
            "STG.ORDERS",
        ),
        (
            "UPDATE dbo.Orders SET Status = 1 FROM stg.Orders JOIN stg.S s ON s.Id = Orders.Id;",
            "DBO.ORDERS",
        ),
    ] {
        assert_eq!(
            written_canonical(sql, mssql()),
            BTreeSet::from([written.to_string()]),
            "{sql}"
        );
        let ids = rule_ids(sql, mssql());
        assert!(
            ids.contains("DML-WRITE-XSCHEMA") && ids.contains(RULE),
            "{sql}: {ids:?}"
        );
    }
    // A name the item answers to, with no part in conflict, is the item;
    // UPDATE and DELETE write the same table.
    for sql in [
        "DELETE Orders FROM dbo.Orders JOIN stg.S s ON s.Id = Orders.Id;",
        "DELETE FROM Orders FROM dbo.Orders JOIN stg.S s ON s.Id = Orders.Id;",
        "UPDATE Orders SET Status = 1 FROM dbo.Orders JOIN stg.S s ON s.Id = Orders.Id;",
        "DELETE dbo.Orders FROM Orders JOIN stg.S s ON s.Id = Orders.Id;",
        "UPDATE dbo.Orders SET Status = 1 FROM Orders JOIN stg.S s ON s.Id = Orders.Id;",
    ] {
        assert_eq!(
            written_canonical(sql, mssql()),
            BTreeSet::from(["DBO.ORDERS".to_string()]),
            "{sql}"
        );
        assert_bounded(sql, mssql());
    }
    // A qualified target is no alias.
    let sql =
        "UPDATE dbo.Orders SET Status = 1 FROM stg.Orders Orders JOIN stg.S s ON s.Id = Orders.Id;";
    assert_eq!(
        written_canonical(sql, mssql()),
        BTreeSet::from(["DBO.ORDERS".to_string()]),
        "{sql}"
    );
    assert_unbounded(sql, mssql());
}

#[test]
fn a_mysql_delete_target_names_the_item_of_its_table_written_with_more_parts() {
    let mysql = lexega_core::dialect::mysql;
    let sql = "DELETE a, b FROM db1.a JOIN db1.b ON a.id = b.id;";
    assert_eq!(
        written_tables(sql, mysql()),
        BTreeSet::from(["A".to_string(), "B".to_string()])
    );
    assert_bounded(sql, mysql());
    assert_unbounded(
        "DELETE a, b FROM db1.a LEFT JOIN db1.b ON a.id = b.id;",
        mysql(),
    );
}

#[test]
fn a_mysql_delete_from_a_target_list_using_a_from_list_writes_each_target() {
    let mysql = lexega_core::dialect::mysql;
    assert_eq!(
        written_tables(
            "DELETE FROM b, a USING b RIGHT JOIN a ON a.id = b.id;",
            mysql()
        ),
        BTreeSet::from(["A".to_string(), "B".to_string()])
    );
    // `a` is the preserved side: every row of it.
    assert_unbounded(
        "DELETE FROM b, a USING b RIGHT JOIN a ON a.id = b.id;",
        mysql(),
    );
    assert_bounded("DELETE FROM a, b USING a JOIN b ON a.id = b.id;", mysql());
    assert_bounded(
        "DELETE FROM a.*, b.* USING a JOIN b ON a.id = b.id;",
        mysql(),
    );
}

/// The findings of `sql` and the number of its statements left unparsed.
fn findings_and_skipped(sql: &str, dialect: DialectRef) -> (BTreeSet<String>, usize) {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis succeeds");
    let ids = report
        .entries()
        .map(|finding| {
            let RuleMatch::Analysis(analysis) = finding;
            analysis.matched_rule.clone()
        })
        .collect();
    (ids, report.summary.statements_skipped)
}

#[test]
fn a_tsql_write_with_two_output_clauses_keeps_its_where() {
    for sql in [
        "DELETE FROM dbo.Orders OUTPUT deleted.* INTO @t OUTPUT deleted.Id WHERE Id = 1;",
        "UPDATE o SET Status = 1 OUTPUT inserted.* INTO @t OUTPUT inserted.Id FROM dbo.Orders o WHERE o.Id = 1;",
        "INSERT INTO dbo.Orders (Id) OUTPUT inserted.Id INTO @a OUTPUT inserted.Id VALUES (1);",
    ] {
        let (ids, skipped) = findings_and_skipped(sql, lexega_core::dialect::mssql());
        assert!(ids.is_empty(), "{sql}: {ids:?}");
        assert_eq!(skipped, 0, "{sql}");
    }
}

#[test]
fn a_tsql_join_hint_leaves_the_join_as_it_is() {
    let mssql = lexega_core::dialect::mssql;
    // A hint changes how the server runs a join, not the rows it keeps.
    for (hinted, plain, bounded) in [
        (
            "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER MERGE JOIN dbo.T t ON t.id = s.id) v;",
            "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER JOIN dbo.T t ON t.id = s.id) v;",
            false,
        ),
        (
            "UPDATE dbo.E SET x = 1 FROM (SELECT s.id FROM dbo.S s LEFT OUTER LOOP JOIN dbo.T t ON t.id = s.id) v;",
            "UPDATE dbo.E SET x = 1 FROM (SELECT s.id FROM dbo.S s LEFT OUTER JOIN dbo.T t ON t.id = s.id) v;",
            false,
        ),
        (
            "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER MERGE JOIN dbo.T t ON t.id = s.id) v WHERE e.id = 1;",
            "UPDATE e SET x = 1 FROM dbo.E e CROSS APPLY (SELECT s.c FROM dbo.S s INNER JOIN dbo.T t ON t.id = s.id) v WHERE e.id = 1;",
            true,
        ),
        (
            "UPDATE t SET a = 1 FROM dbo.t t INNER HASH JOIN dbo.s s ON s.id = t.id WHERE t.k = 1;",
            "UPDATE t SET a = 1 FROM dbo.t t INNER JOIN dbo.s s ON s.id = t.id WHERE t.k = 1;",
            true,
        ),
        (
            "DELETE t FROM dbo.t t INNER LOOP JOIN dbo.s s ON s.id = t.id WHERE t.k = 1;",
            "DELETE t FROM dbo.t t INNER JOIN dbo.s s ON s.id = t.id WHERE t.k = 1;",
            true,
        ),
        (
            "UPDATE e SET x = 1 FROM dbo.E e INNER REMOTE JOIN dbo.S s ON s.id = e.id OPTION (LOOP JOIN);",
            "UPDATE e SET x = 1 FROM dbo.E e INNER JOIN dbo.S s ON s.id = e.id;",
            true,
        ),
        (
            "DELETE e FROM dbo.E e LEFT HASH JOIN dbo.S s ON s.id = e.id OPTION (HASH JOIN, MAXDOP 1);",
            "DELETE e FROM dbo.E e LEFT JOIN dbo.S s ON s.id = e.id;",
            false,
        ),
    ] {
        let (hinted_ids, skipped) = findings_and_skipped(hinted, mssql());
        assert_eq!(skipped, 0, "{hinted}");
        let (plain_ids, _) = findings_and_skipped(plain, mssql());
        assert_eq!(hinted_ids, plain_ids, "{hinted}");
        assert_eq!(!hinted_ids.contains(RULE), bounded, "{hinted}: {hinted_ids:?}");
    }
}
