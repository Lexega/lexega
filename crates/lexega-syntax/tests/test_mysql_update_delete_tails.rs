// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL UPDATE/DELETE tail + ALTER ADD COLUMN attribute coverage.
//!
//! Covers:
//!   1. Format round-trip safety for every construct
//!   2. AST structure: ORDER BY ... LIMIT tails, LOW_PRIORITY/IGNORE/QUICK
//!      modifiers, multi-table UPDATE (join + comma), multi-table DELETE
//!      target lists (`t1, t2` / `t1.*`), DELETE PARTITION
//!   3. Dialect gating: MySQL-only DML surface degrades under Snowflake
//!   4. ALTER ADD COLUMN full attribute tail (UNSIGNED/ZEROFILL/NOT NULL/...)
//!      stays within the statement

use lexega_syntax::ast::AstStmt;
use lexega_syntax::dialect::{mysql, snowflake};
use lexega_syntax::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

// ============================================================================
// Helpers
// ============================================================================

fn mysql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: mysql(),
        ..Default::default()
    }
}

fn format_and_verify(sql: &str) {
    let config = mysql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("MySQL formatting verification failed: {}", e));
}

fn parse_mysql(sql: &str) -> lexega_syntax::ast::AstScript {
    parse_sql_with_dialect(sql, mysql().as_ref())
        .unwrap_or_else(|e| panic!("MySQL parse failed for {:?}: {:?}", sql, e))
}

#[test]
fn a_mysql_row_alias_is_parsed_with_its_columns() {
    for (sql, alias, columns) in [
        (
            "INSERT INTO t (a, b) VALUES (1, 2) AS /* row */ new (m, n) \
             ON DUPLICATE KEY UPDATE b = m + n",
            "new",
            vec!["m", "n"],
        ),
        (
            "INSERT INTO t (a, b) VALUES (1, 2) AS new_row ON DUPLICATE KEY UPDATE b = new_row.b",
            "new_row",
            vec![],
        ),
    ] {
        let script = parse_mysql(sql);
        let [AstStmt::Insert(insert)] = script.stmts.as_slice() else {
            panic!("{sql}: expected one INSERT, got {:?}", script.stmts);
        };
        let Some(row_alias) = insert.row_alias.as_ref() else {
            panic!("{sql}: expected a row alias");
        };
        let text = |span: lexega_syntax::Span| &sql[span.start as usize..span.end as usize];
        assert_eq!(text(row_alias.alias.span), alias, "{sql}");
        let written: Vec<&str> = row_alias.columns.iter().map(|c| text(c.span)).collect();
        assert_eq!(written, columns, "{sql}");
        assert!(insert.row_alias_span.is_some(), "{sql}");
    }
    // No alias: nothing is carried.
    let script = parse_mysql("INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = 2");
    let [AstStmt::Insert(insert)] = script.stmts.as_slice() else {
        panic!("expected one INSERT, got {:?}", script.stmts);
    };
    assert!(insert.row_alias.is_none());
}

/// Variant name from Debug output — avoids a `_ =>` arm on `AstStmt`.
fn stmt_name(stmt: &AstStmt) -> String {
    let dbg = format!("{:?}", stmt);
    dbg.split(|c: char| c == '(' || c == '{' || c.is_whitespace())
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

fn single_update(sql: &str) -> Box<lexega_syntax::ast::AstUpdate> {
    let mut script = parse_mysql(sql);
    assert_eq!(
        script.stmts.len(),
        1,
        "expected one statement for {:?}",
        sql
    );
    match script.stmts.remove(0) {
        AstStmt::Update(u) => u,
        other => panic!("expected Update for {:?}, got {}", sql, stmt_name(&other)),
    }
}

fn single_delete(sql: &str) -> Box<lexega_syntax::ast::AstDelete> {
    let mut script = parse_mysql(sql);
    assert_eq!(
        script.stmts.len(),
        1,
        "expected one statement for {:?}",
        sql
    );
    match script.stmts.remove(0) {
        AstStmt::Delete(d) => d,
        other => panic!("expected Delete for {:?}, got {}", sql, stmt_name(&other)),
    }
}

/// Assert the SQL parses as a single statement of the expected variant — no
/// OpaqueContent / ClauseFragment shear.
fn assert_single(sql: &str, expected_variant: &str) {
    let script = parse_mysql(sql);
    assert_eq!(
        script.stmts.len(),
        1,
        "{:?} should parse to one statement, got {:?}",
        sql,
        script.stmts.iter().map(stmt_name).collect::<Vec<_>>()
    );
    assert_eq!(
        stmt_name(&script.stmts[0]),
        expected_variant,
        "{:?} parsed as wrong variant",
        sql
    );
}

fn assert_snowflake_opaque(sql: &str) {
    let script = parse_sql_with_dialect(sql, snowflake().as_ref())
        .unwrap_or_else(|e| panic!("script-level parse should not hard-fail: {:?}", e));
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "Snowflake should degrade {:?} (at least one opaque), got {:?}",
        sql,
        script.stmts.iter().map(stmt_name).collect::<Vec<_>>()
    );
}

// ============================================================================
// 1. Round-trip safety
// ============================================================================

#[test]
fn test_roundtrip_update_order_limit() {
    format_and_verify("UPDATE t SET a = 1 WHERE b > 0 ORDER BY c DESC LIMIT 10;");
}

#[test]
fn test_roundtrip_update_modifiers() {
    format_and_verify("UPDATE LOW_PRIORITY IGNORE t SET a = a + 1 LIMIT 5;");
}

#[test]
fn test_roundtrip_update_multi_table_join() {
    format_and_verify("UPDATE t1 JOIN t2 ON t1.id = t2.id SET t1.x = t2.y WHERE t2.z IS NULL;");
}

#[test]
fn test_roundtrip_update_multi_table_comma() {
    format_and_verify("UPDATE t1, t2 SET t1.x = t2.y, t2.w = 0 WHERE t1.id = t2.id;");
}

#[test]
fn test_roundtrip_delete_order_limit() {
    format_and_verify("DELETE FROM t WHERE b < 0 ORDER BY c LIMIT 100;");
}

#[test]
fn test_roundtrip_delete_modifiers() {
    format_and_verify("DELETE LOW_PRIORITY QUICK IGNORE FROM t WHERE x = 1;");
}

#[test]
fn test_roundtrip_delete_multi_target() {
    format_and_verify("DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.id WHERE t2.flag = 1;");
}

#[test]
fn test_roundtrip_delete_star_target() {
    format_and_verify("DELETE t1.* FROM t1 INNER JOIN t2 ON t1.id = t2.id;");
}

#[test]
fn test_roundtrip_delete_using_join() {
    format_and_verify("DELETE FROM t1 USING t1 JOIN t2 ON t1.id = t2.id WHERE t2.flag = 0;");
}

#[test]
fn test_roundtrip_delete_partition() {
    format_and_verify("DELETE FROM t PARTITION (p0, p1) WHERE x = 1;");
}

#[test]
fn test_roundtrip_alter_add_unsigned() {
    format_and_verify("ALTER TABLE t ADD COLUMN c BIGINT UNSIGNED;");
}

#[test]
fn test_roundtrip_alter_add_unsigned_zerofill_notnull() {
    format_and_verify("ALTER TABLE t ADD COLUMN d INT UNSIGNED ZEROFILL NOT NULL;");
}

#[test]
fn test_roundtrip_alter_add_decimal_unsigned() {
    format_and_verify("ALTER TABLE t ADD COLUMN e DECIMAL(10,2) UNSIGNED;");
}

#[test]
fn test_roundtrip_alter_add_default_comment() {
    format_and_verify(
        "ALTER TABLE t ADD COLUMN f INT UNSIGNED DEFAULT 0 COMMENT 'count', \
         ADD COLUMN g VARCHAR(20) NOT NULL;",
    );
}

// ============================================================================
// 2. AST structure
// ============================================================================

#[test]
fn test_update_order_by_and_limit_typed() {
    let u = single_update("UPDATE t SET a = 1 WHERE b > 0 ORDER BY c DESC LIMIT 10;");
    assert!(u.order_by.is_some(), "ORDER BY should be typed");
    assert!(u.limit.is_some(), "LIMIT should be typed");
    assert!(u.limit_keyword_span.is_some());
}

#[test]
fn test_update_modifiers_typed() {
    let u = single_update("UPDATE LOW_PRIORITY IGNORE t SET a = 1;");
    assert!(u.low_priority_span.is_some(), "LOW_PRIORITY span missing");
    assert!(u.ignore_span.is_some(), "IGNORE span missing");
}

#[test]
fn test_update_multi_table_join_attached() {
    let u = single_update("UPDATE t1 JOIN t2 ON t1.id = t2.id SET t1.x = t2.y;");
    let target = u.target_table.as_ref().expect("target table");
    assert_eq!(target.joins.len(), 1, "join should attach to target");
    assert!(u.additional_targets.is_empty());
}

#[test]
fn test_update_multi_table_comma_targets() {
    let u = single_update("UPDATE t1, t2 SET t1.x = t2.y;");
    assert_eq!(
        u.additional_targets.len(),
        1,
        "comma form should record one additional target"
    );
}

#[test]
fn test_update_target_has_its_own_node_id_where_several_tables_are_listed() {
    for sql in [
        "UPDATE t1 JOIN t2 ON t1.id = t2.id SET t1.x = t2.y;",
        "UPDATE t1, t2 SET t1.x = t2.y;",
        "UPDATE t1, t2 JOIN t3 ON t3.id = t2.id SET t1.x = t3.y;",
    ] {
        let u = single_update(sql);
        let target = u.target_table.as_ref().expect("target table");
        let id = u
            .target_node_id
            .expect("a target id for a multi-table UPDATE");
        assert_ne!(id, target.node_id, "{sql}");
        assert_ne!(id, u.node_id, "{sql}");
        let occurrences = format!("{u:?}").matches(&format!("{id:?}")).count();
        assert_eq!(occurrences, 1, "{sql}");
    }
    for sql in [
        "UPDATE t1 SET x = 1;",
        "UPDATE t1 AS a SET a.x = 1 WHERE a.id = 2 ORDER BY a.id LIMIT 1;",
    ] {
        assert_eq!(single_update(sql).target_node_id, None, "{sql}");
    }
}

#[test]
fn test_delete_order_by_and_limit_typed() {
    let d = single_delete("DELETE FROM t WHERE b < 0 ORDER BY c LIMIT 100;");
    assert!(d.order_by.is_some());
    assert!(d.limit.is_some());
}

#[test]
fn test_delete_modifiers_typed() {
    let d = single_delete("DELETE LOW_PRIORITY QUICK IGNORE FROM t WHERE x = 1;");
    assert!(d.low_priority_span.is_some());
    assert!(d.quick_span.is_some());
    assert!(d.ignore_span.is_some());
}

#[test]
fn test_delete_multi_target_list() {
    let d = single_delete("DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.id;");
    assert_eq!(d.targets.len(), 2, "two pre-FROM targets expected");
}

#[test]
fn test_delete_star_target_list() {
    let d = single_delete("DELETE t1.* FROM t1 INNER JOIN t2 ON t1.id = t2.id;");
    assert_eq!(d.targets.len(), 1, "one `t1.*` target expected");
}

#[test]
fn test_delete_partition_typed() {
    // PARTITION selection lives on the target table ref (the carrier shared
    // with SELECT FROM), not at statement level.
    let d = single_delete("DELETE FROM t PARTITION (p0, p1) WHERE x = 1;");
    let target = d.target_table.as_ref().expect("target table present");
    let ps = target
        .partition_selection
        .as_ref()
        .expect("PARTITION selection missing on target table ref");
    assert_eq!(ps.partition_name_spans.len(), 2, "two partition names");
}

#[test]
fn test_update_partition_typed() {
    let u = single_update("UPDATE t PARTITION (p0) SET a = 1 WHERE x = 1;");
    let target = u.target_table.as_ref().expect("target table present");
    assert!(
        target.partition_selection.is_some(),
        "PARTITION selection missing on UPDATE target table ref"
    );
}

#[test]
fn test_delete_using_join_attached() {
    let d = single_delete("DELETE FROM t1 USING t1 JOIN t2 ON t1.id = t2.id;");
    assert_eq!(d.using.len(), 1, "single USING table");
    assert_eq!(
        d.using[0].joins.len(),
        1,
        "join should attach to the USING table, not shear off"
    );
}

// ============================================================================
// 3. Dialect gating (Snowflake must not absorb MySQL DML surface)
// ============================================================================

#[test]
fn test_snowflake_rejects_update_order_limit() {
    assert_snowflake_opaque("UPDATE t SET a = 1 WHERE b > 0 ORDER BY c LIMIT 10;");
}

#[test]
fn test_snowflake_rejects_delete_order_limit() {
    assert_snowflake_opaque("DELETE FROM t WHERE b < 0 ORDER BY c LIMIT 100;");
}

#[test]
fn test_snowflake_rejects_multi_table_update_comma() {
    assert_snowflake_opaque("UPDATE t1, t2 SET t1.x = t2.y WHERE t1.id = t2.id;");
}

#[test]
fn test_snowflake_rejects_multi_table_delete() {
    assert_snowflake_opaque("DELETE t1, t2 FROM t1 JOIN t2 ON t1.id = t2.id;");
}

// ============================================================================
// 4. ALTER ADD COLUMN attribute tail no longer shears
// ============================================================================

#[test]
fn test_alter_add_unsigned_not_opaque() {
    assert_single("ALTER TABLE t ADD COLUMN c BIGINT UNSIGNED;", "AlterTable");
}

#[test]
fn test_alter_add_not_null_not_opaque() {
    assert_single("ALTER TABLE t ADD COLUMN c BIGINT NOT NULL;", "AlterTable");
}

#[test]
fn test_alter_add_full_attribute_tail_not_opaque() {
    assert_single(
        "ALTER TABLE t ADD COLUMN c INT UNSIGNED ZEROFILL NOT NULL DEFAULT 0 \
         COMMENT 'c' COLLATE utf8mb4_bin;",
        "AlterTable",
    );
}

#[test]
fn a_variable_assignment_is_a_value_in_an_update_set() {
    use lexega_syntax::ast::BinaryOperator;
    use lexega_syntax::AstExpr;
    for sql in [
        "UPDATE users SET flag = @n := 1 WHERE id = 1",
        "UPDATE users SET flag = @n := @n + 1",
    ] {
        let script = parse_sql_with_dialect(sql, &*mysql()).expect("parses");
        let Some(AstStmt::Update(update)) = script.stmts.first() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let AstExpr::BinaryOp {
            operator, right, ..
        } = update.set_assignments[0].value.as_ref()
        else {
            panic!("{sql}: {:?}", update.set_assignments[0].value);
        };
        assert!(matches!(operator, BinaryOperator::Assign), "{sql}");
        assert!(sql.ends_with(&sql[right.span().start as usize..]), "{sql}");
        let formatted = format_sql_with_config(sql, &mysql_config()).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &*mysql())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
}

#[test]
fn adjacent_strings_are_one_literal_where_the_dialect_joins_them() {
    use lexega_syntax::ast::{AstLiteral, AstProjectionKind, ProjectionItemKind};
    use lexega_syntax::AstExpr;
    let first_item = |sql: &str, dialect: &str| {
        let dialect = lexega_syntax::dialect_from_name(dialect).expect("dialect");
        let script = parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
        let Some(AstStmt::Select(select)) = script.stmts.first() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("no select list");
        };
        let ProjectionItemKind::SelectItem(item) = &items[0].kind else {
            panic!("no item");
        };
        (
            item.expr.clone(),
            item.alias
                .as_ref()
                .map(|a| sql[a.ident.span.start as usize..a.ident.span.end as usize].to_string()),
        )
    };
    for (dialect, sql) in [
        ("mysql", "SELECT 'a' 'b' FROM u"),
        ("databricks", "SELECT \"a\" \"b\" AS x FROM u"),
    ] {
        let (expr, _) = first_item(sql, dialect);
        assert!(
            matches!(&expr, AstExpr::Literal { literal: AstLiteral::Adjacent { parts }, .. } if parts.len() == 2),
            "{sql}: {expr:?}"
        );
    }
    // T-SQL reads the second string as the first's alias, as MySQL reads one
    // after a typed literal.
    let (_, alias) = first_item("SELECT 'a' 'b' FROM u", "mssql");
    assert_eq!(alias.as_deref(), Some("'b'"));
    let (_, alias) = first_item("SELECT DATE '2024-01-01' 'd' FROM u", "mysql");
    assert_eq!(alias.as_deref(), Some("'d'"));
    let formatted =
        format_sql_with_config("SELECT 'a' 'b' FROM u", &mysql_config()).expect("formats");
    lexega_syntax::verify_formatting_safe_with_dialect(
        "SELECT 'a' 'b' FROM u",
        &formatted,
        &*mysql(),
    )
    .unwrap_or_else(|e| panic!("{e}\n{formatted}"));
}

#[test]
fn mysql_select_options_are_no_columns() {
    use lexega_syntax::ast::{AstProjectionKind, ProjectionItemKind};
    let text = |sql: &str, span: lexega_syntax::lexer::Span| {
        sql[span.start as usize..span.end as usize].to_string()
    };
    let items = |sql: &str| -> (Vec<String>, Vec<(String, Option<String>)>) {
        let script = parse_sql_with_dialect(sql, &*mysql()).expect("parses");
        let Some(AstStmt::Select(select)) = script.stmts.first() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("no select list");
        };
        let listed = items
            .iter()
            .map(|item| match &item.kind {
                ProjectionItemKind::SelectItem(item) => (
                    text(sql, item.expr.span()),
                    item.alias.as_ref().map(|a| text(sql, a.ident.span)),
                ),
                ProjectionItemKind::JinjaBlock(_) => panic!("{sql}"),
            })
            .collect();
        let options = select
            .select_options
            .iter()
            .map(|o| text(sql, *o))
            .collect();
        (options, listed)
    };
    // Read before: a column SQL_CALC_FOUND_ROWS aliased `id`.
    assert_eq!(
        items("SELECT SQL_CALC_FOUND_ROWS id FROM t"),
        (
            vec!["SQL_CALC_FOUND_ROWS".to_string()],
            vec![("id".to_string(), None)]
        )
    );
    assert_eq!(
        items("SELECT HIGH_PRIORITY STRAIGHT_JOIN o.id FROM o").0,
        ["HIGH_PRIORITY", "STRAIGHT_JOIN"]
    );
    // A word a FROM or a comma follows is a column.
    assert_eq!(
        items("SELECT sql_no_cache FROM t"),
        (Vec::new(), vec![("sql_no_cache".to_string(), None)])
    );
    for sql in [
        "SELECT SQL_NO_CACHE DISTINCT a FROM t",
        "SELECT DISTINCTROW a FROM t",
        "SELECT STRAIGHT_JOIN o.id, c.email FROM o STRAIGHT_JOIN c ON c.id = o.customer_id",
    ] {
        let formatted = format_sql_with_config(sql, &mysql_config()).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &*mysql())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
}

#[test]
fn mysql_do_and_values_row_are_read() {
    let script =
        parse_sql_with_dialect("DO SLEEP(0), RELEASE_LOCK('x')", &*mysql()).expect("parses");
    let [AstStmt::MysqlDo(mysql_do)] = script.stmts.as_slice() else {
        panic!("{:?}", script.stmts);
    };
    assert_eq!(mysql_do.exprs.len(), 2);
    // A DO with a body is PostgreSQL's block.
    let pg = lexega_syntax::dialect::postgres();
    let script = parse_sql_with_dialect("DO $$ BEGIN PERFORM 1; END $$;", &*pg).expect("parses");
    assert!(
        matches!(script.stmts.as_slice(), [AstStmt::DoBlock(_)]),
        "{:?}",
        script.stmts
    );

    let sql = "VALUES ROW(1, 'one'), ROW(2, 'two')";
    let script = parse_sql_with_dialect(sql, &*mysql()).expect("parses");
    let [AstStmt::ValuesQuery(values)] = script.stmts.as_slice() else {
        panic!("{:?}", script.stmts);
    };
    assert_eq!(values.values.rows.len(), 2);
    assert!(values.values.row_keywords.iter().all(Option::is_some));
    for sql in [
        sql,
        "SELECT * FROM (VALUES ROW(1, 2)) AS v (a, b)",
        "DO SLEEP(0)",
    ] {
        let formatted = format_sql_with_config(sql, &mysql_config()).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &*mysql())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
}

#[test]
fn mysql_admin_statements_keep_their_parts() {
    use lexega_syntax::ast::{AstMysqlAdminKind, AstMysqlTableOperation};
    let text = |sql: &str, span: lexega_syntax::lexer::Span| {
        sql[span.start as usize..span.end as usize].to_string()
    };
    let admin = |sql: &str| {
        let script = parse_sql_with_dialect(sql, &*mysql()).expect("parses");
        let [AstStmt::MysqlAdmin(admin)] = script.stmts.as_slice() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        admin.kind.clone()
    };

    let sql = "CHECK TABLE db1.orders, `S 1`.t QUICK";
    let AstMysqlAdminKind::TableMaintenance {
        operation: AstMysqlTableOperation::Check,
        tables,
        options_span: Some(options),
    } = admin(sql)
    else {
        panic!("{sql}");
    };
    let names: Vec<String> = tables.iter().map(|t| text(sql, *t)).collect();
    assert_eq!(names, ["db1.orders", "`S 1`.t"]);
    assert_eq!(text(sql, options), "QUICK");

    let sql = "FLUSH TABLES a, b WITH READ LOCK";
    let AstMysqlAdminKind::Flush { tables } = admin(sql) else {
        panic!("{sql}");
    };
    assert_eq!(tables.len(), 2);

    let sql = "RENAME USER 'a'@'h1' TO 'b'@'h2', c TO d";
    let AstMysqlAdminKind::RenameUser { renames } = admin(sql) else {
        panic!("{sql}");
    };
    let pairs: Vec<(String, String)> = renames
        .iter()
        .map(|r| (text(sql, r.from), text(sql, r.to)))
        .collect();
    assert_eq!(
        pairs,
        [
            ("'a'@'h1'".to_string(), "'b'@'h2'".to_string()),
            ("c".to_string(), "d".to_string())
        ]
    );

    let sql = "KILL QUERY 12345";
    let AstMysqlAdminKind::Kill { id } = admin(sql) else {
        panic!("{sql}");
    };
    assert_eq!(text(sql, id), "12345");

    let sql = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ WRITE";
    let script = parse_sql_with_dialect(sql, &*mysql()).expect("parses");
    let [AstStmt::BeginTransaction {
        characteristics, ..
    }] = script.stmts.as_slice()
    else {
        panic!("{:?}", script.stmts);
    };
    let read: Vec<String> = characteristics.iter().map(|c| text(sql, *c)).collect();
    assert_eq!(read, ["WITH CONSISTENT SNAPSHOT", "READ WRITE"]);

    let sql = "EXPLAIN FORMAT=JSON SELECT 1";
    let script = parse_sql_with_dialect(sql, &*mysql()).expect("parses");
    let [AstStmt::Explain(explain)] = script.stmts.as_slice() else {
        panic!("{:?}", script.stmts);
    };
    assert_eq!(
        explain.options_span.map(|s| text(sql, s)).as_deref(),
        Some("FORMAT=JSON")
    );

    for sql in [
        "ANALYZE TABLE orders UPDATE HISTOGRAM ON total WITH 16 BUCKETS",
        "XA START 'txn-1'",
        "ALTER INSTANCE ROTATE INNODB MASTER KEY",
    ] {
        admin(sql);
        format_and_verify(sql);
    }
}
