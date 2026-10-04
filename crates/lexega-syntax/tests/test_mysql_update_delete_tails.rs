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
    let mut config = FormatterConfig::default();
    config.dialect = mysql();
    config
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
