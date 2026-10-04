// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL INSERT-family parser coverage.
//!
//! Covers:
//!   1. Format round-trip safety for every INSERT/REPLACE variant
//!   2. AST structure: ODKU, SET form, modifiers, PARTITION, VALUE synonym,
//!      VALUES ROW(...), row alias, optional INTO, REPLACE INTO
//!   3. Dialect gating: MySQL-only surface stays rejected under Snowflake
//!   4. Analysis pipeline smoke (parse → lower → facts) for the new shapes

use lexega_core::ast::{AstInsertPriority, AstInsertSourceKind, AstStmt};
use lexega_core::dialect::{mysql, snowflake};
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

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
    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("MySQL formatting verification failed: {}", e));
}

fn parse_mysql(sql: &str) -> lexega_core::ast::AstScript {
    parse_sql_with_dialect(sql, mysql().as_ref())
        .unwrap_or_else(|e| panic!("MySQL parse failed for {:?}: {:?}", sql, e))
}

fn single_stmt(sql: &str) -> AstStmt {
    let mut script = parse_mysql(sql);
    assert_eq!(
        script.stmts.len(),
        1,
        "expected one statement for {:?}",
        sql
    );
    script.stmts.remove(0)
}

fn mysql_analysis_config() -> lexega_core::analyzer::AnalysisConfig {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mysql());
    config
}

// ============================================================================
// 1. Format round-trip safety
// ============================================================================

#[test]
fn test_mysql_insert_on_duplicate_key_update_roundtrip() {
    format_and_verify("INSERT INTO t (a, b) VALUES (1, 2) ON DUPLICATE KEY UPDATE b = VALUES(b);");
}

#[test]
fn test_mysql_insert_odku_row_alias_roundtrip() {
    format_and_verify(
        "INSERT INTO t (a, b) VALUES (1, 2) AS new_row ON DUPLICATE KEY UPDATE b = new_row.b;",
    );
    format_and_verify(
        "INSERT INTO t (a, b) VALUES (1, 2) AS new_row (x, y) ON DUPLICATE KEY UPDATE b = y;",
    );
}

#[test]
fn test_mysql_insert_set_form_roundtrip() {
    format_and_verify("INSERT INTO t SET a = 1, b = 2;");
    format_and_verify("INSERT INTO t SET a = 1 ON DUPLICATE KEY UPDATE b = b + 1;");
}

#[test]
fn test_mysql_insert_modifiers_roundtrip() {
    format_and_verify("INSERT LOW_PRIORITY INTO t (a) VALUES (1);");
    format_and_verify("INSERT HIGH_PRIORITY INTO t (a) VALUES (1);");
    format_and_verify("INSERT IGNORE INTO t (a) VALUES (1);");
    format_and_verify("INSERT LOW_PRIORITY IGNORE INTO t (a) VALUES (1);");
}

#[test]
fn test_mysql_insert_partition_roundtrip() {
    format_and_verify("INSERT INTO t PARTITION (p0, p1) (a) VALUES (1);");
}

#[test]
fn test_mysql_insert_value_synonym_roundtrip() {
    format_and_verify("INSERT INTO t VALUE (1, 2);");
}

#[test]
fn test_mysql_insert_values_row_roundtrip() {
    format_and_verify("INSERT INTO t VALUES ROW(1, 2), ROW(3, 4);");
}

#[test]
fn test_mysql_insert_optional_into_roundtrip() {
    format_and_verify("INSERT t (a) VALUES (1);");
}

#[test]
fn test_mysql_insert_select_odku_roundtrip() {
    format_and_verify("INSERT INTO t (a) SELECT x FROM s ON DUPLICATE KEY UPDATE b = t.b;");
}

#[test]
fn test_mysql_replace_roundtrip() {
    format_and_verify("REPLACE INTO t (a, b) VALUES (1, 2);");
    format_and_verify("REPLACE t SET a = 1;");
    format_and_verify("REPLACE LOW_PRIORITY INTO t (a) VALUES (1);");
    format_and_verify("REPLACE INTO t PARTITION (p0) (a) VALUES (1);");
    format_and_verify("REPLACE INTO t SELECT * FROM s;");
}

#[test]
fn test_mysql_insert_quoted_idents_odku_roundtrip() {
    format_and_verify(
        "INSERT INTO `my table` (`select`, `group`) VALUES (1, 2) ON DUPLICATE KEY UPDATE `group` = 3;",
    );
}

#[test]
fn test_mysql_insert_multi_statement_roundtrip() {
    format_and_verify(
        "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = a + 1;\n\
         REPLACE INTO t (a) VALUES (2);\n\
         INSERT IGNORE INTO t SET a = 3;",
    );
}

// ============================================================================
// 2. AST structure
// ============================================================================

#[test]
fn test_mysql_odku_ast() {
    let sql = "INSERT INTO t (a, b) VALUES (1, 2) ON DUPLICATE KEY UPDATE b = VALUES(b);";
    match single_stmt(sql) {
        AstStmt::Insert(ins) => {
            let odku = ins
                .on_duplicate_key_update
                .as_ref()
                .expect("ODKU clause should be parsed");
            assert_eq!(odku.assignments.len(), 1);
            assert_eq!(odku.assignments[0].0, "b");
            // Statement span must cover the full clause (no splitter shear).
            assert_eq!(ins.span.end as usize, sql.len() - 1); // excludes ';'
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_insert_set_form_ast() {
    match single_stmt("INSERT INTO t SET a = 1, b = 2;") {
        AstStmt::Insert(ins) => {
            assert!(matches!(
                ins.source_kind,
                AstInsertSourceKind::SetAssignments
            ));
            assert_eq!(ins.set_assignments.len(), 2);
            assert_eq!(ins.set_assignments[0].0, "a");
            assert_eq!(ins.set_assignments[1].0, "b");
            assert!(ins.set_clause_span.is_some());
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_insert_modifiers_ast() {
    match single_stmt("INSERT LOW_PRIORITY IGNORE INTO t (a) VALUES (1);") {
        AstStmt::Insert(ins) => {
            assert!(matches!(ins.priority, Some(AstInsertPriority::Low { .. })));
            assert!(ins.ignore_span.is_some());
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_insert_partition_ast() {
    match single_stmt("INSERT INTO t PARTITION (p0, p1) (a) VALUES (1);") {
        AstStmt::Insert(ins) => {
            assert!(ins.partition_span.is_some());
            // Column list must be (a), not the partition list.
            let cols = ins.columns_span.expect("column list");
            assert_eq!(cols.end - cols.start, 3); // "(a)"
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_insert_value_synonym_ast() {
    match single_stmt("INSERT INTO t VALUE (1, 2);") {
        AstStmt::Insert(ins) => {
            assert!(matches!(ins.source_kind, AstInsertSourceKind::Values));
            assert_eq!(ins.values_rows.len(), 1);
            assert_eq!(ins.values_rows[0].len(), 2);
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_insert_values_row_ast() {
    match single_stmt("INSERT INTO t VALUES ROW(1, 2), ROW(3, 4);") {
        AstStmt::Insert(ins) => {
            assert!(ins.values_row_constructor);
            assert_eq!(ins.values_rows.len(), 2);
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_insert_row_alias_ast() {
    match single_stmt(
        "INSERT INTO t (a, b) VALUES (1, 2) AS new_row (x, y) ON DUPLICATE KEY UPDATE b = y;",
    ) {
        AstStmt::Insert(ins) => {
            assert!(ins.row_alias_span.is_some());
            assert!(ins.on_duplicate_key_update.is_some());
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_insert_optional_into_ast() {
    match single_stmt("INSERT t (a) VALUES (1);") {
        AstStmt::Insert(ins) => {
            assert!(ins.into_span.is_none());
            assert!(ins.target_table_span.is_some());
        }
        other => panic!("expected Insert, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_replace_values_ast() {
    match single_stmt("REPLACE INTO t (a, b) VALUES (1, 2);") {
        AstStmt::ReplaceInto(rep) => {
            assert!(rep.into_span.is_some());
            assert!(rep.target_table_span.is_some());
            assert!(matches!(rep.source_kind, AstInsertSourceKind::Values));
            assert_eq!(rep.values_rows.len(), 1);
        }
        other => panic!("expected ReplaceInto, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_replace_set_form_ast() {
    match single_stmt("REPLACE t SET a = 1;") {
        AstStmt::ReplaceInto(rep) => {
            assert!(rep.into_span.is_none());
            assert!(matches!(
                rep.source_kind,
                AstInsertSourceKind::SetAssignments
            ));
            assert_eq!(rep.set_assignments.len(), 1);
        }
        other => panic!("expected ReplaceInto, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_replace_low_priority_ast() {
    match single_stmt("REPLACE LOW_PRIORITY INTO t (a) VALUES (1);") {
        AstStmt::ReplaceInto(rep) => {
            assert!(matches!(rep.priority, Some(AstInsertPriority::Low { .. })));
        }
        other => panic!("expected ReplaceInto, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_replace_select_ast() {
    match single_stmt("REPLACE INTO t SELECT * FROM s;") {
        AstStmt::ReplaceInto(rep) => {
            assert!(matches!(rep.source_kind, AstInsertSourceKind::Query));
            assert!(rep.query.is_some());
        }
        other => panic!("expected ReplaceInto, got {:?}", stmt_name(&other)),
    }
}

#[test]
fn test_mysql_multi_statement_all_typed() {
    let script = parse_mysql(
        "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = a + 1;\n\
         REPLACE INTO t (a) VALUES (2);\n\
         INSERT IGNORE INTO t SET a = 3;",
    );
    assert_eq!(script.stmts.len(), 3);
    assert!(matches!(script.stmts[0], AstStmt::Insert(_)));
    assert!(matches!(script.stmts[1], AstStmt::ReplaceInto(_)));
    assert!(matches!(script.stmts[2], AstStmt::Insert(_)));
}

// ============================================================================
// 3. Dialect gating (Snowflake must NOT accept MySQL-only surface)
// ============================================================================

/// The permissive parser degrades rejected statements to OpaqueContent
/// rather than failing the whole script — assert on the variant.
fn assert_snowflake_opaque(sql: &str) {
    let script = parse_sql_with_dialect(sql, snowflake().as_ref())
        .unwrap_or_else(|e| panic!("script-level parse should not hard-fail: {:?}", e));
    assert_eq!(script.stmts.len(), 1);
    assert!(
        matches!(script.stmts[0], AstStmt::OpaqueContent { .. }),
        "Snowflake should degrade {:?} to OpaqueContent, got {}",
        sql,
        stmt_name(&script.stmts[0])
    );
}

#[test]
fn test_snowflake_rejects_insert_set_form() {
    assert_snowflake_opaque("INSERT INTO t SET a = 1;");
}

#[test]
fn test_snowflake_rejects_insert_modifiers() {
    assert_snowflake_opaque("INSERT IGNORE INTO t (a) VALUES (1);");
}

#[test]
fn test_snowflake_rejects_optional_into() {
    assert_snowflake_opaque("INSERT t (a) VALUES (1);");
}

#[test]
fn test_snowflake_rejects_value_synonym() {
    assert_snowflake_opaque("INSERT INTO t VALUE (1);");
}

// ============================================================================
// 4. Analysis pipeline smoke (parse → lower → facts)
// ============================================================================

#[test]
fn test_mysql_insert_family_analysis_smoke() {
    let sql = "INSERT INTO t (a, b) VALUES (1, 2) ON DUPLICATE KEY UPDATE b = VALUES(b);\n\
               REPLACE INTO t (a) VALUES (1);\n\
               INSERT INTO t SET a = 1, b = 2;\n\
               INSERT LOW_PRIORITY IGNORE INTO t PARTITION (p0) (a) VALUES (1);";
    // The pipeline (parse → lower → facts → rules) must not error on any
    // of these shapes.
    let _report = lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
        .expect("analysis should succeed on MySQL INSERT family");
}

// ============================================================================
// Helpers
// ============================================================================

/// Variant name from Debug output — avoids a `_ =>` arm on `AstStmt`.
fn stmt_name(stmt: &AstStmt) -> String {
    let dbg = format!("{:?}", stmt);
    dbg.split(|c: char| c == '(' || c == '{' || c.is_whitespace())
        .next()
        .unwrap_or("Unknown")
        .to_string()
}
