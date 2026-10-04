// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL ALTER INDEX and REINDEX statements.
//!
//! Each construct is tested for:
//!   1. Correct AST variant (not OpaqueContent)
//!   2. Format round-trip with semantic safety verification
//!   3. Multiple syntax variants
//!
//! Token gotchas verified via --debug-tokens:
//!   INDEX, REINDEX, TABLESPACE, ATTACH, DEPENDS, RESET, OWNED, NOWAIT,
//!   STATISTICS, SCHEMA, DATABASE, SYSTEM, CONCURRENTLY, VERBOSE, NO,
//!   EXTENSION → all Identifier (NOT Keywords!)
//!   TABLE → Keyword(Table)
//!   ALL → Keyword(All)

use lexega_syntax::{
    format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt, FormatterConfig,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

fn parses_as(sql: &str, check: fn(&AstStmt) -> bool) -> bool {
    let script = parse_sql(sql).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script.stmts.iter().any(|s| check(s))
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX — RENAME TO
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_rename_to() {
    let sql = "ALTER INDEX my_idx RENAME TO new_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_rename_to_schema_qualified() {
    let sql = "ALTER INDEX myschema.my_idx RENAME TO new_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_if_exists_rename_to() {
    let sql = "ALTER INDEX IF EXISTS my_idx RENAME TO new_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX — SET TABLESPACE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_set_tablespace() {
    let sql = "ALTER INDEX my_idx SET TABLESPACE fast_ssd";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_if_exists_set_tablespace() {
    let sql = "ALTER INDEX IF EXISTS my_idx SET TABLESPACE fast_ssd";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX — ATTACH PARTITION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_attach_partition() {
    let sql = "ALTER INDEX idx_parent ATTACH PARTITION idx_child";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_attach_partition_schema_qualified() {
    let sql = "ALTER INDEX myschema.idx_parent ATTACH PARTITION myschema.idx_child";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX — [NO] DEPENDS ON EXTENSION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_depends_on_extension() {
    let sql = "ALTER INDEX my_idx DEPENDS ON EXTENSION btree_gist";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_no_depends_on_extension() {
    let sql = "ALTER INDEX my_idx NO DEPENDS ON EXTENSION btree_gist";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_if_exists_depends_on_extension() {
    let sql = "ALTER INDEX IF EXISTS my_idx DEPENDS ON EXTENSION btree_gist";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX — SET ( params )
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_set_single_param() {
    let sql = "ALTER INDEX my_idx SET (fillfactor = 75)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_set_multiple_params() {
    let sql = "ALTER INDEX my_idx SET (fillfactor = 75, deduplicate_items = on)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX — RESET ( params )
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_reset_single_param() {
    let sql = "ALTER INDEX my_idx RESET (fillfactor)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_reset_multiple_params() {
    let sql = "ALTER INDEX my_idx RESET (fillfactor, deduplicate_items)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX — ALTER [ COLUMN ] column_number SET STATISTICS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_alter_column_set_statistics() {
    let sql = "ALTER INDEX my_idx ALTER COLUMN 3 SET STATISTICS 1000";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_alter_column_set_statistics_no_column_keyword() {
    let sql = "ALTER INDEX my_idx ALTER 1 SET STATISTICS 500";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALTER INDEX ALL IN TABLESPACE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_all_in_tablespace_basic() {
    let sql = "ALTER INDEX ALL IN TABLESPACE old_ts SET TABLESPACE new_ts";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_all_in_tablespace_nowait() {
    let sql = "ALTER INDEX ALL IN TABLESPACE old_ts SET TABLESPACE new_ts NOWAIT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_all_in_tablespace_owned_by_single_role() {
    let sql = "ALTER INDEX ALL IN TABLESPACE old_ts OWNED BY admin SET TABLESPACE new_ts";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_all_in_tablespace_owned_by_multiple_roles() {
    let sql =
        "ALTER INDEX ALL IN TABLESPACE old_ts OWNED BY role1, role2, role3 SET TABLESPACE new_ts";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_all_in_tablespace_owned_by_nowait() {
    let sql = "ALTER INDEX ALL IN TABLESPACE old_ts OWNED BY admin SET TABLESPACE new_ts NOWAIT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// REINDEX — INDEX
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reindex_index_basic() {
    let sql = "REINDEX INDEX my_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_index_schema_qualified() {
    let sql = "REINDEX INDEX myschema.my_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_index_concurrently() {
    let sql = "REINDEX INDEX CONCURRENTLY my_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// REINDEX — TABLE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reindex_table_basic() {
    let sql = "REINDEX TABLE my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_table_schema_qualified() {
    let sql = "REINDEX TABLE myschema.my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_table_concurrently() {
    let sql = "REINDEX TABLE CONCURRENTLY my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// REINDEX — SCHEMA
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reindex_schema_basic() {
    let sql = "REINDEX SCHEMA my_schema";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_schema_concurrently() {
    let sql = "REINDEX SCHEMA CONCURRENTLY my_schema";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// REINDEX — DATABASE (name optional)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reindex_database_with_name() {
    let sql = "REINDEX DATABASE my_db";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_database_no_name() {
    let sql = "REINDEX DATABASE";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_database_concurrently_with_name() {
    let sql = "REINDEX DATABASE CONCURRENTLY my_db";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_database_concurrently_no_name() {
    let sql = "REINDEX DATABASE CONCURRENTLY";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// REINDEX — SYSTEM (name optional)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reindex_system_with_name() {
    let sql = "REINDEX SYSTEM my_db";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_system_no_name() {
    let sql = "REINDEX SYSTEM";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// REINDEX — with parenthesized options
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reindex_with_verbose_option() {
    let sql = "REINDEX (VERBOSE) TABLE my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_verbose_true() {
    let sql = "REINDEX (VERBOSE true) TABLE my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_verbose_false() {
    let sql = "REINDEX (VERBOSE false) TABLE my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_concurrently_option() {
    let sql = "REINDEX (CONCURRENTLY) INDEX my_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_concurrently_true() {
    let sql = "REINDEX (CONCURRENTLY true) INDEX my_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_tablespace_option() {
    let sql = "REINDEX (TABLESPACE new_ts) TABLE my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_multiple_options() {
    let sql = "REINDEX (VERBOSE, CONCURRENTLY true) TABLE my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_all_options() {
    let sql = "REINDEX (VERBOSE true, TABLESPACE new_ts, CONCURRENTLY false) INDEX my_idx";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_options_and_concurrently_keyword() {
    let sql = "REINDEX (VERBOSE) TABLE CONCURRENTLY myschema.my_table";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_alter_index_statements() {
    let sql = "\
ALTER INDEX idx1 RENAME TO idx1_new;
ALTER INDEX idx2 SET TABLESPACE fast_ssd;
ALTER INDEX idx3 SET (fillfactor = 70)";
    let script = parse_sql(sql).expect("should parse");
    let alter_count = script
        .stmts
        .iter()
        .filter(|s| matches!(s, AstStmt::AlterIndex(_)))
        .count();
    assert_eq!(alter_count, 3, "All three ALTER INDEX stmts should parse");
    format_and_verify(sql);
}

#[test]
fn test_multi_reindex_statements() {
    let sql = "\
REINDEX INDEX my_idx;
REINDEX TABLE my_table;
REINDEX SCHEMA my_schema";
    let script = parse_sql(sql).expect("should parse");
    let reindex_count = script
        .stmts
        .iter()
        .filter(|s| matches!(s, AstStmt::Reindex(_)))
        .count();
    assert_eq!(reindex_count, 3, "All three REINDEX stmts should parse");
    format_and_verify(sql);
}

#[test]
fn test_mixed_alter_index_and_reindex() {
    let sql = "\
ALTER INDEX my_idx SET (fillfactor = 80);
REINDEX INDEX my_idx;
ALTER INDEX IF EXISTS other_idx RENAME TO renamed_idx;
REINDEX TABLE CONCURRENTLY my_table";
    let script = parse_sql(sql).expect("should parse");
    let alter_count = script
        .stmts
        .iter()
        .filter(|s| matches!(s, AstStmt::AlterIndex(_)))
        .count();
    let reindex_count = script
        .stmts
        .iter()
        .filter(|s| matches!(s, AstStmt::Reindex(_)))
        .count();
    assert_eq!(alter_count, 2);
    assert_eq!(reindex_count, 2);
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Quoted identifiers
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_quoted_name() {
    let sql = r#"ALTER INDEX "MyIndex" RENAME TO "NewIndex""#;
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_quoted_name() {
    let sql = r#"REINDEX INDEX "MySchema"."MyIndex""#;
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Semicolons
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_with_semicolon() {
    let sql = "ALTER INDEX my_idx RENAME TO new_idx;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_with_semicolon() {
    let sql = "REINDEX TABLE my_table;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alter_index_reset_if_exists() {
    let sql = "ALTER INDEX IF EXISTS my_idx RESET (fillfactor)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_set_params_if_exists() {
    let sql = "ALTER INDEX IF EXISTS my_idx SET (fillfactor = 90)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_alter_index_attach_partition_if_exists() {
    let sql = "ALTER INDEX IF EXISTS idx_parent ATTACH PARTITION idx_child";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::AlterIndex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_database_system_no_name_with_semicolon() {
    let sql = "REINDEX DATABASE;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}

#[test]
fn test_reindex_system_concurrently_no_name() {
    let sql = "REINDEX SYSTEM CONCURRENTLY";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::Reindex(_))));
    format_and_verify(sql);
}
