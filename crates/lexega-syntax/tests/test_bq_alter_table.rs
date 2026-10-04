// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for BigQuery-specific ALTER TABLE statement variants.
///
/// Covers: SET OPTIONS, DROP PRIMARY KEY, SET DEFAULT COLLATE,
/// ALTER COLUMN SET OPTIONS, ALTER COLUMN DROP NOT NULL,
/// ALTER COLUMN SET DATA TYPE, ALTER COLUMN SET DEFAULT,
/// ALTER COLUMN DROP DEFAULT.
use lexega_syntax::ast::{AstAlterTableActionKind, AstStmt};
use lexega_syntax::{format_sql, parse_stmt_from_str, verify_formatting_safe};

fn fmt(sql: &str) -> String {
    format_sql(sql).unwrap_or_else(|e| panic!("format_sql failed: {e}\nInput: {sql}"))
}

fn roundtrip(sql: &str) {
    let formatted = fmt(sql);
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("verify failed: {e}\nInput: {sql}\nFormatted: {formatted}"));
}

fn parse_alter_action(sql: &str) -> AstAlterTableActionKind {
    let stmt = parse_stmt_from_str(sql).expect("Should parse");
    match stmt {
        AstStmt::AlterTable(alter) => {
            assert!(!alter.actions.is_empty(), "Should have at least one action");
            alter.actions.into_iter().next().unwrap().kind
        }
        other => panic!(
            "Expected AlterTable, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// SET OPTIONS (table-level)
// ============================================================================

#[test]
fn test_bq_set_options_basic() {
    roundtrip("ALTER TABLE mydataset.mytable SET OPTIONS (description='test');");
}

#[test]
fn test_bq_set_options_multiple() {
    roundtrip(
        "ALTER TABLE mydataset.mytable SET OPTIONS (description='My table', expiration_timestamp=TIMESTAMP '2025-01-01 00:00:00 UTC');",
    );
}

#[test]
fn test_bq_set_options_parsed() {
    let kind =
        parse_alter_action("ALTER TABLE mydataset.mytable SET OPTIONS (description='test');");
    match kind {
        AstAlterTableActionKind::SetOptions {
            set_span,
            options_span,
            ..
        } => {
            assert!(set_span.is_some(), "Should have SET span");
            assert!(options_span.is_some(), "Should have OPTIONS span");
        }
        other => panic!(
            "Expected SetOptions, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// DROP PRIMARY KEY
// ============================================================================

#[test]
fn test_bq_drop_primary_key() {
    roundtrip("ALTER TABLE myTable DROP PRIMARY KEY;");
}

#[test]
fn test_bq_drop_primary_key_if_exists() {
    roundtrip("ALTER TABLE myTable DROP PRIMARY KEY IF EXISTS;");
}

#[test]
fn test_bq_drop_primary_key_parsed() {
    let kind = parse_alter_action("ALTER TABLE myTable DROP PRIMARY KEY;");
    match kind {
        AstAlterTableActionKind::DropPrimaryKey {
            drop_span,
            primary_span,
            key_span,
            if_exists_span,
        } => {
            assert!(drop_span.is_some());
            assert!(primary_span.is_some());
            assert!(key_span.is_some());
            assert!(if_exists_span.is_none(), "No IF EXISTS in basic form");
        }
        other => panic!(
            "Expected DropPrimaryKey, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

#[test]
fn test_bq_drop_primary_key_if_exists_parsed() {
    let kind = parse_alter_action("ALTER TABLE myTable DROP PRIMARY KEY IF EXISTS;");
    match kind {
        AstAlterTableActionKind::DropPrimaryKey { if_exists_span, .. } => {
            assert!(if_exists_span.is_some(), "Should have IF EXISTS span");
        }
        other => panic!(
            "Expected DropPrimaryKey, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// SET DEFAULT COLLATE
// ============================================================================

#[test]
fn test_bq_set_default_collate() {
    roundtrip("ALTER TABLE mydataset.mytable SET DEFAULT COLLATE 'und:ci';");
}

#[test]
fn test_bq_set_default_collate_parsed() {
    let kind = parse_alter_action("ALTER TABLE mydataset.mytable SET DEFAULT COLLATE 'und:ci';");
    match kind {
        AstAlterTableActionKind::SetDefaultCollate {
            set_span,
            default_span,
            collate_span,
            ..
        } => {
            assert!(set_span.is_some());
            assert!(default_span.is_some());
            assert!(collate_span.is_some());
        }
        other => panic!(
            "Expected SetDefaultCollate, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// ALTER COLUMN SET OPTIONS
// ============================================================================

#[test]
fn test_bq_alter_column_set_options() {
    roundtrip(
        "ALTER TABLE mydataset.mytable ALTER COLUMN price SET OPTIONS (description = 'Price per unit');",
    );
}

#[test]
fn test_bq_alter_column_set_options_parsed() {
    let kind = parse_alter_action(
        "ALTER TABLE mydataset.mytable ALTER COLUMN price SET OPTIONS (description = 'Price per unit');",
    );
    match kind {
        AstAlterTableActionKind::AlterColumnSetOptions {
            alter_span,
            column_span,
            set_span,
            options_span,
            ..
        } => {
            assert!(alter_span.is_some());
            assert!(column_span.is_some());
            assert!(set_span.is_some());
            assert!(options_span.is_some());
        }
        other => panic!(
            "Expected AlterColumnSetOptions, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// ALTER COLUMN DROP NOT NULL
// ============================================================================

#[test]
fn test_bq_alter_column_drop_not_null() {
    roundtrip("ALTER TABLE mydataset.mytable ALTER COLUMN mycolumn DROP NOT NULL;");
}

#[test]
fn test_bq_alter_column_drop_not_null_parsed() {
    let kind =
        parse_alter_action("ALTER TABLE mydataset.mytable ALTER COLUMN mycolumn DROP NOT NULL;");
    match kind {
        AstAlterTableActionKind::AlterColumnDropNotNull {
            alter_span,
            column_span,
            drop_span,
            not_span,
            null_span,
            ..
        } => {
            assert!(alter_span.is_some());
            assert!(column_span.is_some());
            assert!(drop_span.is_some());
            assert!(not_span.is_some());
            assert!(null_span.is_some());
        }
        other => panic!(
            "Expected AlterColumnDropNotNull, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// ALTER COLUMN SET DATA TYPE
// ============================================================================

#[test]
fn test_bq_alter_column_set_data_type_simple() {
    roundtrip("ALTER TABLE dataset.my_table ALTER COLUMN c1 SET DATA TYPE NUMERIC;");
}

#[test]
fn test_bq_alter_column_set_data_type_string() {
    roundtrip("ALTER TABLE dataset.my_table ALTER COLUMN c1 SET DATA TYPE STRING;");
}

#[test]
fn test_bq_alter_column_set_data_type_parsed() {
    let kind =
        parse_alter_action("ALTER TABLE dataset.my_table ALTER COLUMN c1 SET DATA TYPE NUMERIC;");
    match kind {
        AstAlterTableActionKind::AlterColumnSetDataType {
            alter_span,
            column_span,
            set_span,
            data_span,
            type_span,
            ..
        } => {
            assert!(alter_span.is_some());
            assert!(column_span.is_some());
            assert!(set_span.is_some());
            assert!(data_span.is_some());
            assert!(type_span.is_some());
        }
        other => panic!(
            "Expected AlterColumnSetDataType, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// ALTER COLUMN SET DEFAULT
// ============================================================================

#[test]
fn test_bq_alter_column_set_default_function() {
    roundtrip(
        "ALTER TABLE mydataset.mytable ALTER COLUMN mycolumn SET DEFAULT CURRENT_TIMESTAMP();",
    );
}

#[test]
fn test_bq_alter_column_set_default_literal() {
    roundtrip("ALTER TABLE mydataset.mytable ALTER COLUMN mycolumn SET DEFAULT 0;");
}

#[test]
fn test_bq_alter_column_set_default_parsed() {
    let kind =
        parse_alter_action("ALTER TABLE mydataset.mytable ALTER COLUMN mycolumn SET DEFAULT 42;");
    match kind {
        AstAlterTableActionKind::AlterColumnSetDefault {
            alter_span,
            column_span,
            set_span,
            default_span,
            ..
        } => {
            assert!(alter_span.is_some());
            assert!(column_span.is_some());
            assert!(set_span.is_some());
            assert!(default_span.is_some());
        }
        other => panic!(
            "Expected AlterColumnSetDefault, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// ALTER COLUMN DROP DEFAULT
// ============================================================================

#[test]
fn test_bq_alter_column_drop_default() {
    roundtrip("ALTER TABLE mydataset.mytable ALTER COLUMN mycolumn DROP DEFAULT;");
}

#[test]
fn test_bq_alter_column_drop_default_parsed() {
    let kind =
        parse_alter_action("ALTER TABLE mydataset.mytable ALTER COLUMN mycolumn DROP DEFAULT;");
    match kind {
        AstAlterTableActionKind::AlterColumnDropDefault {
            alter_span,
            column_span,
            drop_span,
            default_span,
            ..
        } => {
            assert!(alter_span.is_some());
            assert!(column_span.is_some());
            assert!(drop_span.is_some());
            assert!(default_span.is_some());
        }
        other => panic!(
            "Expected AlterColumnDropDefault, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ============================================================================
// Qualified names (dataset.table)
// ============================================================================

#[test]
fn test_bq_alter_table_qualified_name_3part() {
    roundtrip("ALTER TABLE project.dataset.mytable SET OPTIONS (description='test');");
}

#[test]
fn test_bq_alter_table_backtick_name() {
    // Backtick identifiers require BQ dialect lexer, but the parser is permissive
    roundtrip("ALTER TABLE `project.dataset.mytable` SET OPTIONS (description='test');");
}

// ============================================================================
// Multi-statement tests (verify no NodeId collision)
// ============================================================================

#[test]
fn test_bq_alter_table_multi_statement() {
    let sql = r#"
ALTER TABLE t1 SET OPTIONS (description='first');
ALTER TABLE t2 DROP PRIMARY KEY;
ALTER TABLE t3 SET DEFAULT COLLATE 'und:ci';
ALTER TABLE t4 ALTER COLUMN c1 SET OPTIONS (description='col');
ALTER TABLE t5 ALTER COLUMN c1 DROP NOT NULL;
ALTER TABLE t6 ALTER COLUMN c1 SET DATA TYPE NUMERIC;
ALTER TABLE t7 ALTER COLUMN c1 SET DEFAULT 0;
ALTER TABLE t8 ALTER COLUMN c1 DROP DEFAULT;
"#;
    let formatted = fmt(sql);
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("Multi-stmt verify failed: {e}"));
}

// ============================================================================
// Non-interference: Snowflake ALTER TABLE still works
// ============================================================================

#[test]
fn test_snowflake_alter_table_still_works() {
    roundtrip("ALTER TABLE users ADD COLUMN age INT;");
    roundtrip("ALTER TABLE users DROP COLUMN age;");
    roundtrip("ALTER TABLE users RENAME TO users_v2;");
    roundtrip("ALTER TABLE users RENAME COLUMN old_name TO new_name;");
    roundtrip("ALTER TABLE users SET TAG env = 'prod';");
    roundtrip("ALTER TABLE users CLUSTER BY (id, name);");
}
