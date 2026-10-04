// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Virtual / generated / computed column definitions (Snowflake virtual
//! columns, MySQL/PG/Databricks GENERATED ALWAYS, MSSQL computed columns).
//!
//! Covers:
//! - Span carving: `type_span` excludes the AS clause; `virtual_expr_span`,
//!   `generated_always_span`, `storage_keyword_span` populated per shape
//! - Identity exclusion: `GENERATED ... AS IDENTITY` carves no expression
//! - Formatting (semantic preservation, all dialects, multi-statement)
//! - Tail clauses after the expression (COMMENT, WITH MASKING POLICY, WITH TAG)

use lexega_syntax::ast::{AstAlterTableActionKind, AstAlterTableColumnDef, AstCreateTableColumn};
use lexega_syntax::{
    format_sql_with_config, parse_sql, parse_sql_with_dialect, verify_formatting_safe,
    verify_formatting_safe_with_dialect, AstStmt, Dialect, FormatterConfig, MsSqlDialect,
    MySqlDialect, PostgresDialect, Span,
};

fn slice(sql: &str, span: Span) -> &str {
    &sql[span.start as usize..span.end as usize]
}

fn create_table_columns(sql: &str) -> Vec<AstCreateTableColumn> {
    let script = parse_sql(sql).expect("should parse");
    for s in &script.stmts {
        if let AstStmt::CreateTable(ct) = s {
            return ct.columns.clone();
        }
    }
    panic!("no CreateTable statement in:\n{}", sql);
}

fn create_table_columns_with_dialect(
    sql: &str,
    dialect: &dyn Dialect,
) -> Vec<AstCreateTableColumn> {
    let script = parse_sql_with_dialect(sql, dialect).expect("should parse");
    for s in &script.stmts {
        if let AstStmt::CreateTable(ct) = s {
            return ct.columns.clone();
        }
    }
    panic!("no CreateTable statement in:\n{}", sql);
}

// ---------------------------------------------------------------------------
// Snowflake: <type> AS ( expr )
// ---------------------------------------------------------------------------

#[test]
fn test_snowflake_virtual_column_spans() {
    let sql = "CREATE TABLE t (base_col NUMBER, virt_col NUMBER AS ( base_col * 2 ));";
    let cols = create_table_columns(sql);
    assert_eq!(cols.len(), 2);

    let base = &cols[0];
    assert!(base.virtual_expr_span.is_none());
    assert!(base.generated_always_span.is_none());
    assert!(base.storage_keyword_span.is_none());

    let virt = &cols[1];
    assert_eq!(slice(sql, virt.type_span.expect("type")), "NUMBER");
    assert_eq!(
        slice(sql, virt.virtual_expr_span.expect("expr")),
        "AS ( base_col * 2 )"
    );
    assert!(virt.generated_always_span.is_none());
    assert!(virt.storage_keyword_span.is_none());
}

#[test]
fn test_snowflake_virtual_column_with_comment() {
    let sql =
        "CREATE TABLE t (name VARCHAR, prefix VARCHAR(3) AS ( SUBSTR(name, 1, 3) ) COMMENT 'd');";
    let cols = create_table_columns(sql);
    let virt = &cols[1];
    assert_eq!(slice(sql, virt.type_span.expect("type")), "VARCHAR(3)");
    assert_eq!(
        slice(sql, virt.virtual_expr_span.expect("expr")),
        "AS ( SUBSTR(name, 1, 3) )"
    );
    assert_eq!(
        slice(sql, virt.comment_span.expect("comment")),
        "COMMENT 'd'"
    );
}

#[test]
fn test_snowflake_virtual_column_chained_reference() {
    let sql = "CREATE TABLE t (a NUMBER, b NUMBER AS ( a + 1 ), c NUMBER AS ( b * 2 ));";
    let cols = create_table_columns(sql);
    assert_eq!(
        slice(sql, cols[2].virtual_expr_span.expect("expr")),
        "AS ( b * 2 )"
    );
}

#[test]
fn test_snowflake_virtual_column_nested_cast_as() {
    // Inner AS (in CAST) must not confuse the carve.
    let sql = "CREATE TABLE t (a NUMBER, c VARCHAR AS ( SUBSTR(CAST(a AS VARCHAR), 1, 3) ));";
    let cols = create_table_columns(sql);
    assert_eq!(
        slice(sql, cols[1].virtual_expr_span.expect("expr")),
        "AS ( SUBSTR(CAST(a AS VARCHAR), 1, 3) )"
    );
}

#[test]
fn test_snowflake_virtual_column_formats_safely() {
    let sql = "CREATE TABLE t (\n  a NUMBER,\n  b NUMBER AS ( a * 2 ),\n  c VARCHAR AS ( SUBSTR(CAST(a AS VARCHAR), 1, 2) ) COMMENT 'x'\n);\nCREATE TABLE t2 (d NUMBER, e NUMBER AS ( d + 1 ));";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_virtual_column_with_masking_policy_and_tag() {
    let sql = "CREATE TABLE t (a NUMBER, b NUMBER AS ( a * 2 ) WITH MASKING POLICY mp.m1, c NUMBER AS ( a + 1 ) WITH TAG (gov.t1 = 'v'));";
    let cols = create_table_columns(sql);
    assert_eq!(
        slice(sql, cols[1].virtual_expr_span.expect("expr")),
        "AS ( a * 2 )"
    );
    assert_eq!(
        slice(sql, cols[1].masking_policy_span.expect("masking")),
        "WITH MASKING POLICY mp.m1"
    );
    assert_eq!(
        slice(sql, cols[2].virtual_expr_span.expect("expr")),
        "AS ( a + 1 )"
    );
    assert_eq!(
        slice(sql, cols[2].tag_span.expect("tag")),
        "WITH TAG (gov.t1 = 'v')"
    );
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ---------------------------------------------------------------------------
// MySQL: [GENERATED ALWAYS] AS ( expr ) [VIRTUAL | STORED]
// ---------------------------------------------------------------------------

#[test]
fn test_mysql_generated_column_spans() {
    let sql = "CREATE TABLE t (a INT, b INT GENERATED ALWAYS AS ( a * 2 ) VIRTUAL, c INT AS ( a - 1 ) STORED, d INT GENERATED ALWAYS AS ( a + 1 ) STORED NOT NULL);";
    let cols = create_table_columns_with_dialect(sql, &MySqlDialect);

    let b = &cols[1];
    assert_eq!(slice(sql, b.type_span.expect("type")), "INT");
    assert_eq!(
        slice(sql, b.generated_always_span.expect("gen")),
        "GENERATED ALWAYS"
    );
    assert_eq!(
        slice(sql, b.virtual_expr_span.expect("expr")),
        "AS ( a * 2 )"
    );
    assert_eq!(
        slice(sql, b.storage_keyword_span.expect("storage")),
        "VIRTUAL"
    );

    let c = &cols[2];
    assert!(c.generated_always_span.is_none());
    assert_eq!(
        slice(sql, c.virtual_expr_span.expect("expr")),
        "AS ( a - 1 )"
    );
    assert_eq!(
        slice(sql, c.storage_keyword_span.expect("storage")),
        "STORED"
    );

    let d = &cols[3];
    assert_eq!(
        slice(sql, d.storage_keyword_span.expect("storage")),
        "STORED"
    );
    assert_eq!(slice(sql, d.not_null_span.expect("not null")), "NOT NULL");
}

#[test]
fn test_mysql_generated_column_formats_safely() {
    let sql = "CREATE TABLE t (a INT, b INT GENERATED ALWAYS AS ( a * 2 ) VIRTUAL, c INT AS ( a - 1 ) STORED NOT NULL);";
    let config = FormatterConfig {
        dialect: lexega_syntax::dialect::mysql(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("should preserve semantics");
}

// ---------------------------------------------------------------------------
// PostgreSQL: GENERATED ALWAYS AS ( expr ) STORED, identity exclusion
// ---------------------------------------------------------------------------

#[test]
fn test_pg_generated_stored_column_spans() {
    let sql = "CREATE TABLE t (a INTEGER, b INTEGER GENERATED ALWAYS AS ( a * 2 ) STORED);";
    let cols = create_table_columns_with_dialect(sql, &PostgresDialect);
    let b = &cols[1];
    assert_eq!(slice(sql, b.type_span.expect("type")), "INTEGER");
    assert_eq!(
        slice(sql, b.generated_always_span.expect("gen")),
        "GENERATED ALWAYS"
    );
    assert_eq!(
        slice(sql, b.virtual_expr_span.expect("expr")),
        "AS ( a * 2 )"
    );
    assert_eq!(
        slice(sql, b.storage_keyword_span.expect("storage")),
        "STORED"
    );
}

#[test]
fn test_pg_identity_columns_carve_no_expression() {
    let sql = "CREATE TABLE t (id BIGINT GENERATED ALWAYS AS IDENTITY, id2 BIGINT GENERATED BY DEFAULT AS IDENTITY);";
    let cols = create_table_columns_with_dialect(sql, &PostgresDialect);

    let id = &cols[0];
    assert_eq!(slice(sql, id.type_span.expect("type")), "BIGINT");
    assert_eq!(
        slice(sql, id.generated_always_span.expect("gen")),
        "GENERATED ALWAYS AS"
    );
    assert!(id.virtual_expr_span.is_none());
    assert_eq!(
        slice(sql, id.identity_or_autoincrement_span.expect("identity")),
        "IDENTITY"
    );

    let id2 = &cols[1];
    assert_eq!(
        slice(sql, id2.generated_always_span.expect("gen")),
        "GENERATED BY DEFAULT AS"
    );
    assert!(id2.virtual_expr_span.is_none());
    assert!(id2.default_expr_span.is_none());
}

#[test]
fn test_pg_identity_columns_format_safely() {
    let sql = "CREATE TABLE t (id BIGINT GENERATED ALWAYS AS IDENTITY, id2 BIGINT GENERATED BY DEFAULT AS IDENTITY, b INTEGER GENERATED ALWAYS AS ( id + 1 ) STORED);";
    let config = FormatterConfig {
        dialect: lexega_syntax::dialect::postgres(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("should preserve semantics");
}

// ---------------------------------------------------------------------------
// MSSQL: name AS expr [PERSISTED] — typeless, parens optional
// ---------------------------------------------------------------------------

#[test]
fn test_mssql_computed_column_spans() {
    let sql = "CREATE TABLE t (price MONEY, qty INT, total AS price * qty, total2 AS ( price * qty ) PERSISTED, total3 AS price * qty PERSISTED NOT NULL);";
    let cols = create_table_columns_with_dialect(sql, &MsSqlDialect);

    let total = &cols[2];
    assert!(total.type_span.is_none(), "typeless computed column");
    assert_eq!(
        slice(sql, total.virtual_expr_span.expect("expr")),
        "AS price * qty"
    );
    assert!(total.storage_keyword_span.is_none());

    let total2 = &cols[3];
    assert!(total2.type_span.is_none());
    assert_eq!(
        slice(sql, total2.virtual_expr_span.expect("expr")),
        "AS ( price * qty )"
    );
    assert_eq!(
        slice(sql, total2.storage_keyword_span.expect("storage")),
        "PERSISTED"
    );

    let total3 = &cols[4];
    assert_eq!(
        slice(sql, total3.virtual_expr_span.expect("expr")),
        "AS price * qty"
    );
    assert_eq!(
        slice(sql, total3.storage_keyword_span.expect("storage")),
        "PERSISTED"
    );
    assert_eq!(
        slice(sql, total3.not_null_span.expect("not null")),
        "NOT NULL"
    );
}

#[test]
fn test_mssql_computed_column_formats_safely() {
    let sql = "CREATE TABLE t (price MONEY, qty INT, total AS price * qty, total2 AS ( price * qty ) PERSISTED NOT NULL);";
    let config = FormatterConfig {
        dialect: lexega_syntax::dialect::mssql(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("should preserve semantics");
}

// ---------------------------------------------------------------------------
// ALTER TABLE ADD [COLUMN]
// ---------------------------------------------------------------------------

fn alter_add_columns(sql: &str) -> Vec<AstAlterTableColumnDef> {
    let script = parse_sql(sql).expect("should parse");
    for s in &script.stmts {
        if let AstStmt::AlterTable(at) = s {
            for action in &at.actions {
                if let AstAlterTableActionKind::AddColumn { columns, .. } = &action.kind {
                    return columns.clone();
                }
            }
        }
    }
    panic!("no AlterTable AddColumn in:\n{}", sql);
}

#[test]
fn test_alter_add_virtual_column_spans() {
    let sql = "ALTER TABLE t ADD COLUMN v NUMBER AS ( a * 3 );";
    let cols = alter_add_columns(sql);
    assert_eq!(cols.len(), 1);
    assert_eq!(
        slice(sql, cols[0].virtual_expr_span.expect("expr")),
        "AS ( a * 3 )"
    );
    assert!(cols[0].generated_always_span.is_none());
}

#[test]
fn test_alter_add_generated_stored_column_spans() {
    let sql = "ALTER TABLE t ADD v INT GENERATED ALWAYS AS ( a + 2 ) STORED;";
    let cols = alter_add_columns(sql);
    assert_eq!(
        slice(sql, cols[0].generated_always_span.expect("gen")),
        "GENERATED ALWAYS"
    );
    assert_eq!(
        slice(sql, cols[0].virtual_expr_span.expect("expr")),
        "AS ( a + 2 )"
    );
    assert_eq!(
        slice(sql, cols[0].storage_keyword_span.expect("storage")),
        "STORED"
    );
}

#[test]
fn test_alter_add_identity_column_carves_no_expression() {
    let sql = "ALTER TABLE t ADD id BIGINT GENERATED BY DEFAULT AS IDENTITY;";
    let cols = alter_add_columns(sql);
    assert_eq!(
        slice(sql, cols[0].generated_always_span.expect("gen")),
        "GENERATED BY DEFAULT AS"
    );
    assert!(cols[0].virtual_expr_span.is_none());
}

#[test]
fn test_alter_add_mssql_computed_column_spans() {
    let sql = "ALTER TABLE t ADD total AS price * qty PERSISTED;";
    let cols = alter_add_columns(sql);
    assert!(cols[0].type_span.is_none(), "typeless computed column");
    assert_eq!(
        slice(sql, cols[0].virtual_expr_span.expect("expr")),
        "AS price * qty"
    );
    assert_eq!(
        slice(sql, cols[0].storage_keyword_span.expect("storage")),
        "PERSISTED"
    );
}

#[test]
fn test_alter_add_virtual_column_formats_safely() {
    let sql = "ALTER TABLE t ADD COLUMN v NUMBER AS ( a * 3 );\nALTER TABLE t ADD w INT GENERATED ALWAYS AS ( a + 1 ) STORED;";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

#[test]
fn test_alter_bare_add_routes_to_add_column() {
    // Bare ADD (no COLUMN keyword) with a plain column definition.
    let sql = "ALTER TABLE t ADD v2 INT NOT NULL;";
    let cols = alter_add_columns(sql);
    assert_eq!(cols.len(), 1);
    assert_eq!(slice(sql, cols[0].name_span.expect("name")), "v2");
    assert_eq!(slice(sql, cols[0].type_span.expect("type")), "INT ");
}

fn alter_has_add_column_action(sql: &str) -> bool {
    let script = parse_sql(sql).expect("should parse");
    for s in &script.stmts {
        if let AstStmt::AlterTable(at) = s {
            return at
                .actions
                .iter()
                .any(|a| matches!(a.kind, AstAlterTableActionKind::AddColumn { .. }));
        }
    }
    panic!("no AlterTable in:\n{}", sql);
}

#[test]
fn test_alter_non_column_add_starters_stay_unrouted() {
    // Anonymous constraints / indexes / old-style defaults must NOT
    // classify as AddColumn.
    for sql in [
        "ALTER TABLE t ADD PRIMARY KEY (a);",
        "ALTER TABLE t ADD UNIQUE (a);",
        "ALTER TABLE t ADD FOREIGN KEY (a) REFERENCES o (b);",
        "ALTER TABLE t ADD CHECK (a > 0);",
        "ALTER TABLE t ADD INDEX idx (a);",
        "ALTER TABLE t ADD DEFAULT 0 FOR a;",
    ] {
        assert!(
            !alter_has_add_column_action(sql),
            "{} misrouted to AddColumn",
            sql
        );
    }
}

#[test]
fn test_alter_bare_add_formats_safely() {
    let sql = "ALTER TABLE t ADD v INT GENERATED ALWAYS AS ( a + 2 ) STORED;\nALTER TABLE t ADD total AS price * qty PERSISTED;\nALTER TABLE t ADD PRIMARY KEY (a);";
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_plain_columns_have_no_generated_spans() {
    let sql =
        "CREATE TABLE t (a NUMBER DEFAULT 1 NOT NULL, b VARCHAR COLLATE 'en-ci' COMMENT 'x');";
    let cols = create_table_columns(sql);
    for col in &cols {
        assert!(col.generated_always_span.is_none());
        assert!(col.virtual_expr_span.is_none());
        assert!(col.storage_keyword_span.is_none());
    }
    assert_eq!(
        slice(sql, cols[0].default_expr_span.expect("default")),
        "DEFAULT 1"
    );
}

#[test]
fn test_ctas_unaffected_by_virtual_column_carve() {
    let sql = "CREATE TABLE t (a, b) AS SELECT x, y FROM src;";
    let script = parse_sql(sql).expect("should parse");
    let ct = script
        .stmts
        .iter()
        .find_map(|s| {
            if let AstStmt::CreateTable(ct) = s {
                Some(ct)
            } else {
                None
            }
        })
        .expect("CreateTable");
    for col in &ct.columns {
        assert!(col.virtual_expr_span.is_none());
    }
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
