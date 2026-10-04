// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe, AstStmt,
    BigQueryDialect, DatabricksDialect, Dialect, FormatterConfig, MsSqlDialect, PostgresDialect,
    SnowflakeDialect,
};

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::databricks(),
        ..Default::default()
    }
}

fn mssql_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_syntax::dialect::mssql(),
        ..Default::default()
    }
}

fn assert_no_opaque_dbx(sql: &str) {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for stmt in &script.stmts {
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "Databricks statement parsed as OpaqueContent:\n{}",
            sql
        );
    }
}

fn assert_no_opaque_mssql(sql: &str) {
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("should parse");
    for stmt in &script.stmts {
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "MSSQL statement parsed as OpaqueContent:\n{}",
            sql
        );
    }
}

fn assert_rejected_or_opaque_snowflake(sql: &str) {
    match parse_sql_with_dialect(sql, &SnowflakeDialect) {
        Ok(script) => {
            assert!(
                script
                    .stmts
                    .iter()
                    .any(|stmt| matches!(stmt, AstStmt::OpaqueContent { .. })),
                "Snowflake SQL should be rejected or opaque, but parsed cleanly:\n{}",
                sql
            );
        }
        Err(_) => {}
    }
}

fn assert_rejected_or_opaque_dbx(sql: &str) {
    match parse_sql_with_dialect(sql, &DatabricksDialect) {
        Ok(script) => {
            assert!(
                script
                    .stmts
                    .iter()
                    .any(|stmt| matches!(stmt, AstStmt::OpaqueContent { .. })),
                "Databricks SQL should be rejected or opaque, but parsed cleanly:\n{}",
                sql
            );
        }
        Err(_) => {}
    }
}

#[test]
fn databricks_distribute_by_not_opaque_and_safe() {
    let sql = "SELECT * FROM t DISTRIBUTE BY c;";
    assert_no_opaque_dbx(sql);

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn databricks_sort_and_cluster_by_not_opaque_and_safe() {
    let sql = "SELECT * FROM t SORT BY c, d CLUSTER BY region;";
    assert_no_opaque_dbx(sql);

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn databricks_named_window_not_opaque_and_safe() {
    let sql = "SELECT a, sum(b) OVER w FROM t WINDOW w AS (PARTITION BY a);";
    assert_no_opaque_dbx(sql);

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn databricks_star_except_nested_field_not_opaque_and_safe() {
    let sql = "SELECT * EXCEPT(c2.b) FROM VALUES(1, named_struct('a',2,'b',3)) AS t(c1,c2);";
    assert_no_opaque_dbx(sql);

    let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn mssql_option_clause_not_opaque_and_safe() {
    let sql = "SELECT * FROM t OPTION (RECOMPILE);";
    assert_no_opaque_mssql(sql);

    let formatted = format_sql_with_config(sql, &mssql_config()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn databricks_select_alias_keywords_not_opaque_and_safe() {
    for sql in ["SELECT 1 AS anti;", "SELECT 1 AS from;"] {
        assert_no_opaque_dbx(sql);
        let formatted = format_sql_with_config(sql, &dbx_config()).expect("should format");
        verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
    }
}

#[test]
fn databricks_table_alias_restricted_keyword_rejected() {
    let sql = "SELECT * FROM information_schema.catalogs AS anti LIMIT 1;";
    assert_rejected_or_opaque_dbx(sql);
}

#[test]
fn databricks_table_alias_restricted_keyword_set_rejected() {
    for keyword in [
        "ANTI",
        "INNER",
        "INTERSECT",
        "JOIN",
        "LEFT",
        "NATURAL",
        "ON",
        "RIGHT",
        "UNION",
        "USING",
    ] {
        let sql = format!(
            "SELECT * FROM information_schema.catalogs AS {} LIMIT 1;",
            keyword
        );
        assert_rejected_or_opaque_dbx(&sql);
    }
}

#[test]
fn databricks_table_alias_nonrestricted_keywords_allowed() {
    for keyword in ["QUALIFY", "WINDOW", "LIMIT", "ORDER"] {
        let sql = format!(
            "SELECT * FROM information_schema.catalogs AS {} LIMIT 1;",
            keyword
        );
        assert_no_opaque_dbx(&sql);
    }
}

#[test]
fn snowflake_select_alias_reserved_keyword_rejected() {
    assert_rejected_or_opaque_snowflake("SELECT 1 AS from;");
}

#[test]
fn window_alias_is_dialect_sensitive() {
    // Snowflake docs: QUALIFY and WINDOW are reserved.
    assert!(SnowflakeDialect.is_reserved_keyword("QUALIFY"));
    assert!(SnowflakeDialect.is_reserved_keyword("WINDOW"));

    // Databricks allows WINDOW as identifier in general.
    assert!(DatabricksDialect.keyword_can_be_unquoted_identifier("WINDOW"));
}

#[test]
fn keyword_identifier_matrix_smoke_test() {
    // WINDOW: reserved in Snowflake; Databricks allows it as identifier but has alias restrictions for specific words.
    assert!(!SnowflakeDialect.keyword_can_be_unquoted_identifier("WINDOW"));
    assert!(PostgresDialect.keyword_can_be_unquoted_identifier("WINDOW"));
    assert!(DatabricksDialect.keyword_can_be_unquoted_identifier("WINDOW"));

    // RETURNING differs between Snowflake (unreserved) and PostgreSQL (reserved).
    assert!(SnowflakeDialect.keyword_can_be_unquoted_identifier("RETURNING"));
    assert!(!PostgresDialect.keyword_can_be_unquoted_identifier("RETURNING"));

    // QUALIFY is reserved in both BigQuery and Snowflake.
    assert!(!BigQueryDialect.keyword_can_be_unquoted_identifier("QUALIFY"));
    assert!(!SnowflakeDialect.keyword_can_be_unquoted_identifier("QUALIFY"));
    assert!(DatabricksDialect.keyword_can_be_unquoted_identifier("QUALIFY"));

    // Databricks alias-restricted words must be quoted as table aliases.
    assert!(!DatabricksDialect.keyword_can_be_unquoted_alias("ANTI"));
    assert!(DatabricksDialect.keyword_can_be_unquoted_alias("QUALIFY"));

    // OPTION should remain reserved in MSSQL.
    assert!(!MsSqlDialect.keyword_can_be_unquoted_identifier("OPTION"));
}
