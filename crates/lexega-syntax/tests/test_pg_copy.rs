// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL COPY statement.
//!
//! Each construct is tested for:
//!   1. Correct AST variant (not OpaqueContent)
//!   2. Format round-trip with semantic safety verification
//!   3. Multiple syntax variants
//!
//! Token gotchas verified via --debug-tokens:
//!   COPY → Keyword(Copy) (shared with Snowflake COPY INTO)
//!   FROM/TO/WITH/WHERE → Keywords
//!   STDIN/STDOUT/PROGRAM → Identifier (lexeme comparison)
//!   NULL → Literal(Null) ⚠️  (option name lexes as null literal)
//!   ESCAPE → Keyword(Escape) ⚠️
//!   FORMAT → Keyword(Format) ⚠️
//!   DEFAULT → Keyword(Default) ⚠️
//!   HEADER/FREEZE/DELIMITER/QUOTE → Identifier
//!   FORCE_QUOTE/FORCE_NOT_NULL/FORCE_NULL → single Identifier tokens
//!   ON_ERROR/ENCODING/LOG_VERBOSITY/REJECT_LIMIT → single Identifier tokens

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe, AstStmt,
    FormatterConfig, PostgresDialect,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn pg_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = std::sync::Arc::new(PostgresDialect);
    config
}

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &pg_config())
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
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse");
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
// COPY FROM — Basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_from_file_basic() {
    let sql = "COPY my_table FROM '/path/to/file.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_file_with_semicolon() {
    let sql = "COPY my_table FROM '/path/to/file.csv';";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_stdin() {
    let sql = "COPY my_table FROM STDIN";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_stdin_semicolon() {
    let sql = "COPY my_table FROM STDIN;";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_program() {
    let sql = "COPY my_table FROM PROGRAM 'cat /path/to/file.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// COPY TO — Basic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_to_file() {
    let sql = "COPY my_table TO '/path/to/output.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_to_stdout() {
    let sql = "COPY my_table TO STDOUT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_to_program() {
    let sql = "COPY my_table TO PROGRAM 'gzip > /tmp/out.csv.gz'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// COPY (query) TO — Subquery syntax
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_query_to_file() {
    let sql = "COPY (SELECT * FROM users WHERE active = true) TO '/tmp/active_users.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_query_to_stdout() {
    let sql = "COPY (SELECT id, name FROM users) TO STDOUT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_query_to_stdout_with_options() {
    let sql = "COPY (SELECT id, name FROM users) TO STDOUT WITH (FORMAT csv, HEADER)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Column lists
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_from_with_columns() {
    let sql = "COPY my_table (col1, col2, col3) FROM '/path/to/data.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_to_with_columns() {
    let sql = "COPY my_table (id, name) TO '/tmp/out.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Schema-qualified table names
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_schema_qualified() {
    let sql = "COPY public.my_table FROM '/path/to/data.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_schema_qualified_with_columns() {
    let sql = "COPY public.my_table (col1, col2) FROM '/path/to/data.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_catalog_schema_qualified() {
    let sql = "COPY mydb.public.my_table FROM '/path/to/data.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH (options) clause — FORMAT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_with_format_csv() {
    let sql = "COPY my_table FROM '/f' WITH (FORMAT csv)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_format_text() {
    let sql = "COPY my_table FROM '/f' WITH (FORMAT text)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_format_binary() {
    let sql = "COPY my_table FROM '/f' WITH (FORMAT binary)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH (options) — Multiple options
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_with_multiple_options() {
    let sql = "COPY my_table FROM '/f' WITH (FORMAT csv, HEADER true, DELIMITER ',')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_to_with_options() {
    let sql = "COPY my_table TO '/tmp/out.csv' WITH (FORMAT csv, HEADER, DELIMITER '|')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_null_option() {
    // NULL is Literal(Null) — must be handled as option name
    let sql = r"COPY t FROM '/f' WITH (NULL '\N')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_escape_option() {
    // ESCAPE is Keyword(Escape) — must be handled as option name
    let sql = r"COPY t FROM '/f' WITH (ESCAPE '\\')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_quote_option() {
    let sql = r#"COPY t FROM '/f' WITH (QUOTE '"')"#;
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_default_option() {
    // DEFAULT is Keyword(Default) — must be handled as option name
    let sql = "COPY t FROM '/f' WITH (DEFAULT 'N/A')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_freeze_true() {
    let sql = "COPY t FROM '/f' WITH (FREEZE true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_freeze_no_value() {
    // FREEZE without a value (boolean defaults to true)
    let sql = "COPY t FROM '/f' WITH (FREEZE)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH (options) — FORCE_QUOTE, FORCE_NOT_NULL, FORCE_NULL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_with_force_quote_columns() {
    let sql = "COPY t TO '/f' WITH (FORMAT csv, FORCE_QUOTE (col1, col2))";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_force_quote_star() {
    let sql = "COPY t TO '/f' WITH (FORMAT csv, FORCE_QUOTE *)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_force_not_null() {
    let sql = "COPY t FROM '/f' WITH (FORMAT csv, FORCE_NOT_NULL (col1, col2))";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_force_null() {
    let sql = "COPY t FROM '/f' WITH (FORMAT csv, FORCE_NULL (col1))";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH (options) — ON_ERROR, ENCODING, LOG_VERBOSITY, REJECT_LIMIT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_with_on_error() {
    let sql = "COPY t FROM '/f' WITH (ON_ERROR ignore)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_encoding() {
    let sql = "COPY t FROM '/f' WITH (ENCODING 'UTF8')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_log_verbosity() {
    let sql = "COPY t FROM '/f' WITH (LOG_VERBOSITY verbose)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_reject_limit() {
    let sql = "COPY t FROM '/f' WITH (ON_ERROR ignore, REJECT_LIMIT 100)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// WITH (options) — HEADER MATCH
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_with_header_match() {
    let sql = "COPY t FROM '/f' WITH (FORMAT csv, HEADER MATCH)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_with_header_true() {
    let sql = "COPY t FROM '/f' WITH (HEADER true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// WHERE clause (COPY FROM only)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_from_where() {
    let sql = "COPY my_table FROM '/f' WHERE id > 100";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_where_with_string() {
    let sql = "COPY my_table FROM '/f' WHERE status = 'active'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_with_options_and_where() {
    let sql = "COPY my_table FROM '/f' WITH (FORMAT csv, HEADER true) WHERE status = 'active'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Options without WITH keyword
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_options_without_with() {
    let sql = "COPY t FROM '/f' (FORMAT csv, HEADER true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Complex combinations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_all_options_kitchen_sink() {
    let sql = "COPY t FROM '/f' WITH (FORMAT csv, HEADER true, DELIMITER ',', NULL '\\N', QUOTE '\"', ESCAPE '\\\\')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_program_with_options() {
    let sql = "COPY my_table FROM PROGRAM 'cat /tmp/data.csv' WITH (FORMAT csv, HEADER)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_to_program_with_options() {
    let sql = "COPY my_table TO PROGRAM 'gzip > /tmp/out.csv.gz' WITH (FORMAT csv, HEADER)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_stdin_with_options() {
    let sql = "COPY my_table FROM STDIN WITH (FORMAT csv, HEADER true)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_to_stdout_with_delimiter() {
    let sql = "COPY country TO STDOUT WITH (DELIMITER '|')";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-statement — test multiple COPY in one script
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_multi_statement() {
    let sql = "\
COPY t1 FROM '/f1';
COPY t2 TO '/f2';
COPY (SELECT * FROM t3) TO STDOUT;
";
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse");
    let copy_count = script
        .stmts
        .iter()
        .filter(|s| matches!(s, AstStmt::PgCopy(_)))
        .count();
    assert_eq!(copy_count, 3, "All 3 statements should parse as PgCopy");
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// Snowflake COPY INTO still works (dialect isolation)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_snowflake_copy_into_still_works() {
    // Default dialect = Snowflake, COPY INTO must still route correctly
    let sql = "COPY INTO my_table FROM @my_stage";
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Snowflake COPY INTO should still work");
    verify_formatting_safe(sql, &formatted).expect("Snowflake COPY INTO safety check failed");
}

// ═══════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_from_lowercase() {
    let sql = "copy my_table from '/f'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_mixed_case() {
    let sql = "Copy My_Table FROM '/path/to/file.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_file_with_spaces_in_path() {
    let sql = "COPY t FROM '/path/with spaces/file.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_query_with_join_to_file() {
    let sql = "COPY (SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id) TO '/tmp/report.csv'";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_query_with_subquery_to_stdout() {
    let sql = "COPY (SELECT * FROM users WHERE id IN (SELECT user_id FROM active_users)) TO STDOUT";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

// ═══════════════════════════════════════════════════════════════════════════
// psql variable placeholders as endpoint
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_from_psql_variable() {
    let sql = "COPY tmp_table FROM :source";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_to_psql_quoted_variable() {
    let sql = "COPY t TO :'outfile' WITH (format csv)";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_from_colon_number_is_not_placeholder() {
    // `:5` is not a valid psql variable; must fall back gracefully (opaque),
    // not be accepted as a clean PgCopy endpoint.
    let sql = "COPY t FROM :5";
    let pg = PostgresDialect;
    let script = parse_sql_with_dialect(sql, &pg).expect("should parse (as opaque)");
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "`:5` should not be accepted as a psql variable endpoint"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Legacy (pre-9.0) un-parenthesized WITH options
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_copy_legacy_with_options_no_parens() {
    let sql = "COPY t FROM '/f' WITH csv header";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_placeholder_with_legacy_options() {
    // A psql variable endpoint followed by the un-parenthesized options.
    let sql = "COPY staging_rows FROM :input_path WITH delimiter E'\\t' quote E'\\b' csv";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}

#[test]
fn test_copy_legacy_options_then_where() {
    let sql = "COPY t FROM '/f' WITH csv header WHERE id > 0";
    assert!(parses_as(sql, |s| matches!(s, AstStmt::PgCopy(_))));
    format_and_verify(sql);
}
