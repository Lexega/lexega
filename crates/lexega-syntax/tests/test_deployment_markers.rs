// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A deployment marker (`${NAME}`) written in a name position is one part
//! of the name, and the formatter prints it as written.

use lexega_syntax::ast::{AstNamePart, AstStmt};
use lexega_syntax::lexer::tokenize_with_dialect;
use lexega_syntax::{
    dialect, format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect,
    DialectRef, FormatterConfig,
};

/// Formats `sql` in `dialect` with the default and the compact style and
/// checks each output: the same significant tokens as the source, each
/// marker printed whole, formatting it again changes nothing, and the
/// formatter's own safety check passes it.
fn assert_formats_to_source_tokens(sql: &str, dialect: DialectRef) {
    let lexemes = |text: &str| -> Vec<String> {
        tokenize_with_dialect(text, dialect.as_ref())
            .tokens
            .iter()
            .map(|t| t.lexeme(text).to_ascii_uppercase())
            .collect()
    };
    let markers: Vec<&str> = sql
        .match_indices("${")
        .filter_map(|(at, _)| sql[at..].find('}').map(|len| &sql[at..=at + len]))
        .collect();
    for base in [FormatterConfig::default(), FormatterConfig::compact()] {
        let config = FormatterConfig {
            dialect: dialect.clone(),
            ..base
        };
        let formatted = format_sql_with_config(sql, &config)
            .unwrap_or_else(|e| panic!("format failed for {sql:?}: {e:?}"));
        assert_eq!(
            lexemes(&formatted),
            lexemes(sql),
            "formatted text holds other tokens than the source:\n{formatted}"
        );
        for marker in &markers {
            assert!(
                formatted.contains(marker),
                "marker {marker} not printed whole:\n{formatted}"
            );
        }
        let again = format_sql_with_config(&formatted, &config)
            .unwrap_or_else(|e| panic!("reformat failed for {formatted:?}: {e:?}"));
        assert_eq!(again, formatted, "formatting is not idempotent");
        verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
            .unwrap_or_else(|e| panic!("safety check refused {formatted:?}: {e}"));
    }
}

#[test]
fn marker_in_every_name_position_formats_as_written() {
    let snowflake_only = [
        "USE DATABASE ${DB_NAME};",
        "USE SCHEMA ${DB}.${SCHEMA};",
        "USE ${DB_NAME};",
    ];
    for sql in snowflake_only {
        assert_formats_to_source_tokens(sql, dialect::snowflake());
    }
    let every_dialect = [
        "SELECT a FROM ${SCHEMA}.t WHERE x = 1;",
        "SELECT a FROM db.${S}.t WHERE x = 1;",
        "SELECT a FROM ${T} WHERE x = 1;",
        "SELECT t.a FROM db.s.t JOIN ${DB}.s.u ON t.id = u.id WHERE t.x = 1;",
        "INSERT INTO ${DB}.s.t (a) VALUES (1);",
        "UPDATE ${DB}.s.t SET a = 1 WHERE b = 2;",
        "DELETE FROM ${DB}.s.t WHERE a = 1;",
        "CREATE TABLE ${DB}.s.t (a INT);",
        "DROP TABLE ${ELT_DB}.staging.orders;",
    ];
    for d in [
        dialect::snowflake(),
        dialect::postgres(),
        dialect::redshift(),
        dialect::bigquery(),
        dialect::databricks(),
        dialect::mssql(),
        dialect::mysql(),
    ] {
        for sql in every_dialect {
            assert_formats_to_source_tokens(sql, d.clone());
        }
    }
}

#[test]
fn marker_is_one_name_part() {
    let sql = "DROP TABLE ${ELT_DB}.staging.orders;";
    let script = parse_sql_with_dialect(sql, &lexega_syntax::SnowflakeDialect).expect("parses");
    let Some(AstStmt::Drop(drop)) = script.stmts.first() else {
        panic!("not a DROP: {:?}", script.stmts.first());
    };
    let name = &drop.targets[0].name;
    let parts: Vec<&str> = name
        .parts
        .as_deref()
        .expect("the name has parts")
        .iter()
        .map(|part| {
            let span = part
                .as_ref()
                .map(AstNamePart::span)
                .expect("no omitted part");
            &sql[span.start as usize..span.end as usize]
        })
        .collect();
    assert_eq!(parts, ["${ELT_DB}", "staging", "orders"]);
}
