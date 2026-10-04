// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake `CREATE [OR REPLACE] PROCEDURE SCOPED { TEMP |
//! TEMPORARY } TABLE <name> (<cols>)` — a table scoped to a single stored-
//! procedure execution. Despite the `PROCEDURE` keyword it creates a TABLE;
//! it is routed through the CREATE TABLE pipeline so columns are recognized,
//! and the `PROCEDURE SCOPED` prefix is captured as the `scoped` recognition
//! primitive (the table is also `temporary`). No built-in rule — a procedure-
//! scoped temp table is not inherently risky; this is coverage + recognition.

use lexega_core::api::analyze_risk;
use lexega_core::ast::AstStmt;
use lexega_core::facts::extract::derive_facts_from_table_plan;
use lexega_core::ir::lower_create_table_to_table_plan;
use lexega_core::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};

/// (`scoped`, `temporary`) flags from the first CREATE TABLE in `sql`.
/// The `.expect("CREATE TABLE")` also asserts the statement parsed as a
/// table — not as a procedure or OpaqueContent.
fn scoped_temp_flags(sql: &str) -> (bool, bool) {
    let script = parse_sql(sql).expect("should parse");
    let ct = script
        .stmts
        .iter()
        .find_map(|s| {
            if let AstStmt::CreateTable(t) = s {
                Some(t.as_ref())
            } else {
                None
            }
        })
        .expect("a CREATE TABLE statement");
    let plan = lower_create_table_to_table_plan(ct, sql);
    let facts = derive_facts_from_table_plan(&plan, sql);
    let opts = facts.ddl.expect("ddl facts present").options;
    (opts.scoped, opts.temporary)
}

fn skipped(sql: &str) -> usize {
    analyze_risk(sql)
        .expect("should analyze")
        .summary
        .statements_skipped
}

// ── Recognition / coverage ──────────────────────────────────────────────

#[test]
fn scoped_temp_table_is_analyzed_not_opaque() {
    assert_eq!(
        skipped("CREATE OR REPLACE PROCEDURE SCOPED TEMPORARY TABLE tt (a INT, ssn VARCHAR);"),
        0
    );
}

#[test]
fn scoped_temp_table_parses_as_a_table() {
    // The helper's expect asserts an AstStmt::CreateTable was produced (not a
    // procedure, not opaque).
    let (scoped, temporary) = scoped_temp_flags("CREATE PROCEDURE SCOPED TEMP TABLE tt (a INT);");
    assert!(scoped, "scoped flag should be set");
    assert!(temporary, "a scoped temp table is also temporary");
}

#[test]
fn scoped_temporary_keyword_variant() {
    let (scoped, temporary) = scoped_temp_flags(
        "CREATE OR REPLACE PROCEDURE SCOPED TEMPORARY TABLE db.sch.tt (a INT, b VARCHAR(10));",
    );
    assert!(scoped);
    assert!(temporary);
}

// ── Negative: ordinary tables carry scoped = false ──────────────────────

#[test]
fn ordinary_temporary_table_is_not_scoped() {
    let (scoped, temporary) = scoped_temp_flags("CREATE TEMPORARY TABLE t (a INT);");
    assert!(!scoped, "a session temp table is not procedure-scoped");
    assert!(temporary);
}

#[test]
fn ordinary_table_is_neither() {
    let (scoped, temporary) = scoped_temp_flags("CREATE TABLE t (a INT);");
    assert!(!scoped);
    assert!(!temporary);
}

// ── Regression: a real CREATE PROCEDURE is still a procedure ────────────

#[test]
fn create_procedure_still_parses_as_procedure() {
    let sql =
        "CREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS $$ BEGIN RETURN 'x'; END; $$;";
    let script = parse_sql(sql).expect("should parse");
    let has_table = script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::CreateTable(_)));
    assert!(
        !has_table,
        "a real CREATE PROCEDURE must not parse as a table"
    );
    assert_eq!(skipped(sql), 0);
}

#[test]
fn scoped_temp_in_procedure_body_is_recognized() {
    // The construct's real home: inside a Snowflake Scripting procedure body.
    let sql = "CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS $$ BEGIN \
               CREATE PROCEDURE SCOPED TEMPORARY TABLE tt (a INT); RETURN 'x'; END; $$;";
    assert_eq!(skipped(sql), 0);
}

// ── Formatting: semantic round-trip ─────────────────────────────────────

fn assert_format_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn format_temp_variant() {
    assert_format_safe("CREATE PROCEDURE SCOPED TEMP TABLE tt (a INT);");
}

#[test]
fn format_or_replace_temporary_qualified() {
    assert_format_safe(
        "CREATE OR REPLACE PROCEDURE SCOPED TEMPORARY TABLE db.sch.tt (a INT, b VARCHAR(10));",
    );
}

#[test]
fn format_multi_statement() {
    assert_format_safe(
        "CREATE PROCEDURE SCOPED TEMP TABLE a (x INT);\n\
         CREATE PROCEDURE SCOPED TEMPORARY TABLE b (y INT);\n",
    );
}
