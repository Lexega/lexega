// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PL/pgSQL function body parsing
//!
//! Verifies that CREATE FUNCTION/PROCEDURE with `$$...$$` bodies and
//! `LANGUAGE plpgsql` (in any position) are correctly parsed and
//! format-round-tripped with all PL/pgSQL constructs preserved:
//!
//!   - PERFORM (discard query result)
//!   - RAISE NOTICE/WARNING/EXCEPTION/DEBUG
//!   - GET DIAGNOSTICS
//!   - FOREACH ... IN ARRAY ... LOOP
//!   - <<label>> blocks
//!   - RETURN QUERY / RETURN QUERY EXECUTE
//!   - SELECT INTO / SELECT INTO STRICT
//!   - EXECUTE ... USING (dynamic SQL)
//!   - %TYPE / %ROWTYPE references
//!   - EXCEPTION ... WHEN handlers
//!   - DECLARE with variable types

use lexega_core::{
    format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt, FormatterConfig,
};

use lexega_core::api::analyze_risk;

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

fn is_create_function(stmt: &AstStmt) -> bool {
    matches!(stmt, AstStmt::CreateFunction(_))
}

fn is_create_procedure(stmt: &AstStmt) -> bool {
    matches!(stmt, AstStmt::CreateProcedure(_))
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
    script.stmts.iter().any(check)
}

// ═══════════════════════════════════════════════════════════════════════════
// LANGUAGE clause position: LANGUAGE plpgsql BEFORE vs AFTER body
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_language_before_body() {
    let sql = r#"
CREATE FUNCTION greet(name TEXT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN 'Hello, ' || name;
END;
$$;
"#;
    assert!(parses_as(sql.trim(), is_create_function));
    format_and_verify(sql.trim());
}

#[test]
fn test_language_after_body() {
    let sql = r#"
CREATE FUNCTION greet(name TEXT)
RETURNS TEXT
AS $$
BEGIN
    RETURN 'Hello, ' || name;
END;
$$ LANGUAGE plpgsql;
"#;
    assert!(parses_as(sql.trim(), is_create_function));
    format_and_verify(sql.trim());
}

#[test]
fn test_procedure_language_after_body() {
    let sql = r#"
CREATE PROCEDURE do_thing()
AS $$
BEGIN
    INSERT INTO log_table (msg) VALUES ('called');
END;
$$ LANGUAGE plpgsql;
"#;
    assert!(parses_as(sql.trim(), is_create_procedure));
    format_and_verify(sql.trim());
}

// ═══════════════════════════════════════════════════════════════════════════
// PERFORM
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_perform_simple() {
    let sql = r#"
CREATE FUNCTION test_perform()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_sleep(1);
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(
        formatted.contains("PERFORM pg_sleep(1)"),
        "PERFORM should be preserved in output"
    );
}

#[test]
fn test_perform_with_query() {
    let sql = r#"
CREATE FUNCTION test_perform_query()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM count(*) FROM users WHERE active = true;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("PERFORM"), "PERFORM should be preserved");
}

// ═══════════════════════════════════════════════════════════════════════════
// RAISE variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_raise_notice() {
    let sql = r#"
CREATE FUNCTION test_raise()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE NOTICE 'Count is %', 42;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("RAISE NOTICE"));
}

#[test]
fn test_raise_exception_with_errcode() {
    let sql = r#"
CREATE FUNCTION test_raise_exception()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Fatal error: %', 'bad' USING ERRCODE = '22000';
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("RAISE EXCEPTION"));
    assert!(formatted.contains("USING ERRCODE"));
}

#[test]
fn test_raise_warning_and_debug() {
    let sql = r#"
CREATE FUNCTION test_raise_levels()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE WARNING 'Something bad: %', 'oops';
    RAISE DEBUG 'debugging info';
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("RAISE WARNING"));
    assert!(formatted.contains("RAISE DEBUG"));
}

// ═══════════════════════════════════════════════════════════════════════════
// GET DIAGNOSTICS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_get_diagnostics() {
    let sql = r#"
CREATE FUNCTION test_get_diag()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    cnt integer;
BEGIN
    DELETE FROM t WHERE x = 1;
    GET DIAGNOSTICS cnt = ROW_COUNT;
    RETURN cnt;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(
        formatted.contains("GET DIAGNOSTICS"),
        "GET DIAGNOSTICS should be preserved"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// FOREACH ... IN ARRAY ... LOOP
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_foreach_in_array() {
    let sql = r#"
CREATE FUNCTION test_foreach(ids integer[])
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    id integer;
BEGIN
    FOREACH id IN ARRAY ids LOOP
        UPDATE items SET done = true WHERE item_id = id;
    END LOOP;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("FOREACH"));
    assert!(formatted.contains("IN ARRAY"));
    assert!(formatted.contains("END LOOP"));
}

// ═══════════════════════════════════════════════════════════════════════════
// <<label>> blocks
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_labeled_block() {
    let sql = r#"
CREATE FUNCTION test_labels()
RETURNS void
LANGUAGE plpgsql
AS $$
<<main>>
BEGIN
    NULL;
END main;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(
        formatted.contains("<<main>>"),
        "Block label should be preserved"
    );
}

#[test]
fn test_nested_labeled_blocks() {
    let sql = r#"
CREATE FUNCTION test_nested_labels()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    <<outer_block>>
    BEGIN
        <<inner_block>>
        FOR i IN 1..10
        LOOP
            IF i = 5 THEN
                EXIT outer_block;
            END IF;
        END LOOP;
    END;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("<<outer_block>>"));
    assert!(formatted.contains("<<inner_block>>"));
    assert!(formatted.contains("EXIT outer_block"));
}

// ═══════════════════════════════════════════════════════════════════════════
// RETURN QUERY
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_return_query() {
    let sql = r#"
CREATE FUNCTION test_return_query()
RETURNS SETOF integer
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY SELECT id FROM users;
    RETURN;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(
        formatted.contains("RETURN QUERY"),
        "RETURN QUERY should be preserved"
    );
}

#[test]
fn test_return_query_execute() {
    let sql = r#"
CREATE FUNCTION get_active_users()
RETURNS TABLE(id INTEGER, name TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY SELECT u.id, u.name FROM users u WHERE u.active = true;
    RETURN QUERY EXECUTE 'SELECT id, name FROM users WHERE active = $1' USING true;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("RETURN QUERY SELECT"));
    assert!(formatted.contains("RETURN QUERY EXECUTE"));
}

// ═══════════════════════════════════════════════════════════════════════════
// SELECT INTO / SELECT INTO STRICT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_select_into() {
    let sql = r#"
CREATE FUNCTION test_select_into()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_count integer;
BEGIN
    SELECT count(*) INTO v_count FROM users;
    RETURN v_count;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("INTO v_count"));
}

#[test]
fn test_select_into_strict() {
    let sql = r#"
CREATE FUNCTION test_select_into_strict(p_id integer)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    result text;
BEGIN
    SELECT name INTO STRICT result FROM users WHERE id = p_id;
    RETURN result;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("INTO STRICT"));
}

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTE ... USING (PL/pgSQL dynamic SQL)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_using() {
    let sql = r#"
CREATE FUNCTION test_execute(tname text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE 'DELETE FROM ' || tname || ' WHERE x = $1' USING 42;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("EXECUTE"));
    assert!(formatted.contains("USING 42"));
}

#[test]
fn test_execute_into_using() {
    let sql = r#"
CREATE FUNCTION test_execute_into(tname text)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_count integer;
BEGIN
    EXECUTE 'SELECT count(*) FROM ' || tname INTO v_count USING tname;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("EXECUTE"));
    assert!(formatted.contains("INTO v_count"));
}

// ═══════════════════════════════════════════════════════════════════════════
// %TYPE / %ROWTYPE references
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_percent_type() {
    let sql = r#"
CREATE FUNCTION test_percent_type(p_id employees.id%TYPE)
RETURNS employees.name%TYPE
LANGUAGE plpgsql
AS $$
DECLARE
    v_name employees.name%TYPE;
BEGIN
    SELECT name INTO v_name FROM employees WHERE id = p_id;
    RETURN v_name;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("%TYPE"), "%TYPE should be preserved");
}

// ═══════════════════════════════════════════════════════════════════════════
// EXCEPTION handlers
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_exception_handler() {
    let sql = r#"
CREATE FUNCTION test_exception()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO log_table (msg) VALUES ('test');
EXCEPTION
    WHEN unique_violation THEN
        RAISE NOTICE 'Duplicate found';
    WHEN OTHERS THEN
        RAISE NOTICE 'Other error';
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("EXCEPTION"));
    assert!(formatted.contains("WHEN unique_violation THEN"));
    assert!(formatted.contains("WHEN OTHERS THEN"));
}

// ═══════════════════════════════════════════════════════════════════════════
// FOR ... IN query LOOP
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_for_in_query_loop() {
    let sql = r#"
CREATE FUNCTION test_for_query()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_rec RECORD;
BEGIN
    FOR v_rec IN SELECT id, name FROM users
    LOOP
        RAISE NOTICE 'User: % %', v_rec.id, v_rec.name;
    END LOOP;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("FOR v_rec IN"));
    assert!(formatted.contains("END LOOP"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Comprehensive body with all constructs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_comprehensive_plpgsql_body() {
    let sql = r#"
CREATE FUNCTION comprehensive_test()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
    v_name TEXT;
    v_rec RECORD;
    v_arr INTEGER[] := ARRAY[1,2,3];
    v_elem INTEGER;
BEGIN
    PERFORM pg_sleep(1);
    PERFORM count(*) FROM users WHERE active = true;
    SELECT count(*) INTO v_count FROM users;
    SELECT name INTO STRICT v_name FROM users WHERE id = 1;
    RAISE NOTICE 'Count is %', v_count;
    RAISE WARNING 'Something bad: % %', v_count, v_name;
    RAISE EXCEPTION 'Fatal error: %', v_name USING ERRCODE = '22000';
    RAISE DEBUG 'debugging info';
    GET DIAGNOSTICS v_count = ROW_COUNT;
    FOREACH v_elem IN ARRAY v_arr
    LOOP
        RAISE NOTICE 'Element: %', v_elem;
    END LOOP;
    EXECUTE 'SELECT count(*) FROM ' || v_name INTO v_count USING v_name;
    FOR v_rec IN SELECT id, name FROM users
    LOOP
        RAISE NOTICE 'User: % %', v_rec.id, v_rec.name;
    END LOOP;
    <<outer_block>>
    BEGIN
        <<inner_block>>
        FOR i IN 1..10
        LOOP
            IF i = 5 THEN
                EXIT outer_block;
            END IF;
        END LOOP;
    END;
    BEGIN
        INSERT INTO log_table (msg) VALUES ('test');
    EXCEPTION
        WHEN unique_violation THEN
            RAISE NOTICE 'Duplicate found';
        WHEN OTHERS THEN
            RAISE NOTICE 'Other error';
    END;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());

    // All key constructs preserved
    assert!(formatted.contains("PERFORM pg_sleep(1)"));
    assert!(formatted.contains("INTO v_count"));
    assert!(formatted.contains("INTO STRICT v_name"));
    assert!(formatted.contains("RAISE NOTICE"));
    assert!(formatted.contains("RAISE WARNING"));
    assert!(formatted.contains("RAISE EXCEPTION"));
    assert!(formatted.contains("RAISE DEBUG"));
    assert!(formatted.contains("GET DIAGNOSTICS"));
    assert!(formatted.contains("FOREACH"));
    assert!(formatted.contains("IN ARRAY"));
    assert!(formatted.contains("EXECUTE"));
    assert!(formatted.contains("<<outer_block>>"));
    assert!(formatted.contains("<<inner_block>>"));
    assert!(formatted.contains("EXIT outer_block"));
    assert!(formatted.contains("EXCEPTION"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-function scripts
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_multiple_plpgsql_functions() {
    let sql = r#"
CREATE FUNCTION func1()
RETURNS void
AS $$
BEGIN
    PERFORM pg_sleep(1);
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION func2()
RETURNS integer
AS $$
DECLARE
    cnt integer;
BEGIN
    SELECT count(*) INTO cnt FROM users;
    RETURN cnt;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION func3(ids integer[])
RETURNS void
AS $$
DECLARE
    id integer;
BEGIN
    FOREACH id IN ARRAY ids LOOP
        RAISE NOTICE 'id: %', id;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
"#;
    let script = parse_sql(sql.trim()).expect("should parse");

    // All three should be CreateFunction, not OpaqueContent
    assert_eq!(script.stmts.len(), 3, "Should parse 3 functions");
    for (i, stmt) in script.stmts.iter().enumerate() {
        assert!(
            is_create_function(stmt),
            "Function {} should be CreateFunction, not {:?}",
            i + 1,
            std::mem::discriminant(stmt)
        );
    }

    format_and_verify(sql.trim());
}

// ═══════════════════════════════════════════════════════════════════════════
// Risk analysis (no OpaqueContent)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_plpgsql_risk_analysis() {
    let sql = r#"
CREATE FUNCTION audit_delete(p_table TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    cnt integer;
BEGIN
    EXECUTE 'DELETE FROM ' || p_table || ' WHERE expired = true';
    GET DIAGNOSTICS cnt = ROW_COUNT;
    RAISE NOTICE 'Deleted % rows from %', cnt, p_table;
END;
$$;
"#;
    let report = analyze_risk(sql.trim()).expect("analysis should succeed");

    // The CREATE FUNCTION should be analyzed as a proper statement
    assert!(
        report.summary.statements_analyzed >= 1,
        "Should analyze at least 1 statement, got {}",
        report.summary.statements_analyzed
    );
}

#[test]
fn test_plpgsql_multi_function_risk_analysis() {
    let sql = r#"
CREATE FUNCTION f1() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_sleep(1);
END;
$$;

CREATE FUNCTION f2() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    RAISE NOTICE 'hello';
END;
$$;

CREATE FUNCTION f3() RETURNS integer LANGUAGE plpgsql AS $$
BEGIN
    RETURN 42;
END;
$$;
"#;
    let report = analyze_risk(sql.trim()).expect("analysis should succeed");
    assert!(
        report.summary.statements_analyzed >= 3,
        "Should analyze at least 3 statements, got {}",
        report.summary.statements_analyzed
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// OR REPLACE variant
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_or_replace_function_plpgsql() {
    let sql = r#"
CREATE OR REPLACE FUNCTION upsert_user(p_name TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO users (name) VALUES (p_name)
    ON CONFLICT (name) DO UPDATE SET updated_at = now();
EXCEPTION
    WHEN OTHERS THEN
        RAISE WARNING 'Failed to upsert: %', SQLERRM;
END;
$$;
"#;
    assert!(parses_as(sql.trim(), is_create_function));
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("CREATE OR REPLACE FUNCTION"));
    assert!(formatted.contains("EXCEPTION"));
}

// ═══════════════════════════════════════════════════════════════════════════
// DECLARE with diverse types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_declare_diverse_types() {
    let sql = r#"
CREATE FUNCTION test_declare()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_int INTEGER := 0;
    v_text TEXT DEFAULT 'hello';
    v_bool BOOLEAN := true;
    v_arr INTEGER[] := ARRAY[1,2,3];
    v_rec RECORD;
    v_ts TIMESTAMP := now();
BEGIN
    RAISE NOTICE 'v_int=%, v_text=%', v_int, v_text;
END;
$$;
"#;
    let formatted = format_and_verify(sql.trim());
    assert!(formatted.contains("v_int INTEGER"));
    assert!(formatted.contains("v_text TEXT"));
    assert!(formatted.contains("v_bool BOOLEAN"));
    assert!(formatted.contains("v_arr INTEGER[]"));
    assert!(formatted.contains("v_rec RECORD"));
}

// ═══════════════════════════════════════════════════════════════════════════
// FOREACH ... IN ARRAY loop (PL/pgSQL)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_foreach_basic() {
    let sql = r#"
CREATE FUNCTION sum_each(arr INTEGER[])
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    total INTEGER := 0;
    x INTEGER;
BEGIN
    FOREACH x IN ARRAY arr LOOP
        total := total + x;
    END LOOP;
    RETURN total;
END;
$$;
"#;
    assert!(parses_as(sql.trim(), is_create_function));
    let formatted = format_and_verify(sql.trim());
    assert!(
        formatted
            .to_uppercase()
            .contains("FOREACH X IN ARRAY ARR LOOP"),
        "FOREACH header not preserved:\n{}",
        formatted
    );
}

#[test]
fn test_foreach_slice() {
    let sql = r#"
CREATE FUNCTION walk_matrix(m INTEGER[])
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    row_slice INTEGER[];
BEGIN
    FOREACH row_slice SLICE 1 IN ARRAY m LOOP
        RAISE NOTICE '%', row_slice;
    END LOOP;
END;
$$;
"#;
    assert!(parses_as(sql.trim(), is_create_function));
    let formatted = format_and_verify(sql.trim());
    assert!(
        formatted.to_uppercase().contains("SLICE 1 IN ARRAY M LOOP"),
        "FOREACH SLICE header not preserved:\n{}",
        formatted
    );
}

#[test]
fn test_foreach_multi_statement() {
    // Two FOREACH-bearing functions — catches NodeId collisions and gap/semicolon
    // handling across statements.
    let sql = r#"
CREATE FUNCTION a(arr INTEGER[]) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE x INTEGER;
BEGIN
    FOREACH x IN ARRAY arr LOOP
        RAISE NOTICE '%', x;
    END LOOP;
END;
$$;
CREATE FUNCTION b(arr TEXT[]) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE y TEXT;
BEGIN
    FOREACH y IN ARRAY arr LOOP
        RAISE NOTICE '%', y;
    END LOOP;
END;
$$;
"#;
    format_and_verify(sql.trim());
}

#[test]
fn a_plpgsql_select_into_assigns_variables_and_reads_its_table() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let shapes = [
        ("postgres", "DO $$ DECLARE n int; v int; BEGIN {} END $$;"),
        (
            "postgres",
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ DECLARE n int; v int; BEGIN {} RETURN v; END $$;",
        ),
        (
            "postgres",
            "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ DECLARE n int; v int; BEGIN {} END $$;",
        ),
        (
            "redshift",
            "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ DECLARE n int; v int; BEGIN {} END $$;",
        ),
    ];
    let bodies = [
        "SELECT c INTO STRICT v FROM zz_src WHERE id = 1;",
        "SELECT c, d INTO n, v FROM zz_src;",
        "SELECT c INTO v FROM zz_src;",
    ];
    for (name, shape) in shapes {
        for body in bodies {
            let sql = shape.replace("{}", body);
            let cfg = AnalysisConfig {
                dialect: dialect::dialect_from_name(name),
                trace_mode: true,
                ..Default::default()
            };
            let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
            let json = serde_json::to_value(&report).expect("report serializes");
            assert_eq!(
                json["summary"]["statements_skipped"], 0,
                "a statement skipped in {sql}"
            );
            let statements = json["statement_traces"]
                .as_array()
                .expect("statement facts");
            let kinds: Vec<&str> = statements
                .iter()
                .filter_map(|s| s["facts"]["kind"].as_str())
                .collect();
            assert!(
                !kinds.contains(&"create_table"),
                "no table is created in {sql}: {kinds:?}"
            );
            let reads_src = statements.iter().any(|s| {
                s["facts"]["query"]["reads_table"]
                    .as_array()
                    .is_some_and(|reads| {
                        reads
                            .iter()
                            .any(|r| r["table"]["name"]["raw"].as_str() == Some("zz_src"))
                    })
            });
            assert!(reads_src, "the read of zz_src is published in {sql}");
        }
    }
}

/// Each path at which `a` and `b` differ, with both values shortened. A
/// statement's preview is left out: it folds the source's whitespace.
fn differing_paths(
    a: &serde_json::Value,
    b: &serde_json::Value,
    path: String,
    out: &mut Vec<String>,
) {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys = x.keys().chain(y.keys().filter(|k| !x.contains_key(*k)));
            for key in keys.filter(|k| k.as_str() != "statement_preview") {
                let (p, q) = (x.get(key), y.get(key));
                differing_paths(
                    p.unwrap_or(&Value::Null),
                    q.unwrap_or(&Value::Null),
                    format!("{path}.{key}"),
                    out,
                );
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                differing_paths(p, q, format!("{path}[{i}]"), out);
            }
        }
        _ if a != b => {
            let short = |v: &Value| v.to_string().chars().take(160).collect::<String>();
            out.push(format!("{path}: {} | {}", short(a), short(b)));
        }
        _ => {}
    }
}

#[test]
fn perform_reports_what_the_same_select_reports() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    // `PERFORM q` and `SELECT  q` are the same length, so every offset in
    // the two reports is the same.
    let shapes = [
        "DO $$ BEGIN {} END $$;",
        "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN IF true THEN {} END IF; END $$;",
        "CREATE PROCEDURE p(n int) LANGUAGE plpgsql AS $b$ DECLARE v int; BEGIN {} RETURN; END $b$;",
    ];
    let queries = [
        "zz_f(1, 'x');",
        "* FROM users;",
        "id FROM users WHERE name = NULL;",
        "count(*) FROM orders o, users u;",
        "id FROM users ORDER BY random() LIMIT 1;",
        "DISTINCT u.id FROM users u JOIN orders o ON o.user_id = u.id WHERE o.total > 10;",
        "pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'zz';",
        "set_config('search_path', 'public', false);",
    ];
    let report = |sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name("postgres"),
            trace_mode: true,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let mut json = serde_json::to_value(&report).expect("report serializes");
        json["timestamp"] = serde_json::Value::Null;
        json
    };
    let mut differ = Vec::new();
    for shape in shapes {
        for query in queries {
            let perform = shape.replace("{}", &format!("PERFORM {query}"));
            let select = shape.replace("{}", &format!("SELECT  {query}"));
            let performed = report(&perform);
            let selected = report(&select);
            assert_eq!(
                performed["summary"]["statements_skipped"], 0,
                "a statement skipped in {perform}"
            );
            let performed: serde_json::Value = serde_json::from_str(
                &serde_json::to_string(&performed)
                    .expect("report serializes")
                    .replace("PERFORM", "SELECT "),
            )
            .expect("report parses");
            let mut paths = Vec::new();
            differing_paths(&performed, &selected, String::new(), &mut paths);
            if !paths.is_empty() {
                let count = paths.len();
                paths.truncate(6);
                differ.push(format!(
                    "{perform}\n  ({count} paths)\n  {}",
                    paths.join("\n  ")
                ));
            }
        }
    }
    assert!(differ.is_empty(), "{}", differ.join("\n"));

    // A set operation after the query is read with it.
    let sql = "DO $$ BEGIN PERFORM id FROM users UNION SELECT id FROM archive; END $$;";
    let summary = &report(sql)["summary"];
    assert_eq!(summary["statements_skipped"], 0, "{sql}");
    assert_eq!(summary["tables_read"], 2, "{sql}");
}
