// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CREATE [TEMP|TEMPORARY] [AGGREGATE] FUNCTION [IF NOT EXISTS]
//!
//! Covers BigQuery-style temporary function syntax variants:
//!   - CREATE TEMP FUNCTION (SQL UDF)
//!   - CREATE TEMPORARY FUNCTION (SQL UDF)
//!   - CREATE OR REPLACE TEMP FUNCTION
//!   - CREATE TEMP FUNCTION IF NOT EXISTS
//!   - CREATE TEMP AGGREGATE FUNCTION (BigQuery UDAF)
//!   - CREATE TEMP TABLE FUNCTION (BigQuery TVF)
//!   - CREATE TEMPORARY TABLE FUNCTION
//!   - CREATE TEMP AGGREGATE FUNCTION IF NOT EXISTS
//!   - JavaScript UDF body variant (LANGUAGE js)
//!   - PostgreSQL CREATE AGGREGATE (dispatch disambiguation regression)

use lexega_syntax::{
    format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt, FormatterConfig,
};

// =============================================================================
// SECTION 1: PARSING — verify correct AST variant and spans
// =============================================================================

#[test]
fn test_parse_create_temp_function_sql_udf() {
    let sql = "CREATE TEMP FUNCTION add_tax(x FLOAT64) RETURNS FLOAT64 AS (x * 1.1);";
    let script = parse_sql(sql).expect("should parse CREATE TEMP FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let name_span = func_stmt.name_span;
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMP keyword span"
            );
            let temp_text = &sql[temp_keyword_span.unwrap().start as usize
                ..temp_keyword_span.unwrap().end as usize];
            assert_eq!(temp_text, "TEMP");
            let name = &sql[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "add_tax");
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_temporary_function() {
    let sql =
        "CREATE TEMPORARY FUNCTION greet(name STRING) RETURNS STRING AS (CONCAT('Hello, ', name));";
    let script = parse_sql(sql).expect("should parse CREATE TEMPORARY FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let name_span = func_stmt.name_span;
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMPORARY keyword span"
            );
            let temp_text = &sql[temp_keyword_span.unwrap().start as usize
                ..temp_keyword_span.unwrap().end as usize];
            assert_eq!(temp_text, "TEMPORARY");
            let name = &sql[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "greet");
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_or_replace_temp_function() {
    let sql = "CREATE OR REPLACE TEMP FUNCTION add_tax(x FLOAT64) RETURNS FLOAT64 AS (x * 1.1);";
    let script = parse_sql(sql).expect("should parse CREATE OR REPLACE TEMP FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let or_replace_span = func_stmt.or_replace_span;
            let temp_keyword_span = func_stmt.temp_keyword_span;
            assert!(or_replace_span.is_some(), "should capture OR REPLACE span");
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMP keyword span"
            );
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_temp_function_if_not_exists() {
    let sql = "CREATE TEMP FUNCTION IF NOT EXISTS safe_divide(a FLOAT64, b FLOAT64) RETURNS FLOAT64 AS (IF(b = 0, NULL, a / b));";
    let script = parse_sql(sql).expect("should parse CREATE TEMP FUNCTION IF NOT EXISTS");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let if_not_exists_span = func_stmt.if_not_exists_span;
            let name_span = func_stmt.name_span;
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMP keyword span"
            );
            assert!(
                if_not_exists_span.is_some(),
                "should capture IF NOT EXISTS span"
            );
            let ine_text = &sql[if_not_exists_span.unwrap().start as usize
                ..if_not_exists_span.unwrap().end as usize];
            assert_eq!(ine_text, "IF NOT EXISTS");
            let name = &sql[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "safe_divide");
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_temp_aggregate_function() {
    let sql = "CREATE TEMP AGGREGATE FUNCTION weighted_avg(val FLOAT64, weight FLOAT64) RETURNS FLOAT64 AS (SUM(val * weight) / SUM(weight));";
    let script = parse_sql(sql).expect("should parse CREATE TEMP AGGREGATE FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let aggregate_keyword_span = func_stmt.aggregate_keyword_span;
            let name_span = func_stmt.name_span;
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMP keyword span"
            );
            assert!(
                aggregate_keyword_span.is_some(),
                "should capture AGGREGATE keyword span"
            );
            let agg_text = &sql[aggregate_keyword_span.unwrap().start as usize
                ..aggregate_keyword_span.unwrap().end as usize];
            assert_eq!(agg_text, "AGGREGATE");
            let name = &sql[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "weighted_avg");
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_or_replace_temp_aggregate_function() {
    let sql =
        "CREATE OR REPLACE TEMP AGGREGATE FUNCTION running_sum(x INT64) RETURNS INT64 AS (SUM(x));";
    let script = parse_sql(sql).expect("should parse CREATE OR REPLACE TEMP AGGREGATE FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let or_replace_span = func_stmt.or_replace_span;
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let aggregate_keyword_span = func_stmt.aggregate_keyword_span;
            assert!(or_replace_span.is_some(), "OR REPLACE should be captured");
            assert!(temp_keyword_span.is_some(), "TEMP should be captured");
            assert!(
                aggregate_keyword_span.is_some(),
                "AGGREGATE should be captured"
            );
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_temp_aggregate_function_if_not_exists() {
    let sql =
        "CREATE TEMP AGGREGATE FUNCTION IF NOT EXISTS my_sum(x INT64) RETURNS INT64 AS (SUM(x));";
    let script = parse_sql(sql).expect("should parse CREATE TEMP AGGREGATE FUNCTION IF NOT EXISTS");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let aggregate_keyword_span = func_stmt.aggregate_keyword_span;
            let if_not_exists_span = func_stmt.if_not_exists_span;
            let name_span = func_stmt.name_span;
            assert!(temp_keyword_span.is_some(), "TEMP should be captured");
            assert!(
                aggregate_keyword_span.is_some(),
                "AGGREGATE should be captured"
            );
            assert!(
                if_not_exists_span.is_some(),
                "IF NOT EXISTS should be captured"
            );
            let name = &sql[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "my_sum");
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_temp_table_function() {
    let sql = "CREATE TEMP TABLE FUNCTION my_tvf(filter_val STRING) RETURNS TABLE<id INT64, name STRING> AS SELECT id, name FROM my_table WHERE category = filter_val;";
    let script = parse_sql(sql).expect("should parse CREATE TEMP TABLE FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTableFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let name_span = func_stmt.name_span;
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMP keyword span"
            );
            let temp_text = &sql[temp_keyword_span.unwrap().start as usize
                ..temp_keyword_span.unwrap().end as usize];
            assert_eq!(temp_text, "TEMP");
            let name = &sql[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "my_tvf");
        }
        other => panic!(
            "expected CreateTableFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_create_temporary_table_function() {
    let sql = "CREATE TEMPORARY TABLE FUNCTION my_tvf(x INT64) RETURNS TABLE<id INT64> AS SELECT id FROM t WHERE id = x;";
    let script = parse_sql(sql).expect("should parse CREATE TEMPORARY TABLE FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTableFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMPORARY keyword span"
            );
            let temp_text = &sql[temp_keyword_span.unwrap().start as usize
                ..temp_keyword_span.unwrap().end as usize];
            assert_eq!(temp_text, "TEMPORARY");
        }
        other => panic!(
            "expected CreateTableFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_parse_plain_create_function_no_temp() {
    // Ensure non-TEMP functions still work and have temp_keyword_span = None
    let sql = "CREATE FUNCTION double_val(x INT64) RETURNS INT64 AS (x * 2);";
    let script = parse_sql(sql).expect("should parse CREATE FUNCTION without TEMP");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let aggregate_keyword_span = func_stmt.aggregate_keyword_span;
            let if_not_exists_span = func_stmt.if_not_exists_span;
            assert!(
                temp_keyword_span.is_none(),
                "plain CREATE FUNCTION should not have temp span"
            );
            assert!(
                aggregate_keyword_span.is_none(),
                "plain CREATE FUNCTION should not have aggregate span"
            );
            assert!(
                if_not_exists_span.is_none(),
                "plain CREATE FUNCTION should not have INE span"
            );
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

// =============================================================================
// SECTION 2: FORMATTING — verify round-trip semantic preservation and output
// =============================================================================

/// Helper: format and verify roundtrip, returning the formatted string for content checks.
fn format_roundtrip(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("should format: {e}"));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("should preserve semantics: {e}"));
    formatted
}

#[test]
fn test_format_create_temp_function_roundtrip() {
    let formatted =
        format_roundtrip("CREATE TEMP FUNCTION add_tax(x FLOAT64) RETURNS FLOAT64 AS (x * 1.1);");
    assert!(
        formatted.contains("TEMP"),
        "formatted output should contain TEMP keyword"
    );
    assert!(
        formatted.contains("FUNCTION"),
        "formatted output should contain FUNCTION keyword"
    );
    assert!(
        formatted.contains("add_tax"),
        "formatted output should contain function name"
    );
}

#[test]
fn test_format_create_temporary_function_roundtrip() {
    let formatted = format_roundtrip(
        "CREATE TEMPORARY FUNCTION greet(name STRING) RETURNS STRING AS (CONCAT('Hello, ', name));",
    );
    assert!(
        formatted.contains("TEMPORARY"),
        "formatted output should preserve TEMPORARY (not normalize to TEMP)"
    );
}

#[test]
fn test_format_create_or_replace_temp_function_roundtrip() {
    let formatted = format_roundtrip(
        "CREATE OR REPLACE TEMP FUNCTION add_tax(x FLOAT64) RETURNS FLOAT64 AS (x * 1.1);",
    );
    // Verify keyword ordering in output
    let or_replace_pos = formatted
        .find("OR REPLACE")
        .expect("should contain OR REPLACE");
    let temp_pos = formatted.find("TEMP").expect("should contain TEMP");
    let func_pos = formatted.find("FUNCTION").expect("should contain FUNCTION");
    assert!(or_replace_pos < temp_pos, "OR REPLACE should precede TEMP");
    assert!(temp_pos < func_pos, "TEMP should precede FUNCTION");
}

#[test]
fn test_format_create_temp_function_if_not_exists_roundtrip() {
    let formatted = format_roundtrip("CREATE TEMP FUNCTION IF NOT EXISTS safe_divide(a FLOAT64, b FLOAT64) RETURNS FLOAT64 AS (IF(b = 0, NULL, a / b));");
    let temp_pos = formatted.find("TEMP").expect("should contain TEMP");
    let func_pos = formatted.find("FUNCTION").expect("should contain FUNCTION");
    let ine_pos = formatted
        .find("IF NOT EXISTS")
        .expect("should contain IF NOT EXISTS");
    assert!(temp_pos < func_pos, "TEMP should precede FUNCTION");
    assert!(func_pos < ine_pos, "FUNCTION should precede IF NOT EXISTS");
}

#[test]
fn test_format_create_temp_aggregate_function_roundtrip() {
    let formatted = format_roundtrip("CREATE TEMP AGGREGATE FUNCTION weighted_avg(val FLOAT64, weight FLOAT64) RETURNS FLOAT64 AS (SUM(val * weight) / SUM(weight));");
    let temp_pos = formatted.find("TEMP").expect("should contain TEMP");
    let agg_pos = formatted
        .find("AGGREGATE")
        .expect("should contain AGGREGATE");
    let func_pos = formatted.find("FUNCTION").expect("should contain FUNCTION");
    assert!(temp_pos < agg_pos, "TEMP should precede AGGREGATE");
    assert!(agg_pos < func_pos, "AGGREGATE should precede FUNCTION");
}

#[test]
fn test_format_create_or_replace_temp_aggregate_function_roundtrip() {
    format_roundtrip(
        "CREATE OR REPLACE TEMP AGGREGATE FUNCTION running_sum(x INT64) RETURNS INT64 AS (SUM(x));",
    );
}

#[test]
fn test_format_create_temp_aggregate_function_if_not_exists_roundtrip() {
    let formatted = format_roundtrip(
        "CREATE TEMP AGGREGATE FUNCTION IF NOT EXISTS my_sum(x INT64) RETURNS INT64 AS (SUM(x));",
    );
    assert!(formatted.contains("AGGREGATE"), "should contain AGGREGATE");
    assert!(
        formatted.contains("IF NOT EXISTS"),
        "should contain IF NOT EXISTS"
    );
}

#[test]
fn test_format_create_temp_table_function_roundtrip() {
    format_roundtrip("CREATE TEMP TABLE FUNCTION my_tvf(filter_val STRING) RETURNS TABLE<id INT64, name STRING> AS SELECT id, name FROM my_table WHERE category = filter_val;");
}

#[test]
fn test_format_create_or_replace_temp_table_function_roundtrip() {
    format_roundtrip("CREATE OR REPLACE TEMP TABLE FUNCTION my_tvf(x INT64) RETURNS TABLE<id INT64, name STRING> AS SELECT * FROM t WHERE id = x;");
}

#[test]
fn test_format_create_temporary_table_function_roundtrip() {
    let formatted = format_roundtrip("CREATE TEMPORARY TABLE FUNCTION my_tvf(x INT64) RETURNS TABLE<id INT64> AS SELECT id FROM t WHERE id = x;");
    assert!(
        formatted.contains("TEMPORARY"),
        "should preserve TEMPORARY (not normalize to TEMP)"
    );
}

// =============================================================================
// SECTION 3: MULTI-STATEMENT — verify multiple temp functions don't collide
// =============================================================================

#[test]
fn test_multi_temp_function_statements() {
    let sql = r#"
CREATE TEMP FUNCTION add_one(x INT64) RETURNS INT64 AS (x + 1);
CREATE TEMP FUNCTION add_two(x INT64) RETURNS INT64 AS (x + 2);
CREATE TEMP AGGREGATE FUNCTION my_sum(x INT64) RETURNS INT64 AS (SUM(x));
    "#;
    let script = parse_sql(sql).expect("should parse multiple temp function statements");
    assert_eq!(script.stmts.len(), 3, "should parse 3 separate statements");

    // Verify each is CreateFunction with correct spans
    for (i, stmt) in script.stmts.iter().enumerate() {
        match stmt {
            AstStmt::CreateFunction(func_stmt) => {
                let temp_keyword_span = func_stmt.temp_keyword_span;
                let aggregate_keyword_span = func_stmt.aggregate_keyword_span;
                assert!(
                    temp_keyword_span.is_some(),
                    "stmt {} should have TEMP span",
                    i
                );
                if i == 2 {
                    assert!(
                        aggregate_keyword_span.is_some(),
                        "stmt 2 should have AGGREGATE span"
                    );
                } else {
                    assert!(
                        aggregate_keyword_span.is_none(),
                        "stmt {} should NOT have AGGREGATE span",
                        i
                    );
                }
            }
            other => panic!(
                "stmt {}: expected CreateFunction, got {:?}",
                i,
                std::mem::discriminant(other)
            ),
        }
    }

    // Verify formatting roundtrip
    format_roundtrip(sql);
}

#[test]
fn test_multi_mixed_function_types() {
    // Mix of TEMP FUNCTION, TEMP TABLE FUNCTION, and plain FUNCTION
    let sql = r#"
CREATE TEMP FUNCTION fn_a(x INT64) RETURNS INT64 AS (x);
CREATE TEMP TABLE FUNCTION fn_b(x INT64) RETURNS TABLE<id INT64> AS SELECT x AS id;
CREATE FUNCTION fn_c(x INT64) RETURNS INT64 AS (x * 2);
    "#;
    let script = parse_sql(sql).expect("should parse mixed function types");
    assert_eq!(script.stmts.len(), 3, "should parse 3 separate statements");

    // stmt 0: CreateFunction with TEMP
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            assert!(temp_keyword_span.is_some(), "stmt 0 should have TEMP");
        }
        other => panic!(
            "stmt 0: expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    // stmt 1: CreateTableFunction with TEMP
    match &script.stmts[1] {
        AstStmt::CreateTableFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            assert!(temp_keyword_span.is_some(), "stmt 1 should have TEMP");
        }
        other => panic!(
            "stmt 1: expected CreateTableFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    // stmt 2: CreateFunction without TEMP
    match &script.stmts[2] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            assert!(temp_keyword_span.is_none(), "stmt 2 should NOT have TEMP");
        }
        other => panic!(
            "stmt 2: expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }

    format_roundtrip(sql);
}

// =============================================================================
// SECTION 4: REGRESSION — existing functions and dispatch disambiguation
// =============================================================================

#[test]
fn test_existing_snowflake_create_function_unaffected() {
    let sql = r#"CREATE OR REPLACE FUNCTION calculate_total(price FLOAT, quantity INT)
RETURNS FLOAT
LANGUAGE SQL
AS
$$
    SELECT price * quantity
$$;"#;
    format_roundtrip(sql);
}

#[test]
fn test_existing_create_table_function_unaffected() {
    format_roundtrip("CREATE TABLE FUNCTION my_dataset.my_tvf(x INT64) RETURNS TABLE<id INT64, name STRING> AS SELECT id, name FROM t WHERE id = x;");
}

#[test]
fn test_pg_create_aggregate_not_broken_by_bq_aggregate_function() {
    // CRITICAL REGRESSION TEST: PostgreSQL's CREATE AGGREGATE name(...) uses a completely
    // different grammar from BigQuery's CREATE AGGREGATE FUNCTION name(...).
    // The dispatch in core.rs must route these correctly:
    //   - "AGGREGATE" followed by FUNCTION → BigQuery UDAF → parse_create_function
    //   - "AGGREGATE" followed by name     → PostgreSQL    → try_parse_pg_create_aggregate_stmt
    let sql = "CREATE AGGREGATE my_avg (float8) (sfunc = float8_accum, stype = float8[]);";
    let script = parse_sql(sql).expect("PG CREATE AGGREGATE should still parse");
    assert_eq!(script.stmts.len(), 1);
    // Must NOT be CreateFunction — that would mean dispatch routed wrong
    match &script.stmts[0] {
        AstStmt::CreateFunction(_) => {
            panic!("PG CREATE AGGREGATE should NOT become CreateFunction — dispatch is broken!");
        }
        _ => {} // Any other variant (PgCreateAggregate, OpaqueContent, etc.) is acceptable
    }
    format_roundtrip(sql);
}

#[test]
fn test_pg_create_aggregate_with_order_by() {
    // Another PG AGGREGATE variant to ensure no dispatch regression
    let sql = "CREATE AGGREGATE my_percentile (float8 ORDER BY float8) (sfunc = ordered_set_transition, stype = internal);";
    let script = parse_sql(sql).expect("PG CREATE AGGREGATE with ORDER BY should parse");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(_) => {
            panic!("PG CREATE AGGREGATE with ORDER BY should NOT become CreateFunction");
        }
        _ => {}
    }
}

// =============================================================================
// SECTION 5: EDGE CASES — non-obvious combinations and body variants
// =============================================================================

#[test]
fn test_create_aggregate_function_without_temp() {
    // AGGREGATE without TEMP — should still parse as CreateFunction
    let sql = "CREATE AGGREGATE FUNCTION my_agg(x FLOAT64) RETURNS FLOAT64 AS (SUM(x));";
    let script = parse_sql(sql).expect("should parse CREATE AGGREGATE FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            let aggregate_keyword_span = func_stmt.aggregate_keyword_span;
            assert!(temp_keyword_span.is_none(), "no TEMP");
            assert!(
                aggregate_keyword_span.is_some(),
                "should capture AGGREGATE span"
            );
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_create_or_replace_aggregate_function() {
    format_roundtrip(
        "CREATE OR REPLACE AGGREGATE FUNCTION my_agg(x FLOAT64) RETURNS FLOAT64 AS (SUM(x));",
    );
}

#[test]
fn test_create_temp_function_javascript_udf() {
    // BigQuery TEMP FUNCTIONs can use LANGUAGE js — a realistic production pattern
    let sql = r#"CREATE TEMP FUNCTION custom_hash(input STRING)
RETURNS STRING
LANGUAGE js AS """
  return input.split('').reverse().join('');
""";"#;
    let script = parse_sql(sql).expect("should parse JS TEMP FUNCTION");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let temp_keyword_span = func_stmt.temp_keyword_span;
            assert!(
                temp_keyword_span.is_some(),
                "should capture TEMP span for JS UDF"
            );
        }
        other => panic!(
            "expected CreateFunction, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    let formatted = format_roundtrip(sql);
    assert!(formatted.contains("TEMP"), "JS UDF should preserve TEMP");
    assert!(
        formatted.contains("LANGUAGE"),
        "JS UDF should preserve LANGUAGE clause"
    );
}

#[test]
fn test_create_temp_function_qualified_name() {
    // Qualified name with dataset prefix — parser currently doesn't support
    // dot-qualified names in CREATE FUNCTION (pre-existing limitation, not
    // specific to TEMP). Verify it at least parses without crashing.
    let sql = "CREATE TEMP FUNCTION my_dataset.add_tax(x FLOAT64) RETURNS FLOAT64 AS (x * 1.1);";
    let script = parse_sql(sql).expect("should parse (possibly as OpaqueContent)");
    assert_eq!(script.stmts.len(), 1);
    // Don't assert CreateFunction — may fall back to OpaqueContent due to
    // dot-qualified name. The important thing is it doesn't panic.
    format_roundtrip(sql);
}
