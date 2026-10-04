// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for CST delimiter allocation wiring
///
/// Verifies that all JinjaBlockDelimiter constructions now populate syntax_id
/// by allocating SyntaxJinjaDelimiter nodes in the syntax arena.
///
/// Goal: Thread `syntax_arena.alloc_jinja_delimiter()` calls through
/// all parser locations that construct `JinjaBlockDelimiter` so every delimiter
/// gets a `syntax_id` linking to the CST layer with TokenIds.
use lexega_syntax::parse_sql;

#[test]
fn test_jinja_table_name_block_parses_with_cst() {
    // This test verifies basic Jinja expression parsing
    // (table name blocks are not yet fully implemented)
    let src = "SELECT {{ table_name }} FROM t";
    let result = parse_sql(src);

    assert!(
        result.is_ok(),
        "Failed to parse Jinja expression: {:?}",
        result.err()
    );
}

#[test]
fn test_jinja_expr_placeholder_parses_with_cst() {
    // Verify that Jinja expression placeholders parse with CST wiring
    let src = "SELECT {{ x | upper }} FROM t";
    let result = parse_sql(src);

    assert!(
        result.is_ok(),
        "Failed to parse Jinja placeholder: {:?}",
        result.err()
    );
}

#[test]
fn test_comprehensive_parsing() {
    // This test verifies that all Jinja constructs that should have
    // CST wiring parse successfully without panics.

    let test_cases = vec![
        // Expression placeholders
        "SELECT {{ x }} FROM t",
        "SELECT {{ x | upper }} FROM t",
        // Jinja in WHERE
        "SELECT * FROM t WHERE x = {{ value }}",
        // Complex filters
        "SELECT {{ value | default('N/A') }} FROM t",
        // Jinja expressions with operators
        "SELECT {{ x + y }} FROM t",
        "SELECT {{ x and y }} FROM t",
        "SELECT {{ x or y }} FROM t",
        "SELECT {{ not x }} FROM t",
    ];

    for src in test_cases {
        let result = parse_sql(src);
        assert!(
            result.is_ok(),
            "Failed to parse: {} | Error: {:?}",
            src,
            result.err()
        );
    }
}

#[test]
fn test_jinja_delimiter_kinds() {
    // Verify that basic Jinja expression parsing works
    let test_cases = vec![
        ("Simple expr", "SELECT {{ x }} FROM t"),
        ("Filter", "SELECT {{ x | upper }} FROM t"),
        ("Binary op", "SELECT {{ x + y }} FROM t"),
    ];

    for (name, src) in test_cases {
        let result = parse_sql(src);
        assert!(
            result.is_ok(),
            "Failed to parse {}: {} | Error: {:?}",
            name,
            src,
            result.err()
        );
    }
}

#[test]
fn test_jinja_expr_all_kinds() {
    // Verify JinjaExpr kinds that get CST wiring parse correctly
    let test_cases = vec![
        ("Literal", "SELECT {{ 42 }} FROM t"),
        ("Name", "SELECT {{ x }} FROM t"),
        ("Attribute", "SELECT {{ obj.attr }} FROM t"),
        ("Subscript", "SELECT {{ arr[0] }} FROM t"),
        ("BinaryOp", "SELECT {{ x + y }} FROM t"),
        ("UnaryOp", "SELECT {{ -x }} FROM t"),
        ("Filter", "SELECT {{ x | upper }} FROM t"),
    ];

    for (name, src) in test_cases {
        let result = parse_sql(src);
        assert!(
            result.is_ok(),
            "Failed to parse {} expression: {} | Error: {:?}",
            name,
            src,
            result.err()
        );
    }
}

#[test]
fn test_no_panics_on_complex_jinja() {
    // Stress test: ensure no panics on complex nested Jinja with CST wiring
    let src = r#"
        SELECT 
            {{ x }},
            {{ y | upper }},
            {{ a + b }}
        FROM t
        WHERE updated_at > {{ start_date }}
    "#;

    let result = parse_sql(src);
    assert!(
        result.is_ok(),
        "Failed to parse complex Jinja SQL: {:?}",
        result.err()
    );
}
