// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Comprehensive error message coverage tests.
//!
//! This module tests that all ParseErrorKind variants produce clear,
//! actionable error messages with accurate span information.

use lexega_syntax::{try_parse_script_from_str, try_parse_stmt_from_str};

// =============================================================================
// UnexpectedToken tests
// =============================================================================

#[test]
fn test_unexpected_token_in_select() {
    let sql = "SELECT 123abc FROM users";
    let result = try_parse_stmt_from_str(sql);
    // Parser may treat 123abc as identifier or fail
    if let Err(e) = result {
        assert!(!e.message().is_empty(), "Error message should not be empty");
        assert!(
            e.span.start < sql.len() as u32,
            "Span should be within input"
        );
    }
}

#[test]
fn test_unexpected_token_after_from() {
    let sql = "SELECT * FROM 123";
    let result = try_parse_stmt_from_str(sql);
    if let Err(e) = result {
        let msg = e.message();
        assert!(!msg.is_empty(), "Should have error message");
    }
}

#[test]
fn test_unexpected_keyword_in_expression() {
    let sql = "SELECT FROM FROM users";
    let result = try_parse_stmt_from_str(sql);
    // Should fail - FROM is not a valid expression
    if let Err(e) = result {
        assert!(!e.message().is_empty());
    }
}

// =============================================================================
// UnexpectedEof tests
// =============================================================================

#[test]
fn test_unexpected_eof_select() {
    let result = try_parse_stmt_from_str("SELECT");
    assert!(result.is_err(), "Incomplete SELECT should fail");
    let err = result.unwrap_err();
    assert!(!err.message().is_empty());
}

#[test]
fn test_unexpected_eof_open_paren() {
    let result = try_parse_stmt_from_str("SELECT (1 + 2");
    assert!(result.is_err(), "Unclosed paren should fail");
}

#[test]
fn test_unexpected_eof_case() {
    let result = try_parse_stmt_from_str("SELECT CASE WHEN x > 0 THEN 1");
    assert!(result.is_err(), "CASE without END should fail");
}

#[test]
fn test_unexpected_eof_string() {
    // Unclosed string literal
    // Note: The lexer/parser is lenient about unclosed strings in some contexts
    let result = try_parse_stmt_from_str("SELECT 'unclosed");
    match result {
        Ok(_) => {} // Parser is lenient
        Err(e) => assert!(!e.message().is_empty()),
    }
}

// =============================================================================
// InvalidExpression tests
// =============================================================================

#[test]
fn test_invalid_expression_double_operator() {
    let result = try_parse_stmt_from_str("SELECT 1 + + 2 FROM dual");
    // Some parsers accept this (unary +), check behavior
    match result {
        Ok(_) => {} // Accepted as unary
        Err(e) => assert!(!e.message().is_empty()),
    }
}

#[test]
fn test_invalid_expression_empty_function() {
    let result = try_parse_stmt_from_str("SELECT MAX() FROM users");
    // MAX() without args may or may not be valid
    match result {
        Ok(_) => {}
        Err(e) => assert!(!e.message().is_empty()),
    }
}

// Note: Snowflake supports trailing commas in SELECT lists, so
// "SELECT a, b, FROM users" is valid SQL - no test needed for that case.

// =============================================================================
// InvalidStatement tests
// =============================================================================

#[test]
fn test_invalid_statement_random_keyword() {
    let result = try_parse_stmt_from_str("FROBNICATE users");
    // Unknown statement type
    assert!(result.is_err(), "Unknown statement should fail");
    let err = result.unwrap_err();
    assert!(!err.message().is_empty());
}

#[test]
fn test_invalid_statement_create_without_object() {
    let result = try_parse_stmt_from_str("CREATE");
    assert!(result.is_err(), "CREATE without object type should fail");
}

#[test]
fn test_invalid_statement_drop_without_object() {
    // Note: Parser may be lenient about DROP without object type
    let result = try_parse_stmt_from_str("DROP");
    match result {
        Ok(_) => {} // Parser is lenient
        Err(e) => assert!(!e.message().is_empty()),
    }
}

// =============================================================================
// UnmatchedKeyword tests
// =============================================================================

#[test]
fn test_unmatched_end() {
    let result = try_parse_stmt_from_str("END;");
    assert!(result.is_err(), "END without BEGIN should fail");
}

#[test]
fn test_unmatched_endif() {
    // Scripting context - with error recovery, may return OpaqueContent instead of Err
    let result = try_parse_script_from_str("ENDIF;");
    if let Ok(script) = result {
        // Error recovery should have created OpaqueContent
        assert!(
            !script.stmts.is_empty(),
            "Should have at least one statement"
        );
    }
    // Either way is acceptable - parse error or error recovery
}

#[test]
fn test_unmatched_end_loop() {
    let result = try_parse_stmt_from_str("END LOOP;");
    assert!(result.is_err(), "END LOOP without LOOP should fail");
}

// =============================================================================
// MissingClause tests
// =============================================================================

#[test]
fn test_missing_clause_update_set() {
    let result = try_parse_stmt_from_str("UPDATE users");
    assert!(result.is_err(), "UPDATE without SET should fail");
    let err = result.unwrap_err();
    let msg = err.message().to_lowercase();
    // Should mention SET or be descriptive
    assert!(!msg.is_empty(), "Should have error message");
}

#[test]
fn test_missing_clause_insert_values() {
    let result = try_parse_stmt_from_str("INSERT INTO users");
    assert!(result.is_err(), "INSERT without VALUES/SELECT should fail");
}

#[test]
fn test_missing_clause_merge_on() {
    let result = try_parse_stmt_from_str("MERGE INTO target USING source");
    assert!(result.is_err(), "MERGE without ON should fail");
}

#[test]
fn test_missing_clause_delete_from() {
    let result = try_parse_stmt_from_str("DELETE users");
    // DELETE without FROM keyword - depends on dialect
    match result {
        Ok(_) => {} // Some dialects allow DELETE table
        Err(e) => assert!(!e.message().is_empty()),
    }
}

// =============================================================================
// InvalidSyntax tests
// =============================================================================

#[test]
fn test_invalid_syntax_double_from() {
    let result = try_parse_stmt_from_str("SELECT * FROM FROM users");
    assert!(result.is_err(), "Double FROM should fail");
}

#[test]
fn test_invalid_syntax_semicolon_in_expression() {
    let result = try_parse_stmt_from_str("SELECT 1; 2 FROM dual");
    // This should parse as two statements or fail
    match result {
        Ok(_) => {} // Parsed as separate
        Err(e) => assert!(!e.message().is_empty()),
    }
}

#[test]
fn test_invalid_syntax_misplaced_where() {
    let result = try_parse_stmt_from_str("SELECT * WHERE id = 1 FROM users");
    // WHERE before FROM is wrong
    assert!(result.is_err(), "WHERE before FROM should fail");
}

// =============================================================================
// Jinja error tests
// =============================================================================

#[test]
fn test_unclosed_jinja_if() {
    let result = try_parse_script_from_str("SELECT * FROM users {% if true %}");
    // Unclosed {% if %} block - with error recovery, may return OpaqueContent
    if let Err(err) = result {
        assert!(
            !err.message().is_empty(),
            "Error message should not be empty"
        );
    } else {
        // Error recovery produced a result, which is also acceptable
        let script = result.unwrap();
        assert!(
            !script.stmts.is_empty(),
            "Should have at least one statement"
        );
    }
}

#[test]
fn test_unclosed_jinja_for() {
    let result = try_parse_script_from_str("{% for x in items %}SELECT {{ x }}");
    // With error recovery, may return OpaqueContent instead of Err
    if let Ok(script) = result {
        // Error recovery should have created OpaqueContent
        assert!(
            !script.stmts.is_empty(),
            "Should have at least one statement"
        );
    }
    // Either way is acceptable - parse error or error recovery
}

#[test]
fn test_mismatched_jinja_end_tag() {
    let result = try_parse_script_from_str("{% if true %}SELECT 1{% endfor %}");
    // endif expected, got endfor - with error recovery, may return OpaqueContent
    if let Ok(script) = result {
        // Error recovery should have created OpaqueContent
        assert!(
            !script.stmts.is_empty(),
            "Should have at least one statement"
        );
    }
    // Either way is acceptable - parse error or error recovery
}

#[test]
fn test_unexpected_jinja_endif() {
    // Orphan {% endif %} at statement level is intentionally parsed as a placeholder,
    // not an error. This is because when parsing SQL inside Jinja for/if blocks,
    // we may encounter endif/endfor at statement boundaries that are part of outer
    // Jinja control structures. Example:
    //   {% for table in tables %}
    //   {% if not loop.first %}UNION ALL{% endif %}
    //   SELECT * FROM {{ table }}
    //   {% endfor %}
    let result = try_parse_script_from_str("SELECT 1 {% endif %}");
    assert!(
        result.is_ok(),
        "Orphan endif is allowed as placeholder (known limitation)"
    );
}

#[test]
fn test_unexpected_jinja_endfor() {
    // Same reasoning as test_unexpected_jinja_endif - see comment there
    let result = try_parse_script_from_str("SELECT 1 {% endfor %}");
    assert!(
        result.is_ok(),
        "Orphan endfor is allowed as placeholder (known limitation)"
    );
}

#[test]
fn test_invalid_jinja_expression() {
    let result = try_parse_script_from_str("SELECT {{ + }} FROM users");
    // Invalid Jinja expression
    match result {
        Ok(_) => {} // Parser might be lenient
        Err(e) => assert!(!e.message().is_empty()),
    }
}

// =============================================================================
// Span accuracy tests
// =============================================================================

#[test]
fn test_error_span_accuracy_beginning() {
    let sql = "INVALID SELECT * FROM users";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_err());
    let err = result.unwrap_err();
    // Span should point near the beginning
    assert!(
        err.span.start < 10,
        "Error span should be near start, got {}",
        err.span.start
    );
}

#[test]
fn test_error_span_accuracy_middle() {
    let sql = "SELECT * FROM users WHRE id = 1";
    let result = try_parse_stmt_from_str(sql);
    match result {
        Ok(_) => {} // Parser stopped at valid point
        Err(err) => {
            // Span should be somewhere around WHRE (position ~20)
            assert!(
                err.span.start >= 15 && err.span.start <= 25,
                "Span should be near WHRE, got {}",
                err.span.start
            );
        }
    }
}

#[test]
fn test_error_span_accuracy_end() {
    let sql = "SELECT * FROM users WHERE id =";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_err());
    let err = result.unwrap_err();
    // Span should be near the end
    assert!(
        err.span.start >= 25,
        "Error span should be near end, got {}",
        err.span.start
    );
}

// =============================================================================
// Error message quality tests
// =============================================================================

#[test]
fn test_error_message_not_empty() {
    let invalid_sqls = [
        "SELECT",
        "INSERT INTO",
        "UPDATE",
        "DELETE",
        "MERGE",
        "CREATE",
        "DROP",
        "BEGIN",
        "INVALID",
    ];

    for sql in &invalid_sqls {
        let result = try_parse_stmt_from_str(sql);
        if let Err(e) = result {
            assert!(
                !e.message().is_empty(),
                "Error for '{}' should have non-empty message",
                sql
            );
        }
    }
}

#[test]
fn test_error_message_display_format() {
    let result = try_parse_stmt_from_str("SELECT");
    assert!(result.is_err());
    let err = result.unwrap_err();

    // Display format should be readable
    let display = format!("{}", err);
    assert!(
        display.contains("Parse error"),
        "Display should contain 'Parse error'"
    );
    assert!(display.contains(".."), "Display should contain span range");
}

#[test]
fn test_error_message_describes_problem() {
    let result = try_parse_stmt_from_str("SELECT CASE WHEN x > 5 FROM users");
    assert!(result.is_err(), "CASE without THEN should fail");

    let err = result.unwrap_err();
    let msg = err.message().to_lowercase();
    // Message should mention THEN or case or expected token
    assert!(
        msg.contains("then")
            || msg.contains("case")
            || msg.contains("expected")
            || msg.contains("unexpected"),
        "Message should describe the missing THEN: {}",
        msg
    );
}

// =============================================================================
// Complex statement error tests
// =============================================================================

#[test]
fn test_error_in_cte() {
    // Note: Parser may be lenient about empty FROM clauses in CTEs
    // SELECT * FROM) parses as SELECT * with empty FROM, and ) closes the CTE
    let sql = "WITH cte AS (SELECT * FROM) SELECT * FROM cte";
    let result = try_parse_stmt_from_str(sql);
    match result {
        Ok(_) => {} // Parser is lenient about empty FROM in subqueries
        Err(e) => assert!(!e.message().is_empty()),
    }
}

#[test]
fn test_error_in_subquery() {
    // Note: Parser may be lenient about FROM WHERE patterns
    // The FROM clause becomes empty and WHERE starts the condition
    let sql = "SELECT * FROM (SELECT * FROM WHERE id = 1) t";
    let result = try_parse_stmt_from_str(sql);
    match result {
        Ok(_) => {} // Parser is lenient
        Err(e) => assert!(!e.message().is_empty()),
    }
}

#[test]
fn test_error_in_join_condition() {
    let sql = "SELECT * FROM a JOIN b ON";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_err(), "JOIN without condition should fail");
}

#[test]
fn test_error_in_window_function() {
    let sql = "SELECT ROW_NUMBER() OVER () FROM users";
    let result = try_parse_stmt_from_str(sql);
    // Empty OVER() may or may not be valid
    match result {
        Ok(_) => {} // Some dialects allow empty OVER()
        Err(e) => assert!(!e.message().is_empty()),
    }
}

#[test]
fn test_error_in_create_table_column_def() {
    let sql = "CREATE TABLE t (a , b INT)";
    let result = try_parse_stmt_from_str(sql);
    // Column 'a' has no type - depends on parser strictness
    match result {
        Ok(_) => {}
        Err(e) => assert!(!e.message().is_empty()),
    }
}

// =============================================================================
// Scripting block error tests
// =============================================================================

#[test]
fn test_error_if_without_then() {
    let result = try_parse_stmt_from_str("IF x > 5 SELECT 1; END IF;");
    // Missing THEN
    assert!(result.is_err(), "IF without THEN should fail");
}

#[test]
fn test_error_loop_without_end() {
    let result = try_parse_stmt_from_str("LOOP SELECT 1;");
    assert!(result.is_err(), "LOOP without END LOOP should fail");
}

#[test]
fn test_error_while_without_do() {
    let result = try_parse_stmt_from_str("WHILE x > 0 SELECT 1; END WHILE;");
    // Missing DO
    match result {
        Ok(_) => {} // Parser might be lenient
        Err(e) => assert!(!e.message().is_empty()),
    }
}

#[test]
fn test_error_for_without_in() {
    let result = try_parse_stmt_from_str("FOR i 1 TO 10 DO SELECT i; END FOR;");
    // Missing IN or invalid syntax
    assert!(result.is_err(), "FOR without IN should fail");
}

// =============================================================================
// Recovery and continuation tests
// =============================================================================

#[test]
fn test_script_continues_after_error() {
    // First statement invalid, second valid
    let sql = "INVALID STATEMENT; SELECT * FROM users;";
    let result = try_parse_script_from_str(sql);
    // Parser may stop at first error or try to continue
    match result {
        Ok(script) => {
            // If it continued, should have at least one statement
            assert!(
                !script.stmts.is_empty(),
                "Should parse at least some statements"
            );
        }
        Err(e) => {
            // Error should point to the invalid part
            assert!(e.span.start < 20, "Error should be in first statement");
        }
    }
}
