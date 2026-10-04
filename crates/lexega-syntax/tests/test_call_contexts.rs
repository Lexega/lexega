// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for CALL statements in both scripting and non-scripting contexts
// Verifies consistent behavior and formatting regardless of context

use lexega_syntax::{format_sql_with_config, parse_sql, FormatterConfig};

/// Test CALL statement in standalone (non-scripting) context
#[test]
fn test_call_standalone_simple() {
    let input = "CALL my_procedure(123, 'test');";
    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Should parse and format successfully
    assert!(result.contains("CALL"));
    assert!(result.contains("my_procedure"));
}

/// Test CALL statement inside BEGIN...END scripting block
#[test]
fn test_call_inside_scripting_block() {
    let input = r#"
BEGIN
    LET x := 10;
    CALL my_procedure(x, 'test');
    RETURN x;
END;
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL inside BEGIN...END");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("my_procedure"));
}

/// Test CALL with complex arguments in standalone context
#[test]
fn test_call_standalone_complex_args() {
    let input = "CALL calculate_metrics(CURRENT_DATE(), 100, 'active', NULL);";

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL with complex args");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("calculate_metrics"));
    assert!(result.contains("CURRENT_DATE"));
}

/// Test CALL with complex arguments inside scripting block
#[test]
fn test_call_scripting_complex_args() {
    let input = r#"
BEGIN
    CALL calculate_metrics(CURRENT_DATE(), 100, 'active', NULL);
END;
"#;

    let parsed = parse_sql(input);
    assert!(
        parsed.is_ok(),
        "failed to parse CALL with complex args in block"
    );

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("calculate_metrics"));
}

/// Test CALL with schema-qualified procedure name
#[test]
fn test_call_qualified_name_standalone() {
    let input = "CALL my_schema.my_procedure(1, 2, 3);";

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse qualified CALL");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("my_schema"));
    assert!(result.contains("my_procedure"));
}

/// Test CALL with schema-qualified procedure name in scripting
#[test]
fn test_call_qualified_name_scripting() {
    let input = r#"
BEGIN
    CALL my_schema.my_procedure(1, 2, 3);
END;
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse qualified CALL in block");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("my_schema"));
}

/// Test CALL with comments in standalone context
#[test]
fn test_call_with_comments_standalone() {
    let input =
        "CALL /* comment */ my_proc /* before args */ (123 /* in arg */, 'test'); /* trailing */";

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL with comments");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Verify no comment duplication
    assert_eq!(
        input.matches("/* comment */").count(),
        result.matches("/* comment */").count(),
        "Comment duplication detected in standalone CALL"
    );
    assert_eq!(
        input.matches("/* in arg */").count(),
        result.matches("/* in arg */").count(),
        "Comment duplication detected in standalone CALL"
    );
}

/// Test CALL with comments inside scripting block
#[test]
fn test_call_with_comments_scripting() {
    let input = r#"
BEGIN
    CALL /* comment */ my_proc /* before args */ (123 /* in arg */, 'test'); /* trailing */
END;
"#;

    let parsed = parse_sql(input);
    assert!(
        parsed.is_ok(),
        "failed to parse CALL with comments in block"
    );

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Verify no comment duplication
    assert_eq!(
        input.matches("/* comment */").count(),
        result.matches("/* comment */").count(),
        "Comment duplication detected in scripting CALL"
    );
    assert_eq!(
        input.matches("/* in arg */").count(),
        result.matches("/* in arg */").count(),
        "Comment duplication detected in scripting CALL"
    );
}

/// Test multiple CALL statements in sequence (standalone)
#[test]
fn test_multiple_calls_standalone() {
    let input = r#"
CALL proc1(1);
CALL proc2(2);
CALL proc3(3);
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse multiple CALLs");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(result.matches("CALL").count(), 3);
}

/// Test multiple CALL statements inside scripting block
#[test]
fn test_multiple_calls_scripting() {
    let input = r#"
BEGIN
    CALL proc1(1);
    CALL proc2(2);
    CALL proc3(3);
END;
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse multiple CALLs in block");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(result.matches("CALL").count(), 3);
}

/// Test CALL with no arguments (standalone)
#[test]
fn test_call_no_args_standalone() {
    let input = "CALL my_procedure();";

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL with no args");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("my_procedure"));
    assert!(result.contains("()"));
}

/// Test CALL with no arguments (scripting)
#[test]
fn test_call_no_args_scripting() {
    let input = r#"
BEGIN
    CALL my_procedure();
END;
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL with no args in block");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("my_procedure"));
}

/// Test CALL with variable references in scripting context
#[test]
fn test_call_with_variables_scripting() {
    let input = r#"
BEGIN
    LET user_id := 123;
    LET status := 'active';
    CALL update_user(:user_id, :status);
    RETURN user_id;
END;
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL with variable refs");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("update_user"));
    assert!(result.contains(":user_id") || result.contains(": user_id"));
}

/// Test CALL inside IF statement (scripting context)
#[test]
fn test_call_inside_if_statement() {
    let input = r#"
BEGIN
    LET x := 10;
    IF (x > 5) THEN
        CALL process_large_value(x);
    ELSE
        CALL process_small_value(x);
    END IF;
END;
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL inside IF");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert_eq!(result.matches("CALL").count(), 2);
    assert!(result.contains("process_large_value"));
    assert!(result.contains("process_small_value"));
}

/// Test CALL inside LOOP (scripting context)
#[test]
fn test_call_inside_loop() {
    let input = r#"
BEGIN
    LET i := 0;
    LOOP
        CALL process_item(i);
        i := i + 1;
        IF (i >= 10) THEN
            BREAK;
        END IF;
    END LOOP;
END;
"#;

    let parsed = parse_sql(input);
    assert!(parsed.is_ok(), "failed to parse CALL inside LOOP");

    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");

    assert!(result.contains("CALL"));
    assert!(result.contains("process_item"));
}

/// Verify formatting consistency between contexts
#[test]
fn test_call_formatting_consistency() {
    let standalone = "CALL my_procedure(123, 'test', NULL);";
    let scripting = r#"
BEGIN
    CALL my_procedure(123, 'test', NULL);
END;
"#;

    let result_standalone = format_sql_with_config(standalone, &FormatterConfig::default())
        .expect("formatting should succeed");
    let result_scripting = format_sql_with_config(scripting, &FormatterConfig::default())
        .expect("formatting should succeed");

    // Both should parse successfully
    assert!(parse_sql(standalone).is_ok());
    assert!(parse_sql(scripting).is_ok());

    // The CALL statement itself should be formatted identically in both contexts
    let call_pattern = "CALL my_procedure";
    assert!(result_standalone.contains(call_pattern));
    assert!(result_scripting.contains(call_pattern));
}
