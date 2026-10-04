// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Snowflake Scripting statement tests
// Tests for EXECUTE IMMEDIATE, RAISE, OBJECT_CONSTRUCT, and other scripting features
use lexega_syntax::parse_sql;

#[test]
fn test_execute_immediate_with_using_clause() {
    let src = r#"
BEGIN
    LET sql_stmt := 'SELECT COUNT(*) FROM table WHERE col = ?';
    EXECUTE IMMEDIATE :sql_stmt USING (value) INTO :result;
    RETURN result;
END;
"#;

    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse EXECUTE IMMEDIATE with USING"
    );
}

#[test]
fn test_raise_exception_with_code_and_message() {
    let src = r#"
BEGIN
    LET x := 0;
    IF (x = 0) THEN
        RAISE EXCEPTION -20001, 'Custom error message';
    END IF;
    RETURN x;
END;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse RAISE EXCEPTION with code");
}

#[test]
fn test_object_construct_function() {
    let src = r#"
BEGIN
    LET result := OBJECT_CONSTRUCT(
        'key1', 'value1',
        'key2', 123,
        'key3', CURRENT_TIMESTAMP()
    );
    RETURN result;
END;
"#;

    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse OBJECT_CONSTRUCT");
}
