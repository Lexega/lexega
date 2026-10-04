// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for regex functions: RLIKE, REGEXP_REPLACE, REGEXP_COUNT, REGEXP_SUBSTR, REGEXP_INSTR
use lexega_syntax::parse_stmt_from_str;

// RLIKE function-call syntax tests

#[test]
fn test_rlike_function_basic() {
    // RLIKE(subject, pattern)
    let sql = "SELECT * FROM logs WHERE RLIKE(message, '^ERROR.*');";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse RLIKE function basic");
}

#[test]
fn test_rlike_function_with_parameters() {
    // RLIKE(subject, pattern, parameters) - case insensitive
    let sql = "SELECT * FROM data WHERE RLIKE(city, 'san.*', 'i');";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse RLIKE function with parameters"
    );
}

#[test]
fn test_regexp_like_alias() {
    // REGEXP_LIKE is an alias for RLIKE
    let sql =
        "SELECT * FROM users WHERE REGEXP_LIKE(email, '\\\\w+@[a-zA-Z_]+\\\\.[a-zA-Z]{2,3}');";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse REGEXP_LIKE");
}

// REGEXP_REPLACE tests

#[test]
fn test_regexp_replace_basic() {
    // REGEXP_REPLACE(subject, pattern, replacement)
    let sql = "SELECT REGEXP_REPLACE('Hello World', 'World', 'Universe');";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse REGEXP_REPLACE basic");
}

#[test]
fn test_regexp_replace_with_position() {
    // REGEXP_REPLACE(subject, pattern, replacement, position)
    let sql = "SELECT REGEXP_REPLACE('It was the best of times', 'times', 'days', 1);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_REPLACE with position"
    );
}

#[test]
fn test_regexp_replace_with_occurrence() {
    // REGEXP_REPLACE(subject, pattern, replacement, position, occurrence)
    let sql = "SELECT REGEXP_REPLACE('It was the best of times, it was the worst of times', 'times', 'days', 1, 2);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_REPLACE with occurrence"
    );
}

#[test]
fn test_regexp_replace_with_parameters() {
    // REGEXP_REPLACE(subject, pattern, replacement, position, occurrence, parameters)
    let sql = "SELECT REGEXP_REPLACE(body, '\\\\b(\\\\S*)o(\\\\S*)\\\\b', '\\\\2@@\\\\1', 3, 3, 'i') FROM demo;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_REPLACE with all parameters"
    );
}

#[test]
fn test_regexp_replace_remove_spaces() {
    // Doc example: remove all spaces
    let sql = "SELECT REGEXP_REPLACE('It was the best of times', '( ){1,}', '') AS result;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_REPLACE remove spaces"
    );
}

#[test]
fn test_regexp_replace_with_backreferences() {
    // Doc example: using backreferences
    let sql = "SELECT REGEXP_REPLACE('firstname middlename lastname', '(.*) (.*) (.*)', '\\\\3, \\\\1 \\\\2') AS name_sort;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_REPLACE with backreferences"
    );
}

// REGEXP_COUNT tests

#[test]
fn test_regexp_count_basic() {
    // REGEXP_COUNT(subject, pattern)
    let sql = "SELECT REGEXP_COUNT('test test test', 'test');";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse REGEXP_COUNT basic");
}

#[test]
fn test_regexp_count_with_position() {
    // REGEXP_COUNT(subject, pattern, position)
    let sql = "SELECT REGEXP_COUNT('It was the best of times, it was the worst of times', '\\\\bwas\\\\b', 1) AS result;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_COUNT with position"
    );
}

#[test]
fn test_regexp_count_with_parameters() {
    // REGEXP_COUNT(subject, pattern, position, parameters)
    let sql = "SELECT REGEXP_COUNT('Excelence', 'e', 1, 'i') AS e_in_excelence;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_COUNT with parameters"
    );
}

#[test]
fn test_regexp_count_doc_example_errors() {
    // Doc example: count errors
    let sql = "SELECT dt, REGEXP_COUNT(messages, '\\\\bER-[0-9]{4}') AS number_of_errors FROM regexp_count_demo;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse REGEXP_COUNT doc example");
}

// REGEXP_SUBSTR tests

#[test]
fn test_regexp_substr_basic() {
    // REGEXP_SUBSTR(subject, pattern)
    let sql = "SELECT REGEXP_SUBSTR('test@example.com', '[a-z]+@[a-z]+\\\\.[a-z]+');";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse REGEXP_SUBSTR basic");
}

#[test]
fn test_regexp_substr_with_extract() {
    // REGEXP_SUBSTR with 'e' parameter to extract submatches
    let sql =
        "SELECT REGEXP_SUBSTR('Release 24', 'Release\\\\W+(\\\\d+)', 1, 1, 'e') AS release_number;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse REGEXP_SUBSTR with extract parameter"
    );
}

// REGEXP_INSTR tests

#[test]
fn test_regexp_instr_basic() {
    // REGEXP_INSTR(subject, pattern)
    let sql = "SELECT REGEXP_INSTR('Hello World', 'World');";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse REGEXP_INSTR basic");
}

// Complex queries with regex functions

#[test]
fn test_regex_in_case_expression() {
    let sql = r#"
SELECT 
    CASE 
        WHEN REGEXP_COUNT(email, '@') = 1 THEN 'Valid'
        ELSE 'Invalid'
    END as status
FROM users;
"#;
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse regex in CASE expression");
}

#[test]
fn test_regex_in_where_clause() {
    let sql = "SELECT * FROM products WHERE REGEXP_COUNT(description, 'snowflake', 1, 'i') > 0;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse regex in WHERE clause");
}

#[test]
fn test_nested_regex_functions() {
    let sql = "SELECT REGEXP_REPLACE(REGEXP_SUBSTR(text, 'ID-[0-9]+'), '-', '_') FROM logs;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse nested regex functions");
}

#[test]
fn test_regex_with_cte() {
    let sql = r#"
WITH clean_data AS (
    SELECT REGEXP_REPLACE(phone, '[^0-9]', '') as clean_phone
    FROM contacts
)
SELECT * FROM clean_data WHERE REGEXP_COUNT(clean_phone, '[0-9]') = 10;
"#;
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse regex functions with CTE");
}

#[test]
fn test_multiple_regex_functions_in_select() {
    let sql = r#"
SELECT 
    email,
    REGEXP_COUNT(email, '@') as at_count,
    REGEXP_SUBSTR(email, '[^@]+', 1, 1) as username,
    REGEXP_REPLACE(email, '@.*', '') as local_part
FROM users;
"#;
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse multiple regex functions in SELECT"
    );
}
