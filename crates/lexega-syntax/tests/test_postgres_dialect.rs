// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::dialect::{postgres, snowflake};

#[test]
fn test_postgres_dialect_name() {
    let dialect = postgres();
    assert_eq!(dialect.name(), "postgresql");
}

#[test]
fn test_postgres_reserved_keywords() {
    let dialect = postgres();

    // Core SQL keywords
    assert!(dialect.is_reserved_keyword("SELECT"));
    assert!(dialect.is_reserved_keyword("FROM"));
    assert!(dialect.is_reserved_keyword("WHERE"));
    assert!(dialect.is_reserved_keyword("JOIN"));

    // PostgreSQL-specific reserved
    assert!(dialect.is_reserved_keyword("RETURNING"));
    assert!(dialect.is_reserved_keyword("LATERAL"));
    assert!(dialect.is_reserved_keyword("TABLESAMPLE"));
    assert!(dialect.is_reserved_keyword("OFFSET"));
    assert!(dialect.is_reserved_keyword("FETCH"));

    // Not reserved
    assert!(!dialect.is_reserved_keyword("foo"));
    assert!(!dialect.is_reserved_keyword("my_table"));
}

#[test]
fn test_postgres_all_keywords() {
    let dialect = postgres();

    // Reserved
    assert!(dialect.is_keyword("SELECT"));
    assert!(dialect.is_keyword("RETURNING"));

    // Non-reserved but recognized
    assert!(dialect.is_keyword("ARRAY"));
    assert!(dialect.is_keyword("INTERVAL"));
    assert!(dialect.is_keyword("COALESCE"));
    assert!(dialect.is_keyword("VACUUM"));
    assert!(dialect.is_keyword("ANALYZE"));
    assert!(dialect.is_keyword("EXPLAIN"));
}

#[test]
fn test_postgres_identifier_rules() {
    let dialect = postgres();

    // Double quotes for identifiers
    assert_eq!(dialect.identifier_quote_char(), '"');

    // Max identifier length (NAMEDATALEN - 1)
    assert_eq!(dialect.max_identifier_length(), Some(63));

    // Case insensitive (folds to lowercase in PostgreSQL)
    assert!(!dialect.unquoted_identifiers_case_sensitive());
}

#[test]
fn test_postgres_string_rules() {
    let dialect = postgres();

    // Single quotes for strings
    assert_eq!(dialect.string_quote_char(), '\'');

    // Double quotes are ONLY for identifiers, not strings
    assert!(!dialect.supports_double_quoted_strings());

    // Supports backslash escapes
    assert!(dialect.supports_string_escapes());
}

#[test]
fn test_postgres_comment_rules() {
    let dialect = postgres();

    // PostgreSQL supports nested block comments
    assert!(dialect.supports_nested_block_comments());
}

#[test]
fn test_postgres_statement_support() {
    let dialect = postgres();

    // Supported statements
    assert!(dialect.supports_merge()); // PostgreSQL 15+
    assert!(dialect.supports_cte());
    assert!(dialect.supports_lateral());
    assert!(dialect.supports_window_functions());
    assert!(dialect.supports_values_as_table());

    // Snowflake-specific (NOT supported in PostgreSQL)
    assert!(!dialect.supports_qualify());
    assert!(!dialect.supports_sample()); // Has TABLESAMPLE instead
    assert!(!dialect.supports_time_travel());
    assert!(!dialect.supports_pivot());
    assert!(!dialect.supports_unpivot());
    assert!(!dialect.supports_flatten());
}

#[test]
fn test_postgres_operator_support() {
    let dialect = postgres();

    // String concatenation
    assert!(dialect.pipe_pipe_is_concat());

    // JSON operators
    assert!(dialect.supports_json_operators());

    // Named arguments
    assert!(dialect.supports_named_args_operator());
}

#[test]
fn test_postgres_vs_snowflake_differences() {
    let postgres = postgres();
    let snowflake = snowflake();

    // Dialect names
    assert_eq!(postgres.name(), "postgresql");
    assert_eq!(snowflake.name(), "snowflake");

    // Both use double quotes for identifiers
    assert_eq!(postgres.identifier_quote_char(), '"');
    assert_eq!(snowflake.identifier_quote_char(), '"');

    // Different identifier length limits
    assert_eq!(postgres.max_identifier_length(), Some(63));
    assert_eq!(snowflake.max_identifier_length(), Some(255));

    // Both fold unquoted identifiers (but to different cases)
    assert!(!postgres.unquoted_identifiers_case_sensitive());
    assert!(!snowflake.unquoted_identifiers_case_sensitive());

    // Both use single quotes for strings
    assert_eq!(postgres.string_quote_char(), '\'');
    assert_eq!(snowflake.string_quote_char(), '\'');

    // PostgreSQL ONLY uses single quotes; Snowflake uses double quotes for identifiers only
    assert!(!postgres.supports_double_quoted_strings());
    assert!(!snowflake.supports_double_quoted_strings());

    // Nested comments
    assert!(postgres.supports_nested_block_comments());
    assert!(!snowflake.supports_nested_block_comments());

    // JSON operators
    assert!(postgres.supports_json_operators());
    assert!(!snowflake.supports_json_operators());

    // Snowflake-specific features
    assert!(!postgres.supports_qualify());
    assert!(snowflake.supports_qualify());

    assert!(!postgres.supports_time_travel());
    assert!(snowflake.supports_time_travel());

    assert!(!postgres.supports_flatten());
    assert!(snowflake.supports_flatten());
}

#[test]
fn test_postgres_keyword_case_insensitivity() {
    let dialect = postgres();

    // Test that keywords are recognized regardless of case
    assert!(dialect.is_reserved_keyword("SELECT"));
    assert!(dialect.is_reserved_keyword("select"));
    assert!(dialect.is_reserved_keyword("Select"));

    assert!(dialect.is_keyword("ARRAY"));
    assert!(dialect.is_keyword("array"));
    assert!(dialect.is_keyword("Array"));
}

#[test]
fn test_postgres_british_spelling() {
    let dialect = postgres();

    // PostgreSQL accepts both American and British spelling
    assert!(dialect.is_keyword("ANALYZE"));
    assert!(dialect.is_keyword("ANALYSE"));
}
