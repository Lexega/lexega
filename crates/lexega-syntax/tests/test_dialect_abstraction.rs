// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::dialect::{Dialect, SnowflakeDialect};
use lexega_syntax::{format_sql, try_parse_script_from_str};

#[test]
fn test_default_dialect_is_snowflake() {
    let dialect = SnowflakeDialect;
    assert_eq!(dialect.name(), "snowflake");
}

#[test]
fn test_snowflake_features() {
    let dialect = SnowflakeDialect;

    // Snowflake-specific features should be enabled
    assert!(dialect.supports_qualify());
    assert!(dialect.supports_lateral());
    assert!(dialect.supports_window_functions());
    assert!(dialect.supports_merge());
    assert!(dialect.supports_cte());
}

#[test]
fn test_snowflake_reserved_keywords() {
    let dialect = SnowflakeDialect;

    // Standard SQL keywords should be reserved
    assert!(dialect.is_reserved_keyword("SELECT"));
    assert!(dialect.is_reserved_keyword("select"));
    assert!(dialect.is_reserved_keyword("FROM"));
    assert!(dialect.is_reserved_keyword("WHERE"));

    // Non-keywords should not be reserved
    assert!(!dialect.is_reserved_keyword("my_column"));
    assert!(!dialect.is_reserved_keyword("users"));
}

#[test]
fn test_parsing_with_default_dialect() {
    // Test that parsing still works with default Snowflake dialect
    let sql = "SELECT * FROM users WHERE id > 10";
    let result = try_parse_script_from_str(sql);
    assert!(result.is_ok(), "Should parse with Snowflake dialect");
}

#[test]
fn test_parsing_snowflake_specific_features() {
    // Test QUALIFY (Snowflake-specific)
    let sql = "SELECT * FROM t QUALIFY row_number() OVER (ORDER BY x) = 1";
    let result = try_parse_script_from_str(sql);
    assert!(
        result.is_ok(),
        "Should parse QUALIFY with Snowflake dialect"
    );

    // Test time travel (Snowflake-specific)
    let sql = "SELECT * FROM t AT (TIMESTAMP => '2024-01-01'::TIMESTAMP)";
    let result = try_parse_script_from_str(sql);
    assert!(
        result.is_ok(),
        "Should parse time travel with Snowflake dialect"
    );
}

#[test]
fn test_formatting_preserves_dialect_features() {
    let sql = "SELECT * FROM t QUALIFY row_number() OVER (ORDER BY x) = 1";
    let result = format_sql(sql);
    assert!(result.is_ok(), "Should format QUALIFY clause");

    let formatted = result.unwrap();
    assert!(
        formatted.to_uppercase().contains("QUALIFY"),
        "QUALIFY should be preserved in formatted output"
    );
}

#[test]
fn test_snowflake_operators() {
    let dialect = SnowflakeDialect;

    // || is string concatenation in Snowflake
    assert!(dialect.pipe_pipe_is_concat());

    // Snowflake uses : for JSON, not -> or ->>
    assert!(!dialect.supports_json_operators());

    // => for named arguments
    assert!(dialect.supports_named_args_operator());
}
