// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::ast::UnknownKind;
/// Test the defensive design pattern: unknown Snowflake features are preserved
/// instead of causing parse failures.
///
/// This test verifies that when Snowflake adds new properties/clauses that our
/// parser doesn't recognize, we capture them as AstUnknownClause entries and
/// preserve them in formatting, ensuring forward compatibility.
use lexega_syntax::{format_sql_with_config, try_parse_script_from_str, AstStmt, FormatterConfig};

#[test]
fn test_alter_stage_unknown_property() {
    // Simulates a future Snowflake SET property we don't recognize yet
    let sql = r#"
ALTER STAGE my_stage
  SET FUTURE_SNOWFLAKE_PROPERTY = 'some_value';
"#;

    // Should parse without error (defensive pattern)
    let result = try_parse_script_from_str(sql);
    assert!(
        result.is_ok(),
        "Parser should handle unknown SET properties gracefully"
    );

    let script = result.unwrap();

    // Check that we captured the unknown property
    if let Some(stmt) = script.stmts.first() {
        if let AstStmt::AlterStage(alter_stage) = &stmt {
            // Should have captured the unknown property in extras
            assert!(
                !alter_stage.extras.is_empty(),
                "Unknown SET property should be captured in extras Vec"
            );

            assert_eq!(
                alter_stage.extras.len(),
                1,
                "Should have exactly one unknown property"
            );

            // Verify it's marked as the right kind (Property for SET unknown props)
            assert_eq!(alter_stage.extras[0].kind, UnknownKind::Property);
        } else {
            panic!("Expected AlterStage statement");
        }
    } else {
        panic!("Expected at least one statement");
    }

    // Should format without error (preservation)
    let formatted = format_sql_with_config(sql, &FormatterConfig::default());
    assert!(
        formatted.is_ok(),
        "Formatter should preserve unknown properties"
    );
}

#[test]
fn test_create_stage_unknown_property() {
    // Simulates a future Snowflake CREATE STAGE feature
    let sql = r#"
CREATE STAGE my_stage
  URL = 's3://mybucket/path'
  ENCRYPTION = (TYPE = 'AWS_SSE_S3')
  NEW_SNOWFLAKE_OPTION = 'value'
  COMMENT = 'Test stage';
"#;

    // Should parse without error
    let result = try_parse_script_from_str(sql);
    assert!(
        result.is_ok(),
        "Parser should handle unknown CREATE STAGE properties gracefully"
    );

    let script = result.unwrap();

    // Check that we captured the unknown property
    if let Some(stmt) = script.stmts.first() {
        if let AstStmt::CreateStage(create_stage) = &stmt {
            assert!(
                !create_stage.extras.is_empty(),
                "Unknown property should be captured in extras Vec"
            );

            assert_eq!(
                create_stage.extras.len(),
                1,
                "Should have exactly one unknown property"
            );
        } else {
            panic!("Expected CreateStage statement");
        }
    }

    // Should format without error
    let formatted = format_sql_with_config(sql, &FormatterConfig::default());
    assert!(
        formatted.is_ok(),
        "Formatter should preserve unknown properties"
    );
}

#[test]
fn test_known_properties_not_in_extras() {
    // All known properties should be parsed normally, not go into extras
    // Note: In Snowflake, SET ENCRYPTION and SET TAG are separate statement forms
    // We test with two separate statements
    let sql = r#"
ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'AWS_SSE_S3');
ALTER STAGE my_stage SET TAG owner = 'team';
"#;

    let result = try_parse_script_from_str(sql);
    assert!(result.is_ok());

    let script = result.unwrap();

    // Both statements should have no unknowns
    for stmt in &script.stmts {
        if let AstStmt::AlterStage(alter_stage) = &stmt {
            // Known properties should NOT be in extras
            assert!(
                alter_stage.extras.is_empty(),
                "Known properties should be parsed normally, not captured as unknown"
            );
        }
    }
}

#[test]
fn test_formatting_preserves_unknown_properties() {
    // Test that unknown properties are preserved exactly in formatted output
    let sql = r#"ALTER STAGE my_stage SET FUTURE_PROPERTY = 'value';"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Should format without error");

    // Unknown property text should be preserved in output
    assert!(
        formatted.contains("FUTURE_PROPERTY"),
        "Unknown property name should be preserved in formatted output"
    );
    assert!(
        formatted.contains("'value'"),
        "Unknown property value should be preserved in formatted output"
    );
}

#[test]
fn test_create_stage_formatting_preserves_unknown() {
    let sql = r#"CREATE STAGE s URL = 's3://bucket' NEW_OPTION = 'val' COMMENT = 'test';"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Should format without error");

    // All parts should be preserved
    assert!(
        formatted.contains("NEW_OPTION"),
        "Unknown option should be preserved"
    );
    assert!(
        formatted.contains("'val'"),
        "Unknown value should be preserved"
    );
    assert!(formatted.contains("URL"), "Known clauses should still work");
    assert!(
        formatted.contains("COMMENT"),
        "Known clauses should still work"
    );
}
