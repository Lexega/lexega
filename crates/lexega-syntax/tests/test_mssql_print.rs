// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL PRINT statement support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
use lexega_syntax::ast::AstStmt;
use lexega_syntax::dialect::mssql;
use lexega_syntax::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};

// ============================================================================
// Helpers
// ============================================================================

fn mssql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mssql();
    config
}

fn parse_mssql(sql: &str) -> Vec<AstStmt> {
    let dialect = mssql();
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    script.stmts
}

fn ast_variant_name(stmt: &AstStmt) -> &'static str {
    match stmt {
        AstStmt::MssqlPrint(_) => "MssqlPrint",
        AstStmt::CreateProcedure(_) => "CreateProcedure",
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

fn format_verify_and_assert_variant(sql: &str, expected_variant: &str) {
    let config = mssql_config();

    let stmts = parse_mssql(sql);
    assert!(!stmts.is_empty(), "Should parse at least one statement");
    let variant_name = ast_variant_name(&stmts[0]);
    assert_eq!(
        variant_name, expected_variant,
        "Expected AST variant {}, got {} — parser likely fell back to OpaqueContent\nSQL: {}",
        expected_variant, variant_name, sql
    );

    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed: {}\nSQL: {}", e, sql));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
}

// ============================================================================
// Basic PRINT expressions
// ============================================================================

#[test]
fn test_print_string_literal() {
    format_verify_and_assert_variant("PRINT 'Hello World';", "MssqlPrint");
}

#[test]
fn test_print_variable() {
    format_verify_and_assert_variant("PRINT @message;", "MssqlPrint");
}

#[test]
fn test_print_concatenation() {
    format_verify_and_assert_variant("PRINT 'Count: ' + CAST(@n AS VARCHAR);", "MssqlPrint");
}

#[test]
fn test_print_cast_expression() {
    format_verify_and_assert_variant("PRINT CAST(42 AS VARCHAR(10));", "MssqlPrint");
}

#[test]
fn test_print_numeric() {
    format_verify_and_assert_variant("PRINT 42;", "MssqlPrint");
}

#[test]
fn test_print_unicode_string() {
    format_verify_and_assert_variant("PRINT N'Unicode text';", "MssqlPrint");
}

#[test]
fn test_print_no_semicolon() {
    // MSSQL allows statements without semicolons
    format_verify_and_assert_variant("PRINT 'no semi'", "MssqlPrint");
}

// ============================================================================
// PRINT inside procedure / BEGIN...END
// ============================================================================

#[test]
fn test_print_inside_procedure() {
    let sql = r#"CREATE OR ALTER PROCEDURE dbo.usp_Test
AS
BEGIN
    PRINT 'Starting procedure';
    SELECT 1;
    PRINT 'Done';
END;"#;
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed: {}\nSQL: {}", e, sql));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });

    // Verify PRINT text is preserved in output
    assert!(
        formatted.contains("PRINT 'Starting procedure'"),
        "First PRINT preserved"
    );
    assert!(formatted.contains("PRINT 'Done'"), "Second PRINT preserved");
}

#[test]
fn test_print_inside_begin_end_block() {
    let sql = r#"BEGIN
    PRINT 'Step 1';
    PRINT 'Step 2';
END;"#;
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed: {}\nSQL: {}", e, sql));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
    assert!(
        formatted.contains("PRINT 'Step 1'"),
        "First PRINT preserved"
    );
    assert!(
        formatted.contains("PRINT 'Step 2'"),
        "Second PRINT preserved"
    );
}

#[test]
fn test_print_with_semicolons_inside_block() {
    // Semicolons must be preserved inside blocks
    let sql = r#"BEGIN
    PRINT 'a';
    PRINT 'b';
    PRINT 'c';
END;"#;
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed: {}\nSQL: {}", e, sql));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });

    // Count semicolons — should have at least 3 (one per PRINT) plus the END;
    let semi_count = formatted.matches(';').count();
    assert!(
        semi_count >= 4,
        "Expected at least 4 semicolons (3 PRINT + END), got {}",
        semi_count
    );
}

// ============================================================================
// Multi-statement at top level
// ============================================================================

#[test]
fn test_print_multi_statement() {
    let sql = "PRINT 'first';\nPRINT 'second';\nPRINT 'third';";
    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 3, "Should parse as three statements");
    for (i, stmt) in stmts.iter().enumerate() {
        assert_eq!(
            ast_variant_name(stmt),
            "MssqlPrint",
            "Statement {} should be MssqlPrint, got {}",
            i,
            ast_variant_name(stmt)
        );
    }

    let config = mssql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}

// ============================================================================
// Dialect gating: PRINT is NOT special in non-MSSQL dialects
// ============================================================================

#[test]
fn test_print_as_identifier_in_snowflake() {
    // In Snowflake, "print" is just a regular identifier (column/alias name)
    let sql = "SELECT print FROM my_table;";
    let config = FormatterConfig::default(); // Snowflake
    let formatted = format_sql_with_config(sql, &config).expect("Should format as normal SELECT");
    lexega_syntax::verify_formatting_safe(sql, &formatted).expect("Verification should pass");
    assert!(formatted.contains("print"), "'print' identifier preserved");
}

#[test]
fn test_print_as_alias_in_snowflake() {
    let sql = "SELECT 1 AS print;";
    let config = FormatterConfig::default();
    let formatted = format_sql_with_config(sql, &config).expect("Should format as normal SELECT");
    lexega_syntax::verify_formatting_safe(sql, &formatted).expect("Verification should pass");
}

// ============================================================================
// PRINT mixed with other MSSQL constructs
// ============================================================================

#[test]
fn test_print_in_try_catch() {
    let sql = r#"BEGIN TRY
    SELECT 1 / 0;
END TRY
BEGIN CATCH
    PRINT ERROR_MESSAGE();
END CATCH;"#;
    let config = mssql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
    assert!(
        formatted.contains("PRINT ERROR_MESSAGE()"),
        "PRINT with function call preserved"
    );
}

#[test]
fn test_print_in_if_else() {
    let sql = r#"IF @count > 0
    PRINT 'Found rows'
ELSE
    PRINT 'No rows';"#;
    let config = mssql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}

#[test]
fn test_print_in_while_loop() {
    let sql = r#"WHILE @i < 10
BEGIN
    PRINT CAST(@i AS VARCHAR);
    SET @i = @i + 1;
END;"#;
    let config = mssql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Verification failed: {}", e));
}
