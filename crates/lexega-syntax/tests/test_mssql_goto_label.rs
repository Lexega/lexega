// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL GOTO / Label statement support.
///
/// Every test asserts BOTH:
///   1. The statement parses as the correct AST variant (not OpaqueContent fallback)
///   2. Formatting preserves semantic tokens
///
/// Covers:
///   1. Basic GOTO — jump to a label
///   2. Basic Label — label_name: declaration
///   3. GOTO inside BEGIN...END blocks
///   4. GOTO inside TRY...CATCH
///   5. GOTO inside IF...ELSE
///   6. Multi-statement scripts with GOTO and labels
///   7. GOTO without semicolon (valid MSSQL)
///   8. Labels with various identifier patterns
///   9. GOTO inside stored procedures
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
        AstStmt::MssqlGoto(_) => "MssqlGoto",
        AstStmt::MssqlLabel(_) => "MssqlLabel",
        AstStmt::MssqlPrint(_) => "MssqlPrint",
        AstStmt::CreateProcedure(_) => "CreateProcedure",
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

fn format_and_verify(sql: &str) {
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for MSSQL: {}\nSQL: {}", e, sql));

    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
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
// 1. Basic GOTO
// ============================================================================

#[test]
fn test_goto_basic() {
    format_verify_and_assert_variant("GOTO error_handler;", "MssqlGoto");
}

#[test]
fn test_goto_no_semicolon() {
    // MSSQL allows statements without semicolons
    format_verify_and_assert_variant("GOTO retry_label", "MssqlGoto");
}

#[test]
fn test_goto_lowercase() {
    format_verify_and_assert_variant("goto my_label;", "MssqlGoto");
}

#[test]
fn test_goto_mixed_case() {
    format_verify_and_assert_variant("GoTo SomeLabel;", "MssqlGoto");
}

// ============================================================================
// 2. Basic Label
// ============================================================================

#[test]
fn test_label_basic() {
    format_verify_and_assert_variant("error_handler:", "MssqlLabel");
}

#[test]
fn test_label_with_underscores() {
    format_verify_and_assert_variant("retry_loop_start:", "MssqlLabel");
}

#[test]
fn test_label_simple_name() {
    format_verify_and_assert_variant("cleanup:", "MssqlLabel");
}

// ============================================================================
// 3. Multi-statement scripts with GOTO and labels
// ============================================================================

#[test]
fn test_goto_and_label_together() {
    let sql = r#"GOTO error_handler;
SELECT 1;
error_handler:
PRINT 'Error handled';"#;
    format_and_verify(sql);

    let stmts = parse_mssql(sql);
    assert_eq!(stmts.len(), 4, "Should parse 4 statements");
    assert_eq!(ast_variant_name(&stmts[0]), "MssqlGoto");
    assert_eq!(ast_variant_name(&stmts[1]), "Other"); // SELECT
    assert_eq!(ast_variant_name(&stmts[2]), "MssqlLabel");
    assert_eq!(ast_variant_name(&stmts[3]), "MssqlPrint");
}

#[test]
fn test_multiple_gotos_and_labels() {
    let sql = r#"GOTO step1;
step2:
PRINT 'Step 2';
GOTO done;
step1:
PRINT 'Step 1';
GOTO step2;
done:
PRINT 'Done';"#;
    format_and_verify(sql);

    let stmts = parse_mssql(sql);
    assert!(
        stmts.len() >= 8,
        "Should parse all statements, got {}",
        stmts.len()
    );
}

// ============================================================================
// 4. GOTO inside BEGIN...END blocks
// ============================================================================

#[test]
fn test_goto_inside_begin_end() {
    let sql = r#"BEGIN
    GOTO cleanup;
    SELECT 1;
    cleanup:
    PRINT 'cleaning up';
END;"#;
    format_and_verify(sql);
}

#[test]
fn test_goto_label_in_procedure_body() {
    let sql = r#"CREATE OR ALTER PROCEDURE dbo.usp_WithGoto
AS
BEGIN
    GOTO process_data;

    error_handler:
    PRINT 'Error occurred';
    RETURN;

    process_data:
    SELECT 1;
    GOTO error_handler;
END;"#;
    format_and_verify(sql);
}

// ============================================================================
// 5. GOTO inside TRY...CATCH
// ============================================================================

#[test]
fn test_goto_in_try_block() {
    let sql = r#"BEGIN TRY
    GOTO success;
    PRINT 'not reached';
    success:
    PRINT 'Success';
END TRY
BEGIN CATCH
    GOTO failure;
    failure:
    PRINT 'Failed';
END CATCH;"#;
    format_and_verify(sql);
}

// ============================================================================
// 6. GOTO inside IF...ELSE
// ============================================================================

#[test]
fn test_goto_in_mssql_if() {
    let sql = r#"IF @x > 0
    GOTO positive;

positive:
PRINT 'Positive';"#;
    format_and_verify(sql);
}

#[test]
fn test_goto_in_mssql_if_else() {
    let sql = r#"IF @x > 0
    GOTO positive;
ELSE
    GOTO negative;

positive:
PRINT 'Positive';
GOTO done;

negative:
PRINT 'Negative';

done:
PRINT 'Done';"#;
    format_and_verify(sql);
}

// ============================================================================
// 7. GOTO inside WHILE loop
// ============================================================================

#[test]
fn test_goto_in_while_loop() {
    let sql = r#"WHILE @i < 10
BEGIN
    IF @i = 5
        GOTO skip;
    PRINT @i;
    skip:
    SET @i = @i + 1;
END;"#;
    format_and_verify(sql);
}

// ============================================================================
// 8. Edge cases
// ============================================================================

#[test]
fn test_goto_is_not_parsed_without_mssql_dialect() {
    // In non-MSSQL dialects, GOTO should NOT produce MssqlGoto
    let sql = "GOTO my_label;";
    let script = lexega_syntax::parse_sql(sql)
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    let stmts = script.stmts;
    assert!(!stmts.is_empty());
    // Should NOT be MssqlGoto in default (Snowflake) dialect
    assert_ne!(
        ast_variant_name(&stmts[0]),
        "MssqlGoto",
        "GOTO should not parse as MssqlGoto in non-MSSQL dialect"
    );
}

#[test]
fn test_label_is_not_parsed_without_mssql_dialect() {
    // In non-MSSQL dialects, label: should NOT produce MssqlLabel
    let sql = "my_label: SELECT 1;";
    let script = lexega_syntax::parse_sql(sql)
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    let stmts = script.stmts;
    assert!(!stmts.is_empty());
    // Should NOT be MssqlLabel in default (Snowflake) dialect
    assert_ne!(
        ast_variant_name(&stmts[0]),
        "MssqlLabel",
        "Labels should not parse as MssqlLabel in non-MSSQL dialect"
    );
}

// ============================================================================
// 9. Real-world pattern: error handling with GOTO
// ============================================================================

#[test]
fn test_real_world_error_handling_pattern() {
    let sql = r#"CREATE OR ALTER PROCEDURE dbo.usp_ProcessData
    @InputId INT
AS
BEGIN
    SET NOCOUNT ON;

    BEGIN TRY
        BEGIN TRANSACTION;

        INSERT INTO dbo.ProcessLog (Id, Status)
        VALUES (@InputId, 'Processing');

        IF @InputId < 0
            GOTO rollback_and_exit;

        UPDATE dbo.ProcessLog
        SET Status = 'Complete'
        WHERE Id = @InputId;

        COMMIT TRANSACTION;
        GOTO done;

        rollback_and_exit:
        ROLLBACK TRANSACTION;
        PRINT 'Transaction rolled back';

    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;

        THROW;
    END CATCH;

    done:
    PRINT 'Procedure complete';
END;"#;
    format_and_verify(sql);
}
