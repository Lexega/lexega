// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL T-SQL control flow: IF...ELSE and WHILE.
///
/// Covers:
///   1. Basic IF — single statement body
///   2. IF with BEGIN...END block body
///   3. IF...ELSE — both branches
///   4. IF...ELSE with BEGIN...END blocks
///   5. Nested IF — IF inside IF
///   6. IF with EXISTS condition
///   7. WHILE with BEGIN...END block
///   8. WHILE with single statement
///   9. WHILE with BREAK/CONTINUE
///  10. Nested WHILE inside IF
///  11. IF/WHILE inside BEGIN...END block
///  12. IF/WHILE inside TRY...CATCH
///  13. Multiple sequential IF/WHILE statements
///  14. AST node verification (MssqlIf / MssqlWhile variants)
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

fn parse_mssql(sql: &str) -> Vec<AstStmt> {
    let dialect = mssql();
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    script.stmts
}

// ============================================================================
// 1. Basic IF — single statement body
// ============================================================================

#[test]
fn test_if_basic_single_statement() {
    let sql = "IF @x > 0\n    SELECT 'positive';";
    format_and_verify(sql);
}

#[test]
fn test_if_basic_set() {
    let sql = "IF @count > 0\n    SET @result = 1;";
    format_and_verify(sql);
}

// ============================================================================
// 2. IF with BEGIN...END block body
// ============================================================================

#[test]
fn test_if_with_begin_end_block() {
    let sql = r#"IF @x > 0
BEGIN
    SET @y = 1
    SET @z = 2
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 3. IF...ELSE — both branches
// ============================================================================

#[test]
fn test_if_else_single_statements() {
    let sql = "IF @x > 0\n    SELECT 'positive'\nELSE\n    SELECT 'non-positive';";
    format_and_verify(sql);
}

#[test]
fn test_if_else_with_semicolons() {
    // Semicolon between body and ELSE
    let sql = "IF @x > 0\n    SELECT 'yes';\nELSE\n    SELECT 'no';";
    format_and_verify(sql);
}

// ============================================================================
// 4. IF...ELSE with BEGIN...END blocks
// ============================================================================

#[test]
fn test_if_else_begin_end_blocks() {
    let sql = r#"IF @x > 0
BEGIN
    SET @y = 1
    SET @z = 2
END
ELSE
BEGIN
    SET @y = 0
    SET @z = 0
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 5. Nested IF — IF inside IF
// ============================================================================

#[test]
fn test_nested_if() {
    let sql = r#"IF @x > 0
    IF @y > 0
        SELECT 'both positive'
    ELSE
        SELECT 'x only'
ELSE
    SELECT 'x non-positive';"#;
    format_and_verify(sql);
}

#[test]
fn test_nested_if_with_blocks() {
    let sql = r#"IF @x > 0
BEGIN
    IF @y > 0
    BEGIN
        SET @result = 'both'
    END
    ELSE
    BEGIN
        SET @result = 'x only'
    END
END
ELSE
BEGIN
    SET @result = 'none'
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 6. IF with EXISTS condition
// ============================================================================

#[test]
fn test_if_exists_condition() {
    let sql = "IF EXISTS (SELECT 1 FROM users WHERE active = 1)\n    SELECT 'has active users';";
    format_and_verify(sql);
}

#[test]
fn test_if_not_exists_condition() {
    let sql = "IF NOT EXISTS (SELECT 1 FROM orders WHERE customer_id = @id)\n    INSERT INTO orders (customer_id) VALUES (@id);";
    format_and_verify(sql);
}

// ============================================================================
// 7. WHILE with BEGIN...END block
// ============================================================================

#[test]
fn test_while_basic_block() {
    let sql = r#"WHILE @i < 10
BEGIN
    SET @i = @i + 1
END"#;
    format_and_verify(sql);
}

#[test]
fn test_while_complex_block() {
    let sql = r#"WHILE @i < 100
BEGIN
    INSERT INTO results (val) VALUES (@i)
    SET @i = @i + 1
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 8. WHILE with single statement
// ============================================================================

#[test]
fn test_while_single_statement() {
    let sql = "WHILE @i < 10\n    SET @i = @i + 1;";
    format_and_verify(sql);
}

// ============================================================================
// 9. WHILE with BREAK/CONTINUE
// ============================================================================

#[test]
fn test_while_with_break_continue() {
    let sql = r#"WHILE 1 = 1
BEGIN
    SET @i = @i + 1
    IF @i > 10
        BREAK
    IF @i % 2 = 0
        CONTINUE
    SELECT @i
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 10. Nested WHILE inside IF
// ============================================================================

#[test]
fn test_while_inside_if() {
    let sql = r#"IF @count > 0
BEGIN
    WHILE @i < @count
    BEGIN
        SET @i = @i + 1
    END
END"#;
    format_and_verify(sql);
}

#[test]
fn test_if_inside_while() {
    let sql = r#"WHILE @i < 10
BEGIN
    IF @i % 2 = 0
        SELECT @i
    SET @i = @i + 1
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 11. IF/WHILE inside BEGIN...END block
// ============================================================================

#[test]
fn test_if_inside_begin_end() {
    let sql = r#"BEGIN
    IF @x > 0
        SET @y = 1
    ELSE
        SET @y = 0
END"#;
    format_and_verify(sql);
}

#[test]
fn test_while_inside_begin_end() {
    let sql = r#"BEGIN
    WHILE @i < 10
    BEGIN
        SET @i = @i + 1
    END
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 12. IF/WHILE inside TRY...CATCH
// ============================================================================

#[test]
fn test_if_inside_try_catch() {
    let sql = r#"BEGIN TRY
    IF @x > 0
        SELECT @x
    ELSE
        SELECT 0
END TRY
BEGIN CATCH
    SELECT 'error'
END CATCH"#;
    format_and_verify(sql);
}

#[test]
fn test_while_inside_try_catch() {
    let sql = r#"BEGIN TRY
    WHILE @i < 10
    BEGIN
        SET @i = @i + 1
    END
END TRY
BEGIN CATCH
    SELECT 'error'
END CATCH"#;
    format_and_verify(sql);
}

// ============================================================================
// 13. Multiple sequential IF/WHILE statements
// ============================================================================

#[test]
fn test_multiple_if_statements() {
    let sql = r#"IF @a > 0
    SET @x = 1;

IF @b > 0
    SET @y = 2;

IF @c > 0
    SET @z = 3;"#;
    format_and_verify(sql);
}

#[test]
fn test_if_then_while() {
    let sql = r#"IF @count > 0
    SET @running = 1;

WHILE @i < @count
BEGIN
    SET @i = @i + 1
END"#;
    format_and_verify(sql);
}

// ============================================================================
// 14. AST node verification
// ============================================================================

#[test]
fn test_ast_mssql_if_variant() {
    let stmts = parse_mssql("IF @x > 0\n    SELECT 1;");
    assert_eq!(stmts.len(), 1, "Should parse as one IF statement");
    assert!(
        matches!(&stmts[0], AstStmt::MssqlIf(_)),
        "Should be MssqlIf variant, got: {:?}",
        std::mem::discriminant(&stmts[0])
    );
}

#[test]
fn test_ast_mssql_if_else_variant() {
    let stmts = parse_mssql("IF @x > 0\n    SELECT 1\nELSE\n    SELECT 0;");
    assert_eq!(stmts.len(), 1, "Should parse as one IF...ELSE statement");
    if let AstStmt::MssqlIf(ref s) = stmts[0] {
        assert!(s.else_span.is_some(), "Should have ELSE span");
        assert_eq!(s.else_body.len(), 1, "ELSE should have one body statement");
        assert_eq!(s.then_body.len(), 1, "IF should have one body statement");
    } else {
        panic!("Expected MssqlIf variant");
    }
}

#[test]
fn test_ast_mssql_while_variant() {
    let stmts = parse_mssql("WHILE @i < 10\nBEGIN\n    SET @i = @i + 1\nEND");
    assert_eq!(stmts.len(), 1, "Should parse as one WHILE statement");
    assert!(
        matches!(&stmts[0], AstStmt::MssqlWhile(_)),
        "Should be MssqlWhile variant, got: {:?}",
        std::mem::discriminant(&stmts[0])
    );
}

#[test]
fn test_ast_mssql_while_body() {
    let stmts = parse_mssql("WHILE @i < 10\n    SET @i = @i + 1;");
    assert_eq!(stmts.len(), 1);
    if let AstStmt::MssqlWhile(ref w) = stmts[0] {
        assert_eq!(
            w.body.len(),
            1,
            "WHILE should have exactly one body statement"
        );
    } else {
        panic!("Expected MssqlWhile variant");
    }
}

// ============================================================================
// 15. Real-world T-SQL patterns
// ============================================================================

#[test]
fn test_real_world_cursor_pattern() {
    // Common T-SQL pattern: WHILE with @@FETCH_STATUS
    let sql = r#"WHILE @@FETCH_STATUS = 0
BEGIN
    SELECT @name
    SET @i = @i + 1
END"#;
    format_and_verify(sql);
}

#[test]
fn test_real_world_retry_pattern() {
    // Common retry pattern with nested IF + WHILE
    let sql = r#"WHILE @retries < 3
BEGIN
    BEGIN TRY
        INSERT INTO target SELECT * FROM source
        SET @retries = 3
    END TRY
    BEGIN CATCH
        SET @retries = @retries + 1
        IF @retries >= 3
            SELECT 'Max retries exceeded'
    END CATCH
END"#;
    format_and_verify(sql);
}

#[test]
fn test_real_world_conditional_insert() {
    let sql = r#"IF NOT EXISTS (SELECT 1 FROM dbo.config WHERE [key] = 'version')
    INSERT INTO dbo.config ([key], [value]) VALUES ('version', '1.0')
ELSE
    UPDATE dbo.config SET [value] = '1.0' WHERE [key] = 'version';"#;
    format_and_verify(sql);
}

#[test]
fn test_comparison_expression_while() {
    // Boolean-style condition
    let sql = "WHILE 1 = 1\n    SELECT 1;";
    format_and_verify(sql);
}
