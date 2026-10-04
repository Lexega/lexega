// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL TRY...CATCH error handling block support.
///
/// Covers:
///   1. Basic TRY...CATCH — simple error handling
///   2. Nested TRY...CATCH — inner and outer blocks
///   3. TRY...CATCH with transactions — common real-world pattern
///   4. Empty CATCH block — valid MSSQL syntax
///   5. TRY...CATCH with multiple statements in both blocks
///   6. TRY...CATCH inside BEGIN...END block (stored procedure body)
///   7. Multiple sequential TRY...CATCH blocks
use lexega_syntax::dialect::mssql;
use lexega_syntax::{format_sql_with_config, FormatterConfig};

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

fn format_mssql(sql: &str) -> String {
    let config = mssql_config();
    format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for MSSQL: {}\nSQL: {}", e, sql))
}

// ============================================================================
// 1. Basic TRY...CATCH
// ============================================================================

#[test]
fn test_try_catch_basic() {
    format_and_verify(
        "BEGIN TRY\n    SELECT 1/0;\nEND TRY\nBEGIN CATCH\n    SELECT ERROR_MESSAGE();\nEND CATCH;",
    );
}

#[test]
fn test_try_catch_preserves_structure() {
    let sql =
        "BEGIN TRY\n    SELECT 1/0;\nEND TRY\nBEGIN CATCH\n    SELECT ERROR_MESSAGE();\nEND CATCH;";
    let formatted = format_mssql(sql);
    assert!(formatted.contains("BEGIN TRY"), "Should preserve BEGIN TRY");
    assert!(formatted.contains("END TRY"), "Should preserve END TRY");
    assert!(
        formatted.contains("BEGIN CATCH"),
        "Should preserve BEGIN CATCH"
    );
    assert!(formatted.contains("END CATCH"), "Should preserve END CATCH");
}

#[test]
fn test_try_catch_single_statement_in_each_block() {
    format_and_verify(
        "BEGIN TRY\n    INSERT INTO t VALUES (1);\nEND TRY\nBEGIN CATCH\n    SELECT 'error';\nEND CATCH;",
    );
}

// ============================================================================
// 2. Nested TRY...CATCH
// ============================================================================

#[test]
fn test_try_catch_nested() {
    let sql = r#"BEGIN TRY
    BEGIN TRY
        INSERT INTO t VALUES (1);
    END TRY
    BEGIN CATCH
        SELECT 'inner error';
    END CATCH
END TRY
BEGIN CATCH
    SELECT ERROR_NUMBER(), ERROR_MESSAGE();
END CATCH;"#;
    format_and_verify(sql);
}

#[test]
fn test_try_catch_nested_in_catch() {
    let sql = r#"BEGIN TRY
    SELECT 1/0;
END TRY
BEGIN CATCH
    BEGIN TRY
        INSERT INTO error_log (msg) VALUES (ERROR_MESSAGE());
    END TRY
    BEGIN CATCH
        SELECT 'logging failed';
    END CATCH
END CATCH;"#;
    format_and_verify(sql);
}

// ============================================================================
// 3. TRY...CATCH with transactions
// ============================================================================

#[test]
fn test_try_catch_with_transaction() {
    let sql = r#"BEGIN TRY
    BEGIN TRANSACTION;
    UPDATE accounts SET balance = balance - 100 WHERE id = 1;
    UPDATE accounts SET balance = balance + 100 WHERE id = 2;
    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    ROLLBACK TRANSACTION;
END CATCH;"#;
    format_and_verify(sql);
}

#[test]
fn test_try_catch_with_commit_only() {
    let sql = r#"BEGIN TRY
    BEGIN TRANSACTION;
    INSERT INTO orders (product_id) VALUES (42);
    COMMIT;
END TRY
BEGIN CATCH
    ROLLBACK;
END CATCH;"#;
    format_and_verify(sql);
}

// ============================================================================
// 4. Empty/minimal CATCH block
// ============================================================================

#[test]
fn test_try_catch_empty_catch_body() {
    // Empty CATCH block is valid in MSSQL (ignore errors)
    let sql = "BEGIN TRY\n    SELECT 1/0;\nEND TRY\nBEGIN CATCH\nEND CATCH;";
    format_and_verify(sql);
}

// ============================================================================
// 5. Multiple statements in TRY and CATCH blocks
// ============================================================================

#[test]
fn test_try_catch_multiple_statements() {
    let sql = r#"BEGIN TRY
    DECLARE @x INT;
    SET @x = 1;
    INSERT INTO t1 VALUES (@x);
    INSERT INTO t2 VALUES (@x + 1);
END TRY
BEGIN CATCH
    SELECT ERROR_NUMBER();
    SELECT ERROR_MESSAGE();
    SELECT ERROR_SEVERITY();
    SELECT ERROR_STATE();
END CATCH;"#;
    format_and_verify(sql);
}

// ============================================================================
// 6. TRY...CATCH inside BEGIN...END block
// ============================================================================

#[test]
fn test_try_catch_inside_begin_end() {
    let sql = r#"BEGIN
    BEGIN TRY
        DELETE FROM orders WHERE order_date < '2020-01-01';
    END TRY
    BEGIN CATCH
        SELECT ERROR_MESSAGE();
    END CATCH
END;"#;
    format_and_verify(sql);
}

// ============================================================================
// 7. Multiple sequential TRY...CATCH blocks
// ============================================================================

#[test]
fn test_multiple_try_catch_blocks() {
    let sql = r#"BEGIN TRY
    INSERT INTO t1 VALUES (1);
END TRY
BEGIN CATCH
    SELECT 'error in t1';
END CATCH;

BEGIN TRY
    INSERT INTO t2 VALUES (2);
END TRY
BEGIN CATCH
    SELECT 'error in t2';
END CATCH;"#;
    format_and_verify(sql);
}

// ============================================================================
// 8. TRY...CATCH with DML statements
// ============================================================================

#[test]
fn test_try_catch_with_update() {
    let sql = r#"BEGIN TRY
    UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
END TRY
BEGIN CATCH
    SELECT ERROR_MESSAGE();
END CATCH;"#;
    format_and_verify(sql);
}

#[test]
fn test_try_catch_with_delete() {
    let sql = r#"BEGIN TRY
    DELETE FROM temp_data WHERE created_at < '2024-01-01';
END TRY
BEGIN CATCH
    SELECT ERROR_MESSAGE();
END CATCH;"#;
    format_and_verify(sql);
}

// ============================================================================
// 9. TRY...CATCH should parse as a proper AST node
// ============================================================================

#[test]
fn test_try_catch_is_not_opaque() {
    // Verify TRY...CATCH is parsed into a real AST node, not OpaqueContent
    use lexega_syntax::parse_sql_with_dialect;
    let sql = "BEGIN TRY\n    SELECT 1;\nEND TRY\nBEGIN CATCH\n    SELECT 2;\nEND CATCH;";
    let script = parse_sql_with_dialect(sql, mssql().as_ref()).expect("should parse");
    assert_eq!(
        script.stmts.len(),
        1,
        "Should be a single TRY...CATCH statement"
    );
    match &script.stmts[0] {
        lexega_syntax::AstStmt::MssqlTryCatch(tc) => {
            assert!(!tc.try_body.is_empty(), "TRY body should have content");
            assert!(!tc.catch_body.is_empty(), "CATCH body should have content");
        }
        other => panic!(
            "Expected MssqlTryCatch, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}
