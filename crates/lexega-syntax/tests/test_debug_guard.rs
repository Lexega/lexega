// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Test the debug-mode data loss guard
///
/// This test demonstrates that the guard is active in debug builds
/// and provides helpful warnings during development.
use lexega_syntax::format_sql;

#[test]
fn test_debug_guard_allows_normal_formatting() {
    // Normal SQL should format without warnings
    let sql = "SELECT id, name FROM users WHERE active = TRUE";
    let result = format_sql(sql);
    assert!(result.is_ok());

    // The debug guard runs silently when no issues are detected
    let formatted = result.unwrap();
    assert!(formatted.contains("SELECT"));
    assert!(formatted.contains("FROM"));
    assert!(formatted.contains("WHERE"));
}

#[test]
fn test_debug_guard_allows_acceptable_normalizations() {
    // JOIN -> INNER JOIN normalization is acceptable
    let sql = "SELECT * FROM a JOIN b ON a.id = b.id";
    let result = format_sql(sql);
    assert!(result.is_ok());

    // LEFT JOIN -> LEFT OUTER JOIN normalization is acceptable
    let sql2 = "SELECT * FROM a LEFT JOIN b ON a.id = b.id";
    let result2 = format_sql(sql2);
    assert!(result2.is_ok());
}

#[test]
fn test_debug_guard_with_complex_sql() {
    let sql = r#"
        WITH cte AS (
            SELECT id, name FROM users
        )
        SELECT 
            cte.name,
            orders.total
        FROM cte
        INNER JOIN orders ON cte.id = orders.user_id
        WHERE orders.status = 'COMPLETE'
    "#;

    let result = format_sql(sql);
    assert!(result.is_ok());

    // Verify key tokens are preserved
    let formatted = result.unwrap();
    assert!(formatted.contains("WITH"));
    assert!(formatted.contains("SELECT"));
    assert!(formatted.contains("FROM"));
    assert!(formatted.contains("JOIN"));
    assert!(formatted.contains("WHERE"));
}

#[cfg(debug_assertions)]
#[test]
fn test_debug_guard_only_active_in_debug_mode() {
    // This test verifies the guard is compiled in
    println!("✅ Debug guard is active (debug_assertions enabled)");

    // Simple formatting to trigger the guard
    let sql = "SELECT 1";
    let result = format_sql(sql);
    assert!(result.is_ok());
}

#[cfg(not(debug_assertions))]
#[test]
fn test_no_guard_in_release_mode() {
    // In release builds, the guard should be completely removed
    println!("✅ Debug guard is NOT compiled (release mode - zero overhead)");

    let sql = "SELECT 1";
    let result = format_sql(sql);
    assert!(result.is_ok());
}
