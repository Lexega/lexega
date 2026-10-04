// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL EXPLAIN statement parsing and formatting.
//!
//! EXPLAIN wraps an inner statement (SELECT, INSERT, UPDATE, DELETE) with
//! optional analysis options. The inner statement is a full AST node, not just
//! opaque text — so formatting applies recursively.

use lexega_syntax::{
    format_sql_with_config, parse_sql, verify_formatting_safe, AstStmt, FormatterConfig,
};

// ============================================================================
// Helper
// ============================================================================

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

fn parses_as_explain(sql: &str) -> bool {
    let script = parse_sql(sql).expect("should parse");
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::Explain(_)))
}

// ============================================================================
// Basic parsing — verify we get an AstExplain, not OpaqueContent
// ============================================================================

#[test]
fn test_explain_basic_select_is_explain_variant() {
    assert!(
        parses_as_explain("EXPLAIN SELECT 1;"),
        "EXPLAIN SELECT should parse as AstStmt::Explain"
    );
}

#[test]
fn test_explain_analyze_is_explain_variant() {
    assert!(
        parses_as_explain("EXPLAIN ANALYZE SELECT * FROM users;"),
        "EXPLAIN ANALYZE should parse as AstStmt::Explain"
    );
}

#[test]
fn test_explain_parenthesized_options_is_explain_variant() {
    assert!(
        parses_as_explain("EXPLAIN (ANALYZE, COSTS, VERBOSE) SELECT 1;"),
        "EXPLAIN (...) should parse as AstStmt::Explain"
    );
}

// ============================================================================
// Formatting — simple cases
// ============================================================================

#[test]
fn test_explain_bare_select() {
    let sql = "EXPLAIN SELECT * FROM users;";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.starts_with("EXPLAIN"),
        "Should start with EXPLAIN"
    );
    assert!(formatted.contains("SELECT"), "Should contain inner SELECT");
}

#[test]
fn test_explain_analyze_select() {
    let sql = "EXPLAIN ANALYZE SELECT * FROM users WHERE active = true;";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("EXPLAIN ANALYZE"),
        "Should preserve EXPLAIN ANALYZE"
    );
}

#[test]
fn test_explain_parenthesized_options() {
    let sql = "EXPLAIN (ANALYZE, COSTS, VERBOSE, FORMAT JSON) SELECT * FROM users;";
    let formatted = format_and_verify(sql);
    assert!(formatted.contains("EXPLAIN"), "Should start with EXPLAIN");
    assert!(
        formatted.contains("FORMAT JSON"),
        "Should preserve FORMAT JSON option"
    );
}

#[test]
fn test_explain_options_with_boolean_values() {
    let sql = "EXPLAIN (ANALYZE true, BUFFERS true, COSTS false) SELECT 1;";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("ANALYZE true"),
        "Should preserve ANALYZE true"
    );
    assert!(
        formatted.contains("BUFFERS true"),
        "Should preserve BUFFERS true"
    );
}

// ============================================================================
// Inner statement formatting — verify formatter recurses properly
// ============================================================================

#[test]
fn test_explain_formats_inner_select_with_joins() {
    let sql = r#"EXPLAIN ANALYZE SELECT u.id, u.name, o.amount FROM users u INNER JOIN orders o ON u.id = o.user_id LEFT JOIN payments p ON o.id = p.order_id WHERE u.active = true AND o.amount > 100 ORDER BY o.amount DESC LIMIT 50;"#;
    let formatted = format_and_verify(sql);
    // The inner SELECT should be fully formatted (multi-line)
    assert!(
        formatted.contains("INNER JOIN"),
        "Should preserve INNER JOIN"
    );
    assert!(formatted.contains("LEFT JOIN"), "Should preserve LEFT JOIN");
    assert!(formatted.contains("ORDER BY"), "Should preserve ORDER BY");
}

#[test]
fn test_explain_formats_inner_select_with_subquery() {
    let sql = r#"EXPLAIN (ANALYZE) SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE amount > 100);"#;
    let formatted = format_and_verify(sql);
    assert!(formatted.contains("IN ("), "Should preserve IN subquery");
}

#[test]
fn test_explain_formats_inner_select_with_cte() {
    let sql = r#"EXPLAIN ANALYZE WITH active_users AS (SELECT id, name FROM users WHERE active = true), recent_orders AS (SELECT user_id, SUM(amount) AS total FROM orders WHERE created_at > '2024-01-01' GROUP BY user_id) SELECT a.name, r.total FROM active_users a JOIN recent_orders r ON a.id = r.user_id ORDER BY r.total DESC;"#;
    let formatted = format_and_verify(sql);
    assert!(formatted.contains("WITH"), "Should preserve CTE WITH");
    assert!(
        formatted.contains("active_users"),
        "Should preserve CTE name"
    );
    assert!(
        formatted.contains("recent_orders"),
        "Should preserve second CTE"
    );
}

#[test]
fn test_explain_formats_inner_select_with_window_functions() {
    let sql = r#"EXPLAIN (VERBOSE, COSTS true) SELECT id, name, salary, RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS dept_rank, AVG(salary) OVER (PARTITION BY department) AS dept_avg FROM employees WHERE active = true;"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("RANK()"),
        "Should preserve RANK() window function"
    );
    assert!(
        formatted.contains("PARTITION BY"),
        "Should preserve PARTITION BY"
    );
}

// ============================================================================
// DML inner statements — INSERT, UPDATE, DELETE
// ============================================================================

#[test]
fn test_explain_insert_with_on_conflict() {
    let sql = r#"EXPLAIN ANALYZE INSERT INTO users (name, email) VALUES ('alice', 'alice@example.com'), ('bob', 'bob@example.com') ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name WHERE users.active = true;"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("ON CONFLICT"),
        "Should preserve ON CONFLICT"
    );
    assert!(formatted.contains("DO UPDATE"), "Should preserve DO UPDATE");
    assert!(
        formatted.contains("EXCLUDED.name"),
        "Should preserve EXCLUDED reference"
    );
}

#[test]
fn test_explain_insert_returning() {
    let sql = r#"EXPLAIN INSERT INTO users (name) VALUES ('alice') ON CONFLICT (name) DO NOTHING RETURNING id, name;"#;
    let formatted = format_and_verify(sql);
    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(
        formatted.contains("DO NOTHING"),
        "Should preserve DO NOTHING"
    );
}

#[test]
fn test_explain_update_complex() {
    let sql = r#"EXPLAIN (ANALYZE, VERBOSE) UPDATE orders SET status = 'shipped', shipped_at = NOW(), updated_by = 'system' WHERE status = 'paid' AND created_at < CURRENT_DATE - INTERVAL '30 days';"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("UPDATE orders"),
        "Should preserve UPDATE target"
    );
    assert!(
        formatted.contains("shipped_at"),
        "Should preserve SET columns"
    );
}

#[test]
fn test_explain_delete_with_using() {
    let sql = r#"EXPLAIN ANALYZE DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE status = 'cancelled');"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("DELETE FROM"),
        "Should preserve DELETE FROM"
    );
}

// ============================================================================
// Multi-statement scripts
// ============================================================================

#[test]
fn test_explain_multi_statement_script() {
    let sql = r#"
EXPLAIN SELECT 1;
EXPLAIN ANALYZE SELECT * FROM users;
EXPLAIN (VERBOSE) SELECT * FROM orders;
SELECT * FROM products;
"#;
    let formatted = format_and_verify(sql);
    // All three EXPLAINs plus the plain SELECT should be present
    let explain_count = formatted.matches("EXPLAIN").count();
    assert!(
        explain_count >= 3,
        "Should have at least 3 EXPLAIN occurrences, got {}",
        explain_count
    );
}

#[test]
fn test_explain_mixed_with_dml() {
    let sql = r#"
INSERT INTO logs (msg) VALUES ('starting');
EXPLAIN ANALYZE SELECT u.id, u.name FROM users u WHERE u.active = true;
UPDATE logs SET completed = true WHERE msg = 'starting';
EXPLAIN (ANALYZE, COSTS) DELETE FROM temp_data WHERE created_at < '2024-01-01';
"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("INSERT INTO"),
        "Should preserve standalone INSERT"
    );
    assert!(
        formatted.contains("EXPLAIN ANALYZE SELECT"),
        "Should preserve EXPLAIN ANALYZE SELECT"
    );
    assert!(
        formatted.contains("UPDATE logs"),
        "Should preserve standalone UPDATE"
    );
}

// ============================================================================
// Idempotency — format(format(x)) == format(x)
// ============================================================================

#[test]
fn test_explain_idempotent_bare() {
    let sql = "EXPLAIN SELECT * FROM users WHERE id > 10 ORDER BY name;";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(first, second, "EXPLAIN formatting should be idempotent");
}

#[test]
fn test_explain_idempotent_analyze() {
    let sql = "EXPLAIN ANALYZE SELECT u.id, u.name, COUNT(o.id) AS order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.name HAVING COUNT(o.id) > 5;";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(
        first, second,
        "EXPLAIN ANALYZE formatting should be idempotent"
    );
}

#[test]
fn test_explain_idempotent_options() {
    let sql = "EXPLAIN (ANALYZE true, COSTS false, BUFFERS true, FORMAT JSON) SELECT * FROM users;";
    let first = format_and_verify(sql);
    let second = format_and_verify(&first);
    assert_eq!(
        first, second,
        "EXPLAIN with parenthesized options formatting should be idempotent"
    );
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_explain_analyse_british_spelling() {
    // PostgreSQL accepts ANALYSE as an alias for ANALYZE
    let sql = "EXPLAIN ANALYSE SELECT * FROM users;";
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("ANALYSE"),
        "Should preserve British spelling ANALYSE"
    );
}

#[test]
fn test_explain_case_insensitive() {
    let sql = "explain analyze select * from users;";
    let formatted = format_and_verify(sql);
    // Should parse and format — keywords get uppercased by formatter
    assert!(!formatted.is_empty(), "Should produce output");
}

#[test]
fn test_explain_with_deeply_nested_subqueries() {
    let sql = r#"EXPLAIN (ANALYZE, VERBOSE) SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE product_id IN (SELECT id FROM products WHERE category IN (SELECT id FROM categories WHERE name = 'electronics')));"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("categories"),
        "Should preserve deeply nested subquery tables"
    );
}

#[test]
fn test_explain_select_star_from_multiple_tables() {
    let sql = r#"EXPLAIN SELECT a.*, b.*, c.total FROM accounts a CROSS JOIN regions b INNER JOIN (SELECT account_id, SUM(amount) AS total FROM transactions GROUP BY account_id) c ON a.id = c.account_id;"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("CROSS JOIN"),
        "Should preserve CROSS JOIN"
    );
}

#[test]
fn test_explain_with_case_expression() {
    let sql = r#"EXPLAIN ANALYZE SELECT id, CASE WHEN status = 'active' THEN 'Active' WHEN status = 'inactive' THEN 'Inactive' ELSE 'Unknown' END AS status_label FROM users;"#;
    let formatted = format_and_verify(sql);
    assert!(
        formatted.contains("CASE"),
        "Should preserve CASE expression"
    );
    assert!(formatted.contains("WHEN"), "Should preserve WHEN clauses");
}

#[test]
fn test_explain_with_aggregate_and_groupby() {
    let sql = r#"EXPLAIN (COSTS false) SELECT department, COUNT(*) AS cnt, AVG(salary) AS avg_salary, MAX(salary) AS max_salary FROM employees GROUP BY department HAVING COUNT(*) > 5 ORDER BY avg_salary DESC;"#;
    let formatted = format_and_verify(sql);
    assert!(formatted.contains("GROUP BY"), "Should preserve GROUP BY");
    assert!(formatted.contains("HAVING"), "Should preserve HAVING");
}

// ============================================================================
// AST structure verification
// ============================================================================

#[test]
fn test_explain_ast_inner_stmt_is_select() {
    let script = parse_sql("EXPLAIN SELECT 1;").expect("should parse");
    let stmt = &script.stmts[0];
    match stmt {
        AstStmt::Explain(explain) => {
            assert!(
                matches!(*explain.inner_stmt, AstStmt::Select(_)),
                "Inner stmt should be Select, got {:?}",
                std::mem::discriminant(&*explain.inner_stmt)
            );
            assert!(
                explain.options_span.is_none(),
                "Bare EXPLAIN should have no options_span"
            );
        }
        other => panic!(
            "Expected AstStmt::Explain, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_explain_analyze_ast_has_options_span() {
    let script = parse_sql("EXPLAIN ANALYZE SELECT 1;").expect("should parse");
    let stmt = &script.stmts[0];
    match stmt {
        AstStmt::Explain(explain) => {
            assert!(
                explain.options_span.is_some(),
                "EXPLAIN ANALYZE should have an options_span"
            );
        }
        other => panic!(
            "Expected AstStmt::Explain, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_explain_parenthesized_ast_has_options_span() {
    let script =
        parse_sql("EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT 1;").expect("should parse");
    let stmt = &script.stmts[0];
    match stmt {
        AstStmt::Explain(explain) => {
            assert!(
                explain.options_span.is_some(),
                "EXPLAIN (...) should have an options_span"
            );
            assert!(
                matches!(*explain.inner_stmt, AstStmt::Select(_)),
                "Inner stmt should be Select"
            );
        }
        other => panic!(
            "Expected AstStmt::Explain, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_explain_ast_inner_stmt_is_insert() {
    let script = parse_sql("EXPLAIN INSERT INTO t (a) VALUES (1);").expect("should parse");
    let stmt = &script.stmts[0];
    match stmt {
        AstStmt::Explain(explain) => {
            assert!(
                matches!(*explain.inner_stmt, AstStmt::Insert(_)),
                "Inner stmt should be Insert"
            );
        }
        other => panic!(
            "Expected AstStmt::Explain, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_explain_ast_inner_stmt_is_update() {
    let script = parse_sql("EXPLAIN UPDATE t SET a = 1 WHERE b = 2;").expect("should parse");
    let stmt = &script.stmts[0];
    match stmt {
        AstStmt::Explain(explain) => {
            assert!(
                matches!(*explain.inner_stmt, AstStmt::Update(_)),
                "Inner stmt should be Update"
            );
        }
        other => panic!(
            "Expected AstStmt::Explain, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_explain_ast_inner_stmt_is_delete() {
    let script = parse_sql("EXPLAIN DELETE FROM t WHERE a = 1;").expect("should parse");
    let stmt = &script.stmts[0];
    match stmt {
        AstStmt::Explain(explain) => {
            assert!(
                matches!(*explain.inner_stmt, AstStmt::Delete(_)),
                "Inner stmt should be Delete"
            );
        }
        other => panic!(
            "Expected AstStmt::Explain, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

// ============================================================================
// Span coverage — the explain span should cover the full statement
// ============================================================================

#[test]
fn test_explain_span_covers_full_statement() {
    let sql = "EXPLAIN ANALYZE SELECT * FROM users;";
    let script = parse_sql(sql).expect("should parse");
    let stmt = &script.stmts[0];
    match stmt {
        AstStmt::Explain(explain) => {
            let span = explain.span;
            // Should start at 0 (EXPLAIN is first token)
            assert_eq!(span.start, 0, "Span should start at beginning");
            // Should end at or beyond the last token before semicolon
            assert!(
                span.end >= 35,
                "Span should cover at least through 'users', got end={}",
                span.end
            );
            // explain_span should be just EXPLAIN
            assert_eq!(explain.explain_span.start, 0);
            assert_eq!(explain.explain_span.end, 7); // "EXPLAIN" = 7 chars
        }
        other => panic!("Expected Explain, got {:?}", std::mem::discriminant(other)),
    }
}
