// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatting of SELECT clauses: GROUP BY, ORDER BY, WITH, TOP.

use lexega_core::context::RenderContext;
use lexega_core::formatter::Formatter;
use lexega_core::lexer::tokenize;
use lexega_core::parser::parse_script;

fn format_sql(source: &str) -> Result<String, String> {
    let tokens = tokenize(source);
    let script = parse_script(source, &tokens.tokens).ok_or_else(|| "Parse failed".to_string())?;
    let context = RenderContext::from_source(source.to_string());
    let formatter = Formatter::new();
    let result = formatter
        .format_script(context, &script)
        .map_err(|e| format!("{:?}", e))?;
    result
        .formatted()
        .map(|f| f.formatted_sql().to_string())
        .ok_or_else(|| "Formatting failed".to_string())
}

// GROUP BY Tests

#[test]
fn test_group_by_single() {
    let result = format_sql("SELECT name, COUNT(*) FROM users GROUP BY name");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY name"));
}

#[test]
fn test_group_by_multiple() {
    let result = format_sql("SELECT dept, role, COUNT(*) FROM users GROUP BY dept, role");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY\n    dept,\n    role"));
}

#[test]
fn test_group_by_with_having() {
    let result = format_sql("SELECT name, COUNT(*) FROM users GROUP BY name HAVING COUNT(*) > 5");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY name"));
    assert!(formatted.contains("HAVING COUNT(*) > 5"));
}

#[test]
fn test_group_by_all() {
    let result = format_sql("SELECT name, COUNT(*) FROM users GROUP BY ALL");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY ALL"));
}

#[test]
fn test_group_by_cube() {
    let result = format_sql("SELECT dept, role, SUM(salary) FROM users GROUP BY CUBE(dept, role)");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY CUBE(dept, role)"));
}

#[test]
fn test_group_by_rollup() {
    let result =
        format_sql("SELECT dept, role, SUM(salary) FROM users GROUP BY ROLLUP(dept, role)");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY ROLLUP(dept, role)"));
}

#[test]
fn test_group_by_grouping_sets() {
    let result = format_sql(
        "SELECT dept, role, SUM(salary) FROM users GROUP BY GROUPING SETS((dept), (role), ())",
    );
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY GROUPING SETS"));
}

// ORDER BY Tests

#[test]
fn test_order_by_single() {
    let result = format_sql("SELECT * FROM users ORDER BY name");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("ORDER BY name"));
}

#[test]
fn test_order_by_asc() {
    let result = format_sql("SELECT * FROM users ORDER BY name ASC");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("ORDER BY name ASC"));
}

#[test]
fn test_order_by_desc() {
    let result = format_sql("SELECT * FROM users ORDER BY created_at DESC");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("ORDER BY created_at DESC"));
}

#[test]
fn test_order_by_multiple() {
    let result = format_sql("SELECT * FROM users ORDER BY dept ASC, name DESC");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("ORDER BY\n    dept ASC,\n    name DESC"));
}

#[test]
fn test_order_by_nulls_first() {
    let result = format_sql("SELECT * FROM users ORDER BY name NULLS FIRST");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("ORDER BY name NULLS FIRST"));
}

#[test]
fn test_order_by_nulls_last() {
    let result = format_sql("SELECT * FROM users ORDER BY name NULLS LAST");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("ORDER BY name NULLS LAST"));
}

#[test]
fn test_order_by_desc_nulls_first() {
    let result = format_sql("SELECT * FROM users ORDER BY created_at DESC NULLS FIRST");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("ORDER BY created_at DESC NULLS FIRST"));
}

// GROUP BY + ORDER BY Combined

#[test]
fn test_group_by_order_by() {
    let result = format_sql("SELECT dept, COUNT(*) FROM users GROUP BY dept ORDER BY dept");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY dept"));
    assert!(formatted.contains("ORDER BY dept"));
}

#[test]
fn test_group_by_having_order_by() {
    let result = format_sql("SELECT dept, COUNT(*) as cnt FROM users GROUP BY dept HAVING COUNT(*) > 10 ORDER BY cnt DESC");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("GROUP BY dept"));
    assert!(formatted.contains("HAVING"));
    assert!(formatted.contains("ORDER BY"));
}

// TOP Tests

#[test]
fn test_top_simple() {
    let result = format_sql("SELECT TOP 10 * FROM users");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("TOP 10"));
}

#[test]
fn test_top_with_where() {
    let result = format_sql("SELECT TOP 5 name FROM users WHERE active = true");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("TOP 5"));
    assert!(formatted.contains("WHERE"));
}

// WITH (CTE) Tests

#[test]
fn test_with_simple_cte() {
    let result = format_sql(
        "WITH active_users AS (SELECT * FROM users WHERE active = true) SELECT * FROM active_users",
    );
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("WITH"));
    assert!(formatted.contains("active_users"));
    assert!(formatted.contains("AS"));
}

#[test]
fn test_with_multiple_ctes() {
    let result = format_sql(
        "WITH cte1 AS (SELECT * FROM t1), cte2 AS (SELECT * FROM t2) SELECT * FROM cte1 JOIN cte2",
    );
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("WITH"));
    assert!(formatted.contains("cte1"));
    assert!(formatted.contains("cte2"));
}

#[test]
fn test_with_recursive_cte() {
    let result = format_sql("WITH RECURSIVE ancestors AS (SELECT * FROM emp WHERE id = 1 UNION ALL SELECT e.* FROM emp e JOIN ancestors a ON e.mgr_id = a.id) SELECT * FROM ancestors");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("WITH RECURSIVE"));
}

#[test]
fn test_with_column_list() {
    let result = format_sql("WITH numbered (id, name, rn) AS (SELECT id, name, ROW_NUMBER() OVER (ORDER BY id) FROM users) SELECT * FROM numbered");
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("WITH"));
    assert!(formatted.contains("numbered"));
}

// Complex Combined Tests

#[test]
fn test_full_select_all_clauses() {
    let result = format_sql(
        "SELECT DISTINCT dept, COUNT(*) as cnt FROM users WHERE active = true GROUP BY dept HAVING COUNT(*) > 5 ORDER BY cnt DESC LIMIT 10 OFFSET 5"
    );
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("SELECT DISTINCT"));
    assert!(formatted.contains("FROM users"));
    assert!(formatted.contains("WHERE"));
    assert!(formatted.contains("GROUP BY dept"));
    assert!(formatted.contains("HAVING"));
    assert!(formatted.contains("ORDER BY"));
    assert!(formatted.contains("LIMIT 10"));
    assert!(formatted.contains("OFFSET 5"));
}

#[test]
fn test_with_cte_group_order() {
    let result = format_sql(
        "WITH dept_stats AS (SELECT dept, COUNT(*) as cnt FROM users GROUP BY dept) SELECT * FROM dept_stats WHERE cnt > 10 ORDER BY cnt DESC"
    );
    assert!(result.is_ok(), "Failed: {:?}", result);
    let formatted = result.unwrap();
    assert!(formatted.contains("WITH"));
    assert!(formatted.contains("dept_stats"));
    assert!(formatted.contains("GROUP BY"));
    assert!(formatted.contains("ORDER BY"));
}
