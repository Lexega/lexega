// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Test to understand Snowflake's SELECT projection rules
use lexega_syntax::{ast, parse_stmt_from_str};

fn main() {
    println!("Testing Snowflake SELECT projection patterns\n");

    let tests = vec![
        // Basic cases
        ("SELECT * FROM t;", "Unqualified star"),
        ("SELECT t.* FROM t;", "Qualified star"),
        ("SELECT a, b, c FROM t;", "Just columns"),
        // Star with columns
        ("SELECT *, a FROM t;", "Star then column"),
        ("SELECT a, * FROM t;", "Column then star"),
        ("SELECT *, a, b FROM t;", "Star then multiple columns"),
        // Qualified star with columns
        ("SELECT t.*, a FROM t;", "Qualified star then column"),
        ("SELECT a, t.* FROM t;", "Column then qualified star"),
        ("SELECT a, t.*, b FROM t;", "Column, qualified star, column"),
        // Multiple stars (from joins)
        ("SELECT t1.*, t2.* FROM t1 JOIN t2;", "Two qualified stars"),
        (
            "SELECT t1.*, a, t2.* FROM t1 JOIN t2;",
            "Two qualified stars with column",
        ),
        (
            "SELECT a, t1.*, b, t2.*, c FROM t1 JOIN t2;",
            "Multiple qualified stars mixed with columns",
        ),
        // Star modifications
        ("SELECT * EXCLUDE (a) FROM t;", "Star with EXCLUDE"),
        (
            "SELECT * EXCLUDE (a), b FROM t;",
            "Star with EXCLUDE then column",
        ),
        (
            "SELECT t.* EXCLUDE (a) FROM t;",
            "Qualified star with EXCLUDE",
        ),
        (
            "SELECT t.* EXCLUDE (a), b FROM t;",
            "Qualified star with EXCLUDE then column",
        ),
    ];

    for (sql, desc) in tests {
        let status = match parse_stmt_from_str(sql) {
            Some(ast::AstStmt::Select(select)) => match &select.projection.kind {
                ast::AstProjectionKind::Star(_) => "✓ Star".to_string(),
                ast::AstProjectionKind::Columns(cols) => format!("✓ Columns({})", cols.len()),
            },
            _ => "✗ FAILS".to_string(),
        };
        println!("{:<55} {}", desc, status);
    }

    println!("\n================================================");
    println!("Key insight: If qualified stars (t.*) can mix with columns,");
    println!("we may need: AstProjection::Mixed(Vec<StarOrColumn>)");
}
