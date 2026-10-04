// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatting of SELECT statements: projections, joins and WHERE conditions.

use lexega_syntax::{format_sql, format_sql_with_config, FormatterConfig};

#[test]
fn test_current_select_formatting() {
    let sql = "SELECT id, name, email, created_at, updated_at FROM users WHERE status = 'active' AND age > 18 ORDER BY created_at DESC";

    let formatted = format_sql(sql).expect("Failed to format");
    println!("=== DEFAULT FORMATTING ===");
    println!("{}", formatted);

    let readable_config = FormatterConfig::readable();
    let formatted_readable =
        format_sql_with_config(sql, &readable_config).expect("Failed to format");
    println!("\n=== READABLE FORMATTING ===");
    println!("{}", formatted_readable);
}

#[test]
fn test_join_formatting() {
    let sql = "SELECT u.id, u.name, o.order_id, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id LEFT OUTER JOIN payments p ON o.order_id = p.order_id WHERE u.status = 'active'";

    let formatted = format_sql(sql).expect("Failed to format");
    println!("=== JOIN FORMATTING (DEFAULT) ===");
    println!("{}", formatted);

    let readable_config = FormatterConfig::readable();
    let formatted_readable =
        format_sql_with_config(sql, &readable_config).expect("Failed to format");
    println!("\n=== JOIN FORMATTING (READABLE WITH ALIGN) ===");
    println!("{}", formatted_readable);
}

#[test]
fn test_complex_where() {
    let sql = "SELECT * FROM products WHERE (category = 'electronics' AND price > 100) OR (category = 'books' AND price > 20 AND in_stock = true)";

    let formatted = format_sql(sql).expect("Failed to format");
    println!("=== COMPLEX WHERE (DEFAULT) ===");
    println!("{}", formatted);

    let readable_config = FormatterConfig::readable();
    let formatted_readable =
        format_sql_with_config(sql, &readable_config).expect("Failed to format");
    println!("\n=== COMPLEX WHERE (READABLE) ===");
    println!("{}", formatted_readable);
}

#[test]
fn test_comprehensive_formatting() {
    let sql = "SELECT u.id, u.name, u.email, o.order_id, o.total, p.payment_date FROM users u INNER JOIN orders o ON u.id = o.user_id LEFT OUTER JOIN payments p ON o.order_id = p.order_id WHERE u.status = 'active' AND u.age > 18 AND (o.total > 100 OR p.payment_date IS NOT NULL) ORDER BY u.created_at DESC LIMIT 10";

    println!("=== COMPREHENSIVE EXAMPLE ===\n");

    println!("Original (one line):");
    println!("{}\n", sql);

    let formatted_default = format_sql(sql).expect("Failed to format");
    println!("Default config:");
    println!("{}\n", formatted_default);

    let readable_config = FormatterConfig::readable();
    let formatted_readable =
        format_sql_with_config(sql, &readable_config).expect("Failed to format");
    println!("Readable config (with alignment & multi-line conditions):");
    println!("{}", formatted_readable);
}
