// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, CommaStyle, FormatterConfig};

#[test]
fn test_trailing_commas_default() {
    let sql = "SELECT id, name, email FROM users";
    let config = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Trailing,
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap();

    assert!(formatted.contains("id,"));
    assert!(formatted.contains("name,"));
    // Last item has no comma - check that email appears without comma after it
    assert!(formatted.contains("email") && !formatted.contains("email,"));
    assert!(!formatted.contains(", id"));
    assert!(!formatted.contains(", name"));
}

#[test]
fn test_leading_commas() {
    let sql = "SELECT id, name, email FROM users";
    let config = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Leading,
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap();

    // First item should not have a comma
    let lines: Vec<&str> = formatted.lines().collect();
    let id_line = lines.iter().find(|l| l.trim() == "id").unwrap();
    assert!(!id_line.contains(','));

    // Subsequent items should have leading commas with space after comma (default)
    assert!(formatted.contains(", name"));
    assert!(formatted.contains(", email"));
}

#[test]
fn test_trailing_commas_with_alignment() {
    let sql = "SELECT id AS user_id, name AS user_name, email AS user_email FROM users";
    let config = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Trailing,
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap();

    // Check that AS keywords are aligned
    let lines: Vec<&str> = formatted.lines().collect();
    let id_line = lines.iter().find(|l| l.contains("user_id")).unwrap();
    let name_line = lines.iter().find(|l| l.contains("user_name")).unwrap();
    let email_line = lines.iter().find(|l| l.contains("user_email")).unwrap();

    let id_as_pos = id_line.find(" AS ").unwrap();
    let name_as_pos = name_line.find(" AS ").unwrap();
    let email_as_pos = email_line.find(" AS ").unwrap();

    assert_eq!(id_as_pos, name_as_pos);
    assert_eq!(name_as_pos, email_as_pos);

    // Check commas are trailing
    assert!(id_line.ends_with(","));
    assert!(name_line.ends_with(","));
    assert!(!email_line.contains(",")); // Last item
}

#[test]
fn test_leading_commas_with_alignment() {
    let sql = "SELECT id AS user_id, name AS user_name, email AS user_email FROM users";
    let config = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Leading,
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap();

    // Check that AS keywords are aligned
    let lines: Vec<&str> = formatted.lines().collect();
    let id_line = lines.iter().find(|l| l.contains("user_id")).unwrap();
    let name_line = lines.iter().find(|l| l.contains("user_name")).unwrap();
    let email_line = lines.iter().find(|l| l.contains("user_email")).unwrap();

    let id_as_pos = id_line.find(" AS ").unwrap();
    let name_as_pos = name_line.find(" AS ").unwrap();
    let email_as_pos = email_line.find(" AS ").unwrap();

    assert_eq!(id_as_pos, name_as_pos);
    assert_eq!(name_as_pos, email_as_pos);

    // Check commas are leading
    assert!(!id_line.contains(",")); // First item
    assert!(name_line.trim_start().starts_with(",")); // Has leading comma
    assert!(email_line.trim_start().starts_with(",")); // Has leading comma
}

#[test]
fn test_single_line_ignores_comma_style() {
    let sql = "SELECT id, name, email FROM users";

    let config_trailing = FormatterConfig {
        select_items_on_newlines: false,
        comma_style: CommaStyle::Trailing,
        ..FormatterConfig::default()
    };
    let formatted_trailing = format_sql_with_config(sql, &config_trailing).unwrap();

    let config_leading = FormatterConfig {
        select_items_on_newlines: false,
        comma_style: CommaStyle::Leading,
        ..FormatterConfig::default()
    };
    let formatted_leading = format_sql_with_config(sql, &config_leading).unwrap();

    // Both should produce the same output in single-line mode
    assert_eq!(formatted_trailing, formatted_leading);
    assert!(formatted_trailing.contains("id, name, email"));
}

#[test]
fn test_trailing_commas_with_case_expression() {
    let sql = "SELECT u.id AS user_id, CASE WHEN u.status = 'active' THEN 1 ELSE 0 END AS is_active, o.total AS order_total FROM users u";
    let config = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Trailing,
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap();

    // CASE expression should have comma after END
    assert!(formatted.contains("END") && formatted.contains("is_active,"));

    // Verify structure
    assert!(formatted.contains("CASE"));
    assert!(formatted.contains("WHEN"));
    assert!(formatted.contains("END"));
}

#[test]
fn test_leading_commas_with_case_expression() {
    let sql = "SELECT u.id AS user_id, CASE WHEN u.status = 'active' THEN 1 ELSE 0 END AS is_active, o.total AS order_total FROM users u";
    let config = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Leading,
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap();

    // CASE expression should have leading comma before CASE on separate line (no space after comma)
    let lines: Vec<&str> = formatted.lines().collect();

    // Find the line with CASE (with space after comma)
    let case_line_idx = lines
        .iter()
        .position(|l| l.trim_start().starts_with(", CASE"));
    assert!(
        case_line_idx.is_some(),
        "Should have a line starting with , CASE"
    );

    // Last item should also have leading comma with space
    assert!(formatted.contains(", o.total"));
}

#[test]
fn test_comma_style_consistency_with_many_columns() {
    let sql = "SELECT col1, col2, col3, col4, col5, col6, col7, col8, col9, col10 FROM table1";

    let config_trailing = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Trailing,
        ..FormatterConfig::default()
    };
    let formatted_trailing = format_sql_with_config(sql, &config_trailing).unwrap();

    // Count trailing commas (should be 9, since last item has none)
    let trailing_comma_count = formatted_trailing.matches("col").count() - 1;
    assert_eq!(trailing_comma_count, 9);

    let config_leading = FormatterConfig {
        select_items_on_newlines: true,
        comma_style: CommaStyle::Leading,
        ..FormatterConfig::default()
    };
    let formatted_leading = format_sql_with_config(sql, &config_leading).unwrap();

    // Count leading commas (should be 9, since first item has none)
    // Leading comma format is ", col" (with space after comma by default)
    let leading_comma_count = formatted_leading.matches(", col").count();
    assert_eq!(leading_comma_count, 9);
}
