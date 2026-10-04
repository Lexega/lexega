// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::dialect::PostgresDialect;
use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::sync::Arc;

fn postgres_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = Arc::new(PostgresDialect);
    config
}

#[test]
fn test_insert_returning_basic() {
    let sql = "INSERT INTO users (name, email) VALUES ('John', 'john@example.com') RETURNING id;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format INSERT with RETURNING");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(formatted.contains("id"), "Should preserve returned column");
}

#[test]
fn test_insert_returning_multiple_columns() {
    let sql = "INSERT INTO users (name, email) VALUES ('John', 'john@example.com') RETURNING id, created_at, name;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format INSERT with multiple RETURNING columns");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(formatted.contains("id"), "Should preserve id");
    assert!(
        formatted.contains("created_at"),
        "Should preserve created_at"
    );
    assert!(formatted.contains("name"), "Should preserve name");
}

#[test]
fn test_insert_returning_star() {
    let sql = "INSERT INTO users (name) VALUES ('John') RETURNING *;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format INSERT with RETURNING *");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(formatted.contains("*"), "Should preserve star");
}

#[test]
fn test_update_returning_basic() {
    let sql = "UPDATE users SET email = 'newemail@example.com' WHERE id = 1 RETURNING id, email;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format UPDATE with RETURNING");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(formatted.contains("id"), "Should preserve id");
    assert!(formatted.contains("email"), "Should preserve email");
}

#[test]
fn test_update_returning_expressions() {
    let sql =
        "UPDATE users SET email = 'new@example.com' RETURNING id, UPPER(name), LENGTH(email);";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format UPDATE with RETURNING expressions");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(formatted.contains("UPPER"), "Should preserve function");
}

#[test]
fn test_delete_returning_basic() {
    let sql = "DELETE FROM users WHERE inactive = true RETURNING id, name, email;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DELETE with RETURNING");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(formatted.contains("id"), "Should preserve id");
    assert!(formatted.contains("name"), "Should preserve name");
}

#[test]
fn test_delete_returning_star() {
    let sql = "DELETE FROM users WHERE id = 1 RETURNING *;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DELETE with RETURNING *");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        formatted.contains("RETURNING *"),
        "Should preserve RETURNING *"
    );
}

#[test]
fn test_insert_without_returning_still_works() {
    let sql = "INSERT INTO users (name) VALUES ('John');";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format INSERT without RETURNING");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        !formatted.contains("RETURNING"),
        "Should not contain RETURNING"
    );
}

#[test]
fn test_update_without_returning_still_works() {
    let sql = "UPDATE users SET email = 'new@example.com' WHERE id = 1;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format UPDATE without RETURNING");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        !formatted.contains("RETURNING"),
        "Should not contain RETURNING"
    );
}

#[test]
fn test_delete_without_returning_still_works() {
    let sql = "DELETE FROM users WHERE id = 1;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format DELETE without RETURNING");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(
        !formatted.contains("RETURNING"),
        "Should not contain RETURNING"
    );
}

#[test]
fn test_returning_parsed_permissively() {
    // RETURNING clause is parsed permissively regardless of target dialect
    // (parse permissively, let the database reject at execution time)
    let sql = "INSERT INTO users (name) VALUES ('John') RETURNING id;";

    let config = FormatterConfig::default(); // Uses Snowflake dialect by default

    // RETURNING is parsed and formatted faithfully even in default (Snowflake) mode
    let formatted =
        format_sql_with_config(sql, &config).expect("RETURNING should parse permissively");

    // Verify it round-trips correctly
    assert!(
        formatted.contains("RETURNING"),
        "Should preserve RETURNING syntax"
    );
    println!("Formatted: {}", formatted);
}

#[test]
fn test_returning_with_qualified_columns() {
    let sql = "UPDATE users SET email = 'new@example.com' RETURNING users.id, users.email;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format RETURNING with qualified columns");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(
        formatted.contains("users"),
        "Should preserve table qualifier"
    );
}

#[test]
fn test_returning_with_aliases() {
    let sql = "INSERT INTO users (name) VALUES ('John') RETURNING id AS user_id, name AS username;";

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format RETURNING with aliases");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
}

#[test]
fn test_insert_multiple_rows_with_returning() {
    let sql = r#"
        INSERT INTO users (name, email)
        VALUES 
            ('John', 'john@example.com'),
            ('Jane', 'jane@example.com')
        RETURNING id, name;
    "#;

    let config = postgres_config();
    let formatted = format_sql_with_config(sql, &config)
        .expect("should parse and format multi-row INSERT with RETURNING");

    verify_formatting_safe(sql, &formatted).expect("formatting should be safe");

    assert!(formatted.contains("RETURNING"), "Should preserve RETURNING");
    assert!(formatted.contains("VALUES"), "Should preserve VALUES");
}
