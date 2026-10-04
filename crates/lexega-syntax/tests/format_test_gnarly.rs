// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, try_parse_script_from_str, FormatterConfig};
use std::fs;

fn main() {
    // Try to read test_gnarly.sql, fall back to simpler test file if it fails
    let sql = fs::read_to_string("tests/scratch/test_gnarly.sql")
        .or_else(|_| fs::read_to_string("test_simple_example.sql"))
        .expect("Failed to read SQL file");

    let config = FormatterConfig::default();

    // Parse to get statement count
    match try_parse_script_from_str(&sql) {
        Ok(script) => {
            // Format the SQL
            match format_sql_with_config(&sql, &config) {
                Ok(formatted) => {
                    fs::write("format_gnarly.sql", &formatted)
                        .expect("Failed to write format_gnarly.sql");

                    println!("✅ Formatted {} statements", script.stmts.len());
                    println!("✅ Output written to format_gnarly.sql");
                    println!("\nFormatted SQL:\n{}", formatted);
                }
                Err(e) => {
                    eprintln!("❌ Format error: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Parse error: {:?}", e);
        }
    }
}
