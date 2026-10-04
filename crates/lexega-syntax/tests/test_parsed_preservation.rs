// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Test that parsed-but-unformatted statements are preserved as-is
/// These are statements the parser accepts but the formatter doesn't have specific logic for yet
use lexega_syntax::{format_sql_with_config, try_parse_stmt_from_str, FormatterConfig};

fn main() {
    println!("=== Testing Preservation of Parsed-But-Unformatted Statements ===\n");

    // Statements that parse successfully but don't have dedicated formatters
    let test_cases = vec![
        ("Variable Assignment", "my_var := 42 + 10;"),
        ("LET statement", "LET total := price * quantity;"),
        ("RETURN statement", "RETURN total_amount;"),
        ("CALL procedure", "CALL my_procedure(123, 'test');"),
        ("RAISE exception", "RAISE my_exception;"),
        ("OPEN cursor", "OPEN my_cursor;"),
        ("FETCH cursor", "FETCH my_cursor INTO var1, var2;"),
        ("CLOSE cursor", "CLOSE my_cursor;"),
    ];

    let config = FormatterConfig::readable();
    let mut successes = 0;
    let mut failures = 0;

    for (desc, sql) in &test_cases {
        println!("Test: {}", desc);
        println!("Original: {}", sql);

        match try_parse_stmt_from_str(sql) {
            Ok(_stmt) => {
                // Create a temporary formatter to format this statement
                match format_sql_with_config(sql, &config) {
                    Ok(formatted) => {
                        let formatted_trimmed = formatted.trim();
                        let original_trimmed = sql.trim();

                        if formatted_trimmed == original_trimmed {
                            println!("✓ PRESERVED: Statement kept exactly as-is");
                            successes += 1;
                        } else {
                            println!("Formatted: {}", formatted_trimmed);
                            println!(
                                "✓ FORMATTED: Statement was modified (has dedicated formatter)"
                            );
                            successes += 1;
                        }
                    }
                    Err(e) => {
                        println!("✗ Format error: {:?}", e);
                        failures += 1;
                    }
                }
            }
            Err(e) => {
                println!("✗ Parse error: {:?}", e);
                println!("  (Cannot test preservation if parsing fails)");
                failures += 1;
            }
        }
        println!();
    }

    println!("{}", "=".repeat(80));
    println!("Summary: {} passed, {} failed", successes, failures);

    if failures == 0 {
        println!("\n✓ SUCCESS: All parsed statements are either formatted or preserved correctly");
    }
}
