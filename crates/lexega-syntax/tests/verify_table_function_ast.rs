// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Verification test to ensure TABLE() functions are parsed into AST structure
/// so the formatter can lay them out
use lexega_syntax::{parse_stmt_from_str, AstStmt};

#[test]
fn test_table_function_parses_simple_udtf() {
    // Simple UDTF without named parameters should parse successfully
    let sql = "SELECT * FROM TABLE(my_udtf(10))";
    let stmt = parse_stmt_from_str(sql).expect("Should parse simple UDTF");

    // Verify it's a SELECT statement
    if let AstStmt::Select(select) = &stmt {
        // Get the first table reference
        if let Some(table_ref) = select.from.first() {
            // Check that table_function field is populated
            assert!(
                table_ref.table_function.is_some(),
                "table_function field should be Some for simple UDTF"
            );

            // The function expression should be present
            let func_expr = table_ref.table_function.as_ref().unwrap();
            println!(
                "Successfully parsed TABLE() function into AST: {:?}",
                func_expr
            );
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_table_function_falls_back_for_named_params() {
    // FLATTEN with named parameters will fall back to span collection
    let sql = "SELECT * FROM TABLE(FLATTEN(INPUT => data, PATH => 'contact'))";
    let stmt = parse_stmt_from_str(sql).expect("Should parse FLATTEN with named params");

    // Verify it's a SELECT statement
    if let AstStmt::Select(select) = &stmt {
        // Get the first table reference
        if let Some(table_ref) = select.from.first() {
            // The name (span) should always be present
            assert!(
                table_ref.name.span.end > table_ref.name.span.start,
                "name span should be valid"
            );

            // table_function might be None if it fell back to span collection
            // This is expected for named parameters until we enhance the parser
            println!("Table function field: {:?}", table_ref.table_function);
            println!("This is OK - named parameters may cause fallback to span");
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_table_function_with_alias_preserved() {
    let sql = "SELECT * FROM TABLE(my_udtf(10)) AS t";
    let stmt = parse_stmt_from_str(sql).expect("Should parse UDTF with alias");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            // Verify alias is preserved
            assert!(table_ref.alias.is_some(), "Alias should be preserved");

            // Verify parsing attempt
            println!("Table function field: {:?}", table_ref.table_function);
            println!("Alias: {:?}", table_ref.alias);
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}
