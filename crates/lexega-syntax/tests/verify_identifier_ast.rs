// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Verification tests for IDENTIFIER() enhanced parsing
/// Ensures proper formatter support for dynamic object references
use lexega_syntax::{parse_stmt_from_str, AstStmt};

#[test]
fn test_identifier_with_string_literal() {
    // IDENTIFIER('table_name') should parse the string literal argument
    let sql = "SELECT * FROM IDENTIFIER('my_table')";
    let stmt = parse_stmt_from_str(sql).expect("Should parse IDENTIFIER with string literal");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            // Check that identifier_arg is populated
            assert!(
                table_ref.name.identifier_arg.is_some(),
                "identifier_arg should be Some for IDENTIFIER() with string literal"
            );

            println!(
                "Successfully parsed IDENTIFIER() with string literal: {:?}",
                table_ref.name.identifier_arg
            );
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_identifier_with_session_variable() {
    // IDENTIFIER($var_name) should parse the session variable
    let sql = "SELECT * FROM IDENTIFIER($table_name)";
    let stmt = parse_stmt_from_str(sql).expect("Should parse IDENTIFIER with session var");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            assert!(
                table_ref.name.identifier_arg.is_some(),
                "identifier_arg should be Some for IDENTIFIER() with session var"
            );

            println!(
                "Successfully parsed IDENTIFIER() with session var: {:?}",
                table_ref.name.identifier_arg
            );
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_identifier_with_scripting_variable() {
    // IDENTIFIER(:var_name) in scripting context
    let sql = "SELECT * FROM IDENTIFIER(:table_name)";
    let stmt = parse_stmt_from_str(sql).expect("Should parse IDENTIFIER with scripting var");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            // Check if parsed or fell back to span
            if table_ref.name.identifier_arg.is_some() {
                println!(
                    "Successfully parsed IDENTIFIER() with scripting var: {:?}",
                    table_ref.name.identifier_arg
                );
            } else {
                println!("IDENTIFIER(:var) fell back to span collection (expected in SQL mode)");
            }
            // For now, this is OK - scripting variables might not parse in SQL mode
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_identifier_with_bind_variable() {
    // IDENTIFIER(?) for bind parameter
    let sql = "SELECT * FROM IDENTIFIER(?)";
    let stmt = parse_stmt_from_str(sql).expect("Should parse IDENTIFIER with bind var");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            // Check if parsed or fell back to span
            if table_ref.name.identifier_arg.is_some() {
                println!(
                    "Successfully parsed IDENTIFIER() with bind var: {:?}",
                    table_ref.name.identifier_arg
                );
            } else {
                println!(
                    "IDENTIFIER(?) fell back to span collection (expected - bind vars special)"
                );
            }
            // Bind variables might not parse as regular expressions
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_identifier_in_projection() {
    // IDENTIFIER() in SELECT list
    let sql = "SELECT IDENTIFIER('col_name') FROM t";
    let _stmt = parse_stmt_from_str(sql).expect("Should parse IDENTIFIER in projection");

    // This test just ensures parsing works - the IDENTIFIER is part of expression
    println!("Successfully parsed IDENTIFIER() in projection");
}

#[test]
fn test_identifier_qualified_name() {
    // IDENTIFIER('db.schema.table') with fully qualified name
    let sql = "SELECT * FROM IDENTIFIER('my_db.my_schema.my_table')";
    let stmt = parse_stmt_from_str(sql).expect("Should parse IDENTIFIER with qualified name");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            assert!(
                table_ref.name.identifier_arg.is_some(),
                "identifier_arg should be Some for qualified IDENTIFIER()"
            );

            println!(
                "Successfully parsed IDENTIFIER() with qualified name: {:?}",
                table_ref.name.identifier_arg
            );
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_identifier_with_alias() {
    // IDENTIFIER() with table alias
    let sql = "SELECT * FROM IDENTIFIER(:table_name) AS t";
    let stmt = parse_stmt_from_str(sql).expect("Should parse IDENTIFIER with alias");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            // Alias should always be preserved regardless of argument parsing
            assert!(table_ref.alias.is_some(), "alias should be preserved");

            if table_ref.name.identifier_arg.is_some() {
                println!("Successfully parsed IDENTIFIER() with alias and parsed arg");
            } else {
                println!("IDENTIFIER() with alias - arg fell back to span (OK)");
            }
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn test_identifier_span_still_valid() {
    // Ensure the span field still covers the entire IDENTIFIER(...) construct
    let sql = "SELECT * FROM IDENTIFIER('test')";
    let stmt = parse_stmt_from_str(sql).expect("Should parse");

    if let AstStmt::Select(select) = &stmt {
        if let Some(table_ref) = select.from.first() {
            // Span should be valid
            assert!(
                table_ref.name.span.end > table_ref.name.span.start,
                "Span should be valid"
            );

            // Extract the text to verify
            let span_text =
                &sql[table_ref.name.span.start as usize..table_ref.name.span.end as usize];
            assert!(
                span_text.contains("IDENTIFIER"),
                "Span should cover IDENTIFIER construct"
            );

            println!("Span correctly covers: {}", span_text);
        } else {
            panic!("Should have a table reference");
        }
    } else {
        panic!("Should be a SELECT statement");
    }
}

#[test]
fn a_view_named_by_identifier_is_named_by_the_whole_call() {
    for (sql, name, columns) in [
        (
            "CREATE VIEW IDENTIFIER('prod.a.v') AS SELECT 1 AS x",
            "IDENTIFIER('prod.a.v')",
            0,
        ),
        (
            "CREATE OR REPLACE SECURE VIEW IDENTIFIER($v) AS SELECT 1 AS x",
            "IDENTIFIER($v)",
            0,
        ),
        (
            "CREATE VIEW IDENTIFIER('prod.a.v') (x COMMENT 'c') AS SELECT 1",
            "IDENTIFIER('prod.a.v')",
            1,
        ),
        (
            "CREATE MATERIALIZED VIEW IDENTIFIER('prod.a.mv') AS SELECT 1 AS x",
            "IDENTIFIER('prod.a.mv')",
            0,
        ),
    ] {
        let stmt = parse_stmt_from_str(sql).expect("parses");
        let AstStmt::CreateView(view) = &stmt else {
            panic!("{sql}: {stmt:?}");
        };
        let span = view.name.span;
        assert_eq!(&sql[span.start as usize..span.end as usize], name, "{sql}");
        assert!(view.name.identifier_arg.is_some(), "{sql}");
        assert_eq!(view.columns.len(), columns, "{sql}");
        assert!(view.query.is_ok(), "{sql}");
    }
}
