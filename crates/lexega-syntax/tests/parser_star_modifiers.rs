// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{ast, parse_stmt_from_str};

// Helper to unwrap ProjectionItem to SelectItem for tests
fn as_select_item(item: &ast::ProjectionItem) -> &ast::AstSelectItem {
    match &item.kind {
        ast::ProjectionItemKind::SelectItem(s) => s,
        _ => panic!("Expected SelectItem in projection"),
    }
}

/// Helper function to parse and extract SELECT statement
fn parse_select(sql: &str) -> ast::AstSelect {
    match parse_stmt_from_str(sql) {
        Some(ast::AstStmt::Select(select)) => select.as_ref().clone(),
        _ => panic!("Failed to parse as SELECT: {}", sql),
    }
}

/// Helper to check if an expression is UnqualifiedStar
fn is_unqualified_star(expr: &ast::AstExpr) -> bool {
    matches!(expr, ast::AstExpr::UnqualifiedStar { .. })
}

#[test]
fn test_unqualified_star_mixed_with_column() {
    let sql = "SELECT col1, * FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2, "Expected 2 items in projection");
            // First should be col1
            assert!(matches!(
                as_select_item(&items[0]).expr,
                ast::AstExpr::Ident { .. }
            ));
            // Second should be unqualified star
            assert!(is_unqualified_star(&as_select_item(&items[1]).expr));
        }
        _ => panic!("Expected Columns projection, got {:?}", select.projection),
    }
}

#[test]
fn test_unqualified_star_with_exclude() {
    let sql = "SELECT col1, * EXCLUDE (id) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::UnqualifiedStar { exclude, .. } = &as_select_item(&items[1]).expr {
                assert!(exclude.is_some(), "Expected EXCLUDE modifier");
                if let Some(excl) = exclude {
                    assert_eq!(excl.columns.len(), 1);
                }
            } else {
                panic!("Expected UnqualifiedStar expression");
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_unqualified_star_with_exclude_multiple() {
    let sql = "SELECT a, * EXCLUDE (id, name, timestamp) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::UnqualifiedStar { exclude, .. } = &as_select_item(&items[1]).expr {
                assert!(exclude.is_some());
                if let Some(excl) = exclude {
                    assert_eq!(excl.columns.len(), 3, "Expected 3 excluded columns");
                }
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_unqualified_star_with_replace() {
    let sql = "SELECT col1, * REPLACE (1 AS id) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::UnqualifiedStar { replace, .. } = &as_select_item(&items[1]).expr {
                assert!(replace.is_some(), "Expected REPLACE modifier");
                if let Some(repl) = replace {
                    assert_eq!(repl.items.len(), 1);
                }
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_unqualified_star_with_replace_multiple() {
    let sql = "SELECT a, * REPLACE (1 AS id, 'test' AS name) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::UnqualifiedStar { replace, .. } = &as_select_item(&items[1]).expr {
                assert!(replace.is_some());
                if let Some(repl) = replace {
                    assert_eq!(repl.items.len(), 2, "Expected 2 replacement items");
                }
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_unqualified_star_with_rename() {
    let sql = "SELECT col1, * RENAME (old_name AS new_name) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::UnqualifiedStar { rename, .. } = &as_select_item(&items[1]).expr {
                assert!(rename.is_some(), "Expected RENAME modifier");
                if let Some(ren) = rename {
                    assert_eq!(ren.items.len(), 1);
                }
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_unqualified_star_all_modifiers() {
    let sql = "SELECT a, * EXCLUDE (id) REPLACE (1 AS status) RENAME (old AS new) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::UnqualifiedStar {
                exclude,
                replace,
                rename,
                ..
            } = &as_select_item(&items[1]).expr
            {
                assert!(exclude.is_some(), "Expected EXCLUDE modifier");
                assert!(replace.is_some(), "Expected REPLACE modifier");
                assert!(rename.is_some(), "Expected RENAME modifier");
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_qualified_star_with_exclude() {
    let sql = "SELECT col1, t.* EXCLUDE (id) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::QualifiedStar { exclude, .. } = &as_select_item(&items[1]).expr {
                assert!(
                    exclude.is_some(),
                    "Expected EXCLUDE modifier on qualified star"
                );
                if let Some(excl) = exclude {
                    assert_eq!(excl.columns.len(), 1);
                }
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_qualified_star_with_replace() {
    let sql = "SELECT col1, t.* REPLACE (1 AS id) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::QualifiedStar { replace, .. } = &as_select_item(&items[1]).expr {
                assert!(
                    replace.is_some(),
                    "Expected REPLACE modifier on qualified star"
                );
                if let Some(repl) = replace {
                    assert_eq!(repl.items.len(), 1);
                }
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_qualified_star_all_modifiers() {
    let sql = "SELECT a, t.* EXCLUDE (id) REPLACE (1 AS status) RENAME (old AS new) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::QualifiedStar {
                exclude,
                replace,
                rename,
                ..
            } = &as_select_item(&items[1]).expr
            {
                assert!(exclude.is_some(), "Expected EXCLUDE modifier");
                assert!(replace.is_some(), "Expected REPLACE modifier");
                assert!(rename.is_some(), "Expected RENAME modifier");
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_star_between_columns() {
    let sql = "SELECT a, *, b FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 3, "Expected 3 items");
            assert!(matches!(
                as_select_item(&items[0]).expr,
                ast::AstExpr::Ident { .. }
            ));
            assert!(is_unqualified_star(&as_select_item(&items[1]).expr));
            assert!(matches!(
                as_select_item(&items[2]).expr,
                ast::AstExpr::Ident { .. }
            ));
        }
        _ => panic!("Expected Columns projection"),
    }
}

#[test]
fn test_star_only_with_modifiers() {
    let sql = "SELECT * EXCLUDE (id, name) FROM t;";
    let select = parse_select(sql);

    // When * appears alone (even with modifiers), it uses Star projection via parse_star_projection
    match &select.projection.kind {
        ast::AstProjectionKind::Star(star) => {
            assert!(
                star.exclude.is_some(),
                "Expected EXCLUDE on star projection"
            );
            if let Some(excl) = &star.exclude {
                assert_eq!(excl.columns.len(), 2);
            }
        }
        _ => panic!("Expected Star projection for standalone *"),
    }
}

#[test]
fn test_star_with_replace_complex_expr() {
    let sql = "SELECT a, * REPLACE (UPPER(name) AS name, id + 1 AS id) FROM t;";
    let select = parse_select(sql);

    match &select.projection.kind {
        ast::AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 2);
            if let ast::AstExpr::UnqualifiedStar { replace, .. } = &as_select_item(&items[1]).expr {
                assert!(replace.is_some());
                if let Some(repl) = replace {
                    assert_eq!(repl.items.len(), 2);
                    // First replacement should be a function call
                    assert!(matches!(
                        repl.items[0].expr,
                        ast::AstExpr::FunctionCall { .. }
                    ));
                    // Second replacement should be a binary op
                    assert!(matches!(repl.items[1].expr, ast::AstExpr::BinaryOp { .. }));
                }
            }
        }
        _ => panic!("Expected Columns projection"),
    }
}
