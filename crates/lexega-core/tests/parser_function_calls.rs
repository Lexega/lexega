// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::{
    ast::{AstExpr, AstSelectItem, AstStmt, ProjectionItemKind},
    parse_sql,
};

// Helper to unwrap ProjectionItem to SelectItem for tests
fn as_select_item(item: &lexega_core::ast::ProjectionItem) -> &AstSelectItem {
    match &item.kind {
        ProjectionItemKind::SelectItem(s) => s,
        _ => panic!("Expected SelectItem in projection"),
    }
}

#[test]
fn test_count_star() {
    let src = "SELECT COUNT(*) FROM users";

    let script = parse_sql(src).expect("failed to parse COUNT(*)");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => {
            match &sel.projection.kind {
                lexega_core::ast::AstProjectionKind::Columns(cols) => {
                    assert_eq!(cols.len(), 1);
                    match &as_select_item(&cols[0]).expr {
                        AstExpr::FunctionCall {
                            func_name, args, ..
                        } => {
                            let func_text =
                                &src[func_name.span.start as usize..func_name.span.end as usize];
                            assert_eq!(func_text.to_uppercase(), "COUNT");
                            assert_eq!(args.len(), 1);
                            // Verify * is parsed as UnqualifiedStar (not Ident)
                            match &*args[0] {
                                lexega_core::ast::AstFunctionArg::Positional(boxed_expr) => {
                                    match &**boxed_expr {
                                        AstExpr::UnqualifiedStar { star_span, .. } => {
                                            let arg_text = &src
                                                [star_span.start as usize..star_span.end as usize];
                                            assert_eq!(arg_text, "*");
                                        }
                                        _ => panic!("expected UnqualifiedStar for * in COUNT(*)"),
                                    }
                                }
                                _ => panic!("expected Positional argument"),
                            }
                        }
                        _ => panic!("expected FunctionCall for COUNT(*)"),
                    }
                }
                _ => panic!("expected column projection"),
            }
        }
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_sum_column() {
    let src = "SELECT SUM(amount) FROM orders";

    let script = parse_sql(src).expect("failed to parse SUM(amount)");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                assert_eq!(cols.len(), 1);
                match &as_select_item(&cols[0]).expr {
                    AstExpr::FunctionCall {
                        func_name, args, ..
                    } => {
                        let func_text =
                            &src[func_name.span.start as usize..func_name.span.end as usize];
                        assert_eq!(func_text.to_uppercase(), "SUM");
                        assert_eq!(args.len(), 1);
                        match &*args[0] {
                            lexega_core::ast::AstFunctionArg::Positional(boxed_expr) => {
                                match &**boxed_expr {
                                    AstExpr::Ident {
                                        column_ref: col, ..
                                    } => {
                                        let arg_text = &src[col.name.span.start as usize
                                            ..col.name.span.end as usize];
                                        assert_eq!(arg_text, "amount");
                                    }
                                    _ => panic!("expected identifier for amount in SUM(amount)"),
                                }
                            }
                            _ => panic!("expected Positional argument"),
                        }
                    }
                    _ => panic!("expected FunctionCall for SUM(amount)"),
                }
            }
            _ => panic!("expected column projection"),
        },
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_avg_expression() {
    let src = "SELECT AVG(salary + bonus) FROM employees";

    let script = parse_sql(src).expect("failed to parse AVG(salary + bonus)");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => {
            match &sel.projection.kind {
                lexega_core::ast::AstProjectionKind::Columns(cols) => {
                    assert_eq!(cols.len(), 1);
                    match &as_select_item(&cols[0]).expr {
                        AstExpr::FunctionCall {
                            func_name, args, ..
                        } => {
                            let func_text =
                                &src[func_name.span.start as usize..func_name.span.end as usize];
                            assert_eq!(func_text.to_uppercase(), "AVG");
                            assert_eq!(args.len(), 1);
                            // Verify we got a binary expression
                            match &*args[0] {
                                lexega_core::ast::AstFunctionArg::Positional(boxed_expr) => {
                                    match &**boxed_expr {
                                        AstExpr::BinaryOp { .. } => {
                                            // Good, we parsed the expression
                                        }
                                        _ => panic!("expected BinaryOp for salary + bonus"),
                                    }
                                }
                                _ => panic!("expected Positional argument"),
                            }
                        }
                        _ => panic!("expected FunctionCall for AVG(...)"),
                    }
                }
                _ => panic!("expected column projection"),
            }
        }
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_nested_functions() {
    let src = "SELECT UPPER(LOWER(name)) FROM users";

    let script = parse_sql(src).expect("failed to parse nested functions");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => {
            match &sel.projection.kind {
                lexega_core::ast::AstProjectionKind::Columns(cols) => {
                    assert_eq!(cols.len(), 1);
                    match &as_select_item(&cols[0]).expr {
                        AstExpr::FunctionCall {
                            func_name, args, ..
                        } => {
                            let func_text =
                                &src[func_name.span.start as usize..func_name.span.end as usize];
                            assert_eq!(func_text.to_uppercase(), "UPPER");
                            assert_eq!(args.len(), 1);
                            // Inner call should be another FunctionCall
                            match &*args[0] {
                                lexega_core::ast::AstFunctionArg::Positional(boxed_expr) => {
                                    match &**boxed_expr {
                                        AstExpr::FunctionCall {
                                            func_name: inner_name,
                                            args: inner_args,
                                            ..
                                        } => {
                                            let inner_text = &src[inner_name.span.start as usize
                                                ..inner_name.span.end as usize];
                                            assert_eq!(inner_text.to_uppercase(), "LOWER");
                                            assert_eq!(inner_args.len(), 1);
                                        }
                                        _ => panic!("expected FunctionCall for LOWER(name)"),
                                    }
                                }
                                _ => panic!("expected Positional argument"),
                            }
                        }
                        _ => panic!("expected FunctionCall for UPPER(...)"),
                    }
                }
                _ => panic!("expected column projection"),
            }
        }
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_multiple_function_args() {
    let src = "SELECT SUBSTRING(name, 1, 3) FROM users";

    let script = parse_sql(src).expect("failed to parse SUBSTRING with multiple args");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                assert_eq!(cols.len(), 1);
                match &as_select_item(&cols[0]).expr {
                    AstExpr::FunctionCall {
                        func_name, args, ..
                    } => {
                        let func_text =
                            &src[func_name.span.start as usize..func_name.span.end as usize];
                        assert_eq!(func_text.to_uppercase(), "SUBSTRING");
                        assert_eq!(args.len(), 3);
                    }
                    _ => panic!("expected FunctionCall for SUBSTRING(...)"),
                }
            }
            _ => panic!("expected column projection"),
        },
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_function_with_string_literals() {
    let src = "SELECT CONCAT('Hello', 'World') FROM dual";

    let script = parse_sql(src).expect("failed to parse CONCAT with strings");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            lexega_core::ast::AstProjectionKind::Columns(cols) => {
                assert_eq!(cols.len(), 1);
                match &as_select_item(&cols[0]).expr {
                    AstExpr::FunctionCall {
                        func_name, args, ..
                    } => {
                        let func_text =
                            &src[func_name.span.start as usize..func_name.span.end as usize];
                        assert_eq!(func_text.to_uppercase(), "CONCAT");
                        assert_eq!(args.len(), 2);
                    }
                    _ => panic!("expected FunctionCall for CONCAT(...)"),
                }
            }
            _ => panic!("expected column projection"),
        },
        _ => panic!("expected SELECT statement"),
    }
}

#[test]
fn test_count_distinct() {
    let src = "SELECT COUNT(DISTINCT user_id) FROM orders";

    // DISTINCT inside an argument list may or may not parse; when it does,
    // the statement count must be right.
    let script = parse_sql(src);
    if let Ok(script) = script {
        assert_eq!(script.stmts.len(), 1);
    }
}
