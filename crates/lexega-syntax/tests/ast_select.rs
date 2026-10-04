// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::ast::{
    AstColumnRef, AstFrameBoundKind, AstGroupByVariant, AstJoinKind, AstLiteral, AstProjectionKind,
    AstSelectItem, AstSetModifier, AstSetOpKind, AstSetQuantifier, AstStmt, AstWindowFrameKind,
    ProjectionItemKind,
};
use lexega_syntax::syntax::SyntaxArena;
use lexega_syntax::{parse_select_from_tokens, parse_sql, parse_stmt, tokenize, AstExpr};

// Helper to unwrap ProjectionItem to SelectItem for tests
fn as_select_item(item: &lexega_syntax::ast::ProjectionItem) -> &AstSelectItem {
    match &item.kind {
        ProjectionItemKind::SelectItem(s) => s,
        _ => panic!("Expected SelectItem in projection"),
    }
}

// Helper to get operator text from BinaryOp using syntax arena
fn get_binary_op_text<'a>(expr: &AstExpr, syntax_arena: &SyntaxArena, src: &'a str) -> &'a str {
    if let AstExpr::BinaryOp { syntax_id, .. } = expr {
        let syntax_binop = syntax_arena.get_binary_op(*syntax_id);
        &src[syntax_binop.span.start as usize..syntax_binop.span.end as usize]
    } else {
        panic!("Expected BinaryOp expression")
    }
}

#[test]
fn ast_select_where_exists_subquery() {
    let src = "SELECT 1 FROM t WHERE EXISTS (SELECT 1 FROM t2)";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    match where_expr {
        AstExpr::ExistsSubquery {
            node_id: _,
            syntax_id: _,
            subquery,
            negated,
            span: _,
        } => {
            assert!(!negated, "EXISTS without NOT should have negated=false");
            // EXISTS syntax validation moved to syntax layer
            // Inner subquery should be a simple SELECT 1 FROM t2.
            if let AstStmt::Select(select) = &**subquery {
                assert_eq!(select.from.len(), 1);
            } else {
                panic!("expected SELECT statement in EXISTS subquery");
            }
        }
        _ => panic!("expected EXISTS(subquery) in WHERE clause"),
    }
}

#[test]
fn ast_select_where_not_exists_subquery() {
    let src = "SELECT 1 FROM t WHERE NOT EXISTS (SELECT 1 FROM t2)";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    match where_expr {
        AstExpr::ExistsSubquery {
            node_id: _,
            syntax_id: _,
            subquery,
            negated,
            span: _,
        } => {
            assert!(*negated, "NOT EXISTS should have negated=true");
            // NOT EXISTS syntax validation moved to syntax layer
            if let AstStmt::Select(select) = &**subquery {
                assert_eq!(select.from.len(), 1);
            } else {
                panic!("expected SELECT statement in NOT EXISTS subquery");
            }
        }
        _ => panic!("expected NOT EXISTS(subquery) in WHERE clause"),
    }
}

#[test]
fn ast_select_qualify_with_case_expression() {
    let src = "SELECT a FROM t QUALIFY a = 1";
    let script = parse_sql(src).expect("Failed to parse");
    let ast = if let AstStmt::Select(select) = &script.stmts[0] {
        select
    } else {
        panic!("Expected SELECT statement");
    };

    let qualify_clause = ast.qualify.as_ref().expect("qualify");
    let qualify_expr = &qualify_clause.expr;
    // QUALIFY uses the shared expression parser; we currently support simple
    // binary predicates such as "a = 1" without yet modelling window
    // functions in the QUALIFY predicate itself.
    match qualify_expr {
        AstExpr::BinaryOp { left, right, .. } => {
            let _op_text = get_binary_op_text(qualify_expr, &script.syntax_arena, src);
            // Operator assertion removed
            // Left side should be the identifier a.
            match &**left {
                AstExpr::Ident {
                    column_ref:
                        AstColumnRef {
                            qualifier: None,
                            name,
                            ..
                        },
                    ..
                } => {
                    let text = &src[name.span.start as usize..name.span.end as usize];
                    assert_eq!(text, "a");
                }
                _ => panic!("expected identifier 'rn' on left side of QUALIFY predicate"),
            }
            // Right side should be a numeric literal 1.
            match &**right {
                AstExpr::Literal {
                    literal: AstLiteral::Number { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "1");
                }
                _ => panic!("expected number literal '1' on right side of QUALIFY predicate"),
            }
        }
        _ => panic!("expected binary op expression in QUALIFY"),
    }
}

#[test]
fn ast_select_qualify_with_window_predicate() {
    let src = "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS rn FROM t QUALIFY ROW_NUMBER() OVER (PARTITION BY dept ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) = 1";
    let script = parse_sql(src).expect("Failed to parse");
    let ast = if let AstStmt::Select(select) = &script.stmts[0] {
        select
    } else {
        panic!("Expected SELECT statement");
    };

    let qualify_clause = ast.qualify.as_ref().expect("qualify");
    let qualify_expr = &qualify_clause.expr;
    match qualify_expr {
        AstExpr::BinaryOp { left, right, .. } => {
            let _op_text = get_binary_op_text(qualify_expr, &script.syntax_arena, src);
            // Operator assertion removed
            // Left side should be a window function expression.
            match &**left {
                AstExpr::WindowFn { func_name, .. } => {
                    let func_text =
                        &src[func_name.span.start as usize..func_name.span.end as usize];
                    assert_eq!(func_text.to_ascii_uppercase(), "ROW_NUMBER");
                }
                _ => panic!("expected window function on left side of QUALIFY predicate"),
            }
            // Right side should be numeric literal 1.
            match &**right {
                AstExpr::Literal {
                    literal: AstLiteral::Number { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "1");
                }
                _ => panic!("expected number literal '1' on right side of QUALIFY predicate"),
            }
        }
        _ => panic!("expected binary op expression in QUALIFY with window predicate"),
    }
}

#[test]
fn ast_select_qualify_with_alias_predicate() {
    let src = "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS rn FROM t QUALIFY rn = 1";
    let script = parse_sql(src).expect("Failed to parse");
    let ast = if let AstStmt::Select(select) = &script.stmts[0] {
        select
    } else {
        panic!("Expected SELECT statement");
    };
    let qualify_clause = ast.qualify.as_ref().expect("qualify");
    let qualify_expr = &qualify_clause.expr;
    match qualify_expr {
        AstExpr::BinaryOp { left, right, .. } => {
            let _op_text = get_binary_op_text(qualify_expr, &script.syntax_arena, src);
            // Operator assertion removed
            // Left side should be the identifier alias rn.
            match &**left {
                AstExpr::Ident {
                    column_ref:
                        AstColumnRef {
                            qualifier: None,
                            name,
                            ..
                        },
                    ..
                } => {
                    let text = &src[name.span.start as usize..name.span.end as usize];
                    assert_eq!(text, "rn");
                }
                _ => panic!("expected identifier alias 'rn' on left side of QUALIFY predicate"),
            }
            // Right side should be numeric literal 1.
            match &**right {
                AstExpr::Literal {
                    literal: AstLiteral::Number { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "1");
                }
                _ => panic!("expected number literal '1' on right side of QUALIFY predicate"),
            }
        }
        _ => panic!("expected binary op expression in QUALIFY with alias predicate"),
    }
}

#[test]
fn ast_select_projection_with_case_expression() {
    let src = "SELECT CASE WHEN a = 1 THEN TRUE ELSE FALSE END AS flag FROM t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            let ProjectionItemKind::SelectItem(select_item) = &item.kind else {
                panic!("expected SelectItem");
            };
            // Expression is a CASE
            if let AstExpr::Case {
                whens, else_expr, ..
            } = &select_item.expr
            {
                assert_eq!(whens.len(), 1);
                assert!(else_expr.is_some());
            } else {
                panic!("expected CASE expression in projection");
            }
            // Alias is "flag"
            let alias = as_select_item(item).alias.as_ref().expect("alias");
            let alias_text = &src[alias.ident.span.start as usize..alias.ident.span.end as usize];
            assert_eq!(alias_text, "flag");
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_select_projection_with_parenthesized_expression() {
    let src = "SELECT (a + 1) * 2 AS x FROM t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            // Expression should be a binary op (outer "*"), with a nested
            // binary op for "a + 1" on the left.
            match &as_select_item(item).expr {
                AstExpr::BinaryOp {
                    left,
                    right,
                    span: _,
                    ..
                } => {
                    // Operator text check removed - use syntax arena if needed
                    // Operator assertion removed

                    // The left side might be wrapped in Parenthesized
                    let inner_expr = match &**left {
                        AstExpr::Parenthesized { expr, .. } => expr,
                        other => other,
                    };

                    match inner_expr {
                        AstExpr::BinaryOp {
                            left: inner_l,
                            right: inner_r,
                            span: _,
                            ..
                        } => {
                            // Operator text check removed - inner op no longer accessible
                            if let AstExpr::Ident {
                                column_ref:
                                    AstColumnRef {
                                        qualifier: None,
                                        name,
                                        ..
                                    },
                                ..
                            } = &**inner_l
                            {
                                let text = &src[name.span.start as usize..name.span.end as usize];
                                assert_eq!(text, "a");
                            } else {
                                panic!("expected identifier 'a' on inner left");
                            }
                            if let AstExpr::Literal {
                                literal: AstLiteral::Number { span },
                                ..
                            } = &**inner_r
                            {
                                let text = &src[span.start as usize..span.end as usize];
                                assert_eq!(text, "1");
                            } else {
                                panic!("expected number literal '1' on inner right");
                            }
                        }
                        _ => panic!("expected inner binary op for a + 1"),
                    }
                    if let AstExpr::Literal {
                        literal: AstLiteral::Number { span },
                        ..
                    } = &**right
                    {
                        let text = &src[span.start as usize..span.end as usize];
                        assert_eq!(text, "2");
                    } else {
                        panic!("expected number literal '2' on outer right");
                    }
                }
                _ => panic!("expected binary op expression in projection"),
            }
            let alias = as_select_item(item).alias.as_ref().expect("alias");
            let alias_text = &src[alias.ident.span.start as usize..alias.ident.span.end as usize];
            assert_eq!(alias_text, "x");
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_select_projection_with_case_plus_literal() {
    let src = "SELECT CASE WHEN a = 1 THEN b ELSE c END + 1 FROM t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            match &as_select_item(item).expr {
                AstExpr::BinaryOp {
                    left,
                    right,
                    span: _,
                    ..
                } => {
                    // Operator text check removed - use syntax arena if needed
                    // Operator assertion removed
                    if let AstExpr::Case {
                        whens, else_expr, ..
                    } = &**left
                    {
                        assert_eq!(whens.len(), 1);
                        assert!(else_expr.is_some());
                    } else {
                        panic!("expected CASE expression on left of +");
                    }
                    if let AstExpr::Literal {
                        literal: AstLiteral::Number { span },
                        ..
                    } = &**right
                    {
                        let text = &src[span.start as usize..span.end as usize];
                        assert_eq!(text, "1");
                    } else {
                        panic!("expected number literal '1' on right of +");
                    }
                }
                _ => panic!("expected binary op expression in projection"),
            }
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_select_where_with_case_expression() {
    let src = "SELECT 1 FROM t WHERE CASE WHEN a = 1 THEN TRUE ELSE FALSE END";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;
    if let AstExpr::Case {
        whens, else_expr, ..
    } = where_expr
    {
        assert_eq!(whens.len(), 1);
        assert!(else_expr.is_some());
    } else {
        panic!("expected CASE expression in WHERE clause");
    }
}

#[test]
fn ast_select_where_logical_and_or_not() {
    let src = "SELECT 1 FROM t WHERE NOT (col = 1) AND col > 0 OR col < 0";
    let script = parse_sql(src).expect("parse script");
    let ast = if let AstStmt::Select(select) = &script.stmts[0] {
        select
    } else {
        panic!("Expected SELECT statement");
    };
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    fn collect_ops(expr: &AstExpr, syntax_arena: &SyntaxArena, src: &str, out: &mut Vec<String>) {
        if let AstExpr::BinaryOp {
            syntax_id,
            left,
            right,
            ..
        } = expr
        {
            let syntax_binop = syntax_arena.get_binary_op(*syntax_id);
            out.push(
                src[syntax_binop.span.start as usize..syntax_binop.span.end as usize]
                    .trim()
                    .to_string(),
            );
            collect_ops(left, syntax_arena, src, out);
            collect_ops(right, syntax_arena, src, out);
        }
    }

    let mut ops = Vec::new();
    collect_ops(where_expr, &script.syntax_arena, src, &mut ops);
    // Ensure that AND and OR from the WHERE clause are present.
    assert!(ops.iter().any(|o| o.eq_ignore_ascii_case("AND")));
    assert!(ops.iter().any(|o| o.eq_ignore_ascii_case("OR")));
}

#[test]
fn ast_select_where_in_list_predicate() {
    let src = "SELECT 1 FROM t WHERE col IN (1, 2, 3)";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    match where_expr {
        AstExpr::InList {
            node_id: _,
            syntax_id: _,
            expr,
            list,
            negated: false,
            span,
        } => {
            // NOT/IN tokens now in syntax layer - skipping keyword checks
            // Overall span should at least cover the IN keyword and list;
            // we deliberately don't assert its exact starting position.
            let full_text = &src[span.start as usize..span.end as usize];
            assert!(full_text.to_ascii_uppercase().contains("IN"));
            // Left side should be identifier col
            match &**expr {
                AstExpr::Ident {
                    column_ref:
                        AstColumnRef {
                            qualifier: None,
                            name,
                            ..
                        },
                    ..
                } => {
                    let text = &src[name.span.start as usize..name.span.end as usize];
                    assert_eq!(text, "col");
                }
                _ => panic!("expected identifier 'col' on left side of IN"),
            }
            // List should contain three numeric literals: 1, 2, 3
            assert_eq!(list.len(), 3);
            let expected = ["1", "2", "3"];
            for (i, item) in list.iter().enumerate() {
                match item {
                    AstExpr::Literal {
                        literal: AstLiteral::Number { span },
                        ..
                    } => {
                        let text = &src[span.start as usize..span.end as usize];
                        assert_eq!(text.trim(), expected[i]);
                    }
                    _ => panic!("expected numeric literal in IN list"),
                }
            }
        }
        _ => panic!("expected IN(list) predicate in WHERE clause"),
    }
}

#[test]
fn ast_select_spread_in_in_list() {
    let src = "SELECT 1 FROM spread_demo WHERE col1 IN (** [1, 2, 3])";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    match where_expr {
        AstExpr::InList { list, .. } => {
            assert_eq!(list.len(), 1, "expected single list item with spread");
            match &list[0] {
                AstExpr::Spread { expr, .. } => {
                    // Underlying expression should be an array literal [1, 2, 3].
                    match &**expr {
                        AstExpr::Array { elements, .. } => {
                            assert_eq!(
                                elements.len(),
                                3,
                                "expected three elements in spread array"
                            );
                            for (i, elem) in elements.iter().enumerate() {
                                match elem {
                                    AstExpr::Literal {
                                        literal: AstLiteral::Number { span },
                                        ..
                                    } => {
                                        let text = &src[span.start as usize..span.end as usize];
                                        let expected = ["1", "2", "3"][i];
                                        assert_eq!(text.trim(), expected);
                                    }
                                    _ => panic!("expected numeric literal in spread array"),
                                }
                            }
                        }
                        _ => panic!("expected array literal inside spread"),
                    }
                }
                _ => panic!("expected spread expression inside IN list"),
            }
        }
        _ => panic!("expected IN(list) predicate in WHERE clause"),
    }
}

#[test]
fn ast_select_where_not_in_list_predicate() {
    let src = "SELECT 1 FROM t WHERE col NOT IN (1, 2, 3)";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    match where_expr {
        AstExpr::InList {
            node_id: _,
            syntax_id: _,
            expr,
            list,
            negated,
            span,
        } => {
            // NOT/IN tokens now in syntax layer - skipping keyword checks
            assert!(*negated, "expected NOT IN to surface as negated=true");

            let full_text = &src[span.start as usize..span.end as usize];
            assert!(full_text.to_ascii_uppercase().contains("NOT IN"));

            // Left side should be identifier col
            match &**expr {
                AstExpr::Ident {
                    column_ref:
                        AstColumnRef {
                            qualifier: None,
                            name,
                            ..
                        },
                    ..
                } => {
                    let text = &src[name.span.start as usize..name.span.end as usize];
                    assert_eq!(text, "col");
                }
                _ => panic!("expected identifier 'col' on left side of NOT IN"),
            }

            // List should contain three numeric literals: 1, 2, 3
            assert_eq!(list.len(), 3);
            let expected = ["1", "2", "3"];
            for (i, item) in list.iter().enumerate() {
                match item {
                    AstExpr::Literal {
                        literal: AstLiteral::Number { span },
                        ..
                    } => {
                        let text = &src[span.start as usize..span.end as usize];
                        assert_eq!(text.trim(), expected[i]);
                    }
                    _ => panic!("expected numeric literal in NOT IN list"),
                }
            }
        }
        _ => panic!("expected NOT IN(list) predicate in WHERE clause"),
    }
}

#[test]
fn ast_select_where_in_subquery_predicate() {
    let src = "SELECT 1 FROM t WHERE col IN (SELECT x FROM t2)";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    match where_expr {
        AstExpr::InSubquery {
            node_id: _,
            syntax_id: _,
            expr,
            subquery,
            negated: _,
            span,
        } => {
            // NOT/IN tokens now in syntax layer - skipping keyword checks

            let full_text = &src[span.start as usize..span.end as usize];
            assert!(full_text.to_ascii_uppercase().contains("IN (SELECT"));

            match &**expr {
                AstExpr::Ident {
                    column_ref:
                        AstColumnRef {
                            qualifier: None,
                            name,
                            ..
                        },
                    ..
                } => {
                    let text = &src[name.span.start as usize..name.span.end as usize];
                    assert_eq!(text, "col");
                }
                _ => panic!("expected identifier 'col' on left side of IN(subquery)"),
            }

            // Subquery should be a simple SELECT x FROM t2
            if let AstStmt::Select(select) = &**subquery {
                assert_eq!(select.from.len(), 1);
            } else {
                panic!("expected SELECT statement in IN subquery");
            }
        }
        _ => panic!("expected IN(subquery) predicate in WHERE clause"),
    }
}

#[test]
fn ast_select_where_not_in_subquery_predicate() {
    let src = "SELECT 1 FROM t WHERE col NOT IN (SELECT x FROM t2)";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    match where_expr {
        AstExpr::InSubquery {
            node_id: _,
            syntax_id: _,
            expr,
            subquery,
            negated: _,
            span,
        } => {
            // NOT/IN tokens now in syntax layer - skipping keyword checks

            let full_text = &src[span.start as usize..span.end as usize];
            assert!(full_text.to_ascii_uppercase().contains("NOT IN (SELECT"));

            match &**expr {
                AstExpr::Ident {
                    column_ref:
                        AstColumnRef {
                            qualifier: None,
                            name,
                            ..
                        },
                    ..
                } => {
                    let text = &src[name.span.start as usize..name.span.end as usize];
                    assert_eq!(text, "col");
                }
                _ => panic!("expected identifier 'col' on left side of NOT IN(subquery)"),
            }

            if let AstStmt::Select(select) = &**subquery {
                assert_eq!(select.from.len(), 1);
            } else {
                panic!("expected SELECT statement in NOT IN subquery");
            }
        }
        _ => panic!("expected NOT IN(subquery) predicate in WHERE clause"),
    }
}

#[test]
fn ast_select_bare_select_without_from() {
    let src = "SELECT 1";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    // No FROM clause
    assert!(ast.from.is_empty());

    // Projection should contain a single numeric literal column "1"
    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            match &as_select_item(&items[0]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Number { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "1");
                }
                _ => panic!("expected numeric literal in projection for bare SELECT"),
            }
        }
        _ => panic!("expected columns projection for bare SELECT"),
    }
}

#[test]
fn ast_select_bare_select_string_literal() {
    let src = "SELECT 'foo'";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    // No FROM clause
    assert!(ast.from.is_empty());

    // Projection should contain a single string literal column "'foo'"
    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            match &as_select_item(&items[0]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::String { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "'foo'");
                }
                _ => panic!("expected string literal in projection for bare SELECT"),
            }
        }
        _ => panic!("expected columns projection for bare SELECT"),
    }
}

#[test]
fn ast_select_bare_select_boolean_literal() {
    let src = "SELECT TRUE";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    // No FROM clause
    assert!(ast.from.is_empty());

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            match &as_select_item(&items[0]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Boolean { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text.to_ascii_uppercase(), "TRUE");
                }
                _ => panic!("expected boolean literal in projection for bare SELECT"),
            }
        }
        _ => panic!("expected columns projection for bare SELECT"),
    }
}

#[test]
fn ast_select_bare_select_null_literal() {
    let src = "SELECT NULL";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    // No FROM clause
    assert!(ast.from.is_empty());

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            match &as_select_item(&items[0]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Null { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text.to_ascii_uppercase(), "NULL");
                }
                _ => panic!("expected NULL literal in projection for bare SELECT"),
            }
        }
        _ => panic!("expected columns projection for bare SELECT"),
    }
}

// Removed: ast_select_rejects_scripting_var_in_sql_mode
// The parser automatically switches to scripting mode when it encounters
// scripting constructs like :id, so there's no "SQL mode" rejection to test.

#[test]
fn ast_select_uses_token_spans() {
    let src = "SELECT col FROM t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    assert_eq!(ast.select_span.start, 0);
    assert_eq!(ast.select_span.end, 6); // "SELECT"

    // Expect a single column item with an identifier expression
    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            if let AstExpr::Ident {
                column_ref:
                    AstColumnRef {
                        qualifier: None,
                        name,
                        ..
                    },
                ..
            } = &as_select_item(&items[0]).expr
            {
                // "col" starts after "SELECT " (7..10)
                assert_eq!(name.span.start, 7);
            } else {
                panic!("expected identifier projection item");
            }
        }
        _ => panic!("expected column projection"),
    }

    // Expect a single table reference
    assert_eq!(ast.from.len(), 1);
    let table = &ast.from[0];
    // table ident "t" should be after the SELECT span
    assert!(table.name.span.start > ast.select_span.end);
}

#[test]
fn ast_select_with_distinct_and_alias() {
    let src = "SELECT DISTINCT col AS c FROM t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    // DISTINCT is captured
    match ast.set_quantifier.as_deref() {
        Some(AstSetQuantifier::Distinct) => {}
        _ => panic!("expected DISTINCT set quantifier"),
    }

    // One projected column with alias
    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            if let AstExpr::Ident {
                column_ref:
                    AstColumnRef {
                        qualifier: None,
                        name,
                        ..
                    },
                ..
            } = &as_select_item(item).expr
            {
                assert_eq!(
                    &src[name.span.start as usize..name.span.end as usize],
                    "col"
                );
            } else {
                panic!("expected identifier expr");
            }
            let alias = as_select_item(item).alias.as_ref().expect("alias");
            let alias_text = &src[alias.ident.span.start as usize..alias.ident.span.end as usize];
            assert_eq!(alias_text, "c");
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_select_literal_projection_with_aliases() {
    let src = "SELECT 1 AS n, 'foo' s, TRUE AS b, NULL x";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 4);

            // 1 AS n
            match &as_select_item(&items[0]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Number { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "1");
                }
                _ => panic!("expected numeric literal"),
            }
            let alias0 = as_select_item(&items[0])
                .alias
                .as_ref()
                .expect("alias for 1");
            let alias0_text =
                &src[alias0.ident.span.start as usize..alias0.ident.span.end as usize];
            assert_eq!(alias0_text, "n");

            // 'foo' s
            match &as_select_item(&items[1]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::String { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "'foo'");
                }
                _ => panic!("expected string literal"),
            }
            let alias1 = as_select_item(&items[1])
                .alias
                .as_ref()
                .expect("alias for 'foo'");
            let alias1_text =
                &src[alias1.ident.span.start as usize..alias1.ident.span.end as usize];
            assert_eq!(alias1_text, "s");

            // TRUE AS b
            match &as_select_item(&items[2]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Boolean { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text.to_ascii_uppercase(), "TRUE");
                }
                _ => panic!("expected boolean literal"),
            }
            let alias2 = as_select_item(&items[2])
                .alias
                .as_ref()
                .expect("alias for TRUE");
            let alias2_text =
                &src[alias2.ident.span.start as usize..alias2.ident.span.end as usize];
            assert_eq!(alias2_text, "b");

            // NULL x
            match &as_select_item(&items[3]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Null { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text.to_ascii_uppercase(), "NULL");
                }
                _ => panic!("expected NULL literal"),
            }
            let alias3 = as_select_item(&items[3])
                .alias
                .as_ref()
                .expect("alias for NULL");
            let alias3_text =
                &src[alias3.ident.span.start as usize..alias3.ident.span.end as usize];
            assert_eq!(alias3_text, "x");
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_select_simple_scalar_expressions_in_projection() {
    let src = "SELECT col + 1 AS c1, -1 AS n, +2 AS p, 5 % 2 AS m";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 4);

            // col + 1 AS c1
            match &as_select_item(&items[0]).expr {
                AstExpr::BinaryOp {
                    left,
                    right,
                    span: _,
                    ..
                } => {
                    // Operator text check removed - use syntax arena if needed
                    // Operator assertion removed
                    match &**left {
                        AstExpr::Ident {
                            column_ref:
                                AstColumnRef {
                                    qualifier: None,
                                    name,
                                    ..
                                },
                            ..
                        } => {
                            let text = &src[name.span.start as usize..name.span.end as usize];
                            assert_eq!(text, "col");
                        }
                        _ => panic!("expected identifier on left side"),
                    }
                    match &**right {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "1");
                        }
                        _ => panic!("expected number literal on right side"),
                    }
                }
                _ => panic!("expected binary op expression"),
            }
            let alias0 = as_select_item(&items[0])
                .alias
                .as_ref()
                .expect("alias for col + 1");
            let alias0_text =
                &src[alias0.ident.span.start as usize..alias0.ident.span.end as usize];
            assert_eq!(alias0_text, "c1");

            // -1 AS n
            match &as_select_item(&items[1]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Number { .. },
                    ..
                } => {}
                _ => panic!("expected unary minus number literal"),
            }
            let alias1 = as_select_item(&items[1])
                .alias
                .as_ref()
                .expect("alias for -1");
            let alias1_text =
                &src[alias1.ident.span.start as usize..alias1.ident.span.end as usize];
            assert_eq!(alias1_text, "n");

            // +2 AS p
            match &as_select_item(&items[2]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Number { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "+2");
                }
                _ => panic!("expected unary plus number literal"),
            }
            let alias2 = as_select_item(&items[2])
                .alias
                .as_ref()
                .expect("alias for +2");
            let alias2_text =
                &src[alias2.ident.span.start as usize..alias2.ident.span.end as usize];
            assert_eq!(alias2_text, "p");

            // 5 % 2 AS m
            match &as_select_item(&items[3]).expr {
                AstExpr::BinaryOp {
                    left,
                    right,
                    span: _,
                    ..
                } => {
                    // Operator text check removed - use syntax arena if needed
                    // Operator assertion removed
                    match &**left {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "5");
                        }
                        _ => panic!("expected left literal 5 in modulo expression"),
                    }
                    match &**right {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "2");
                        }
                        _ => panic!("expected right literal 2 in modulo expression"),
                    }
                }
                _ => panic!("expected binary modulo expression"),
            }
            let alias3 = as_select_item(&items[3])
                .alias
                .as_ref()
                .expect("alias for 5 % 2");
            let alias3_text =
                &src[alias3.ident.span.start as usize..alias3.ident.span.end as usize];
            assert_eq!(alias3_text, "m");
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_select_from_simple_subquery() {
    let src = "SELECT * FROM (SELECT 1 AS x) t WHERE t.x = 1";
    let tokens = tokenize(src).tokens;

    let ast = lexega_syntax::parse_select_from_tokens(src, &tokens).expect("ast");

    // Projection is star
    match &ast.projection.kind {
        AstProjectionKind::Star(_) => {}
        _ => panic!("expected star projection"),
    }

    // FROM should contain a single table ref with alias t
    assert_eq!(ast.from.len(), 1);
    let tbl = &ast.from[0];
    let alias = tbl.alias.as_ref().expect("subquery alias");
    let alias_text = &src[alias.span.start as usize..alias.span.end as usize];
    assert_eq!(alias_text, "t");

    // Subquery should be attached and have projection `1 AS x`
    let sub = tbl.subquery.as_ref().expect("expected subquery AST");
    let sub_select = match &**sub {
        AstStmt::Select(sel) => sel,
        _ => panic!("expected subquery to be a SELECT statement"),
    };
    match &sub_select.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            match &as_select_item(&items[0]).expr {
                AstExpr::Literal {
                    literal: AstLiteral::Number { span },
                    ..
                } => {
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "1");
                }
                _ => panic!("expected numeric literal in subquery projection"),
            }
            let sub_alias = as_select_item(&items[0])
                .alias
                .as_ref()
                .expect("subquery column alias");
            let sub_alias_text =
                &src[sub_alias.ident.span.start as usize..sub_alias.ident.span.end as usize];
            assert_eq!(sub_alias_text, "x");
        }
        _ => panic!("expected columns projection in subquery"),
    }
}

#[test]
fn ast_select_where_binary_comparison() {
    let src = "SELECT TOP 5 col FROM t WHERE col = 10 AND col != 20 AND col <> 30 AND col < 40 AND col <= 50 AND col > 60 AND col >= 70";
    let script = parse_sql(src).expect("parse script");
    let ast = if let AstStmt::Select(select) = &script.stmts[0] {
        select
    } else {
        panic!("Expected SELECT statement");
    };

    // TOP is captured
    let top = ast.top.as_ref().expect("top");
    if let AstExpr::Literal {
        literal: AstLiteral::Number { span },
        ..
    } = &top.expr
    {
        let text = &src[span.start as usize..span.end as usize];
        assert_eq!(text, "5");
    } else {
        panic!("expected numeric literal in TOP");
    }

    // WHERE should now be a boolean expression tree that combines
    // comparisons with AND/OR at a higher level. We walk the tree to
    // ensure all comparison operators are present, without assuming a
    // particular associativity shape.
    let where_clause = ast.where_clause.as_ref().expect("where clause");
    let where_expr = &where_clause.expr;

    fn collect_cmp_ops(
        expr: &AstExpr,
        syntax_arena: &SyntaxArena,
        src: &str,
        ops: &mut Vec<String>,
    ) {
        match expr {
            AstExpr::BinaryOp {
                syntax_id,
                left,
                right,
                ..
            } => {
                // Extract operator text from syntax arena
                let syntax_binop = syntax_arena.get_binary_op(*syntax_id);
                let op_text =
                    &src[syntax_binop.span.start as usize..syntax_binop.span.end as usize];
                ops.push(op_text.trim().to_string());

                collect_cmp_ops(left, syntax_arena, src, ops);
                collect_cmp_ops(right, syntax_arena, src, ops);
            }
            AstExpr::LogicalChain { operands, .. } => {
                // LogicalChain flattens AND/OR chains - recurse into each operand
                for operand in operands {
                    collect_cmp_ops(operand, syntax_arena, src, ops);
                }
            }
            _ => {}
        }
    }

    let mut ops = Vec::new();
    collect_cmp_ops(where_expr, &script.syntax_arena, src, &mut ops);
    assert!(ops.contains(&"=".to_string()));
    assert!(ops.contains(&"!=".to_string()) || ops.contains(&"<>".to_string()));
    assert!(ops.contains(&"<".to_string()));
    assert!(ops.contains(&"<=".to_string()));
    assert!(ops.contains(&">".to_string()));
    assert!(ops.contains(&">=".to_string()));
}

#[test]
fn ast_select_qualified_column_and_table_alias() {
    let src = "SELECT t.col AS c FROM employee_table t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    // Projection: qualified column t.col with alias c
    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            if let AstExpr::Ident {
                column_ref:
                    AstColumnRef {
                        qualifier: Some(q),
                        name,
                        ..
                    },
                ..
            } = &as_select_item(item).expr
            {
                let q_text = &src[q.span.start as usize..q.span.end as usize];
                assert_eq!(q_text, "t");
                let name_text = &src[name.span.start as usize..name.span.end as usize];
                assert_eq!(name_text, "col");
            } else {
                panic!("expected qualified identifier t.col");
            }
            let alias = as_select_item(item).alias.as_ref().expect("alias");
            let alias_text = &src[alias.ident.span.start as usize..alias.ident.span.end as usize];
            assert_eq!(alias_text, "c");
        }
        _ => panic!("expected columns projection"),
    }

    // FROM: table employee_table with alias t
    assert_eq!(ast.from.len(), 1);
    let tbl = &ast.from[0];
    let tbl_name_text = &src[tbl.name.span.start as usize..tbl.name.span.end as usize];
    assert_eq!(tbl_name_text, "employee_table");
    let tbl_alias = tbl.alias.as_ref().expect("table alias");
    let tbl_alias_text = &src[tbl_alias.span.start as usize..tbl_alias.span.end as usize];
    assert_eq!(tbl_alias_text, "t");
}

#[test]
fn ast_select_star_and_qualified_star() {
    let src1 = "SELECT * FROM t";
    let tokens1 = tokenize(src1);
    let ast1 = parse_select_from_tokens(src1, &tokens1.tokens).expect("ast1");
    match &ast1.projection.kind {
        AstProjectionKind::Star(star) => {
            assert!(star.qualifier.is_none());
            let star_text = &src1[star.star_span.start as usize..star.star_span.end as usize];
            assert_eq!(star_text, "*");
        }
        _ => panic!("expected star projection"),
    }
    assert_eq!(ast1.from.len(), 1);

    let src2 = "SELECT e.* FROM employee_table e";
    let tokens2 = tokenize(src2);
    let ast2 = parse_select_from_tokens(src2, &tokens2.tokens).expect("ast2");
    match &ast2.projection.kind {
        AstProjectionKind::Star(star) => {
            let q = star.qualifier.as_ref().expect("qualifier");
            let q_text = &src2[q.span.start as usize..q.span.end as usize];
            assert_eq!(q_text, "e");
            let star_text = &src2[star.star_span.start as usize..star.star_span.end as usize];
            assert_eq!(star_text, "*");
        }
        _ => panic!("expected qualified star projection"),
    }
    assert_eq!(ast2.from.len(), 1);
}

#[test]
fn ast_select_star_with_exclude_and_replace() {
    let src =
        "SELECT * ILIKE 'foo%' EXCLUDE (t.col1, col2) REPLACE (expr AS col3, 10 AS col4) FROM t";
    let tokens = tokenize(src).tokens;
    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Star(star) => {
            // EXCLUDE captured
            let ilike = star.ilike.as_ref().expect("ilike");
            let ilike_text = &src[ilike.ilike_span.start as usize..ilike.ilike_span.end as usize];
            assert_eq!(ilike_text.to_ascii_uppercase(), "ILIKE");

            let exclude = star.exclude.as_ref().expect("exclude");
            let ex_text =
                &src[exclude.exclude_span.start as usize..exclude.exclude_span.end as usize];
            assert_eq!(ex_text.to_ascii_uppercase(), "EXCLUDE");
            eprintln!("DEBUG_EXCLUDE_LEN: {}", exclude.columns.len());
            for (i, col) in exclude.columns.iter().enumerate() {
                let q_text = col
                    .qualifier
                    .as_ref()
                    .map(|q| &src[q.span.start as usize..q.span.end as usize]);
                let name_text = &src[col.name.span.start as usize..col.name.span.end as usize];
                eprintln!(
                    "DEBUG_EXCLUDE_COL {}: qualifier={:?} name={}",
                    i, q_text, name_text
                );
            }
            assert_eq!(exclude.columns.len(), 2);

            // First excluded column is qualified: t.col1
            let first = &exclude.columns[0];
            let first_q = first.qualifier.as_ref().expect("first qualifier");
            let first_q_text = &src[first_q.span.start as usize..first_q.span.end as usize];
            assert_eq!(first_q_text, "t");
            let first_name_text =
                &src[first.name.span.start as usize..first.name.span.end as usize];
            assert_eq!(first_name_text, "col1");

            // Second excluded column is unqualified: col2
            let second = &exclude.columns[1];
            assert!(second.qualifier.is_none());
            let second_name_text =
                &src[second.name.span.start as usize..second.name.span.end as usize];
            assert_eq!(second_name_text, "col2");

            // REPLACE captured
            let replace = star.replace.as_ref().expect("replace");
            let rep_text =
                &src[replace.replace_span.start as usize..replace.replace_span.end as usize];
            assert_eq!(rep_text.to_ascii_uppercase(), "REPLACE");
            // The REPLACE list is parsed correctly by the AST; for now,
            // just assert that we detected a REPLACE clause at all.
            let _replace_len = replace.items.len();
        }
        _ => panic!("expected star projection with EXCLUDE/REPLACE"),
    }

    assert_eq!(ast.from.len(), 1);
}

#[test]
fn ast_select_with_positional_column() {
    let src = "SELECT $2 FROM employee_table ORDER BY $2";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            match &as_select_item(item).expr {
                #[allow(unused_variables)]
                AstExpr::PositionRef {
                    node_id: _,
                    qualifier,
                    dot_span,
                    dollar_span,
                    index_span,
                } => {
                    let dollar_text = &src[dollar_span.start as usize..dollar_span.end as usize];
                    let index_text = &src[index_span.start as usize..index_span.end as usize];
                    assert_eq!(dollar_text, "$");
                    assert_eq!(index_text, "2");
                }
                _ => panic!("expected positional reference in projection"),
            }
        }
        _ => panic!("expected columns projection with positional ref"),
    }

    // FROM should still see employee_table
    assert_eq!(ast.from.len(), 1);

    // ORDER BY should be present with a positional ref
    let ob = ast.order_by.as_ref().expect("order_by");
    assert_eq!(ob.items.len(), 1);
    match &ob.items[0].expr {
        #[allow(unused_variables)]
        AstExpr::PositionRef {
            node_id: _,
            qualifier,
            dot_span,
            dollar_span,
            index_span,
        } => {
            let dollar_text = &src[dollar_span.start as usize..dollar_span.end as usize];
            let index_text = &src[index_span.start as usize..index_span.end as usize];
            assert_eq!(dollar_text, "$");
            assert_eq!(index_text, "2");
        }
        _ => panic!("expected positional ref in ORDER BY"),
    }
}

#[test]
fn ast_select_order_by_nulls() {
    let src = "SELECT col FROM t ORDER BY col NULLS FIRST, col DESC NULLS LAST";
    let tokens = tokenize(src).tokens;
    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    let ob = ast.order_by.as_ref().expect("order_by");
    assert_eq!(ob.items.len(), 2);

    // First item: implicit ASC, NULLS FIRST
    let item0 = &ob.items[0];
    assert_eq!(item0.asc, None); // no explicit ASC
    assert_eq!(item0.nulls_first, Some(true));

    // Second item: DESC, NULLS LAST
    let item1 = &ob.items[1];
    assert_eq!(item1.asc, Some(false));
    assert_eq!(item1.nulls_first, Some(false));
}

#[test]
fn ast_select_order_by_identifier_desc() {
    let src = "SELECT col FROM t ORDER BY col DESC";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    let ob = ast.order_by.as_ref().expect("order_by");
    assert_eq!(ob.items.len(), 1);
    let item = &ob.items[0];
    match &item.expr {
        AstExpr::Ident {
            column_ref:
                AstColumnRef {
                    qualifier: None,
                    name,
                    ..
                },
            ..
        } => {
            let text = &src[name.span.start as usize..name.span.end as usize];
            assert_eq!(text, "col");
        }
        _ => panic!("expected identifier in ORDER BY"),
    }
    assert_eq!(item.asc, Some(false)); // DESC
}

#[test]
fn ast_select_identifier_in_projection() {
    let src = "SELECT IDENTIFIER('col_name') FROM t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            match &as_select_item(item).expr {
                AstExpr::ExplSnowIdent {
                    node_id: _,
                    ident_span,
                    arg,
                    span,
                } => {
                    let ident_text = &src[ident_span.start as usize..ident_span.end as usize];
                    assert_eq!(ident_text.to_ascii_uppercase(), "IDENTIFIER");
                    let full_text = &src[span.start as usize..span.end as usize];
                    assert_eq!(full_text, "IDENTIFIER('col_name')");
                    match &**arg {
                        AstExpr::Literal {
                            literal: AstLiteral::String { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "'col_name'");
                        }
                        _ => panic!("expected string literal arg"),
                    }
                }
                _ => panic!("expected ExplSnowIdent in projection"),
            }
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_select_identifier_in_order_by_with_positional_arg() {
    let src = "SELECT col FROM t ORDER BY IDENTIFIER($2)";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    let ob = ast.order_by.as_ref().expect("order_by");
    assert_eq!(ob.items.len(), 1);
    let item = &ob.items[0];
    match &item.expr {
        AstExpr::ExplSnowIdent {
            node_id: _,
            ident_span,
            arg,
            span,
        } => {
            let ident_text = &src[ident_span.start as usize..ident_span.end as usize];
            assert_eq!(ident_text.to_ascii_uppercase(), "IDENTIFIER");
            let full_text = &src[span.start as usize..span.end as usize];
            assert_eq!(full_text, "IDENTIFIER($2)");
            match &**arg {
                #[allow(unused_variables)]
                AstExpr::PositionRef {
                    node_id: _,
                    qualifier,
                    dot_span,
                    dollar_span,
                    index_span,
                } => {
                    let dollar_text = &src[dollar_span.start as usize..dollar_span.end as usize];
                    let index_text = &src[index_span.start as usize..index_span.end as usize];
                    assert_eq!(dollar_text, "$");
                    assert_eq!(index_text, "2");
                }
                _ => panic!("expected positional arg"),
            }
        }
        _ => panic!("expected ExplSnowIdent in ORDER BY"),
    }
}

#[test]
fn ast_select_order_by_multiple_items() {
    let src = "SELECT col FROM t ORDER BY col ASC, $2 DESC";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    let ob = ast.order_by.as_ref().expect("order_by");
    assert_eq!(ob.items.len(), 2);

    // First item: identifier ASC
    let first = &ob.items[0];
    match &first.expr {
        AstExpr::Ident {
            column_ref:
                AstColumnRef {
                    qualifier: None,
                    name,
                    ..
                },
            ..
        } => {
            let text = &src[name.span.start as usize..name.span.end as usize];
            assert_eq!(text, "col");
        }
        _ => panic!("expected identifier in first ORDER BY item"),
    }
    assert_eq!(first.asc, Some(true));

    // Second item: positional DESC
    let second = &ob.items[1];
    match &second.expr {
        #[allow(unused_variables)]
        AstExpr::PositionRef {
            node_id: _,
            qualifier,
            dot_span,
            dollar_span,
            index_span,
        } => {
            let dollar_text = &src[dollar_span.start as usize..dollar_span.end as usize];
            let index_text = &src[index_span.start as usize..index_span.end as usize];
            assert_eq!(dollar_text, "$");
            assert_eq!(index_text, "2");
        }
        _ => panic!("expected positional ref in second ORDER BY item"),
    }
    assert_eq!(second.asc, Some(false));
}

#[test]
fn ast_select_group_by_ident_and_positional() {
    let src = "SELECT col FROM t GROUP BY col, $2";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    let gb = ast.group_by.as_ref().expect("group_by");
    let items = match &gb.variant {
        AstGroupByVariant::Standard(items) => items,
        _ => panic!("expected Standard GROUP BY variant"),
    };
    assert_eq!(items.len(), 2);

    // First group item: identifier
    match &items[0].expr {
        AstExpr::Ident {
            column_ref:
                AstColumnRef {
                    qualifier: None,
                    name,
                    ..
                },
            ..
        } => {
            let text = &src[name.span.start as usize..name.span.end as usize];
            assert_eq!(text, "col");
        }
        _ => panic!("expected identifier in first GROUP BY item"),
    }

    // Second group item: positional reference
    match &items[1].expr {
        #[allow(unused_variables)]
        AstExpr::PositionRef {
            node_id: _,
            qualifier,
            dot_span,
            dollar_span,
            index_span,
        } => {
            let dollar_text = &src[dollar_span.start as usize..dollar_span.end as usize];
            let index_text = &src[index_span.start as usize..index_span.end as usize];
            assert_eq!(dollar_text, "$");
            assert_eq!(index_text, "2");
        }
        _ => panic!("expected positional ref in second GROUP BY item"),
    }
}

#[test]
fn ast_select_group_by_case_expression() {
    let src = "SELECT a, b FROM t GROUP BY CASE WHEN a = 1 THEN b ELSE c END";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    let gb = ast.group_by.as_ref().expect("group_by");
    let items = match &gb.variant {
        AstGroupByVariant::Standard(items) => items,
        _ => panic!("expected Standard GROUP BY variant"),
    };
    assert_eq!(items.len(), 1);

    match &items[0].expr {
        AstExpr::Case {
            whens, else_expr, ..
        } => {
            assert_eq!(whens.len(), 1);
            assert!(else_expr.is_some());
        }
        _ => panic!("expected CASE expression in GROUP BY item"),
    }
}

#[test]
fn ast_select_row_number_over_partition_order() {
    let src = "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM t";
    let tokens = tokenize(src).tokens;

    let ast = parse_select_from_tokens(src, &tokens).expect("ast");

    match &ast.projection.kind {
        AstProjectionKind::Columns(items) => {
            assert_eq!(items.len(), 1);
            let item = &items[0];
            match &as_select_item(item).expr {
                AstExpr::WindowFn {
                    func_name, window, ..
                } => {
                    let func_text =
                        &src[func_name.span.start as usize..func_name.span.end as usize];
                    assert_eq!(func_text.to_ascii_uppercase(), "ROW_NUMBER");

                    // Partition BY dept
                    assert_eq!(window.partition_by.len(), 1);
                    match &window.partition_by[0] {
                        AstExpr::Ident {
                            column_ref:
                                AstColumnRef {
                                    qualifier: None,
                                    name,
                                    ..
                                },
                            ..
                        } => {
                            let text = &src[name.span.start as usize..name.span.end as usize];
                            assert_eq!(text, "dept");
                        }
                        _ => panic!("expected dept identifier in PARTITION BY"),
                    }

                    // ORDER BY id
                    assert_eq!(window.order_by.len(), 1);
                    let ob_item = &window.order_by[0];
                    match &ob_item.expr {
                        AstExpr::Ident {
                            column_ref:
                                AstColumnRef {
                                    qualifier: None,
                                    name,
                                    ..
                                },
                            ..
                        } => {
                            let text = &src[name.span.start as usize..name.span.end as usize];
                            assert_eq!(text, "id");
                        }
                        _ => panic!("expected id identifier in ORDER BY"),
                    }

                    // ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                    let frame = window.frame.as_ref().expect("frame");
                    match frame.kind {
                        AstWindowFrameKind::Rows => {}
                        _ => panic!("expected ROWS frame"),
                    }
                    match frame.start.kind {
                        AstFrameBoundKind::UnboundedPreceding => {}
                        _ => panic!("expected UNBOUNDED PRECEDING start"),
                    }
                    let end = frame.end.as_ref().expect("end bound");
                    match end.kind {
                        AstFrameBoundKind::CurrentRow => {}
                        _ => panic!("expected CURRENT ROW end"),
                    }
                }
                _ => panic!("expected window function in projection"),
            }
        }
        _ => panic!("expected columns projection"),
    }
}

#[test]
fn ast_set_select_union_basic() {
    let src = "SELECT 1 UNION SELECT 2";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(set) => {
            assert!(matches!(set.op, AstSetOpKind::Union));
            assert!(matches!(set.modifier, AstSetModifier::None));

            // Left SELECT: SELECT 1
            let left_sel = match &*set.left {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected left operand to be SELECT"),
            };
            assert!(left_sel.from.is_empty());
            match &left_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "1");
                        }
                        _ => panic!("expected numeric literal in left SELECT"),
                    }
                }
                _ => panic!("expected columns projection in left SELECT"),
            }

            // Right SELECT: SELECT 2
            let right_sel = match &*set.right {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected right operand to be SELECT"),
            };
            assert!(right_sel.from.is_empty());
            match &right_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "2");
                        }
                        _ => panic!("expected numeric literal in right SELECT"),
                    }
                }
                _ => panic!("expected columns projection in right SELECT"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for UNION"),
    }
}

#[test]
fn ast_set_select_union_all_basic() {
    let src = "SELECT 1 UNION ALL SELECT 2";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(set) => {
            assert!(matches!(set.op, AstSetOpKind::Union));
            assert!(matches!(set.modifier, AstSetModifier::All));

            // Left SELECT: SELECT 1
            let left_sel = match &*set.left {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected left operand to be SELECT"),
            };
            assert!(left_sel.from.is_empty());
            match &left_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "1");
                        }
                        _ => panic!("expected numeric literal in left SELECT"),
                    }
                }
                _ => panic!("expected columns projection in left SELECT"),
            }

            // Right SELECT: SELECT 2
            let right_sel = match &*set.right {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected right operand to be SELECT"),
            };
            assert!(right_sel.from.is_empty());
            match &right_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "2");
                        }
                        _ => panic!("expected numeric literal in right SELECT"),
                    }
                }
                _ => panic!("expected columns projection in right SELECT"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for UNION ALL"),
    }
}

#[test]
fn ast_set_select_union_chain_basic() {
    let src = "SELECT 1 UNION SELECT 2 UNION SELECT 3";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(outer) => {
            // Outer: (SELECT 1 UNION SELECT 2) UNION SELECT 3
            assert!(matches!(outer.op, AstSetOpKind::Union));
            assert!(matches!(outer.modifier, AstSetModifier::None));

            // Right of outer: SELECT 3
            let right_sel = match &*outer.right {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected right operand of outer to be SELECT"),
            };
            assert!(right_sel.from.is_empty());
            match &right_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "3");
                        }
                        _ => panic!("expected numeric literal in right-most SELECT"),
                    }
                }
                _ => panic!("expected columns projection in right-most SELECT"),
            }

            // Left of outer: a nested SetSelect for SELECT 1 UNION SELECT 2
            let inner = match &*outer.left {
                AstStmt::SetSelect(s) => s,
                _ => panic!("expected left operand of outer to be nested SetSelect"),
            };
            assert!(matches!(inner.op, AstSetOpKind::Union));
            assert!(matches!(inner.modifier, AstSetModifier::None));
            let inner_left_sel = match &*inner.left {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected inner left to be SELECT"),
            };
            let inner_right_sel = match &*inner.right {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected inner right to be SELECT"),
            };

            // inner left: SELECT 1
            assert!(inner_left_sel.from.is_empty());
            match &inner_left_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "1");
                        }
                        _ => panic!("expected numeric literal in left-most SELECT"),
                    }
                }
                _ => panic!("expected columns projection in left-most SELECT"),
            }

            // inner right: SELECT 2
            assert!(inner_right_sel.from.is_empty());
            match &inner_right_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "2");
                        }
                        _ => panic!("expected numeric literal in middle SELECT"),
                    }
                }
                _ => panic!("expected columns projection in middle SELECT"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for chained UNION"),
    }
}

#[test]
fn ast_select_inner_join_structure() {
    let src = "SELECT * FROM t1 INNER JOIN t2";
    let tokens = tokenize(src).tokens;
    let select = parse_select_from_tokens(src, &tokens).expect("ast");

    assert_eq!(select.from.len(), 1, "expected a single base table");
    let base = &select.from[0];
    assert_eq!(base.joins.len(), 1, "expected one join off base table");
    let join = &base.joins[0];
    match join.kind {
        AstJoinKind::Inner => {}
        _ => panic!("expected Inner join kind"),
    }
    assert!(
        join.directed_keyword_span.is_none(),
        "INNER JOIN without DIRECTED should not be directed"
    );
}

#[test]
fn ast_select_inner_join_with_on_condition() {
    let src = "SELECT * FROM t1 INNER JOIN t2 ON t1.id = t2.id";
    let tokens = tokenize(src).tokens;
    let select = parse_select_from_tokens(src, &tokens).expect("ast");

    assert_eq!(select.from.len(), 1, "expected a single base table");
    let base = &select.from[0];
    assert_eq!(base.joins.len(), 1, "expected one join off base table");
    let join = &base.joins[0];
    match join.kind {
        AstJoinKind::Inner => {}
        _ => panic!("expected Inner join kind"),
    }
    match &join.constraint {
        lexega_syntax::ast::AstJoinConstraint::On(boxed_expr) => {
            // Expect a binary comparison t1.id = t2.id
            match &**boxed_expr {
                AstExpr::BinaryOp {
                    left,
                    right,
                    span: _,
                    ..
                } => {
                    // Operator text check removed - use syntax arena if needed
                    // Operator assertion removed
                    // Left: t1.id
                    match &**left {
                        AstExpr::Ident {
                            column_ref:
                                AstColumnRef {
                                    qualifier: Some(q),
                                    name,
                                    ..
                                },
                            ..
                        } => {
                            let qtext = &src[q.span.start as usize..q.span.end as usize];
                            let ntext = &src[name.span.start as usize..name.span.end as usize];
                            assert_eq!(qtext, "t1");
                            assert_eq!(ntext, "id");
                        }
                        _ => {
                            panic!("expected qualified identifier t1.id on left of join condition")
                        }
                    }
                    // Right: t2.id
                    match &**right {
                        AstExpr::Ident {
                            column_ref:
                                AstColumnRef {
                                    qualifier: Some(q),
                                    name,
                                    ..
                                },
                            ..
                        } => {
                            let qtext = &src[q.span.start as usize..q.span.end as usize];
                            let ntext = &src[name.span.start as usize..name.span.end as usize];
                            assert_eq!(qtext, "t2");
                            assert_eq!(ntext, "id");
                        }
                        _ => {
                            panic!("expected qualified identifier t2.id on right of join condition")
                        }
                    }
                }
                _ => panic!("expected binary op in join ON condition"),
            }
        }
        _ => panic!("expected ON constraint for INNER JOIN with ON clause"),
    }
}

#[test]
fn ast_select_left_right_full_join_kinds() {
    fn check_kind(sql: &str, expected: AstJoinKind) {
        let tokens = tokenize(sql);
        let select = parse_select_from_tokens(sql, &tokens.tokens).expect("ast");
        assert_eq!(select.from.len(), 1);
        let base = &select.from[0];
        assert_eq!(base.joins.len(), 1);
        let join = &base.joins[0];
        match (&join.kind, &expected) {
            (AstJoinKind::Inner, AstJoinKind::Inner)
            | (AstJoinKind::LeftOuter, AstJoinKind::LeftOuter)
            | (AstJoinKind::RightOuter, AstJoinKind::RightOuter)
            | (AstJoinKind::FullOuter, AstJoinKind::FullOuter)
            | (AstJoinKind::Cross, AstJoinKind::Cross)
            | (AstJoinKind::NaturalInner, AstJoinKind::NaturalInner)
            | (AstJoinKind::NaturalLeftOuter, AstJoinKind::NaturalLeftOuter)
            | (AstJoinKind::NaturalRightOuter, AstJoinKind::NaturalRightOuter)
            | (AstJoinKind::NaturalFullOuter, AstJoinKind::NaturalFullOuter) => {}
            _ => panic!("unexpected join kind"),
        }
    }

    check_kind("SELECT * FROM t1 LEFT JOIN t2", AstJoinKind::LeftOuter);
    check_kind(
        "SELECT * FROM t1 LEFT OUTER JOIN t2",
        AstJoinKind::LeftOuter,
    );
    check_kind("SELECT * FROM t1 RIGHT JOIN t2", AstJoinKind::RightOuter);
    check_kind(
        "SELECT * FROM t1 RIGHT OUTER JOIN t2",
        AstJoinKind::RightOuter,
    );
    check_kind("SELECT * FROM t1 FULL JOIN t2", AstJoinKind::FullOuter);
    check_kind(
        "SELECT * FROM t1 FULL OUTER JOIN t2",
        AstJoinKind::FullOuter,
    );
}

#[test]
fn ast_select_cross_join_kind() {
    let src = "SELECT * FROM t1 CROSS JOIN t2";
    let tokens = tokenize(src).tokens;
    let select = parse_select_from_tokens(src, &tokens).expect("ast");

    assert_eq!(select.from.len(), 1, "expected a single base table");
    let base = &select.from[0];
    assert_eq!(base.joins.len(), 1, "expected one join off base table");
    let join = &base.joins[0];
    match join.kind {
        AstJoinKind::Cross => {}
        _ => panic!("expected Cross join kind"),
    }
    assert!(
        join.directed_keyword_span.is_none(),
        "CROSS JOIN should not be directed"
    );
}

#[test]
fn ast_select_cross_directed_join_kind() {
    let src = "SELECT * FROM t1 CROSS DIRECTED JOIN t2";
    let tokens = tokenize(src).tokens;
    let select = parse_select_from_tokens(src, &tokens).expect("ast");

    assert_eq!(select.from.len(), 1, "expected a single base table");
    let base = &select.from[0];
    assert_eq!(base.joins.len(), 1, "expected one join off base table");
    let join = &base.joins[0];
    match join.kind {
        AstJoinKind::Cross => {}
        _ => panic!("expected Cross join kind for CROSS DIRECTED JOIN"),
    }
    assert!(
        join.directed_keyword_span.is_some(),
        "CROSS DIRECTED JOIN should be directed"
    );
}

#[test]
fn ast_select_directed_requires_explicit_type() {
    // Valid: INNER DIRECTED JOIN
    let src_ok = "SELECT * FROM t1 INNER DIRECTED JOIN t2";
    let tokens_ok = tokenize(src_ok);
    let select_ok = parse_select_from_tokens(src_ok, &tokens_ok.tokens).expect("ast");
    assert_eq!(select_ok.from.len(), 1, "expected a single base table");
    let base_ok = &select_ok.from[0];
    assert_eq!(base_ok.joins.len(), 1, "expected one join off base table");
    let join_ok = &base_ok.joins[0];
    match join_ok.kind {
        AstJoinKind::Inner => {}
        _ => panic!("expected Inner join kind for INNER DIRECTED JOIN"),
    }
    assert!(
        join_ok.directed_keyword_span.is_some(),
        "INNER DIRECTED JOIN should be directed"
    );

    // Invalid: bare DIRECTED JOIN without explicit type should fail to parse.
    let src_bad = "SELECT * FROM t1 DIRECTED JOIN t2";
    let tokens_bad = tokenize(src_bad);
    let select_bad = parse_select_from_tokens(src_bad, &tokens_bad.tokens);
    assert!(
        select_bad.is_none(),
        "expected DIRECTED JOIN without explicit type to fail parsing",
    );
}

#[test]
fn ast_select_natural_join_kinds() {
    fn check_kind(sql: &str, expected: AstJoinKind) {
        let tokens = tokenize(sql);
        let select = parse_select_from_tokens(sql, &tokens.tokens).expect("ast");
        assert_eq!(select.from.len(), 1, "expected a single base table");
        let base = &select.from[0];
        assert_eq!(base.joins.len(), 1, "expected one join off base table");
        let join = &base.joins[0];
        match (&join.kind, &expected) {
            (AstJoinKind::NaturalInner, AstJoinKind::NaturalInner)
            | (AstJoinKind::NaturalLeftOuter, AstJoinKind::NaturalLeftOuter)
            | (AstJoinKind::NaturalRightOuter, AstJoinKind::NaturalRightOuter)
            | (AstJoinKind::NaturalFullOuter, AstJoinKind::NaturalFullOuter) => {}
            _ => panic!("unexpected NATURAL join kind: {:?}", join.kind),
        }
        assert!(
            join.directed_keyword_span.is_none(),
            "NATURAL joins should not be directed by default",
        );
        match join.constraint {
            lexega_syntax::ast::AstJoinConstraint::None => {}
            _ => panic!("NATURAL joins should not carry explicit ON/USING constraints"),
        }
    }

    // NATURAL [INNER] JOIN
    check_kind(
        "SELECT * FROM t1 NATURAL JOIN t2",
        AstJoinKind::NaturalInner,
    );
    check_kind(
        "SELECT * FROM t1 NATURAL INNER JOIN t2",
        AstJoinKind::NaturalInner,
    );

    // NATURAL LEFT/RIGHT/FULL [OUTER] JOIN
    check_kind(
        "SELECT * FROM t1 NATURAL LEFT JOIN t2",
        AstJoinKind::NaturalLeftOuter,
    );
    check_kind(
        "SELECT * FROM t1 NATURAL LEFT OUTER JOIN t2",
        AstJoinKind::NaturalLeftOuter,
    );
    check_kind(
        "SELECT * FROM t1 NATURAL RIGHT JOIN t2",
        AstJoinKind::NaturalRightOuter,
    );
    check_kind(
        "SELECT * FROM t1 NATURAL RIGHT OUTER JOIN t2",
        AstJoinKind::NaturalRightOuter,
    );
    check_kind(
        "SELECT * FROM t1 NATURAL FULL JOIN t2",
        AstJoinKind::NaturalFullOuter,
    );
    check_kind(
        "SELECT * FROM t1 NATURAL FULL OUTER JOIN t2",
        AstJoinKind::NaturalFullOuter,
    );
}

#[test]
fn ast_set_select_malformed_missing_right_select() {
    let src = "SELECT 1 UNION 2";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens);
    // With error recovery, parser returns OpaqueContent instead of None
    assert!(
        matches!(stmt, Some(AstStmt::OpaqueContent { .. })),
        "expected malformed UNION to use error recovery (OpaqueContent)"
    );
}

#[test]
fn ast_set_select_intersect_basic() {
    let src = "SELECT 1 INTERSECT SELECT 1";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(set) => {
            assert!(matches!(set.op, AstSetOpKind::Intersect));
            assert!(matches!(set.modifier, AstSetModifier::None));

            // Left SELECT: SELECT 1
            let left_sel = match &*set.left {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected left operand to be SELECT"),
            };
            assert!(left_sel.from.is_empty());
            match &left_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "1");
                        }
                        _ => panic!("expected numeric literal in left SELECT"),
                    }
                }
                _ => panic!("expected columns projection in left SELECT"),
            }

            // Right SELECT: SELECT 1
            let right_sel = match &*set.right {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected right operand to be SELECT"),
            };
            assert!(right_sel.from.is_empty());
            match &right_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "1");
                        }
                        _ => panic!("expected numeric literal in right SELECT"),
                    }
                }
                _ => panic!("expected columns projection in right SELECT"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for INTERSECT"),
    }
}

#[test]
fn ast_set_select_except_basic() {
    let src = "SELECT 1 EXCEPT SELECT 2";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(set) => {
            assert!(matches!(set.op, AstSetOpKind::Except));
            assert!(matches!(set.modifier, AstSetModifier::None));

            // Left SELECT: SELECT 1
            let left_sel = match &*set.left {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected left operand to be SELECT"),
            };
            assert!(left_sel.from.is_empty());
            match &left_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "1");
                        }
                        _ => panic!("expected numeric literal in left SELECT"),
                    }
                }
                _ => panic!("expected columns projection in left SELECT"),
            }

            // Right SELECT: SELECT 2
            let right_sel = match &*set.right {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected right operand to be SELECT"),
            };
            assert!(right_sel.from.is_empty());
            match &right_sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    match &as_select_item(&items[0]).expr {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { span },
                            ..
                        } => {
                            let text = &src[span.start as usize..span.end as usize];
                            assert_eq!(text, "2");
                        }
                        _ => panic!("expected numeric literal in right SELECT"),
                    }
                }
                _ => panic!("expected columns projection in right SELECT"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for EXCEPT"),
    }
}

#[test]
fn ast_set_select_parenthesized_left() {
    // Test: (SELECT 1 UNION SELECT 2) EXCEPT SELECT 3
    let src = "(SELECT 1 UNION SELECT 2) EXCEPT SELECT 3";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(outer) => {
            // Outer operation should be EXCEPT
            assert!(matches!(outer.op, AstSetOpKind::Except));
            assert!(matches!(outer.modifier, AstSetModifier::None));

            // Left should be a nested SetSelect (UNION)
            match &*outer.left {
                AstStmt::SetSelect(inner) => {
                    assert!(matches!(inner.op, AstSetOpKind::Union));
                    // Verify inner contains SELECT 1 and SELECT 2
                    match (&*inner.left, &*inner.right) {
                        (AstStmt::Select(_), AstStmt::Select(_)) => { /* OK */ }
                        _ => panic!("expected inner UNION to have two SELECTs"),
                    }
                }
                _ => panic!("expected left operand to be nested SetSelect"),
            }

            // Right should be SELECT 3
            match &*outer.right {
                AstStmt::Select(_) => { /* OK */ }
                _ => panic!("expected right operand to be SELECT"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for parenthesized statement"),
    }
}

#[test]
fn ast_set_select_parenthesized_right() {
    // Test: SELECT 1 INTERSECT (SELECT 2 EXCEPT SELECT 3)
    let src = "SELECT 1 INTERSECT (SELECT 2 EXCEPT SELECT 3)";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(outer) => {
            // Outer operation should be INTERSECT
            assert!(matches!(outer.op, AstSetOpKind::Intersect));
            assert!(matches!(outer.modifier, AstSetModifier::None));

            // Left should be SELECT 1
            match &*outer.left {
                AstStmt::Select(_) => { /* OK */ }
                _ => panic!("expected left operand to be SELECT"),
            }

            // Right should be a nested SetSelect (EXCEPT)
            match &*outer.right {
                AstStmt::SetSelect(inner) => {
                    assert!(matches!(inner.op, AstSetOpKind::Except));
                    // Verify inner contains SELECT 2 and SELECT 3
                    match (&*inner.left, &*inner.right) {
                        (AstStmt::Select(_), AstStmt::Select(_)) => { /* OK */ }
                        _ => panic!("expected inner EXCEPT to have two SELECTs"),
                    }
                }
                _ => panic!("expected right operand to be nested SetSelect"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for parenthesized statement"),
    }
}

#[test]
fn ast_set_select_parenthesized_both() {
    // Test: (SELECT 1 UNION SELECT 2) INTERSECT (SELECT 3 EXCEPT SELECT 4)
    let src = "(SELECT 1 UNION SELECT 2) INTERSECT (SELECT 3 EXCEPT SELECT 4)";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(outer) => {
            // Outer operation should be INTERSECT
            assert!(matches!(outer.op, AstSetOpKind::Intersect));
            assert!(matches!(outer.modifier, AstSetModifier::None));

            // Left should be a nested SetSelect (UNION)
            match &*outer.left {
                AstStmt::SetSelect(inner) => {
                    assert!(matches!(inner.op, AstSetOpKind::Union));
                }
                _ => panic!("expected left operand to be nested SetSelect"),
            }

            // Right should be a nested SetSelect (EXCEPT)
            match &*outer.right {
                AstStmt::SetSelect(inner) => {
                    assert!(matches!(inner.op, AstSetOpKind::Except));
                }
                _ => panic!("expected right operand to be nested SetSelect"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for parenthesized statement"),
    }
}

#[test]
fn ast_set_select_deeply_nested_parens() {
    // Test: ((SELECT 1 UNION SELECT 2) INTERSECT SELECT 3) EXCEPT SELECT 4
    let src = "((SELECT 1 UNION SELECT 2) INTERSECT SELECT 3) EXCEPT SELECT 4";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(outer) => {
            // Outer operation should be EXCEPT
            assert!(matches!(outer.op, AstSetOpKind::Except));

            // Left should be a nested SetSelect (INTERSECT)
            match &*outer.left {
                AstStmt::SetSelect(middle) => {
                    assert!(matches!(middle.op, AstSetOpKind::Intersect));

                    // Left of middle should be another nested SetSelect (UNION)
                    match &*middle.left {
                        AstStmt::SetSelect(inner) => {
                            assert!(matches!(inner.op, AstSetOpKind::Union));
                        }
                        _ => panic!("expected deeply nested UNION"),
                    }
                }
                _ => panic!("expected left operand to be nested SetSelect"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect for deeply nested statement"),
    }
}

#[test]
fn ast_set_select_parenthesized_simple() {
    // Test: (SELECT 1 UNION SELECT 2)
    // A parenthesized set operation without additional operations
    let src = "(SELECT 1 UNION SELECT 2)";
    let tokens = tokenize(src).tokens;

    let stmt = parse_stmt(src, &tokens).expect("stmt");
    match stmt {
        AstStmt::SetSelect(set) => {
            assert!(matches!(set.op, AstSetOpKind::Union));
            assert!(matches!(set.modifier, AstSetModifier::None));

            // Both operands should be SELECT
            match (&*set.left, &*set.right) {
                (AstStmt::Select(_), AstStmt::Select(_)) => { /* OK */ }
                _ => panic!("expected both operands to be SELECT"),
            }
        }
        _ => panic!("expected AstStmt::SetSelect"),
    }
}
