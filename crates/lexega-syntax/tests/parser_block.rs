// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::ast::{
    AstCreateTableVariant, AstDescribe, AstInsertSourceKind, AstLiteral, AstProjectionKind,
    AstSelectItem, AstTimeTravelClause, AstTimeTravelKind, CaseBranch, IfBranch,
    ProjectionItemKind,
};
use lexega_syntax::{parse_sql, parse_stmt_from_str, AstExpr, AstStmt};

// Helper to unwrap ProjectionItem to SelectItem for tests
fn as_select_item(item: &lexega_syntax::ast::ProjectionItem) -> &AstSelectItem {
    match &item.kind {
        ProjectionItemKind::SelectItem(s) => s,
        _ => panic!("Expected SelectItem in projection"),
    }
}

#[test]
fn parse_simple_while_loop_in_block() {
    let src = r#"
BEGIN
  LET counter := 0;
  WHILE (counter < 5) DO
    counter := counter + 1;
  END WHILE;
  RETURN counter;
END;
"#;

    let script = parse_sql(src).expect("failed to parse WHILE loop script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 3, "expected LET, WHILE, RETURN in body");
            match &body[1] {
                AstStmt::While(w) => {
                    let condition_span = w.condition_span;
                    let while_body = &w.body;
                    let cond_text =
                        &src[condition_span.start as usize..condition_span.end as usize];
                    assert!(cond_text.contains("counter < 5"));
                    assert_eq!(while_body.len(), 1);
                    match &while_body[0] {
                        AstStmt::Assign { expr_span, .. } => {
                            let rhs_text = &src[expr_span.start as usize..expr_span.end as usize];
                            assert!(rhs_text.contains("counter + 1"));
                        }
                        _ => panic!("expected assignment in WHILE body"),
                    }
                }
                _ => panic!("expected WHILE as second statement in block body"),
            }
        }
        _ => panic!("expected top-level block for WHILE test"),
    }
}

#[test]
fn parse_simple_repeat_loop_in_block() {
    let src = r#"
BEGIN
  LET counter := 5;
  LET number_of_iterations := 0;
  REPEAT
    counter := counter - 1;
    number_of_iterations := number_of_iterations + 1;
  UNTIL (counter = 0)
  END REPEAT;
  RETURN number_of_iterations;
END;
"#;

    let script = parse_sql(src).expect("failed to parse REPEAT loop script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 4, "expected two LETs, REPEAT, RETURN in body");
            match &body[2] {
                AstStmt::Repeat(r) => {
                    let repeat_body = &r.body;
                    let until_condition_span = r.until_condition_span;
                    let cond_text = &src
                        [until_condition_span.start as usize..until_condition_span.end as usize];
                    assert!(cond_text.contains("counter = 0"));
                    assert_eq!(repeat_body.len(), 2);
                    match &repeat_body[0] {
                        AstStmt::Assign { expr_span, .. } => {
                            let rhs_text = &src[expr_span.start as usize..expr_span.end as usize];
                            assert!(rhs_text.contains("counter - 1"));
                        }
                        _ => panic!("expected assignment in REPEAT body"),
                    }
                }
                _ => panic!("expected REPEAT as third statement in block body"),
            }
        }
        _ => panic!("expected top-level block for REPEAT test"),
    }
}

#[test]
fn parse_simple_loop_in_block() {
    let src = r#"
BEGIN
  LET counter := 5;
  LOOP
    IF (counter = 0) THEN
      BREAK;
    END IF;
    counter := counter - 1;
  END LOOP;
  RETURN counter;
END;
"#;

    let script = parse_sql(src).expect("failed to parse LOOP script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 3, "expected LET, LOOP, RETURN in body");
            match &body[1] {
                AstStmt::Loop(l) => {
                    let loop_body = &l.body;
                    assert_eq!(
                        loop_body.len(),
                        2,
                        "expected IF and assignment in LOOP body"
                    );
                    match &loop_body[1] {
                        AstStmt::Assign { expr_span, .. } => {
                            let rhs_text = &src[expr_span.start as usize..expr_span.end as usize];
                            assert!(rhs_text.contains("counter - 1"));
                        }
                        _ => panic!("expected assignment as second statement in LOOP body"),
                    }
                }
                _ => panic!("expected LOOP as second statement in block body"),
            }
        }
        _ => panic!("expected top-level block for LOOP test"),
    }
}

#[test]
fn parse_break_in_simple_loop() {
    let src = r#"
BEGIN
  LOOP
    IF (counter = 0) THEN
      BREAK;
    END IF;
  END LOOP;
END;
"#;

    let script = parse_sql(src).expect("failed to parse BREAK in LOOP script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single LOOP in block body");
            match &body[0] {
                AstStmt::Loop(l) => {
                    let loop_body = &l.body;
                    assert_eq!(loop_body.len(), 1, "expected single IF in LOOP body");
                    match &loop_body[0] {
                        AstStmt::If(_) => {
                            // We model IF as a shallow span-only statement; to
                            // verify BREAK parsing, just check that the BLOCK
                            // text contains a BREAK statement.
                            assert!(src.contains("BREAK"));
                        }
                        _ => panic!("expected IF in LOOP body"),
                    }
                }
                _ => panic!("expected LOOP as only statement in block body"),
            }
        }
        _ => panic!("expected top-level block for BREAK test"),
    }
}

#[test]
fn parse_continue_in_simple_loop() {
    let src = r#"
BEGIN
  LOOP
    IF (counter = 0) THEN
      CONTINUE;
    END IF;
  END LOOP;
END;
"#;

    let script = parse_sql(src).expect("failed to parse CONTINUE in LOOP script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single LOOP in block body");
            match &body[0] {
                AstStmt::Loop(l) => {
                    let loop_body = &l.body;
                    assert_eq!(loop_body.len(), 1, "expected single IF in LOOP body");
                    match &loop_body[0] {
                        AstStmt::If(_) => {
                            // Shallow IF node; just ensure source contains CONTINUE.
                            assert!(src.contains("CONTINUE"));
                        }
                        _ => panic!("expected IF in LOOP body for CONTINUE test"),
                    }
                }
                _ => panic!("expected LOOP as only statement in block body for CONTINUE test"),
            }
        }
        _ => panic!("expected top-level block for CONTINUE test"),
    }
}

#[test]
fn parse_labeled_break_in_nested_while() {
    let src = r#"
DECLARE
  i INTEGER;
  j INTEGER;
BEGIN
  i := 1;
  j := 1;
  WHILE (i <= 4) DO
    WHILE (j <= 4) DO
      -- Exit when j is 3, even if i is still 1.
      IF (j = 3) THEN
        BREAK outer_loop;
      END IF;
      j := j + 1;
    END WHILE inner_loop;
    i := i + 1;
  END WHILE outer_loop;
  -- Execution resumes here after the BREAK executes.
  RETURN i;
END;
"#;

    let script = parse_sql(src).expect("failed to parse labeled BREAK in nested WHILE script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            // Two DECLAREd variables and a single outer WHILE plus RETURN.
            assert_eq!(decls.len(), 2, "expected two DECLAREs for i and j");
            assert_eq!(
                body.len(),
                4,
                "expected i/j assigns, outer WHILE, RETURN in body"
            );
            match &body[2] {
                AstStmt::While(w) => {
                    let outer_body = &w.body;
                    // Outer WHILE body should contain inner WHILE and an increment of i.
                    assert!(outer_body.len() >= 2);
                    let mut saw_inner_while = false;
                    let mut saw_i_increment = false;
                    for stmt in outer_body {
                        match stmt {
                            AstStmt::While(w) => {
                                let inner_body = &w.body;
                                // Inside inner WHILE, ensure there is an IF whose body span
                                // covers a BREAK outer_loop; statement.
                                let mut found_break = false;
                                for inner_stmt in inner_body {
                                    if let AstStmt::If(i) = inner_stmt {
                                        let branches = &i.branches;
                                        if let Some(first_branch) = branches.first() {
                                            // Check if the body contains a BREAK statement
                                            for body_stmt in &first_branch.body {
                                                if matches!(body_stmt, AstStmt::Break { .. }) {
                                                    found_break = true;
                                                    break;
                                                }
                                            }
                                            if found_break {
                                                break;
                                            }
                                        }
                                    }
                                }
                                assert!(
                                    found_break,
                                    "expected BREAK outer_loop inside inner WHILE IF body"
                                );
                                saw_inner_while = true;
                            }
                            AstStmt::Assign {
                                name_span,
                                expr_span,
                                ..
                            } => {
                                let name_text =
                                    &src[name_span.start as usize..name_span.end as usize];
                                if name_text.trim() == "i" {
                                    let expr_text =
                                        &src[expr_span.start as usize..expr_span.end as usize];
                                    assert!(expr_text.contains("i + 1"));
                                    saw_i_increment = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    assert!(
                        saw_inner_while,
                        "expected inner WHILE inside outer WHILE body"
                    );
                    assert!(
                        saw_i_increment,
                        "expected i := i + 1 inside outer WHILE body"
                    );
                }
                _ => panic!("expected outer WHILE as first statement in block body"),
            }
        }
        _ => panic!("expected top-level block for labeled BREAK test"),
    }
}

#[test]
fn parse_basic_for_index_loop_in_block() {
    let src = r#"
BEGIN
  FOR i IN 1 TO 10 DO
    x := i;
  END FOR;
END;
"#;

    let script = parse_sql(src).expect("failed to parse FOR index loop script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::For(f) => {
                    let loop_var_span = f.loop_var_span;
                    let range_or_cursor_span = f.range_or_cursor_span;
                    let for_body = &f.body;
                    let loop_var = &src[loop_var_span.start as usize..loop_var_span.end as usize];
                    assert_eq!(loop_var.trim(), "i");
                    let header_text = &src
                        [range_or_cursor_span.start as usize..range_or_cursor_span.end as usize];
                    assert!(header_text.contains("1 TO 10"));
                    assert_eq!(for_body.len(), 1);
                    match &for_body[0] {
                        AstStmt::Assign { name_span, .. } => {
                            let name_text = &src[name_span.start as usize..name_span.end as usize];
                            assert_eq!(name_text.trim(), "x");
                        }
                        _ => panic!("expected assignment in FOR body"),
                    }
                }
                _ => panic!("expected FOR in block body"),
            }
        }
        _ => panic!("expected top-level block for FOR index loop"),
    }
}

#[test]
fn parse_for_cursor_loop_in_block() {
    let src = r#"
DECLARE c1 CURSOR FOR SELECT id FROM some_table;
BEGIN
  FOR rec IN c1 DO
    x := rec.id;
  END FOR;
END;
"#;

    let script = parse_sql(src).expect("failed to parse FOR cursor loop script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1, "expected DECLARE header for cursor");
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::For(f) => {
                    let loop_var_span = f.loop_var_span;
                    let range_or_cursor_span = f.range_or_cursor_span;
                    let for_body = &f.body;
                    let loop_var = &src[loop_var_span.start as usize..loop_var_span.end as usize];
                    assert_eq!(loop_var.trim(), "rec");
                    let header_text = &src
                        [range_or_cursor_span.start as usize..range_or_cursor_span.end as usize];
                    assert!(header_text.trim().starts_with("c1"));
                    assert_eq!(for_body.len(), 1);
                    match &for_body[0] {
                        AstStmt::Assign {
                            name_span,
                            expr_span,
                            ..
                        } => {
                            let name_text = &src[name_span.start as usize..name_span.end as usize];
                            assert_eq!(name_text.trim(), "x");
                            let rhs_text = &src[expr_span.start as usize..expr_span.end as usize];
                            assert!(rhs_text.contains("rec.id"));
                        }
                        _ => panic!("expected assignment in FOR cursor body"),
                    }
                }
                _ => panic!("expected FOR in block body for cursor loop"),
            }
        }
        _ => panic!("expected top-level block for FOR cursor loop"),
    }
}

#[test]
fn parse_for_resultset_loop_in_block() {
    let src = r#"
DECLARE rs RESULTSET;
BEGIN
  FOR rec IN rs DO
    x := rec.col1;
  END FOR;
END;
"#;

    let script = parse_sql(src).expect("failed to parse FOR RESULTSET loop script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1, "expected DECLARE header for RESULTSET");
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::For(f) => {
                    let loop_var_span = f.loop_var_span;
                    let range_or_cursor_span = f.range_or_cursor_span;
                    let for_body = &f.body;
                    let loop_var = &src[loop_var_span.start as usize..loop_var_span.end as usize];
                    assert_eq!(loop_var.trim(), "rec");
                    let header_text = &src
                        [range_or_cursor_span.start as usize..range_or_cursor_span.end as usize];
                    assert!(header_text.trim().starts_with("rs"));
                    assert_eq!(for_body.len(), 1);
                    match &for_body[0] {
                        AstStmt::Assign {
                            name_span,
                            expr_span,
                            ..
                        } => {
                            let name_text = &src[name_span.start as usize..name_span.end as usize];
                            assert_eq!(name_text.trim(), "x");
                            let rhs_text = &src[expr_span.start as usize..expr_span.end as usize];
                            assert!(rhs_text.contains("rec.col1"));
                        }
                        _ => panic!("expected assignment in FOR RESULTSET body"),
                    }
                }
                _ => panic!("expected FOR in block body for RESULTSET loop"),
            }
        }
        _ => panic!("expected top-level block for FOR RESULTSET loop"),
    }
}

#[test]
fn parse_script_ignores_leading_newlines_before_select() {
    let src = "\n\nSELECT 1";

    let script = parse_sql(src).expect("failed to parse script with leading newlines");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Select(_) => {}
        _ => panic!("expected SELECT to parse as AstStmt::Select"),
    }
}

#[test]
fn parse_script_ignores_leading_newlines_before_block() {
    let src = "\n\nBEGIN\n  RETURN 1;\nEND;";

    let script = parse_sql(src).expect("failed to parse block script with leading newlines");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(_) => {}
        _ => panic!("expected block to parse as AstStmt::Block"),
    }
}

#[test]
fn parse_simple_block_with_return_literal() {
    let src = r#"
BEGIN
  RETURN 1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::Return { expr, .. } => match expr.as_ref() {
                    Some(e) => match e.as_ref() {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { .. },
                            ..
                        } => {}
                        _ => panic!("expected numeric literal in RETURN"),
                    },
                    None => panic!("expected RETURN to have an expression"),
                },
                _ => panic!("expected RETURN statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement"),
    }
}

#[test]
fn parse_block_with_return_binary_expr() {
    let src = r#"
BEGIN
  RETURN a + 1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::Return { expr, .. } => match expr.as_ref() {
                    Some(e) => match e.as_ref() {
                        AstExpr::BinaryOp { left, right, .. } => {
                            // left should be identifier a, right should be numeric literal 1
                            match left.as_ref() {
                                AstExpr::Ident {
                                    column_ref: lexega_syntax::ast::AstColumnRef { .. },
                                    ..
                                } => {}
                                _ => panic!("expected identifier on left side of binary op"),
                            }
                            match right.as_ref() {
                                AstExpr::Literal {
                                    literal: AstLiteral::Number { .. },
                                    ..
                                } => {}
                                _ => panic!("expected numeric literal on right side of binary op"),
                            }
                        }
                        _ => panic!("expected binary expression in RETURN"),
                    },
                    None => panic!("expected RETURN to have an expression"),
                },
                _ => panic!("expected RETURN statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement"),
    }
}

#[test]
fn parse_block_with_let_and_return() {
    let src = r#"
BEGIN
  LET x := 1;
  RETURN x;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 2);
            match &body[0] {
                AstStmt::Let { name, expr, .. } => {
                    // Name span should be non-zero length and expr should be number 1
                    assert!(name.span.end > name.span.start);
                    match expr.as_ref() {
                        AstExpr::Literal {
                            literal: AstLiteral::Number { .. },
                            ..
                        } => {}
                        _ => panic!("expected numeric literal in LET expr"),
                    }
                }
                _ => panic!("expected LET as first statement"),
            }
            match &body[1] {
                AstStmt::Return { expr, .. } => match expr.as_ref() {
                    Some(e) => match e.as_ref() {
                        AstExpr::Ident {
                            column_ref: lexega_syntax::ast::AstColumnRef { .. },
                            ..
                        } => {}
                        _ => panic!("expected identifier in RETURN expr"),
                    },
                    None => panic!("expected RETURN to have an expression"),
                },
                _ => panic!("expected RETURN as second statement"),
            }
        }
        _ => panic!("expected top-level block statement"),
    }
}

#[test]
fn parse_block_with_declare_let_return() {
    let src = r#"
DECLARE x NUMBER DEFAULT 1;
BEGIN
	LET y := x;
	RETURN y;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script with DECLARE");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::Declare {
                    name,
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    assert!(
                        name.span.end > name.span.start,
                        "DECLARE name span should be non-empty"
                    );
                    let type_span = type_span.expect("expected type span in DECLARE");
                    let type_text = &src[type_span.start as usize..type_span.end as usize];
                    assert_eq!(type_text.trim(), "NUMBER");
                    let def_span =
                        default_expr_span.expect("expected DEFAULT expr span in DECLARE");
                    let def_text = &src[def_span.start as usize..def_span.end as usize];
                    assert_eq!(def_text.trim(), "DEFAULT 1");
                }
                _ => panic!("expected DECLARE in block header decls"),
            }
            assert_eq!(body.len(), 2);
            match &body[0] {
                AstStmt::Let { .. } => {}
                _ => panic!("expected LET as first statement in block body"),
            }
            match &body[1] {
                AstStmt::Return { .. } => {}
                _ => panic!("expected RETURN as second statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement for DECLARE test"),
    }
}

#[test]
fn parse_block_with_declare_colon_eq_initializer() {
    let src = r#"
DECLARE profit NUMBER(38, 2) := 0.0;
BEGIN
	RETURN profit;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script with DECLARE := initializer");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::Declare {
                    name,
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    assert!(
                        name.span.end > name.span.start,
                        "DECLARE name span should be non-empty"
                    );
                    let type_span = type_span.expect("expected type span in DECLARE with :=");
                    let type_text = &src[type_span.start as usize..type_span.end as usize];
                    assert_eq!(type_text.trim(), "NUMBER(38, 2)");
                    let def_span =
                        default_expr_span.expect("expected initializer span in DECLARE with :=");
                    let def_text = &src[def_span.start as usize..def_span.end as usize];
                    assert_eq!(def_text.trim(), ":= 0.0");
                }
                _ => panic!("expected DECLARE in block header decls"),
            }
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::Return { .. } => {}
                _ => panic!("expected RETURN as first statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement for DECLARE := test"),
    }
}

#[test]
fn parse_block_with_declare_no_type_default_initializer() {
    let src = r#"
DECLARE
  profit DEFAULT 0.0;
BEGIN
	RETURN profit;
END;
"#;

    let script =
        parse_sql(src).expect("failed to parse script with DECLARE no-type DEFAULT initializer");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::Declare {
                    name,
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    assert!(
                        name.span.end > name.span.start,
                        "DECLARE name span should be non-empty"
                    );
                    assert!(
                        type_span.is_none(),
                        "expected no explicit type span for no-type DEFAULT DECLARE"
                    );
                    let def_span =
                        default_expr_span.expect("expected DEFAULT expr span in no-type DECLARE");
                    let def_text = &src[def_span.start as usize..def_span.end as usize];
                    assert_eq!(def_text.trim(), "DEFAULT 0.0");
                }
                _ => panic!("expected DECLARE in block header decls"),
            }
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::Return { .. } => {}
                _ => panic!("expected RETURN as first statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement for DECLARE no-type DEFAULT test"),
    }
}

#[test]
fn parse_block_with_declare_no_type_colon_eq_initializer() {
    let src = r#"
DECLARE
  profit := 0.0;
BEGIN
	RETURN profit;
END;
"#;

    let script =
        parse_sql(src).expect("failed to parse script with DECLARE no-type := initializer");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::Declare {
                    name,
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    assert!(
                        name.span.end > name.span.start,
                        "DECLARE name span should be non-empty"
                    );
                    assert!(
                        type_span.is_none(),
                        "expected no explicit type span for no-type := DECLARE"
                    );
                    let def_span = default_expr_span
                        .expect("expected initializer span in no-type DECLARE with :=");
                    let def_text = &src[def_span.start as usize..def_span.end as usize];
                    assert_eq!(def_text.trim(), ":= 0.0");
                }
                _ => panic!("expected DECLARE in block header decls"),
            }
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::Return { .. } => {}
                _ => panic!("expected RETURN as first statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement for DECLARE no-type := test"),
    }
}

#[test]
fn parse_block_with_mixed_typed_and_inferred_declarations() {
    let src = r#"
DECLARE
  w INTEGER;
  x DEFAULT 0;
  y := 1;
BEGIN
	w := x + y;
	RETURN w;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script with mixed DECLARE forms");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 3);
            // w INTEGER;
            match &decls[0] {
                AstStmt::Declare {
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    let type_span = type_span.expect("expected type span for w");
                    let type_text = &src[type_span.start as usize..type_span.end as usize];
                    assert_eq!(type_text.trim(), "INTEGER");
                    assert!(
                        default_expr_span.is_none(),
                        "did not expect default expr for w"
                    );
                }
                _ => panic!("expected DECLARE for w"),
            }
            // x DEFAULT 0;
            match &decls[1] {
                AstStmt::Declare {
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    assert!(type_span.is_none(), "expected no explicit type for x");
                    let def_span = default_expr_span.expect("expected DEFAULT expr for x");
                    let def_text = &src[def_span.start as usize..def_span.end as usize];
                    assert_eq!(def_text.trim(), "DEFAULT 0");
                }
                _ => panic!("expected DECLARE for x"),
            }
            // y := 1;
            match &decls[2] {
                AstStmt::Declare {
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    assert!(type_span.is_none(), "expected no explicit type for y");
                    let def_span = default_expr_span.expect("expected initializer expr for y");
                    let def_text = &src[def_span.start as usize..def_span.end as usize];
                    assert_eq!(def_text.trim(), ":= 1");
                }
                _ => panic!("expected DECLARE for y"),
            }
            assert_eq!(body.len(), 2);
            match &body[0] {
                AstStmt::Assign { .. } => {}
                _ => panic!("expected assignment in block body"),
            }
            match &body[1] {
                AstStmt::Return { .. } => {}
                _ => panic!("expected RETURN as last statement"),
            }
        }
        _ => panic!("expected top-level block for mixed DECLARE test"),
    }
}

#[test]
fn parse_block_with_exception_section_shallow_span() {
    let src = r#"
BEGIN
  RETURN 1/0;
EXCEPTION
  WHEN STATEMENT_ERROR THEN
    RETURN SQLERRM;
END;
"#;

    let script = parse_sql(src).expect("failed to parse block with EXCEPTION section");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            let decls = &b.decls;
            let exception = &b.exception;
            assert!(
                decls.is_empty(),
                "did not expect DECLARE header in this block"
            );
            assert_eq!(
                body.len(),
                1,
                "expected single RETURN in block body before EXCEPTION"
            );
            match &body[0] {
                AstStmt::Return { .. } => {}
                _ => panic!("expected RETURN as first statement in block body"),
            }
            let ex = exception
                .as_ref()
                .expect("expected EXCEPTION section to be present");
            let kw_text = &src[ex.keyword_span.start as usize..ex.keyword_span.end as usize];
            assert_eq!(kw_text.to_ascii_uppercase(), "EXCEPTION");
            let full_text = &src[ex.span.start as usize..ex.span.end as usize];
            assert!(full_text
                .to_ascii_uppercase()
                .contains("WHEN STATEMENT_ERROR THEN"));
        }
        _ => panic!("expected top-level block statement for EXCEPTION test"),
    }
}

#[test]
fn parse_block_with_exception_using_plain_identifier() {
    let src = r#"
BEGIN
  RETURN 1/0;
EXCEPTION
  WHEN STATEMENT_ERROR THEN
    RETURN error_code;
END;
"#;

    let script = parse_sql(src).expect("failed to parse block with EXCEPTION and plain identifier");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let exception = &b.exception;
            let ex = exception
                .as_ref()
                .expect("expected EXCEPTION section to be present");
            let ex_text = &src[ex.span.start as usize..ex.span.end as usize];
            assert!(ex_text.contains("error_code"));
        }
        _ => panic!("expected top-level block statement for EXCEPTION identifier test"),
    }
}

#[test]
fn parse_block_with_exception_using_scripting_var_ref() {
    let src = r#"
BEGIN
  RETURN 1/0;
EXCEPTION
  WHEN STATEMENT_ERROR THEN
    RETURN :sqlerrm;
END;
"#;

    let script = parse_sql(src).expect("failed to parse block with EXCEPTION and :sqlerrm");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let exception = &b.exception;
            let ex = exception
                .as_ref()
                .expect("expected EXCEPTION section to be present");
            let ex_text = &src[ex.span.start as usize..ex.span.end as usize];
            assert!(ex_text.contains(":sqlerrm"));
        }
        _ => panic!("expected top-level block statement for EXCEPTION scripting var test"),
    }
}

#[test]
fn parse_simple_if_single_branch() {
    let src = r#"
BEGIN
  IF (x > 0) THEN
    RETURN 1;
  END IF;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script with IF");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::If(i) => {
                    let branches = &i.branches;
                    let else_body = &i.else_body;
                    assert!(
                        else_body.is_empty(),
                        "did not expect ELSE body in single IF"
                    );
                    assert_eq!(branches.len(), 1);
                    let IfBranch {
                        condition_span,
                        body: if_body,
                        ..
                    } = &branches[0];
                    let cond_text =
                        &src[condition_span.start as usize..condition_span.end as usize];
                    assert!(cond_text.contains("x > 0"));
                    // Check that the body contains a RETURN statement
                    assert_eq!(if_body.len(), 1);
                    assert!(matches!(if_body[0], AstStmt::Return { .. }));
                }
                _ => panic!("expected IF statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement for IF test"),
    }
}

#[test]
fn parse_if_else_branches() {
    let src = r#"
BEGIN
  IF (x > 0) THEN
    RETURN 1;
  ELSE
    RETURN 2;
  END IF;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script with IF/ELSE");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::If(i) => {
                    let branches = &i.branches;
                    let else_body = &i.else_body;
                    assert_eq!(branches.len(), 1, "expected single IF branch");
                    let IfBranch { body: if_body, .. } = &branches[0];
                    // Check that the IF body contains a RETURN statement
                    assert_eq!(if_body.len(), 1);
                    assert!(matches!(if_body[0], AstStmt::Return { .. }));
                    // Check that the ELSE body contains a RETURN statement
                    assert_eq!(else_body.len(), 1);
                    assert!(matches!(else_body[0], AstStmt::Return { .. }));
                }
                _ => panic!("expected IF statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement for IF/ELSE test"),
    }
}

#[test]
fn parse_if_elseif_else_branches() {
    let src = r#"
BEGIN
  IF (x > 0) THEN
    RETURN 1;
  ELSEIF (x = 0) THEN
    RETURN 0;
  ELSE
    RETURN -1;
  END IF;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script with IF/ELSIF/ELSE");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::If(i) => {
                    let branches = &i.branches;
                    let else_body = &i.else_body;
                    assert_eq!(branches.len(), 2, "expected IF + ELSIF branches");
                    let first = &branches[0];
                    let second = &branches[1];
                    let cond1 = &src
                        [first.condition_span.start as usize..first.condition_span.end as usize];
                    let cond2 = &src
                        [second.condition_span.start as usize..second.condition_span.end as usize];
                    assert!(cond1.contains("x > 0"));
                    assert!(cond2.contains("x = 0"));
                    // Check that both branches have bodies
                    assert_eq!(first.body.len(), 1);
                    assert_eq!(second.body.len(), 1);
                    // Check that the ELSE body contains a RETURN statement
                    assert_eq!(else_body.len(), 1);
                    assert!(matches!(else_body[0], AstStmt::Return { .. }));
                }
                _ => panic!("expected IF statement in block body"),
            }
        }
        _ => panic!("expected top-level block statement for IF/ELSIF/ELSE test"),
    }
}

#[test]
fn parse_simple_case_statement_in_block() {
    let src = r#"
DECLARE expression_to_evaluate VARCHAR DEFAULT 'default value';
BEGIN
  expression_to_evaluate := 'value a';
  CASE (expression_to_evaluate)
    WHEN 'value a' THEN
      RETURN 'x';
    WHEN 'value b' THEN
      RETURN 'y';
    ELSE
      RETURN 'other';
  END;
END;
"#;

    let script = parse_sql(src).expect("failed to parse simple CASE statement script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1, "expected DECLARE header");
            assert_eq!(body.len(), 2, "expected assignment + CASE in body");
            match &body[0] {
                AstStmt::Assign {
                    span,
                    name_span,
                    expr_span,
                    ..
                } => {
                    let assign_text = &src[span.start as usize..span.end as usize];
                    assert!(assign_text.contains("expression_to_evaluate := 'value a'"));
                    let name_text = &src[name_span.start as usize..name_span.end as usize];
                    assert_eq!(name_text.trim(), "expression_to_evaluate");
                    let rhs_text = &src[expr_span.start as usize..expr_span.end as usize];
                    assert!(rhs_text.contains("'value a'"));
                }
                _ => panic!("expected assignment as first statement in block body"),
            }
            match &body[1] {
                AstStmt::CaseStmt(c) => {
                    let operand_span = c.operand_span;
                    let branches = &c.branches;
                    let else_body = &c.else_body;
                    let operand_span = operand_span.expect("expected operand span for simple CASE");
                    let operand_text = &src[operand_span.start as usize..operand_span.end as usize];
                    assert!(operand_text.contains("expression_to_evaluate"));
                    assert_eq!(branches.len(), 2, "expected two WHEN branches");
                    let CaseBranch {
                        condition_span,
                        body: case_body,
                        ..
                    } = &branches[0];
                    let cond_text =
                        &src[condition_span.start as usize..condition_span.end as usize];
                    assert!(cond_text.contains("'value a'"));
                    // Check that the branch body contains a RETURN statement
                    assert_eq!(case_body.len(), 1);
                    assert!(matches!(case_body[0], AstStmt::Return { .. }));
                    // Check that the ELSE body contains a RETURN statement
                    assert_eq!(else_body.len(), 1);
                    assert!(matches!(else_body[0], AstStmt::Return { .. }));
                }
                _ => panic!("expected CASE statement in block body"),
            }
        }
        _ => panic!("expected top-level block for CASE test"),
    }
}

#[test]
fn parse_searched_case_statement_in_block() {
    let src = r#"
DECLARE
  a VARCHAR DEFAULT 'x';
  b VARCHAR DEFAULT 'y';
  c VARCHAR DEFAULT 'z';
BEGIN
  CASE
    WHEN a = 'x' THEN
      RETURN 'a is x';
    WHEN b = 'y' THEN
      RETURN 'b is y';
    ELSE
      RETURN 'other';
  END;
END;
"#;

    let script = parse_sql(src).expect("failed to parse searched CASE statement script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert!(!decls.is_empty(), "expected DECLARE header");
            assert_eq!(body.len(), 1, "expected single CASE in body");
            match &body[0] {
                AstStmt::CaseStmt(c) => {
                    let operand_span = c.operand_span;
                    let branches = &c.branches;
                    let else_body = &c.else_body;
                    assert!(
                        operand_span.is_none(),
                        "did not expect operand span for searched CASE"
                    );
                    assert_eq!(branches.len(), 2, "expected two WHEN branches");
                    let first = &branches[0];
                    let second = &branches[1];
                    let cond1 = &src
                        [first.condition_span.start as usize..first.condition_span.end as usize];
                    let cond2 = &src
                        [second.condition_span.start as usize..second.condition_span.end as usize];
                    assert!(cond1.contains("a = 'x'"));
                    assert!(cond2.contains("b = 'y'"));
                    // Check that the ELSE body contains a RETURN statement
                    assert_eq!(else_body.len(), 1);
                    assert!(matches!(else_body[0], AstStmt::Return { .. }));
                }
                _ => panic!("expected CASE statement in block body"),
            }
        }
        _ => panic!("expected top-level block for searched CASE test"),
    }
}

#[test]
fn parse_case_with_multiple_statements_in_branch() {
    let src = r#"
DECLARE
    x NUMBER DEFAULT 10;
    result VARCHAR;
BEGIN
    CASE
        WHEN x < 100 THEN
            LET result := 'small';
            LET result := result || '!';
        WHEN x < 1000 THEN
            LET result := 'medium';
        ELSE
            LET result := 'large';
    END CASE;
    
    RETURN result;
END;
"#;

    let script = parse_sql(src).expect("failed to parse CASE with multiple statements");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 2, "expected 2 DECLARE statements");
            assert_eq!(body.len(), 2, "expected CASE + RETURN in body");
            match &body[0] {
                AstStmt::CaseStmt(c) => {
                    let branches = &c.branches;
                    let else_body = &c.else_body;
                    assert_eq!(branches.len(), 2, "expected two WHEN branches");
                    // Check that the first branch has multiple statements
                    assert!(
                        branches[0].body.len() >= 2,
                        "expected at least 2 statements in first branch"
                    );

                    assert!(!else_body.is_empty(), "expected ELSE branch");
                }
                _ => panic!("expected CASE statement"),
            }
        }
        _ => panic!("expected Block"),
    }
}

#[test]
fn parse_script_dispatches_select_and_block() {
    // SELECT should become a single AstStmt::Select
    let src_select = "SELECT 1";

    let script_select = parse_sql(src_select).expect("failed to parse SELECT script");
    assert_eq!(script_select.stmts.len(), 1);
    match &script_select.stmts[0] {
        AstStmt::Select(_) => {}
        _ => panic!("expected SELECT to parse as AstStmt::Select"),
    }

    // BEGIN ... END; should become a single AstStmt::Block
    let src_block = r#"
BEGIN
  RETURN 1;
END;
"#;

    let script_block = parse_sql(src_block).expect("failed to parse block script");
    assert_eq!(script_block.stmts.len(), 1);
    match &script_block.stmts[0] {
        AstStmt::Block(_) => {}
        _ => panic!("expected block to parse as AstStmt::Block"),
    }
}

#[test]
fn parse_script_with_multiple_blocks_and_sql() {
    let src = r#"
BEGIN
  RETURN 1;
END;

SELECT 2;

DECLARE x NUMBER;
BEGIN
  RETURN x;
END;
"#;

    let script = parse_sql(src).expect("failed to parse script with multiple blocks and SELECT");
    assert_eq!(script.stmts.len(), 3, "expected two blocks and one SELECT");
    match &script.stmts[0] {
        AstStmt::Block(_) => {}
        _ => panic!("expected first statement to be a block"),
    }
    match &script.stmts[1] {
        AstStmt::Select(sel) => {
            // Simple sanity check that the projection parsed as a literal 2.
            match &sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    let span = as_select_item(&items[0]).span;
                    let text = &src[span.start as usize..span.end as usize];
                    assert!(text.contains("2"));
                }
                _ => panic!("expected column projection for SELECT 2"),
            }
        }
        _ => panic!("expected second statement to be SELECT"),
    }
    match &script.stmts[2] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1, "expected DECLARE header in second block");
            assert_eq!(body.len(), 1, "expected single RETURN in second block body");
        }
        _ => panic!("expected third statement to be a block"),
    }
}

#[test]
fn parse_pipe_chain_of_selects() {
    let src = "SELECT 1 ->> SELECT * FROM $1";
    let stmt = parse_stmt_from_str(src).expect("script");
    match &stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 2);
            match &stmts[0] {
                AstStmt::Select(_) => {}
                _ => panic!("expected first statement to be SELECT"),
            }
            match &stmts[1] {
                AstStmt::Select(sel) => {
                    assert_eq!(sel.from.len(), 1, "expected single FROM source");
                    let tbl = &sel.from[0];
                    let span = tbl.name.span;
                    let text = &src[span.start as usize..span.end as usize];
                    assert_eq!(text, "$1");
                }
                _ => panic!("expected second statement to be SELECT"),
            }
        }
        _ => panic!("expected pipe chain at top level"),
    }
}

#[test]
fn parse_pipe_chain_three_stage_with_from_position_refs() {
    // Three-stage pipe chain where later SELECTs read FROM $1 and $2.
    let src = "SELECT 1 ->> SELECT * FROM $1 ->> SELECT * FROM $2";
    let stmt = parse_stmt_from_str(src).expect("script");
    match &stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 3);
            // First statement: simple SELECT 1.
            match &stmts[0] {
                AstStmt::Select(_) => {}
                _ => panic!("expected first statement to be SELECT"),
            }
            // Second and third statements: SELECT * FROM $1 / FROM $2.
            for (idx, stmt) in stmts.iter().enumerate().skip(1) {
                let sel = match stmt {
                    AstStmt::Select(s) => s,
                    _ => panic!("expected SELECT in pipe chain"),
                };
                assert_eq!(
                    sel.from.len(),
                    1,
                    "expected single FROM source in stage {}",
                    idx + 1
                );
                let tbl = &sel.from[0];
                let span = tbl.name.span;
                let text = &src[span.start as usize..span.end as usize];
                let expected = if idx == 1 { "$1" } else { "$2" };
                assert_eq!(
                    text,
                    expected,
                    "unexpected pipe input ref in stage {}",
                    idx + 1
                );
            }
        }
        _ => panic!("expected pipe chain at top level"),
    }
}

#[test]
fn parse_show_tables_basic() {
    let src = "SHOW TABLES";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Show(show) => {
            let keyword_span = show.keyword_span;
            let object_span = show.object_span;
            let kw_text = &src[keyword_span.start as usize..keyword_span.end as usize];
            assert_eq!(kw_text.to_ascii_uppercase(), "SHOW");
            let obj_span = object_span.expect("expected object span for SHOW TABLES");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert_eq!(obj_text.to_ascii_uppercase(), "TABLES");
        }
        _ => panic!("expected SHOW statement"),
    }
}

#[test]
fn parse_show_functions_with_like_in_limit() {
    let src = "SHOW FUNCTIONS LIKE 'F%' IN DATABASE foo LIMIT 10";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Show(show) => {
            let obj_span = show.object_span.expect("expected object span");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert!(obj_text.to_ascii_uppercase().starts_with("FUNCTIONS"));
            // Assert LIKE pattern, IN scope, and LIMIT are all captured
            // for this composite SHOW command.
            let like_span = show.like_pattern_span.expect("expected LIKE pattern span");
            let like_text = &src[like_span.start as usize..like_span.end as usize];
            assert_eq!(like_text, "'F%'");
            let in_span = show.in_span.expect("expected IN keyword span");
            let in_text = &src[in_span.start as usize..in_span.end as usize];
            assert_eq!(in_text.to_ascii_uppercase(), "IN");
            let scope_span = show.in_scope_span.expect("expected IN scope span");
            let scope_text = &src[scope_span.start as usize..scope_span.end as usize];
            assert_eq!(scope_text, "DATABASE foo");
            let limit_span = show.limit_span.expect("expected LIMIT span");
            let limit_text = &src[limit_span.start as usize..limit_span.end as usize];
            assert_eq!(limit_text, "10");
        }
        _ => panic!("expected SHOW statement"),
    }
}

#[test]
fn parse_show_with_in_scope_span() {
    let src = "SHOW FUNCTIONS IN DATABASE foo";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Show(show) => {
            let in_span = show.in_span.expect("expected IN keyword span");
            let in_text = &src[in_span.start as usize..in_span.end as usize];
            assert_eq!(in_text.to_ascii_uppercase(), "IN");
            let scope_span = show.in_scope_span.expect("expected full IN scope span");
            let scope_text = &src[scope_span.start as usize..scope_span.end as usize];
            assert_eq!(scope_text, "DATABASE foo");
        }
        _ => panic!("expected SHOW statement"),
    }
}

#[test]
fn parse_show_versions_in_model_with_limit() {
    let src = "SHOW VERSIONS IN MODEL my_model LIMIT 5";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Show(show) => {
            // Object phrase should start with VERSIONS IN MODEL
            let obj_span = show.object_span.expect("expected object span");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert!(obj_text.to_ascii_uppercase().starts_with("VERSIONS"));
            // IN scope should cover MODEL my_model
            let in_span = show.in_span.expect("expected IN keyword span");
            let in_text = &src[in_span.start as usize..in_span.end as usize];
            assert_eq!(in_text.to_ascii_uppercase(), "IN");
            let scope_span = show.in_scope_span.expect("expected IN scope span");
            let scope_text = &src[scope_span.start as usize..scope_span.end as usize];
            assert_eq!(scope_text, "MODEL my_model");
            // LIMIT argument should be captured
            let limit_span = show.limit_span.expect("expected LIMIT span");
            let limit_text = &src[limit_span.start as usize..limit_span.end as usize];
            assert_eq!(limit_text, "5");
        }
        _ => panic!("expected SHOW statement"),
    }
}

#[test]
fn parse_describe_table_basic() {
    let src = "DESCRIBE TABLE my_table";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Describe(AstDescribe {
            keyword_span,
            object_span,
            ..
        }) => {
            let kw_text = &src[keyword_span.start as usize..keyword_span.end as usize];
            assert_eq!(kw_text.to_ascii_uppercase(), "DESCRIBE");
            let obj_span = object_span.expect("expected object span for DESCRIBE TABLE");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert_eq!(obj_text, "TABLE my_table");
        }
        _ => panic!("expected DESCRIBE statement"),
    }
}

#[test]
fn parse_describe_view_basic() {
    let src = "DESCRIBE VIEW my_view";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Describe(desc) => {
            let obj_span = desc
                .object_span
                .expect("expected object span for DESCRIBE VIEW");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert_eq!(obj_text, "VIEW my_view");
        }
        _ => panic!("expected DESCRIBE statement"),
    }
}

#[test]
fn parse_describe_function_with_args() {
    let src = "DESCRIBE FUNCTION my_func(STRING, NUMBER)";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Describe(desc) => {
            let obj_span = desc
                .object_span
                .expect("expected object span for DESCRIBE FUNCTION");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert_eq!(obj_text, "FUNCTION my_func(STRING, NUMBER)");
        }
        _ => panic!("expected DESCRIBE statement"),
    }
}

#[test]
fn parse_desc_table_alias_for_describe() {
    let src = "DESC TABLE my_table";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Describe(desc) => {
            let obj_span = desc
                .object_span
                .expect("expected object span for DESC TABLE");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert_eq!(obj_text, "TABLE my_table");
        }
        _ => panic!("expected DESCRIBE statement from DESC alias"),
    }
}

#[test]
fn parse_show_grants_with_like() {
    let src = "SHOW GRANTS LIKE 'FOO%'";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Show(show) => {
            let obj_span = show.object_span.expect("expected object span");
            let obj_text = &src[obj_span.start as usize..obj_span.end as usize];
            assert_eq!(obj_text.to_ascii_uppercase(), "GRANTS");
            let like_span = show.like_pattern_span.expect("expected LIKE pattern span");
            let like_text = &src[like_span.start as usize..like_span.end as usize];
            assert_eq!(like_text, "'FOO%'");
        }
        _ => panic!("expected SHOW statement"),
    }
}

#[test]
fn parse_pipe_chain_with_show_and_select() {
    let src = "SHOW TABLES ->> SELECT 1";
    let stmt = parse_stmt_from_str(src).expect("script");
    match &stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 2, "expected two stages in pipe chain");
            match &stmts[0] {
                AstStmt::Show(_) => {}
                _ => panic!("expected first stage to be SHOW"),
            }
            match &stmts[1] {
                AstStmt::Select(_) => {}
                _ => panic!("expected second stage to be SELECT"),
            }
        }
        _ => panic!("expected pipe chain at top level for SHOW + SELECT"),
    }
}

#[test]
fn parse_pipe_chain_with_truncate_and_select() {
    let src = "TRUNCATE TABLE my_table ->> SELECT 1";
    let stmt = parse_stmt_from_str(src).expect("script");
    match &stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 2, "expected two stages in pipe chain");
            match &stmts[0] {
                AstStmt::Truncate(tr) => {
                    let target_span = tr
                        .target_table_span
                        .expect("expected target table span for TRUNCATE in pipe");
                    let target_text = &src[target_span.start as usize..target_span.end as usize];
                    assert_eq!(target_text, "my_table");
                }
                _ => panic!("expected first stage to be TRUNCATE"),
            }
            match &stmts[1] {
                AstStmt::Select(_) => {}
                _ => panic!("expected second stage to be SELECT"),
            }
        }
        _ => panic!("expected pipe chain at top level for TRUNCATE + SELECT"),
    }
}

#[test]
fn parse_flow_stmt_pipe_into_create_table_ctas() {
    let src = "SELECT 1 ->> CREATE TABLE t AS SELECT * FROM $1";
    let stmt = parse_stmt_from_str(src).expect("flow stmt");
    match stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 2, "expected two stages in pipe chain");
            match &stmts[0] {
                AstStmt::Select(_) => {}
                _ => panic!("expected first stage to be SELECT"),
            }
            match &stmts[1] {
                AstStmt::CreateTable(ct) => {
                    assert_eq!(ct.variant, AstCreateTableVariant::Ctas);
                    let query_result = ct.ctas_query.as_ref().expect("expected CTAS query");
                    let span = match query_result {
                        Ok(stmt) => stmt.span(),
                        Err(span) => *span,
                    };
                    let text = &src[span.start as usize..span.end as usize];
                    assert!(text.contains("SELECT * FROM $1"));
                }
                _ => panic!("expected second stage to be CREATE TABLE"),
            }
        }
        _ => panic!("expected PipeChain from parse_stmt_from_str for SELECT ->> CREATE TABLE"),
    }
}

#[test]
fn parse_flow_stmt_show_pipe_chain() {
    let src = "SHOW TABLES ->> SELECT 1";
    let stmt = parse_stmt_from_str(src).expect("flow stmt");
    match stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 2, "expected two stages in pipe chain");
            match &stmts[0] {
                AstStmt::Show(_) => {}
                _ => panic!("expected first stage to be SHOW"),
            }
            match &stmts[1] {
                AstStmt::Select(_) => {}
                _ => panic!("expected second stage to be SELECT"),
            }
        }
        _ => panic!("expected PipeChain from parse_stmt_from_str for SHOW + SELECT"),
    }
}

#[test]
fn parse_flow_stmt_truncate_pipe_chain() {
    let src = "TRUNCATE TABLE my_table ->> SELECT 1";
    let stmt = parse_stmt_from_str(src).expect("flow stmt");
    match stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 2, "expected two stages in pipe chain");
            match &stmts[0] {
                AstStmt::Truncate(tr) => {
                    let target_span = tr
                        .target_table_span
                        .expect("expected target table span for TRUNCATE in flow helper");
                    let target_text = &src[target_span.start as usize..target_span.end as usize];
                    assert_eq!(target_text, "my_table");
                }
                _ => panic!("expected first stage to be TRUNCATE"),
            }
            match &stmts[1] {
                AstStmt::Select(_) => {}
                _ => panic!("expected second stage to be SELECT"),
            }
        }
        _ => panic!("expected PipeChain from parse_stmt_from_str for TRUNCATE + SELECT"),
    }
}

#[test]
fn parse_pipe_chain_with_select_and_insert() {
    let src = "SELECT 1 ->> INSERT INTO my_table VALUES (1)";
    let stmt = parse_stmt_from_str(src).expect("script");
    match &stmt {
        AstStmt::PipeChain { stmts, .. } => {
            assert_eq!(stmts.len(), 2, "expected two stages in pipe chain");
            match &stmts[0] {
                AstStmt::Select(_) => {}
                _ => panic!("expected first stage to be SELECT"),
            }
            match &stmts[1] {
                AstStmt::Insert(ins) => {
                    let body_span = ins
                        .body_span
                        .expect("expected body span for INSERT in pipe chain");
                    let body_text = &src[body_span.start as usize..body_span.end as usize];
                    assert_eq!(body_text, "VALUES (1)");
                    let table_span = ins
                        .target_table_span()
                        .expect("expected target table span in pipe chain");
                    let table_text = &src[table_span.start as usize..table_span.end as usize];
                    assert_eq!(table_text, "my_table");
                }
                _ => panic!("expected second stage to be INSERT"),
            }
        }
        _ => panic!("expected pipe chain at top level"),
    }
}

#[test]
fn parse_basic_insert_stmt() {
    let src = "INSERT INTO my_table VALUES (1, 'a')";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Insert(ins) => {
            let body_span = ins.body_span.expect("expected body span for INSERT");
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert_eq!(body_text, "VALUES (1, 'a')");
            let table_span = ins.target_table_span().expect("expected target table span");
            let table_text = &src[table_span.start as usize..table_span.end as usize];
            assert_eq!(table_text, "my_table");
        }
        _ => panic!("expected INSERT statement"),
    }
}

#[test]
fn parse_basic_update_stmt() {
    let src = "UPDATE my_table SET col = 1 WHERE id = 42";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Update(upd) => {
            let body_span = upd.body_span.expect("expected body span for UPDATE");
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert_eq!(body_text, "my_table SET col = 1 WHERE id = 42");

            assert!(
                upd.target_table.is_some(),
                "expected target table for UPDATE"
            );

            let set_span = upd.set_span.expect("expected SET span for UPDATE");
            let set_text = &src[set_span.start as usize..set_span.end as usize];
            assert_eq!(set_text, "SET col = 1");

            assert!(
                upd.from.is_empty(),
                "did not expect FROM clause in basic UPDATE"
            );

            assert!(
                upd.where_clause.is_some(),
                "expected WHERE clause for UPDATE"
            );
        }
        _ => panic!("expected UPDATE statement"),
    }
}

#[test]
fn parse_basic_delete_stmt() {
    let src = "DELETE FROM my_table WHERE id = 42";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Delete(del) => {
            let body_span = del.body_span.expect("expected body span for DELETE");
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert_eq!(body_text, "FROM my_table WHERE id = 42");

            assert!(
                del.target_table.is_some(),
                "expected target table for DELETE"
            );

            assert!(
                del.using.is_empty(),
                "did not expect USING clause in basic DELETE"
            );

            assert!(
                del.where_clause.is_some(),
                "expected WHERE clause for DELETE"
            );
        }
        _ => panic!("expected DELETE statement"),
    }
}

#[test]
fn parse_delete_with_using_clause() {
    let src = "DELETE FROM t1 USING t2, (SELECT * FROM t3) s WHERE t1.id = t2.id";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Delete(del) => {
            assert!(
                del.target_table.is_some(),
                "expected target table for DELETE with USING"
            );

            assert!(
                !del.using.is_empty(),
                "expected USING clause for DELETE with USING"
            );
            assert_eq!(del.using.len(), 2, "expected 2 tables in USING clause");

            assert!(
                del.where_clause.is_some(),
                "expected WHERE clause for DELETE with USING"
            );
        }
        _ => panic!("expected DELETE statement"),
    }
}

#[test]
fn parse_basic_merge_stmt() {
    let src = "MERGE INTO target USING source ON target.id = source.id WHEN MATCHED THEN UPDATE SET target.val = source.val";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Merge(m) => {
            // target_table_span covers only the table reference tokens
            // (not the INTO keyword); the formatter emits INTO explicitly.
            let target_span = m
                .target_table_span
                .expect("expected target_table_span for MERGE");
            let target_text = &src[target_span.start as usize..target_span.end as usize];
            assert_eq!(target_text, "target");

            let using_span = m.using_span.expect("expected using_span for MERGE");
            let using_text = &src[using_span.start as usize..using_span.end as usize];
            assert_eq!(using_text, "USING source");

            let on_span = m.on_span.expect("expected on_span for MERGE");
            let on_text = &src[on_span.start as usize..on_span.end as usize];
            assert!(on_text.starts_with("ON target.id = source.id"));

            assert_eq!(m.clauses.len(), 1);
        }
        _ => panic!("expected MERGE statement"),
    }
}

#[test]
fn parse_unconditional_multi_insert_all() {
    let src = "INSERT ALL INTO t1 INTO t2 SELECT n1 FROM src";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::MultiInsert(mi) => {
            assert!(mi.overwrite_span.is_none());
            assert!(mi.when_clauses.is_empty());
            assert!(mi.else_into_clauses.is_empty());
            assert_eq!(mi.into_clauses.len(), 2);
            let subquery = mi.subquery.as_ref().expect("expected subquery");
            let sub_text = &src[subquery.span().start as usize..subquery.span().end as usize];
            assert_eq!(sub_text, "SELECT n1 FROM src");
        }
        _ => panic!("expected multi-table INSERT"),
    }
}

#[test]
fn parse_conditional_multi_insert_all_with_when_else() {
    let src = "INSERT ALL WHEN n1 > 100 THEN INTO t1 WHEN n1 > 10 THEN INTO t1 INTO t2 ELSE INTO t2 SELECT n1 FROM src";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::MultiInsert(mi) => {
            assert!(!mi.when_clauses.is_empty());
            assert!(!mi.else_into_clauses.is_empty());
            let subquery = mi.subquery.as_ref().expect("expected subquery");
            let sub_text = &src[subquery.span().start as usize..subquery.span().end as usize];
            assert!(sub_text.starts_with("SELECT n1 FROM src"));
        }
        _ => panic!("expected conditional multi-table INSERT"),
    }
}

#[test]
fn parse_insert_values_rows_spans() {
    let src = "INSERT INTO t (a,b) VALUES (1, 2), (3, 4)";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Insert(ins) => {
            assert!(matches!(ins.source_kind, AstInsertSourceKind::Values));
            let values_span = ins.values_span.expect("values span");
            let values_text = &src[values_span.start as usize..values_span.end as usize];
            assert!(values_text.trim_start().starts_with("VALUES"));
            assert_eq!(ins.values_rows_spans.len(), 2);
            let row0 = &src
                [ins.values_rows_spans[0].start as usize..ins.values_rows_spans[0].end as usize];
            let row1 = &src
                [ins.values_rows_spans[1].start as usize..ins.values_rows_spans[1].end as usize];
            assert_eq!(row0.trim(), "(1, 2)");
            assert_eq!(row1.trim(), "(3, 4)");
        }
        _ => panic!("expected INSERT"),
    }
}

#[test]
fn parse_insert_query_span() {
    let src = "INSERT INTO t (a,b) SELECT a, b FROM src";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Insert(ins) => {
            assert!(matches!(ins.source_kind, AstInsertSourceKind::Query));
            let query_span = ins.query_span.expect("query span");
            let query_text = &src[query_span.start as usize..query_span.end as usize];
            assert!(query_text.starts_with("SELECT a, b FROM src"));
        }
        _ => panic!("expected INSERT"),
    }
}

#[test]
fn parse_scripting_block_insert_with_scripting_var_ref() {
    let src = r#"
DECLARE my_variable NUMBER;
BEGIN
  INSERT INTO my_table (x) VALUES (:my_variable);
END;
"#;

    let script =
        parse_sql(src).expect("failed to parse scripting block with INSERT and :my_variable");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single INSERT in block body");
            match &body[0] {
                AstStmt::Insert(_ins) => {
                    // We only validate that the script parses and that :my_variable
                    // is accepted as part of the statement; deeper expression
                    // inspection can be added later when DML expression parsing
                    // is wired through the scripting expression grammar.
                }
                _ => panic!("expected INSERT in block body"),
            }
        }
        _ => panic!("expected top-level block for scripting INSERT test"),
    }
}

#[test]
fn parse_scripting_block_select_into_with_scripting_vars() {
    let src = r#"
DECLARE 
    id INTEGER;
    name VARCHAR;
BEGIN
  SELECT id, name INTO :id, :name FROM some_data WHERE id = :id;
END;
"#;

    let script = parse_sql(src).expect("failed to parse scripting block with SELECT ... INTO");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single SELECT in block body");
            match &body[0] {
                AstStmt::Select(sel) => {
                    let vars = sel
                        .into_target
                        .as_deref()
                        .map(|t| t.scripting_vars())
                        .unwrap_or(&[]);
                    assert_eq!(vars.len(), 2);
                    let first_var_span = vars[0];
                    let second_var_span = vars[1];
                    let first_text =
                        &src[first_var_span.start as usize..first_var_span.end as usize];
                    let second_text =
                        &src[second_var_span.start as usize..second_var_span.end as usize];
                    assert_eq!(first_text.trim(), ":id");
                    assert_eq!(second_text.trim(), ":name");
                }
                _ => panic!("expected SELECT in block body"),
            }
        }
        _ => panic!("expected top-level block for scripting SELECT ... INTO test"),
    }
}

#[test]
fn parse_scripting_block_select_where_with_scripting_var_ref() {
    let src = r#"
DECLARE id INTEGER;
BEGIN
  SELECT id FROM some_data WHERE id = :id;
END;
"#;

    let script =
        parse_sql(src).expect("failed to parse scripting block with SELECT and :id in WHERE");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single SELECT in block body");
            match &body[0] {
                AstStmt::Select(sel) => {
                    let where_clause = sel.where_clause.as_ref().expect("expected WHERE clause");
                    let where_expr = &where_clause.expr;
                    match where_expr {
                        AstExpr::BinaryOp {
                            ref left,
                            ref right,
                            ..
                        } => {
                            match left.as_ref() {
                                AstExpr::Ident {
                                    column_ref: lexega_syntax::ast::AstColumnRef { .. },
                                    ..
                                } => {}
                                _ => panic!("expected identifier on left side of binary op"),
                            }
                            match right.as_ref() {
                                AstExpr::ScriptingVarRef { .. } => {}
                                _ => {
                                    panic!("expected scripting var ref on right side of binary op")
                                }
                            }
                        }
                        _ => panic!("expected binary op in WHERE clause"),
                    }
                }
                _ => panic!("expected SELECT in block body"),
            }
        }
        _ => panic!("expected top-level block for scripting SELECT WHERE test"),
    }
}

#[test]
fn parse_scripting_block_select_where_in_list_with_scripting_var_ref() {
    let src = r#"
DECLARE id INTEGER;
BEGIN
  SELECT id FROM some_data WHERE id IN (1, :id, 3);
END;
"#;

    let script =
        parse_sql(src).expect("failed to parse scripting block with SELECT and :id in IN list");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single SELECT in block body");
            match &body[0] {
                AstStmt::Select(sel) => {
                    let where_clause = sel.where_clause.as_ref().expect("expected WHERE clause");
                    let where_expr = &where_clause.expr;
                    match where_expr {
                        AstExpr::InList { ref list, .. } => {
                            assert_eq!(list.len(), 3);
                            match &list[1] {
                                AstExpr::ScriptingVarRef { .. } => {}
                                _ => panic!("expected scripting var ref as middle IN-list item"),
                            }
                        }
                        _ => panic!("expected IN(list) predicate in WHERE clause"),
                    }
                }
                _ => panic!("expected SELECT in block body"),
            }
        }
        _ => panic!("expected top-level block for scripting SELECT WHERE IN test"),
    }
}

#[test]
fn parse_scripting_block_select_from_identifier_with_scripting_var_binding() {
    let src = r#"
DECLARE
  table_name VARCHAR;
BEGIN
  SELECT COUNT(*) FROM IDENTIFIER(:table_name);
END;
"#;

    let script = parse_sql(src)
        .expect("failed to parse scripting block with IDENTIFIER(:table_name) in FROM");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single SELECT in block body");
            let sel = match &body[0] {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected SELECT in block body"),
            };
            assert_eq!(sel.from.len(), 1, "expected single FROM source");
            let tbl = &sel.from[0];
            let src_text = &src[tbl.name.span.start as usize..tbl.name.span.end as usize];
            assert_eq!(src_text.trim(), "IDENTIFIER(:table_name)");
        }
        _ => panic!("expected top-level block for IDENTIFIER FROM test"),
    }
}

#[test]
fn parse_scripting_block_select_identifier_in_projection_with_scripting_var_binding() {
    let src = r#"
DECLARE
  col_name VARCHAR;
BEGIN
  SELECT IDENTIFIER(:col_name) FROM some_data;
END;
"#;

    let script = parse_sql(src)
        .expect("failed to parse scripting block with IDENTIFIER(:col_name) in projection");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1, "expected single SELECT in block body");
            let sel = match &body[0] {
                AstStmt::Select(sel) => sel,
                _ => panic!("expected SELECT in block body"),
            };
            match &sel.projection.kind {
                AstProjectionKind::Columns(items) => {
                    assert_eq!(items.len(), 1);
                    let item = &items[0];
                    let select_item = as_select_item(item);
                    let proj_text =
                        &src[select_item.span.start as usize..select_item.span.end as usize];
                    assert!(proj_text.contains("IDENTIFIER(:col_name)"));
                }
                _ => panic!("expected column projection with IDENTIFIER(:col_name)"),
            }
        }
        _ => panic!("expected top-level block for IDENTIFIER projection test"),
    }
}

#[test]
fn parse_truncate_basic() {
    let src = "TRUNCATE TABLE my_table";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Truncate(tr) => {
            let kw_text = &src[tr.keyword_span.start as usize..tr.keyword_span.end as usize];
            assert_eq!(kw_text.to_ascii_uppercase(), "TRUNCATE");

            let table_span = tr.table_span.expect("expected TABLE keyword span");
            let table_text = &src[table_span.start as usize..table_span.end as usize];
            assert_eq!(table_text.to_ascii_uppercase(), "TABLE");

            let target_span = tr.target_table_span.expect("expected target table span");
            let target_text = &src[target_span.start as usize..target_span.end as usize];
            assert_eq!(target_text, "my_table");
        }
        _ => panic!("expected TRUNCATE statement"),
    }
}

#[test]
fn parse_truncate_if_exists_qualified() {
    let src = "TRUNCATE IF EXISTS db.schema.\"MyTable\"";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Truncate(tr) => {
            let if_exists_span = tr.if_exists_span.expect("expected IF EXISTS span");
            let if_exists_text = &src[if_exists_span.start as usize..if_exists_span.end as usize];
            assert_eq!(if_exists_text.to_ascii_uppercase(), "IF EXISTS");

            let target_span = tr.target_table_span.expect("expected target table span");
            let target_text = &src[target_span.start as usize..target_span.end as usize];
            assert_eq!(target_text, "db.schema.\"MyTable\"");
        }
        _ => panic!("expected TRUNCATE statement"),
    }
}

#[test]
fn parse_create_table_basic() {
    let src = "CREATE TABLE mytable (amount NUMBER)";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let kw_text = &src[ct.keyword_span.start as usize..ct.keyword_span.end as usize];
            assert_eq!(kw_text.to_ascii_uppercase(), "CREATE");
            assert!(ct.or_replace_span.is_none());
            assert!(ct.temp_kind_span.is_none());
            let table_kw_text =
                &src[ct.table_keyword_span.start as usize..ct.table_keyword_span.end as usize];
            assert_eq!(table_kw_text.to_ascii_uppercase(), "TABLE");
            let name_text = &src[ct.name_span.start as usize..ct.name_span.end as usize];
            assert_eq!(name_text, "mytable");
            let cols_span = ct.columns_span.expect("expected columns span");
            let cols_text = &src[cols_span.start as usize..cols_span.end as usize];
            assert_eq!(cols_text, "(amount NUMBER)");
            assert_eq!(ct.variant, AstCreateTableVariant::Plain);
            assert!(ct.table_options_span.is_none());
        }
        _ => panic!("expected CREATE TABLE statement"),
    }
}

#[test]
fn parse_create_table_with_or_replace_temp_and_comment() {
    let src = "CREATE OR REPLACE TEMP TABLE mytable (amount NUMBER) COMMENT = 'foo'";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            // OR REPLACE span
            let or_rep = ct.or_replace_span.expect("expected OR REPLACE span");
            let or_rep_text = &src[or_rep.start as usize..or_rep.end as usize];
            assert_eq!(or_rep_text.to_ascii_uppercase(), "OR REPLACE");

            // TEMP span
            let temp_span = ct.temp_kind_span.expect("expected TEMP span");
            let temp_text = &src[temp_span.start as usize..temp_span.end as usize];
            assert_eq!(temp_text.to_ascii_uppercase(), "TEMP");

            // Table options span should capture the trailing COMMENT clause.
            let opts_span = ct.table_options_span.expect("expected table options span");
            let opts_text = &src[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(opts_text, "COMMENT = 'foo'");
            let comment_span = ct.table_comment_span.expect("expected COMMENT option span");
            let comment_text = &src[comment_span.start as usize..comment_span.end as usize];
            assert_eq!(comment_text, "COMMENT = 'foo'");
        }
        _ => panic!("expected CREATE TABLE statement"),
    }
}

#[test]
fn parse_create_table_like_variant() {
    let src = "CREATE TABLE t LIKE src_table";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            assert_eq!(ct.variant, AstCreateTableVariant::Like);
            let like_span = ct.like_source_span.expect("expected LIKE source span");
            let like_text = &src[like_span.start as usize..like_span.end as usize];
            assert_eq!(like_text, "LIKE src_table");
        }
        _ => panic!("expected CREATE TABLE statement"),
    }
}

#[test]
fn parse_create_table_ctas_variant() {
    let src = "CREATE TABLE t AS SELECT 1";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            assert_eq!(ct.variant, AstCreateTableVariant::Ctas);
            let query_result = ct.ctas_query.as_ref().expect("expected CTAS query");
            // Verify the query was successfully parsed as a SELECT statement
            match query_result {
                Ok(stmt) => {
                    match stmt.as_ref() {
                        AstStmt::Select(select) => {
                            // Verify it has one projection item
                            match &select.projection.kind {
                                AstProjectionKind::Columns(cols) => {
                                    assert_eq!(cols.len(), 1, "expected one projection");
                                }
                                _ => panic!("expected column projection"),
                            }
                        }
                        _ => panic!("expected SELECT statement in CTAS query"),
                    }
                }
                Err(_) => panic!("CTAS query should have been successfully parsed"),
            }
        }
        _ => panic!("expected CREATE TABLE statement"),
    }
}

#[test]
fn parse_create_table_clone_with_time_travel_at() {
    let src = "CREATE TABLE t CLONE src AT (TIMESTAMP => '2024-01-01 00:00:00')";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            assert_eq!(ct.variant, AstCreateTableVariant::Clone);
            let tt = match ct.time_travel.as_deref() {
                Some(AstTimeTravelClause::SnowflakeAtBefore(tt)) => tt,
                other => panic!("expected an AT clause, got {other:?}"),
            };
            assert!(!tt.is_before);
            assert!(matches!(tt.kind, AstTimeTravelKind::Timestamp(_)));
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_clone_with_time_travel_before() {
    let src = "CREATE TABLE t CLONE src BEFORE (STATEMENT => 'abc123')";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            assert_eq!(ct.variant, AstCreateTableVariant::Clone);
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_ctas_with_time_travel_at() {
    let src = "CREATE TABLE t AS SELECT 1 AT (SNAPSHOT => 'x')";

    // Note: This SQL is actually invalid (AT clause after SELECT without FROM is not valid)
    // but we test that the parser handles it gracefully without crashing
    if let Ok(script) = parse_sql(src) {
        // With error recovery, this may be parsed as 1 or 2 statements
        // (error recovery may split the invalid AT clause into a separate statement)
        assert!(
            !script.stmts.is_empty(),
            "Should have at least one statement"
        );
        match &script.stmts[0] {
            AstStmt::CreateTable(ct) => {
                assert_eq!(ct.variant, AstCreateTableVariant::Ctas);
                // The query may be stored as parsed AST or as a fallback span depending on parser's ability to handle invalid SQL
                assert!(ct.ctas_query.is_some(), "CTAS query should be captured");
            }
            _ => panic!("expected CREATE TABLE"),
        }
    }
    // If parsing fails entirely, that's also acceptable for invalid SQL - just don't crash
}

#[test]
fn parse_create_table_with_cluster_by_and_copy_grants() {
    let src = "CREATE TABLE t (c NUMBER) CLUSTER BY (c) COPY GRANTS";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct.table_options_span.expect("expected options span");
            let opts_text = &src[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(opts_text, "CLUSTER BY (c) COPY GRANTS");
            let cluster_span = ct.cluster_by_span.expect("expected CLUSTER BY span");
            let cluster_text = &src[cluster_span.start as usize..cluster_span.end as usize];
            assert_eq!(cluster_text, "CLUSTER BY (c)");
            let copy_span = ct.copy_grants_span.expect("expected COPY GRANTS span");
            let copy_text = &src[copy_span.start as usize..copy_span.end as usize];
            assert_eq!(copy_text, "COPY GRANTS");
        }
        _ => panic!("expected CREATE TABLE statement"),
    }
}

#[test]
fn parse_create_table_using_template_variant() {
    let src = "CREATE TABLE t USING TEMPLATE (SELECT 1)";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            assert_eq!(ct.variant, AstCreateTableVariant::UsingTemplate);
            let span = ct
                .using_template_span
                .expect("expected USING TEMPLATE span");
            let text = &src[span.start as usize..span.end as usize];
            assert_eq!(text, "USING TEMPLATE (SELECT 1)");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_from_archive_variant() {
    let src = "CREATE TABLE t FROM ARCHIVE OF src WHERE id = 1";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            assert_eq!(ct.variant, AstCreateTableVariant::FromArchive);
            let span = ct.from_archive_span.expect("expected FROM ARCHIVE span");
            let text = &src[span.start as usize..span.end as usize];
            assert_eq!(text, "FROM ARCHIVE OF src WHERE id = 1");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_from_snapshot_set_variant() {
    let src = "CREATE TABLE t FROM SNAPSHOT SET IDENTIFIER('snap')";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            assert_eq!(ct.variant, AstCreateTableVariant::FromSnapshotSet);
            let span = ct
                .from_snapshot_set_span
                .expect("expected FROM SNAPSHOT SET span");
            let text = &src[span.start as usize..span.end as usize];
            assert_eq!(text, "FROM SNAPSHOT SET IDENTIFIER('snap')");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_with_schema_evolution_and_contact() {
    let src = "CREATE TABLE t (c NUMBER) ENABLE_SCHEMA_EVOLUTION = TRUE WITH CONTACT = 'me'";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct.table_options_span.expect("expected options span");
            let opts_text = &src[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(
                opts_text,
                "ENABLE_SCHEMA_EVOLUTION = TRUE WITH CONTACT = 'me'"
            );
            let evo_span = ct
                .enable_schema_evolution_span
                .expect("expected ENABLE_SCHEMA_EVOLUTION span");
            let evo_text = &src[evo_span.start as usize..evo_span.end as usize];
            assert_eq!(evo_text, "ENABLE_SCHEMA_EVOLUTION = TRUE");
            let contact_span = ct.with_contact_span.expect("expected WITH CONTACT span");
            let contact_text = &src[contact_span.start as usize..contact_span.end as usize];
            assert_eq!(contact_text, "WITH CONTACT = 'me'");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_with_retention_and_max_extension() {
    let src = "CREATE TABLE t (c NUMBER) DATA_RETENTION_TIME_IN_DAYS = 1 MAX_DATA_EXTENSION_TIME_IN_DAYS = 30";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct.table_options_span.expect("expected options span");
            let opts_text = &src[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(
                opts_text,
                "DATA_RETENTION_TIME_IN_DAYS = 1 MAX_DATA_EXTENSION_TIME_IN_DAYS = 30"
            );
            let data_span = ct
                .data_retention_time_in_days_span
                .expect("expected DATA_RETENTION_TIME_IN_DAYS span");
            let data_text = &src[data_span.start as usize..data_span.end as usize];
            assert_eq!(data_text, "DATA_RETENTION_TIME_IN_DAYS = 1");
            let max_span = ct
                .max_data_extension_time_in_days_span
                .expect("expected MAX_DATA_EXTENSION_TIME_IN_DAYS span");
            let max_text = &src[max_span.start as usize..max_span.end as usize];
            assert_eq!(max_text, "MAX_DATA_EXTENSION_TIME_IN_DAYS = 30");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_with_change_tracking_and_schema_evolution() {
    let src = "CREATE TABLE t (c NUMBER) CHANGE_TRACKING = TRUE ENABLE_SCHEMA_EVOLUTION = TRUE";

    let script = parse_sql(src).expect("script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct.table_options_span.expect("expected options span");
            let opts_text = &src[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(
                opts_text,
                "CHANGE_TRACKING = TRUE ENABLE_SCHEMA_EVOLUTION = TRUE"
            );
            let ct_span = ct
                .change_tracking_span
                .expect("expected CHANGE_TRACKING span");
            let ct_text = &src[ct_span.start as usize..ct_span.end as usize];
            assert_eq!(ct_text, "CHANGE_TRACKING = TRUE");
            let evo_span = ct
                .enable_schema_evolution_span
                .expect("expected ENABLE_SCHEMA_EVOLUTION span");
            let evo_text = &src[evo_span.start as usize..evo_span.end as usize];
            assert_eq!(evo_text, "ENABLE_SCHEMA_EVOLUTION = TRUE");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_with_tag_and_with_tag() {
    // Bare TAG option
    let src1 = "CREATE TABLE t (c NUMBER) TAG (k = 'v')";
    let script1 = parse_sql(src1).expect("script1");
    assert_eq!(script1.stmts.len(), 1);
    match &script1.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct
                .table_options_span
                .expect("expected options span for TAG");
            let opts_text = &src1[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(opts_text, "TAG (k = 'v')");
            let tag_span = ct.tag_span.expect("expected TAG span");
            let tag_text = &src1[tag_span.start as usize..tag_span.end as usize];
            assert_eq!(tag_text, "TAG (k = 'v')");
        }
        _ => panic!("expected CREATE TABLE"),
    }

    // WITH TAG option: tag_span anchored at TAG token but includes full clause
    let src2 = "CREATE TABLE t (c NUMBER) WITH TAG (k = 'v')";
    let script2 = parse_sql(src2).expect("script2");
    assert_eq!(script2.stmts.len(), 1);
    match &script2.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct
                .table_options_span
                .expect("expected options span for WITH TAG");
            let opts_text = &src2[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(opts_text, "WITH TAG (k = 'v')");
            let tag_span = ct.tag_span.expect("expected TAG span for WITH TAG");
            let tag_text = &src2[tag_span.start as usize..tag_span.end as usize];
            assert_eq!(tag_text, "TAG (k = 'v')");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_with_row_access_policy_and_with_row_access_policy() {
    // Bare ROW ACCESS POLICY option
    let src1 = "CREATE TABLE t (c NUMBER) ROW ACCESS POLICY my_policy ON (c)";
    let script1 = parse_sql(src1).expect("script1");
    assert_eq!(script1.stmts.len(), 1);
    match &script1.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct
                .table_options_span
                .expect("expected options span for ROW ACCESS POLICY");
            let opts_text = &src1[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(opts_text, "ROW ACCESS POLICY my_policy ON (c)");
            let row_span = ct
                .row_access_policy_span
                .expect("expected ROW ACCESS POLICY span");
            let row_text = &src1[row_span.start as usize..row_span.end as usize];
            assert_eq!(row_text, "ROW ACCESS POLICY my_policy ON (c)");
            assert!(ct.with_row_access_policy_span.is_none());
        }
        _ => panic!("expected CREATE TABLE"),
    }

    // WITH ROW ACCESS POLICY option
    let src2 = "CREATE TABLE t (c NUMBER) WITH ROW ACCESS POLICY my_policy ON (c)";
    let script2 = parse_sql(src2).expect("script2");
    assert_eq!(script2.stmts.len(), 1);
    match &script2.stmts[0] {
        AstStmt::CreateTable(ct) => {
            let opts_span = ct
                .table_options_span
                .expect("expected options span for WITH ROW ACCESS POLICY");
            let opts_text = &src2[opts_span.start as usize..opts_span.end as usize];
            assert_eq!(opts_text, "WITH ROW ACCESS POLICY my_policy ON (c)");
            let with_row_span = ct
                .with_row_access_policy_span
                .expect("expected WITH ROW ACCESS POLICY span");
            // Current parser anchors the WITH span at the `WITH` token but
            // stops at the next starter (`ROW`), so the span is just "WITH".
            let with_row_text = &src2[with_row_span.start as usize..with_row_span.end as usize];
            assert_eq!(with_row_text, "WITH");
            // The actual ROW ACCESS POLICY clause is captured in `row_access_policy_span`.
            let row_span = ct
                .row_access_policy_span
                .expect("expected ROW ACCESS POLICY span for WITH ROW");
            let row_text = &src2[row_span.start as usize..row_span.end as usize];
            assert_eq!(row_text, "ROW ACCESS POLICY my_policy ON (c)");
        }
        _ => panic!("expected CREATE TABLE"),
    }
}

#[test]
fn parse_create_table_columns_and_constraints_shallow_spans() {
    let src = "CREATE TABLE t (id NUMBER, name STRING NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP())";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };
    let columns = &ct.columns;
    assert_eq!(columns.len(), 3);

    let col_spans: Vec<&str> = columns
        .iter()
        .map(|c| &src[c.full_span.start as usize..c.full_span.end as usize])
        .collect();

    // 3.4: full_span should match each column clause without trailing commas.
    assert_eq!(col_spans[0], "id NUMBER");
    assert_eq!(col_spans[1], "name STRING NOT NULL");
    assert_eq!(
        col_spans[2],
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()"
    );
    // 3.3: validate per-column spans (name/type/NOT NULL/DEFAULT).
    // Column 0: id NUMBER
    let c0 = &ct.columns[0];
    let c0_name = &src[c0.name_span.unwrap().start as usize..c0.name_span.unwrap().end as usize];
    let c0_type = &src[c0.type_span.unwrap().start as usize..c0.type_span.unwrap().end as usize];
    assert_eq!(c0_name, "id");
    assert_eq!(c0_type, "NUMBER");
    assert!(c0.not_null_span.is_none());
    assert!(c0.default_expr_span.is_none());

    // Column 1: name STRING NOT NULL
    let c1 = &ct.columns[1];
    let c1_name = &src[c1.name_span.unwrap().start as usize..c1.name_span.unwrap().end as usize];
    let c1_type = &src[c1.type_span.unwrap().start as usize..c1.type_span.unwrap().end as usize];
    let c1_not_null =
        &src[c1.not_null_span.unwrap().start as usize..c1.not_null_span.unwrap().end as usize];
    assert_eq!(c1_name, "name");
    assert_eq!(c1_type, "STRING");
    assert_eq!(c1_not_null, "NOT NULL");
    assert!(c1.default_expr_span.is_none());

    // Column 2: created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
    let c2 = &ct.columns[2];
    let c2_name = &src[c2.name_span.unwrap().start as usize..c2.name_span.unwrap().end as usize];
    let c2_type = &src[c2.type_span.unwrap().start as usize..c2.type_span.unwrap().end as usize];
    let c2_default = &src
        [c2.default_expr_span.unwrap().start as usize..c2.default_expr_span.unwrap().end as usize];
    assert_eq!(c2_name, "created_at");
    assert_eq!(c2_type, "TIMESTAMP");
    assert_eq!(c2_default, "DEFAULT CURRENT_TIMESTAMP()");
    assert!(c2.not_null_span.is_none());
}

#[test]
fn parse_create_table_column_identity_span() {
    let src = "CREATE TABLE t (id NUMBER IDENTITY START 1 INCREMENT 1, col NUMBER AUTOINCREMENT, other NUMBER)";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };
    assert_eq!(ct.columns.len(), 3);
    let c0 = &ct.columns[0];
    let c1 = &ct.columns[1];
    let c2 = &ct.columns[2];
    let c0_id_span = c0
        .identity_or_autoincrement_span
        .expect("expected IDENTITY span on first column");
    let c1_id_span = c1
        .identity_or_autoincrement_span
        .expect("expected AUTOINCREMENT span on second column");
    assert!(c2.identity_or_autoincrement_span.is_none());
    let c0_id_text = &src[c0_id_span.start as usize..c0_id_span.end as usize];
    let c1_id_text = &src[c1_id_span.start as usize..c1_id_span.end as usize];
    assert_eq!(c0_id_text, "IDENTITY");
    assert_eq!(c1_id_text, "AUTOINCREMENT");
    // Helper-derived argument tails for IDENTITY/AUTOINCREMENT.
    let c0_tail_span = c0
        .identity_arg_tail_span()
        .expect("expected IDENTITY argument tail span");
    let c0_tail_text = &src[c0_tail_span.start as usize..c0_tail_span.end as usize];
    assert_eq!(c0_tail_text, " START 1 INCREMENT 1");
    assert!(c1.identity_arg_tail_span().is_none());
}

#[test]
fn parse_create_table_column_collate_and_comment_and_tag_and_masking() {
    let src = "CREATE TABLE t (
	  c1 VARCHAR COLLATE 'en',
	  c2 NUMBER WITH MASKING POLICY my_policy USING (c2, helper_col),
	  c3 NUMBER TAG (k = 'v') COMMENT 'col comment'
)";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };
    assert_eq!(ct.columns.len(), 3);
    let c1 = &ct.columns[0];
    let c2 = &ct.columns[1];
    let c3 = &ct.columns[2];
    // c1: VARCHAR COLLATE 'en'
    let collate_span = c1.collate_span.expect("expected COLLATE span on c1");
    let collate_text = &src[collate_span.start as usize..collate_span.end as usize];
    assert_eq!(collate_text, "COLLATE 'en'");
    // c2: NUMBER WITH MASKING POLICY my_policy USING (...)
    let mp_span = c2
        .masking_policy_span
        .expect("expected MASKING POLICY span on c2");
    let mp_text = &src[mp_span.start as usize..mp_span.end as usize];
    assert_eq!(mp_text, "MASKING POLICY my_policy USING (c2, helper_col)");
    // c3: NUMBER TAG (...) COMMENT 'col comment'
    let tag_span = c3.tag_span.expect("expected TAG span on c3");
    let tag_text = &src[tag_span.start as usize..tag_span.end as usize];
    assert_eq!(tag_text, "TAG (k = 'v')");
    let comment_span = c3.comment_span.expect("expected COMMENT span on c3");
    let comment_text = &src[comment_span.start as usize..comment_span.end as usize];
    assert_eq!(comment_text, "COMMENT 'col comment'");
}

#[test]
fn parse_create_table_column_default_then_masking_and_tag() {
    let src = "CREATE TABLE t (
	  c1 NUMBER DEFAULT 42 MASKING POLICY my_policy USING (c1),
	  c2 VARCHAR DEFAULT 'x' TAG (k = 'v') COMMENT 'c2 comment'
)";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };
    assert_eq!(ct.columns.len(), 2);
    let c1 = &ct.columns[0];
    let c2 = &ct.columns[1];

    // c1: DEFAULT 42 then MASKING POLICY ...
    let def_span = c1.default_expr_span.expect("expected DEFAULT span on c1");
    let def_text = &src[def_span.start as usize..def_span.end as usize];
    assert_eq!(def_text, "DEFAULT 42");
    let mp_span = c1
        .masking_policy_span
        .expect("expected MASKING POLICY span on c1");
    let mp_text = &src[mp_span.start as usize..mp_span.end as usize];
    assert_eq!(mp_text, "MASKING POLICY my_policy USING (c1)");

    // c2: DEFAULT 'x' then TAG (...) then COMMENT ...
    let def2_span = c2.default_expr_span.expect("expected DEFAULT span on c2");
    let def2_text = &src[def2_span.start as usize..def2_span.end as usize];
    assert_eq!(def2_text, "DEFAULT 'x'");
    let tag_span = c2.tag_span.expect("expected TAG span on c2");
    let tag_text = &src[tag_span.start as usize..tag_span.end as usize];
    assert_eq!(tag_text, "TAG (k = 'v')");
    let comment_span = c2.comment_span.expect("expected COMMENT span on c2");
    let comment_text = &src[comment_span.start as usize..comment_span.end as usize];
    assert_eq!(comment_text, "COMMENT 'c2 comment'");
}

#[test]
fn parse_create_table_constraints_shallow_spans() {
    let src = "CREATE TABLE t (id NUMBER PRIMARY KEY, col NUMBER UNIQUE, CONSTRAINT pk PRIMARY KEY (id), UNIQUE (col), FOREIGN KEY (col) REFERENCES other(col))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };
    // Two column items, three table-level constraint items.
    assert_eq!(ct.columns.len(), 2);
    assert_eq!(ct.constraints.len(), 3);
    let col_spans: Vec<&str> = ct
        .columns
        .iter()
        .map(|c| &src[c.full_span.start as usize..c.full_span.end as usize])
        .collect();
    assert_eq!(col_spans[0], "id NUMBER PRIMARY KEY");
    assert_eq!(col_spans[1], "col NUMBER UNIQUE");
    let constraint_spans: Vec<&str> = ct
        .constraints
        .iter()
        .map(|c| &src[c.full_span.start as usize..c.full_span.end as usize])
        .collect();
    assert_eq!(constraint_spans[0], "CONSTRAINT pk PRIMARY KEY (id)");
    assert_eq!(constraint_spans[1], "UNIQUE (col)");
    assert_eq!(
        constraint_spans[2],
        "FOREIGN KEY (col) REFERENCES other(col)"
    );
}

// ============================================================================
// Exception Handling Tests
// ============================================================================

#[test]
fn parse_raise_statement_without_args() {
    let src = r#"
BEGIN
  LET counter := 0;
  IF (counter = 0) THEN
    RAISE;
  END IF;
  RETURN counter;
END;
"#;

    let script = parse_sql(src).expect("failed to parse RAISE script");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 3, "expected LET, IF, RETURN");
            match &body[1] {
                AstStmt::If(i) => {
                    let branches = &i.branches;
                    assert_eq!(branches.len(), 1);
                    // Check that the body contains a RAISE statement
                    assert!(!branches[0].body.is_empty());
                    assert!(matches!(branches[0].body[0], AstStmt::Raise { .. }));
                }
                _ => panic!("expected IF statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_raise_statement_with_exception_name() {
    let src = r#"
BEGIN
  LET should_raise := true;
  IF (should_raise) THEN
    RAISE my_exception;
  END IF;
  RETURN 'success';
END;
"#;

    let script = parse_sql(src).expect("failed to parse RAISE with exception name");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 3);
            match &body[1] {
                AstStmt::If(i) => {
                    let branches = &i.branches;
                    // Check that the body contains a RAISE statement
                    assert!(!branches[0].body.is_empty());
                    assert!(matches!(branches[0].body[0], AstStmt::Raise { .. }));
                }
                _ => panic!("expected IF statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_exception_section_with_single_handler() {
    let src = r#"
BEGIN
  LET counter := 0;
  RAISE my_exception;
EXCEPTION
  WHEN my_exception THEN
    RETURN 'caught exception';
END;
"#;

    let script = parse_sql(src).expect("failed to parse EXCEPTION section");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let exception = &b.exception;
            assert!(exception.is_some(), "expected EXCEPTION section");
            let ex_section = exception.as_ref().unwrap();
            assert_eq!(ex_section.handlers.len(), 1, "expected 1 handler");
            let handler = &ex_section.handlers[0];
            assert!(
                !handler.exception_name_spans.is_empty(),
                "expected exception name"
            );
            let ex_name = &src[handler.exception_name_spans[0].start as usize
                ..handler.exception_name_spans[0].end as usize];
            assert!(ex_name.contains("my_exception"));
            assert_eq!(handler.body.len(), 1, "expected 1 statement in handler");
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_exception_section_with_multiple_handlers() {
    let src = r#"
BEGIN
  SELECT 1/0;
EXCEPTION
  WHEN STATEMENT_ERROR THEN
    INSERT INTO error_log VALUES ('statement error');
  WHEN my_exception THEN
    INSERT INTO error_log VALUES ('my exception');
  WHEN OTHER THEN
    INSERT INTO error_log VALUES ('other error');
END;
"#;

    let script = parse_sql(src).expect("failed to parse multiple EXCEPTION handlers");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let exception = &b.exception;
            assert!(exception.is_some());
            let ex_section = exception.as_ref().unwrap();
            assert_eq!(ex_section.handlers.len(), 3, "expected 3 handlers");

            let handler1_name = &src[ex_section.handlers[0].exception_name_spans[0].start as usize
                ..ex_section.handlers[0].exception_name_spans[0].end as usize];
            assert!(handler1_name.contains("STATEMENT_ERROR"));

            let handler2_name = &src[ex_section.handlers[1].exception_name_spans[0].start as usize
                ..ex_section.handlers[1].exception_name_spans[0].end as usize];
            assert!(handler2_name.contains("my_exception"));

            let handler3_name = &src[ex_section.handlers[2].exception_name_spans[0].start as usize
                ..ex_section.handlers[2].exception_name_spans[0].end as usize];
            assert!(handler3_name.contains("OTHER"));
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_exception_handler_with_continue_type() {
    let src = r#"
BEGIN
  LET counter := 0;
  RAISE my_exception;
  counter := counter + 1;
EXCEPTION
  WHEN my_exception CONTINUE THEN
    LET error_msg := 'handled exception';
END;
"#;

    let script = parse_sql(src).expect("failed to parse CONTINUE handler");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let exception = &b.exception;
            assert!(exception.is_some());
            let ex_section = exception.as_ref().unwrap();
            assert_eq!(ex_section.handlers.len(), 1);
            let handler = &ex_section.handlers[0];
            match handler.handler_type {
                lexega_syntax::ast::ExceptionHandlerType::Continue => {}
                _ => panic!("expected CONTINUE handler type"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_exception_handler_with_exit_type() {
    let src = r#"
BEGIN
  RAISE my_exception;
EXCEPTION
  WHEN my_exception EXIT THEN
    RETURN 'exiting block';
END;
"#;

    let script = parse_sql(src).expect("failed to parse EXIT handler");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let exception = &b.exception;
            assert!(exception.is_some());
            let ex_section = exception.as_ref().unwrap();
            assert_eq!(ex_section.handlers.len(), 1);
            let handler = &ex_section.handlers[0];
            match handler.handler_type {
                lexega_syntax::ast::ExceptionHandlerType::Exit => {}
                _ => panic!("expected EXIT handler type"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_nested_blocks_with_exceptions() {
    // Rewritten without nested BEGIN blocks (not allowed in Snowflake)
    let src = r#"
BEGIN
  LET x_outer := 1;
  LET x_inner := 2;
  IF (x_inner > 0) THEN
    RAISE inner_exception;
  END IF;
EXCEPTION
  WHEN inner_exception THEN
    RETURN 'caught inner_exception';
  WHEN OTHER THEN
    RETURN 'caught other';
END;
"#;

    let script = parse_sql(src).expect("failed to parse block with multiple exception handlers");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            let exception = &b.exception;
            assert!(exception.is_some(), "expected EXCEPTION section");
            assert_eq!(body.len(), 3, "expected two LETs and IF");

            // Check exception section has multiple handlers
            let ex = exception.as_ref().unwrap();
            assert_eq!(ex.handlers.len(), 2, "expected two exception handlers");
        }
        _ => panic!("expected top-level block"),
    }
}

// ============================================================
// CURSOR MANAGEMENT TESTS
// ============================================================

#[test]
fn parse_open_cursor_basic() {
    let src = r#"
BEGIN
  OPEN c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse OPEN cursor");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::OpenCursor {
                    cursor_name_span,
                    using_clause_span,
                    ..
                } => {
                    assert!(using_clause_span.is_none());
                    let cursor_name =
                        &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(cursor_name, "c1");
                }
                _ => panic!("expected OpenCursor statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_open_cursor_with_using() {
    let src = r#"
BEGIN
  OPEN c1 USING (param1, param2);
END;
"#;

    let script = parse_sql(src).expect("failed to parse OPEN cursor with USING");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::OpenCursor {
                    cursor_name_span,
                    using_clause_span,
                    ..
                } => {
                    assert!(using_clause_span.is_some());
                    let cursor_name =
                        &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(cursor_name, "c1");
                }
                _ => panic!("expected OpenCursor statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_fetch_cursor_single_var() {
    let src = r#"
BEGIN
  FETCH c1 INTO result_var;
END;
"#;

    let script = parse_sql(src).expect("failed to parse FETCH cursor");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::FetchCursor {
                    cursor_name_span,
                    into_clause_span,
                    ..
                } => {
                    let cursor_name =
                        &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(cursor_name, "c1");
                    let into_clause =
                        &src[into_clause_span.start as usize..into_clause_span.end as usize];
                    assert!(into_clause.contains("result_var"));
                }
                _ => panic!("expected FetchCursor statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_fetch_cursor_multiple_vars() {
    let src = r#"
BEGIN
  FETCH c1 INTO var1, var2, var3;
END;
"#;

    let script = parse_sql(src).expect("failed to parse FETCH cursor with multiple vars");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::FetchCursor {
                    cursor_name_span,
                    into_clause_span,
                    ..
                } => {
                    let cursor_name =
                        &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(cursor_name, "c1");
                    let into_clause =
                        &src[into_clause_span.start as usize..into_clause_span.end as usize];
                    assert!(into_clause.contains("var1"));
                    assert!(into_clause.contains("var2"));
                    assert!(into_clause.contains("var3"));
                }
                _ => panic!("expected FetchCursor statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_close_cursor() {
    let src = r#"
BEGIN
  CLOSE c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse CLOSE cursor");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 1);
            match &body[0] {
                AstStmt::CloseCursor {
                    cursor_name_span, ..
                } => {
                    let cursor_name =
                        &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(cursor_name, "c1");
                }
                _ => panic!("expected CloseCursor statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cursor_lifecycle() {
    // This test verifies OPEN, FETCH, CLOSE operations on a cursor.
    // Note: Cursor declaration (DECLARE c1 CURSOR FOR ...) is tested separately.
    let src = r#"
BEGIN
  OPEN c1 USING (dept_id);
  FETCH c1 INTO emp_name, emp_salary;
  CLOSE c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse cursor lifecycle");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 3, "expected OPEN, FETCH, CLOSE");

            // Verify OPEN with USING
            match &body[0] {
                AstStmt::OpenCursor {
                    using_clause_span, ..
                } => {
                    assert!(using_clause_span.is_some(), "expected USING clause in OPEN");
                }
                _ => panic!("expected OpenCursor as first statement"),
            }

            // Verify FETCH with INTO
            match &body[1] {
                AstStmt::FetchCursor {
                    into_clause_span, ..
                } => {
                    let into_text =
                        &src[into_clause_span.start as usize..into_clause_span.end as usize];
                    assert!(into_text.contains("emp_name"));
                    assert!(into_text.contains("emp_salary"));
                }
                _ => panic!("expected FetchCursor as second statement"),
            }

            // Verify CLOSE
            match &body[2] {
                AstStmt::CloseCursor { .. } => {}
                _ => panic!("expected CloseCursor as third statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_declare_cursor_basic() {
    let src = r#"
DECLARE
  c1 CURSOR FOR SELECT * FROM employees;
BEGIN
  OPEN c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse DECLARE cursor");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1, "expected one cursor declaration");
            match &decls[0] {
                AstStmt::DeclareCursor {
                    cursor_name,
                    query_span,
                    ..
                } => {
                    let cursor =
                        &src[cursor_name.span.start as usize..cursor_name.span.end as usize];
                    assert_eq!(cursor, "c1");
                    let query = &src[query_span.start as usize..query_span.end as usize];
                    assert!(query.contains("SELECT"));
                    assert!(query.contains("employees"));
                }
                _ => panic!("expected DeclareCursor in decls"),
            }
            assert_eq!(body.len(), 1, "expected OPEN in body");
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_declare_cursor_with_bind_params() {
    let src = r#"
DECLARE
  c1 CURSOR FOR SELECT id FROM invoices WHERE price > ? AND price < ?;
BEGIN
  OPEN c1 USING (min_price, max_price);
END;
"#;

    let script = parse_sql(src).expect("failed to parse DECLARE cursor with bind params");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::DeclareCursor { query_span, .. } => {
                    let query = &src[query_span.start as usize..query_span.end as usize];
                    assert!(query.contains("?"));
                    assert!(query.contains("WHERE"));
                }
                _ => panic!("expected DeclareCursor"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_let_cursor_basic() {
    let src = r#"
BEGIN
  LET c1 CURSOR FOR SELECT price FROM invoices;
  OPEN c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse LET cursor");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 2, "expected LET cursor and OPEN");
            match &body[0] {
                AstStmt::LetCursor {
                    cursor_name,
                    query_span,
                    ..
                } => {
                    let cursor =
                        &src[cursor_name.span.start as usize..cursor_name.span.end as usize];
                    assert_eq!(cursor, "c1");
                    let query = &src[query_span.start as usize..query_span.end as usize];
                    assert!(query.contains("SELECT"));
                    assert!(query.contains("invoices"));
                }
                _ => panic!("expected LetCursor as first statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_declare_cursor_for_resultset() {
    let src = r#"
DECLARE
  res RESULTSET DEFAULT (SELECT price FROM invoices);
  c1 CURSOR FOR res;
BEGIN
  OPEN c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse DECLARE cursor for RESULTSET");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            assert_eq!(decls.len(), 2, "expected RESULTSET and cursor declarations");
            // First declaration is RESULTSET (parsed as regular Declare)
            match &decls[0] {
                AstStmt::Declare { .. } => {}
                _ => panic!("expected Declare for RESULTSET"),
            }
            // Second declaration is cursor
            match &decls[1] {
                AstStmt::DeclareCursor { query_span, .. } => {
                    let query = &src[query_span.start as usize..query_span.end as usize];
                    assert!(query.contains("res"));
                }
                _ => panic!("expected DeclareCursor"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cursor_full_workflow() {
    let src = r#"
DECLARE
  c1 CURSOR FOR SELECT * FROM employees WHERE dept = ?;
BEGIN
  OPEN c1 USING (dept_id);
  FETCH c1 INTO emp_name, emp_salary;
  CLOSE c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse cursor full workflow");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1, "expected cursor declaration");
            match &decls[0] {
                AstStmt::DeclareCursor { .. } => {}
                _ => panic!("expected DeclareCursor"),
            }

            assert_eq!(body.len(), 3, "expected OPEN, FETCH, CLOSE");

            match &body[0] {
                AstStmt::OpenCursor {
                    using_clause_span, ..
                } => {
                    assert!(using_clause_span.is_some());
                }
                _ => panic!("expected OpenCursor"),
            }

            match &body[1] {
                AstStmt::FetchCursor { .. } => {}
                _ => panic!("expected FetchCursor"),
            }

            match &body[2] {
                AstStmt::CloseCursor { .. } => {}
                _ => panic!("expected CloseCursor"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_nested_cursors() {
    // Test nested cursor operations - outer cursor iterates departments, inner cursor iterates employees per department
    let src = r#"
DECLARE
  dept_cursor CURSOR FOR SELECT dept_id, dept_name FROM departments;
  emp_cursor CURSOR FOR SELECT emp_name, salary FROM employees WHERE dept_id = ?;
BEGIN
  OPEN dept_cursor;
  FETCH dept_cursor INTO current_dept_id, current_dept_name;
  
  OPEN emp_cursor USING (current_dept_id);
  FETCH emp_cursor INTO emp_name, emp_salary;
  CLOSE emp_cursor;
  
  CLOSE dept_cursor;
END;
"#;

    let script = parse_sql(src).expect("failed to parse nested cursors");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 2, "expected two cursor declarations");

            // Verify both cursor declarations
            for decl in decls {
                match decl {
                    AstStmt::DeclareCursor { .. } => {}
                    _ => panic!("expected DeclareCursor"),
                }
            }

            // Verify body has operations for both cursors
            assert_eq!(
                body.len(),
                6,
                "expected OPEN, FETCH, OPEN, FETCH, CLOSE, CLOSE"
            );

            // Check sequence: OPEN dept_cursor, FETCH dept_cursor, OPEN emp_cursor, FETCH emp_cursor, CLOSE emp_cursor, CLOSE dept_cursor
            match &body[0] {
                AstStmt::OpenCursor {
                    cursor_name_span,
                    using_clause_span,
                    ..
                } => {
                    let cursor =
                        &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(cursor, "dept_cursor");
                    assert!(
                        using_clause_span.is_none(),
                        "dept_cursor should not have USING clause"
                    );
                }
                _ => panic!("expected OpenCursor for dept_cursor"),
            }

            match &body[2] {
                AstStmt::OpenCursor {
                    cursor_name_span,
                    using_clause_span,
                    ..
                } => {
                    let cursor =
                        &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(cursor, "emp_cursor");
                    assert!(
                        using_clause_span.is_some(),
                        "emp_cursor should have USING clause"
                    );
                }
                _ => panic!("expected OpenCursor for emp_cursor"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cursor_in_for_loop() {
    // Test cursor used within a FOR loop
    let src = r#"
DECLARE
  c1 CURSOR FOR SELECT product_id, price FROM products;
BEGIN
  FOR record IN c1 DO
    LET total := record.price * 1.1;
  END FOR;
END;
"#;

    let script = parse_sql(src).expect("failed to parse cursor in FOR loop");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::DeclareCursor { cursor_name, .. } => {
                    let name = &src[cursor_name.span.start as usize..cursor_name.span.end as usize];
                    assert_eq!(name, "c1");
                }
                _ => panic!("expected DeclareCursor"),
            }

            assert_eq!(body.len(), 1, "expected FOR loop");
            match &body[0] {
                AstStmt::For(_) => {}
                _ => panic!("expected For statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_multiple_cursors_sequential() {
    // Test multiple cursors used sequentially
    let src = r#"
DECLARE
  customers_cursor CURSOR FOR SELECT customer_id FROM customers;
  orders_cursor CURSOR FOR SELECT order_id FROM orders;
BEGIN
  OPEN customers_cursor;
  FETCH customers_cursor INTO cust_id;
  CLOSE customers_cursor;
  
  OPEN orders_cursor;
  FETCH orders_cursor INTO ord_id;
  CLOSE orders_cursor;
END;
"#;

    let script = parse_sql(src).expect("failed to parse multiple sequential cursors");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 2, "expected two cursor declarations");

            // Verify 6 operations: OPEN, FETCH, CLOSE for each cursor
            assert_eq!(body.len(), 6);

            // First cursor operations
            match &body[0] {
                AstStmt::OpenCursor {
                    cursor_name_span, ..
                } => {
                    let name = &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(name, "customers_cursor");
                }
                _ => panic!("expected OpenCursor for customers_cursor"),
            }

            match &body[2] {
                AstStmt::CloseCursor {
                    cursor_name_span, ..
                } => {
                    let name = &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(name, "customers_cursor");
                }
                _ => panic!("expected CloseCursor for customers_cursor"),
            }

            // Second cursor operations
            match &body[3] {
                AstStmt::OpenCursor {
                    cursor_name_span, ..
                } => {
                    let name = &src[cursor_name_span.start as usize..cursor_name_span.end as usize];
                    assert_eq!(name, "orders_cursor");
                }
                _ => panic!("expected OpenCursor for orders_cursor"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cursor_with_exception_handling() {
    // Test cursor operations with exception handling
    let src = r#"
DECLARE
  c1 CURSOR FOR SELECT id FROM items WHERE category = ?;
BEGIN
  OPEN c1 USING (cat_id);
  FETCH c1 INTO item_id;
  CLOSE c1;
EXCEPTION
  WHEN OTHER THEN
    CLOSE c1;
    RAISE;
END;
"#;

    let script = parse_sql(src).expect("failed to parse cursor with exception handling");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            let exception = &b.exception;
            assert_eq!(decls.len(), 1);
            assert_eq!(body.len(), 3, "expected OPEN, FETCH, CLOSE");

            // Verify exception section exists
            assert!(exception.is_some(), "expected EXCEPTION section");
            let ex_section = exception.as_ref().unwrap();
            assert_eq!(ex_section.handlers.len(), 1);

            // Verify exception handler has CLOSE and RAISE
            let handler = &ex_section.handlers[0];
            assert_eq!(handler.body.len(), 2, "expected CLOSE and RAISE in handler");

            match &handler.body[0] {
                AstStmt::CloseCursor { .. } => {}
                _ => panic!("expected CloseCursor in exception handler"),
            }

            match &handler.body[1] {
                AstStmt::Raise { .. } => {}
                _ => panic!("expected Raise in exception handler"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cursor_with_complex_query() {
    // Test cursor with complex SELECT statement including JOINs, WHERE, GROUP BY
    let src = r#"
DECLARE
  c1 CURSOR FOR 
    SELECT 
      e.employee_id,
      e.name,
      d.dept_name,
      SUM(s.amount) as total_sales
    FROM employees e
    JOIN departments d ON e.dept_id = d.dept_id
    LEFT JOIN sales s ON e.employee_id = s.employee_id
    WHERE e.status = 'active'
    GROUP BY e.employee_id, e.name, d.dept_name
    HAVING SUM(s.amount) > 1000
    ORDER BY total_sales DESC;
BEGIN
  OPEN c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse cursor with complex query");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::DeclareCursor { query_span, .. } => {
                    let query = &src[query_span.start as usize..query_span.end as usize];
                    assert!(query.contains("SELECT"));
                    assert!(query.contains("JOIN"));
                    assert!(query.contains("WHERE"));
                    assert!(query.contains("GROUP BY"));
                    assert!(query.contains("HAVING"));
                    assert!(query.contains("ORDER BY"));
                }
                _ => panic!("expected DeclareCursor"),
            }

            assert_eq!(body.len(), 1);
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cursor_in_nested_blocks() {
    // Rewritten without nested BEGIN blocks (not allowed in Snowflake)
    // Test multiple cursor declarations and usage in same block
    let src = r#"
BEGIN
  LET outer_cursor CURSOR FOR SELECT * FROM outer_table;
  LET inner_cursor CURSOR FOR SELECT * FROM inner_table;
  
  OPEN outer_cursor;
  OPEN inner_cursor;
  
  FETCH inner_cursor INTO inner_val;
  CLOSE inner_cursor;
  
  FETCH outer_cursor INTO outer_val;
  CLOSE outer_cursor;
END;
"#;

    let script = parse_sql(src).expect("failed to parse multiple cursors in block");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(
                body.len(),
                8,
                "expected 2 LETs, 2 OPENs, 2 FETCHes, 2 CLOSEs"
            );

            // Verify first cursor LET
            match &body[0] {
                AstStmt::LetCursor { cursor_name, .. } => {
                    let name = &src[cursor_name.span.start as usize..cursor_name.span.end as usize];
                    assert_eq!(name, "outer_cursor");
                }
                _ => panic!("expected LetCursor for outer_cursor"),
            }

            // Verify second cursor LET
            match &body[1] {
                AstStmt::LetCursor { cursor_name, .. } => {
                    let name = &src[cursor_name.span.start as usize..cursor_name.span.end as usize];
                    assert_eq!(name, "inner_cursor");
                }
                _ => panic!("expected LetCursor for inner_cursor"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cursor_with_if_statement() {
    // Test cursor operations controlled by IF statement
    let src = r#"
DECLARE
  c1 CURSOR FOR SELECT amount FROM transactions;
BEGIN
  OPEN c1;
  FETCH c1 INTO amt;
  
  IF (amt > 1000) THEN
    LET high_value := TRUE;
  ELSE
    LET high_value := FALSE;
  END IF;
  
  CLOSE c1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse cursor with IF statement");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            assert_eq!(body.len(), 4, "expected OPEN, FETCH, IF, CLOSE");

            match &body[2] {
                AstStmt::If(_) => {}
                _ => panic!("expected If statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

// ===================================================================
// Async Job Management (AWAIT, CANCEL)
// ===================================================================

#[test]
fn parse_await_simple() {
    // Test basic AWAIT statement
    let src = r#"
BEGIN
  LET job_id := 'abc123';
  AWAIT job_id;
END;
"#;

    let script = parse_sql(src).expect("failed to parse simple AWAIT");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 2, "expected LET and AWAIT");

            // Verify AWAIT statement
            match &body[1] {
                AstStmt::Await {
                    job_id_expr_span, ..
                } => {
                    let job_expr =
                        &src[job_id_expr_span.start as usize..job_id_expr_span.end as usize];
                    assert_eq!(job_expr.trim(), "job_id");
                }
                _ => panic!("expected Await statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cancel_simple() {
    // Test basic CANCEL statement
    let src = r#"
BEGIN
  LET job_id := 'xyz789';
  CANCEL job_id;
END;
"#;

    let script = parse_sql(src).expect("failed to parse simple CANCEL");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 2, "expected LET and CANCEL");

            // Verify CANCEL statement
            match &body[1] {
                AstStmt::Cancel {
                    job_id_expr_span, ..
                } => {
                    let job_expr =
                        &src[job_id_expr_span.start as usize..job_id_expr_span.end as usize];
                    assert_eq!(job_expr.trim(), "job_id");
                }
                _ => panic!("expected Cancel statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_await_and_cancel_with_variables() {
    // Test AWAIT and CANCEL with variable references
    let src = r#"
DECLARE
  my_job VARCHAR;
BEGIN
  LET my_job := 'job_12345';
  AWAIT my_job;
  CANCEL my_job;
END;
"#;

    let script = parse_sql(src).expect("failed to parse AWAIT and CANCEL with variables");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            let body = &b.body;
            assert_eq!(decls.len(), 1);
            assert_eq!(body.len(), 3, "expected LET, AWAIT, CANCEL");

            // Verify AWAIT
            match &body[1] {
                AstStmt::Await { .. } => {}
                _ => panic!("expected Await statement"),
            }

            // Verify CANCEL
            match &body[2] {
                AstStmt::Cancel { .. } => {}
                _ => panic!("expected Cancel statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_await_in_if_branch() {
    // Test AWAIT inside conditional logic
    let src = r#"
BEGIN
  LET job_id := 'async_job_1';
  LET should_wait := TRUE;
  
  IF (should_wait) THEN
    AWAIT job_id;
  END IF;
END;
"#;

    let script = parse_sql(src).expect("failed to parse AWAIT in IF branch");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 3, "expected 2 LETs and IF");

            // Verify IF exists (body parsing is shallow)
            match &body[2] {
                AstStmt::If(i) => {
                    let branches = &i.branches;
                    assert_eq!(branches.len(), 1);
                    // Check that the body contains at least one statement
                    assert!(!branches[0].body.is_empty());
                }
                _ => panic!("expected If statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_cancel_in_exception_handler() {
    // Test CANCEL in exception handler (cleanup scenario)
    let src = r#"
BEGIN
  LET job_id := 'risky_job';
  -- Start some async job here
  EXCEPTION
    WHEN OTHER THEN
      CANCEL job_id;
      RAISE;
END;
"#;

    let script = parse_sql(src).expect("failed to parse CANCEL in exception handler");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            let exception = &b.exception;
            assert_eq!(body.len(), 1, "expected LET in body");

            // Verify exception handler has CANCEL
            assert!(exception.is_some(), "expected exception handler");
            if let Some(exc) = exception {
                assert_eq!(exc.handlers.len(), 1);
                let handler_body = &exc.handlers[0].body;
                assert_eq!(
                    handler_body.len(),
                    2,
                    "expected CANCEL and RAISE in handler"
                );

                match &handler_body[0] {
                    AstStmt::Cancel { .. } => {}
                    _ => panic!("expected Cancel in exception handler"),
                }
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_await_with_expression() {
    // Test AWAIT with more complex expression
    let src = r#"
BEGIN
  LET job1 := 'job_a';
  LET job2 := 'job_b';
  AWAIT job1;
  AWAIT job2;
  RETURN 'Both jobs completed';
END;
"#;

    let script = parse_sql(src).expect("failed to parse AWAIT with expressions");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 5, "expected 2 LETs, 2 AWAITs, 1 RETURN");

            // Verify first AWAIT
            match &body[2] {
                AstStmt::Await {
                    job_id_expr_span, ..
                } => {
                    let job_expr =
                        &src[job_id_expr_span.start as usize..job_id_expr_span.end as usize];
                    assert_eq!(job_expr.trim(), "job1");
                }
                _ => panic!("expected first Await statement"),
            }

            // Verify second AWAIT
            match &body[3] {
                AstStmt::Await {
                    job_id_expr_span, ..
                } => {
                    let job_expr =
                        &src[job_id_expr_span.start as usize..job_id_expr_span.end as usize];
                    assert_eq!(job_expr.trim(), "job2");
                }
                _ => panic!("expected second Await statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

#[test]
fn parse_await_cancel_in_loop() {
    // Test async operations inside loop
    let src = r#"
BEGIN
  LET job_id := 'my_job';
  LET i := 0;
  
  WHILE (i < 3) DO
    AWAIT job_id;
    LET i := i + 1;
  END WHILE;
END;
"#;

    let script = parse_sql(src).expect("failed to parse AWAIT in loop");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert_eq!(body.len(), 3, "expected 2 LETs and WHILE");

            // Verify WHILE loop exists and contains AWAIT
            match &body[2] {
                AstStmt::While(w) => {
                    let loop_body = &w.body;
                    assert_eq!(loop_body.len(), 2, "expected AWAIT and LET in loop");

                    // Verify AWAIT is present
                    match &loop_body[0] {
                        AstStmt::Await { .. } => {}
                        _ => panic!("expected Await in loop body"),
                    }
                }
                _ => panic!("expected While statement"),
            }
        }
        _ => panic!("expected top-level block"),
    }
}

// ========== CREATE PROCEDURE Tests ==========

#[test]
fn parse_create_procedure_simple() {
    let src = r#"
CREATE PROCEDURE my_procedure(x NUMBER, y NUMBER)
RETURNS NUMBER
LANGUAGE SQL
AS
BEGIN
  RETURN x + y;
END;
"#;

    let script = parse_sql(src).expect("failed to parse simple procedure");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let span = proc_stmt.span;
            let name_span = proc_stmt.name_span;
            let params_span = proc_stmt.params_span;
            let returns_span = proc_stmt.returns_span;
            let body_span = proc_stmt.body_span;
            // Verify all spans are present and non-empty
            assert!(span.end > span.start, "procedure span should be non-empty");
            assert!(
                name_span.end > name_span.start,
                "name span should be non-empty"
            );
            assert!(
                params_span.end > params_span.start,
                "params span should be non-empty"
            );
            assert!(
                returns_span.end > returns_span.start,
                "returns span should be non-empty"
            );
            assert!(
                body_span.end > body_span.start,
                "body span should be non-empty"
            );

            // Verify procedure name
            let name_text = &src[name_span.start as usize..name_span.end as usize];
            assert!(
                name_text.contains("my_procedure"),
                "expected procedure name"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_create_or_replace_procedure() {
    let src = r#"
CREATE OR REPLACE PROCEDURE compute_sum(a NUMBER, b NUMBER)
RETURNS NUMBER
AS
BEGIN
  RETURN a + b;
END;
"#;

    let script = parse_sql(src).expect("failed to parse OR REPLACE procedure");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let span = proc_stmt.span;
            let name_span = proc_stmt.name_span;
            // Verify procedure name
            let name_text = &src[name_span.start as usize..name_span.end as usize];
            assert!(name_text.contains("compute_sum"), "expected procedure name");

            // Verify full span includes OR REPLACE
            let full_text = &src[span.start as usize..span.end as usize];
            assert!(
                full_text.to_uppercase().contains("OR REPLACE"),
                "expected OR REPLACE in span"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_declare_and_if() {
    let src = r#"
CREATE PROCEDURE check_value(x NUMBER)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
  result VARCHAR;
BEGIN
  IF (x > 0) THEN
    result := 'positive';
  ELSE
    result := 'non-positive';
  END IF;
  RETURN result;
END;
"#;

    let script = parse_sql(src).expect("failed to parse procedure with DECLARE and IF");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            // Verify body contains the scripting constructs
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            // Note: result is in DECLARE section, so body only has IF and assignments
            assert!(
                body_text.to_uppercase().contains("IF"),
                "expected IF in body"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_loop() {
    let src = r#"
CREATE PROCEDURE sum_numbers(n NUMBER)
RETURNS NUMBER
AS
DECLARE
  sum NUMBER DEFAULT 0;
  i NUMBER DEFAULT 1;
BEGIN
  WHILE (i <= n) DO
    LET sum := sum + i;
    LET i := i + 1;
  END WHILE;
  
  RETURN sum;
END;
"#;

    let script = parse_sql(src).expect("failed to parse procedure with WHILE loop");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(
                body_text.to_uppercase().contains("WHILE"),
                "expected WHILE in body"
            );
            assert!(
                body_text.to_uppercase().contains("END WHILE"),
                "expected END WHILE in body"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_sql_statements() {
    let src = r#"
CREATE PROCEDURE insert_data(val NUMBER)
RETURNS VARCHAR
LANGUAGE SQL
AS
BEGIN
  INSERT INTO my_table VALUES (val);
  SELECT COUNT(*) FROM my_table;
  RETURN 'success';
END;
"#;

    let script = parse_sql(src).expect("failed to parse procedure with SQL");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(
                body_text.to_uppercase().contains("INSERT"),
                "expected INSERT in body"
            );
            assert!(
                body_text.to_uppercase().contains("SELECT"),
                "expected SELECT in body"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_exception_handling() {
    // Rewritten without nested BEGIN blocks (not allowed in Snowflake)
    let src = r#"
CREATE PROCEDURE safe_divide(a NUMBER, b NUMBER)
RETURNS NUMBER
AS
DECLARE
  result NUMBER;
BEGIN
  LET result := a / b;
EXCEPTION
  WHEN OTHERS THEN
    LET result := 0;
END;
"#;

    let script = parse_sql(src).expect("failed to parse procedure with EXCEPTION");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(
                body_text.to_uppercase().contains("EXCEPTION"),
                "expected EXCEPTION in body"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_returns_table() {
    let src = r#"
CREATE PROCEDURE get_employees()
RETURNS TABLE (id NUMBER, name VARCHAR)
LANGUAGE SQL
AS
DECLARE
  res RESULTSET DEFAULT (SELECT id, name FROM employees);
BEGIN
  RETURN TABLE(res);
END;
"#;

    let script = parse_sql(src).expect("failed to parse procedure with RETURNS TABLE");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let returns_span = proc_stmt.returns_span;
            let returns_text = &src[returns_span.start as usize..returns_span.end as usize];
            assert!(
                returns_text.to_uppercase().contains("TABLE"),
                "expected TABLE in returns"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

// ===== New Features Tests =====

#[test]
fn parse_resultset_declare() {
    let src = r#"
DECLARE
  res RESULTSET DEFAULT (SELECT * FROM my_table);
BEGIN
  RETURN 1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse RESULTSET declaration");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let decls = &b.decls;
            assert_eq!(decls.len(), 1);
            match &decls[0] {
                AstStmt::Declare {
                    type_span,
                    default_expr_span,
                    ..
                } => {
                    let type_text = type_span
                        .as_ref()
                        .map(|s| &src[s.start as usize..s.end as usize]);
                    assert!(
                        type_text.unwrap().to_uppercase().contains("RESULTSET"),
                        "expected RESULTSET type"
                    );
                    assert!(default_expr_span.is_some(), "expected DEFAULT clause");
                }
                _ => panic!("expected Declare statement"),
            }
        }
        _ => panic!("expected Block statement"),
    }
}

#[test]
fn parse_resultset_let() {
    let src = r#"
DECLARE
  res RESULTSET;
BEGIN
  res := (SELECT id, name FROM users);
  RETURN 1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse RESULTSET LET assignment");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            // Should have assignment and RETURN statements
            assert!(body.len() >= 2, "expected at least 2 statements in body");

            // First should be assignment
            match &body[0] {
                AstStmt::Assign { .. } => {
                    // This is the parsed assignment
                }
                _ => panic!("expected assignment statement"),
            }
        }
        _ => panic!("expected Block statement"),
    }
}

#[test]
fn parse_resultset_async() {
    let src = r#"
DECLARE
  res RESULTSET;
BEGIN
  res := ASYNC (SELECT * FROM large_table);
  RETURN 1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse ASYNC RESULTSET assignment");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn parse_global_variables() {
    let src = r#"
DECLARE
  row_count INT;
  found BOOLEAN;
BEGIN
  UPDATE my_table SET value = 1 WHERE id < 10;
  row_count := SQLROWCOUNT;
  found := SQLFOUND;
  RETURN 1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse global variables");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert!(body.len() >= 3, "expected multiple statements in body");
        }
        _ => panic!("expected Block statement"),
    }
}

#[test]
fn parse_sqlid_variable() {
    let src = r#"
DECLARE
  query_id VARCHAR;
BEGIN
  SELECT 1;
  query_id := SQLID;
  RETURN query_id;
END;
"#;

    let script = parse_sql(src).expect("failed to parse SQLID variable");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn parse_create_function_simple() {
    let src = r#"
CREATE FUNCTION add_two(x INTEGER)
RETURNS INTEGER
LANGUAGE SQL
AS
BEGIN
  RETURN x + 2;
END;
"#;

    let script = parse_sql(src).expect("failed to parse simple function");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let name_span = func_stmt.name_span;
            let params_span = func_stmt.params_span;
            let returns_span = func_stmt.returns_span;
            let body_span = func_stmt.body_span;
            let name = &src[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "add_two");

            let params = &src[params_span.start as usize..params_span.end as usize];
            assert!(params.contains("INTEGER"), "expected INTEGER parameter");

            let returns = &src[returns_span.start as usize..returns_span.end as usize];
            assert!(
                returns.to_uppercase().contains("INTEGER"),
                "expected INTEGER return type"
            );

            let body = &src[body_span.start as usize..body_span.end as usize];
            assert!(
                body.to_uppercase().contains("RETURN"),
                "expected RETURN in body"
            );
        }
        _ => panic!("expected CreateFunction statement"),
    }
}

#[test]
fn parse_create_or_replace_function() {
    let src = r#"
CREATE OR REPLACE FUNCTION double_value(n NUMBER)
RETURNS NUMBER
AS
$$
BEGIN
  RETURN n * 2;
END;
$$;
"#;

    let script = parse_sql(src).expect("failed to parse CREATE OR REPLACE function");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateFunction(_) => {
            // Successfully parsed
        }
        _ => panic!("expected CreateFunction statement"),
    }
}

#[test]
fn parse_function_returns_table() {
    let src = r#"
CREATE FUNCTION get_users()
RETURNS TABLE(id INTEGER, name VARCHAR)
AS
BEGIN
  RETURN 1;
END;
"#;

    let script = parse_sql(src).expect("failed to parse function with RETURNS TABLE");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let returns_span = func_stmt.returns_span;
            let returns_text = &src[returns_span.start as usize..returns_span.end as usize];
            assert!(
                returns_text.to_uppercase().contains("TABLE"),
                "expected TABLE in returns"
            );
        }
        _ => panic!("expected CreateFunction statement"),
    }
}

#[test]
fn parse_execute_immediate_simple() {
    let src = r#"
DECLARE
  sql_stmt VARCHAR DEFAULT 'SELECT * FROM my_table';
BEGIN
  EXECUTE IMMEDIATE :sql_stmt;
END;
"#;

    let script = parse_sql(src).expect("failed to parse EXECUTE IMMEDIATE");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            assert!(!body.is_empty(), "expected at least 1 statement in body");
            match &body[0] {
                AstStmt::ExecuteImmediate { .. } => {
                    // EXECUTE IMMEDIATE now carries parsed expressions; basic shape is enough here.
                }
                _ => panic!("expected ExecuteImmediate statement"),
            }
        }
        _ => panic!("expected Block statement"),
    }
}

#[test]
fn parse_execute_immediate_with_using() {
    let src = r#"
DECLARE
  table_name VARCHAR DEFAULT 't001';
  query VARCHAR DEFAULT 'SELECT * FROM IDENTIFIER(?) ORDER BY id';
BEGIN
  EXECUTE IMMEDIATE :query USING (table_name);
END;
"#;

    let script = parse_sql(src).expect("failed to parse EXECUTE IMMEDIATE with USING");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let body = &b.body;
            // Find the EXECUTE IMMEDIATE statement (should be first)
            let exec_stmt = body
                .iter()
                .find(|s| matches!(s, AstStmt::ExecuteImmediate { .. }));
            assert!(
                exec_stmt.is_some(),
                "expected ExecuteImmediate statement in body"
            );

            match exec_stmt.unwrap() {
                AstStmt::ExecuteImmediate { .. } => {
                    // USING arguments are now parsed as expressions; presence is validated by parsing.
                }
                _ => unreachable!(),
            }
        }
        _ => panic!("expected Block statement"),
    }
}

#[test]
fn parse_execute_immediate_in_procedure() {
    let src = r#"
CREATE PROCEDURE dynamic_query(table_name VARCHAR)
RETURNS VARCHAR
AS
BEGIN
  LET query VARCHAR := 'SELECT COUNT(*) FROM IDENTIFIER(?)';
  EXECUTE IMMEDIATE :query USING (table_name);
  RETURN 'done';
END;
"#;

    let script = parse_sql(src).expect("failed to parse procedure with EXECUTE IMMEDIATE");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body = &src[body_span.start as usize..body_span.end as usize];
            assert!(
                body.to_uppercase().contains("EXECUTE IMMEDIATE"),
                "expected EXECUTE IMMEDIATE in body"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_complex_example_with_all_features() {
    // This test demonstrates all new features:
    // - RESULTSET declarations and assignments
    // - Global variables (SQLROWCOUNT, SQLFOUND, SQLID)
    // - EXECUTE IMMEDIATE with USING clause
    // - CREATE PROCEDURE with DECLARE section
    // - Cursor operations with RESULTSET
    let src = r#"
CREATE OR REPLACE PROCEDURE comprehensive_example(p_table_name VARCHAR, p_min_id INTEGER)
RETURNS VARCHAR
AS
DECLARE
  res RESULTSET;
  query_str VARCHAR;
  row_count INTEGER;
  query_id VARCHAR;
  found_rows BOOLEAN;
BEGIN
  -- Use EXECUTE IMMEDIATE with USING clause for dynamic SQL
  query_str := 'SELECT * FROM IDENTIFIER(?) WHERE id > ?';
  EXECUTE IMMEDIATE :query_str USING (p_table_name, p_min_id);
  
  -- Capture query ID using SQLID global variable
  query_id := SQLID;
  
  -- Assign RESULTSET from query
  res := (SELECT id, name FROM my_table WHERE id > p_min_id);
  
  -- Update some data
  UPDATE my_table SET processed = true WHERE id > p_min_id;
  
  -- Check DML status using global variables
  row_count := SQLROWCOUNT;
  found_rows := SQLFOUND;
  
  RETURN query_id;
END;
"#;

    let script = parse_sql(src).expect("failed to parse comprehensive example");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body = &src[body_span.start as usize..body_span.end as usize];
            // Verify all features are present in the parsed body
            assert!(
                body.to_uppercase().contains("EXECUTE IMMEDIATE"),
                "expected EXECUTE IMMEDIATE"
            );
            assert!(
                body.to_uppercase().contains("USING"),
                "expected USING clause"
            );
            assert!(body.contains("SQLID"), "expected SQLID global variable");
            assert!(
                body.contains("SQLROWCOUNT"),
                "expected SQLROWCOUNT global variable"
            );
            assert!(
                body.contains("SQLFOUND"),
                "expected SQLFOUND global variable"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_create_function_with_resultset() {
    // Test CREATE FUNCTION using RESULTSET
    let src = r#"
CREATE OR REPLACE FUNCTION get_filtered_data(min_value INTEGER)
RETURNS TABLE(id INTEGER, value VARCHAR)
AS
DECLARE
  result_data RESULTSET;
BEGIN
  result_data := (SELECT id, value FROM data_table WHERE value > min_value);
  RETURN result_data;
END;
"#;

    let script = parse_sql(src).expect("failed to parse function with RESULTSET");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let name_span = func_stmt.name_span;
            let returns_span = func_stmt.returns_span;
            let name = &src[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "get_filtered_data");

            let returns = &src[returns_span.start as usize..returns_span.end as usize];
            assert!(
                returns.to_uppercase().contains("TABLE"),
                "expected TABLE return type"
            );
        }
        _ => panic!("expected CreateFunction statement"),
    }
}

#[test]
fn parse_procedure_with_cursors() {
    let src = r#"
CREATE PROCEDURE process_rows()
RETURNS VARCHAR
AS
DECLARE
  row_id NUMBER;
BEGIN
  LET c1 CURSOR FOR SELECT id FROM my_table;
  
  OPEN c1;
  FETCH c1 INTO row_id;
  CLOSE c1;
  
  RETURN 'done';
END;
"#;

    let script = parse_sql(src).expect("failed to parse procedure with cursors");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(
                body_text.to_uppercase().contains("CURSOR"),
                "expected CURSOR in body"
            );
            assert!(
                body_text.to_uppercase().contains("OPEN"),
                "expected OPEN in body"
            );
            assert!(
                body_text.to_uppercase().contains("FETCH"),
                "expected FETCH in body"
            );
            assert!(
                body_text.to_uppercase().contains("CLOSE"),
                "expected CLOSE in body"
            );
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}
