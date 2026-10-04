// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for Databricks SQL Scripting: labeled loops, LEAVE/ITERATE, FOR...AS...DO
//
// Databricks supports labels on compound (BEGIN/END) and loop (WHILE, FOR, LOOP, REPEAT)
// statements. Labels use the syntax: label_name: WHILE ... END WHILE label_name;
// LEAVE and ITERATE reference labels to exit or restart labeled loops.
// FOR...AS...DO is an alternative to FOR...IN...DO for cursor iteration.

use lexega_syntax::dialect::databricks;
use lexega_syntax::{
    format_sql_with_config, parse_sql, verify_formatting_safe_with_dialect, AstStmt,
    FormatterConfig,
};

fn db_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = databricks();
    config
}

fn format_and_verify(sql: &str) -> String {
    let config = db_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Databricks format failed:\n{}\nSQL:\n{}", e, sql));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref()).unwrap_or_else(
        |e| {
            panic!(
                "Round-trip verification failed:\n{}\nFormatted:\n{}\nSQL:\n{}",
                e, formatted, sql
            )
        },
    );
    formatted
}

// =============================================================================
// Labeled WHILE
// =============================================================================

#[test]
fn test_labeled_while_basic() {
    let sql = r#"BEGIN
  lbl: WHILE (x > 0) DO
    SET x = x - 1;
  END WHILE lbl;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("lbl:"), "Should preserve start label: {}", fmt);
    assert!(
        fmt.contains("END WHILE lbl"),
        "Should preserve end label: {}",
        fmt
    );
}

#[test]
fn test_labeled_while_no_end_label() {
    let sql = r#"BEGIN
  my_loop: WHILE (TRUE) DO
    BREAK;
  END WHILE;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("my_loop:"),
        "Should preserve start label: {}",
        fmt
    );
}

#[test]
fn test_labeled_while_leave() {
    let sql = r#"BEGIN
  outer_loop: WHILE (TRUE) DO
    IF x > 10 THEN
      LEAVE outer_loop;
    END IF;
    SET x = x + 1;
  END WHILE outer_loop;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("outer_loop:"),
        "Should preserve start label: {}",
        fmt
    );
    assert!(
        fmt.contains("LEAVE outer_loop"),
        "Should preserve LEAVE with label: {}",
        fmt
    );
    assert!(
        fmt.contains("END WHILE outer_loop"),
        "Should preserve end label: {}",
        fmt
    );
}

#[test]
fn test_labeled_while_iterate() {
    let sql = r#"BEGIN
  retry: WHILE (attempts < 3) DO
    IF should_skip THEN
      ITERATE retry;
    END IF;
    SET attempts = attempts + 1;
  END WHILE retry;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("retry:"), "Should preserve start label");
    assert!(
        fmt.contains("ITERATE retry"),
        "Should preserve ITERATE with label"
    );
    assert!(fmt.contains("END WHILE retry"), "Should preserve end label");
}

// =============================================================================
// Labeled LOOP
// =============================================================================

#[test]
fn test_labeled_loop_basic() {
    let sql = r#"BEGIN
  inf: LOOP
    SET i = i + 1;
    IF i > 10 THEN
      LEAVE inf;
    END IF;
  END LOOP inf;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("inf:"), "Should preserve start label: {}", fmt);
    assert!(
        fmt.contains("END LOOP inf"),
        "Should preserve end label: {}",
        fmt
    );
    assert!(fmt.contains("LEAVE inf"), "Should preserve LEAVE: {}", fmt);
}

#[test]
fn test_labeled_loop_no_end_label() {
    let sql = r#"BEGIN
  myloop: LOOP
    BREAK;
  END LOOP;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("myloop:"),
        "Should preserve start label: {}",
        fmt
    );
}

// =============================================================================
// Labeled REPEAT
// =============================================================================

#[test]
fn test_labeled_repeat_basic() {
    let sql = r#"BEGIN
  rpt: REPEAT
    SET counter = counter + 1;
  UNTIL (counter >= 10)
  END REPEAT rpt;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("rpt:"), "Should preserve start label: {}", fmt);
    assert!(
        fmt.contains("END REPEAT rpt"),
        "Should preserve end label: {}",
        fmt
    );
}

// =============================================================================
// Labeled FOR
// =============================================================================

#[test]
fn test_labeled_for_basic() {
    let sql = r#"BEGIN
  scan: FOR rec IN cursor1 DO
    SELECT rec.col1;
  END FOR scan;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("scan:"),
        "Should preserve start label: {}",
        fmt
    );
    assert!(
        fmt.contains("END FOR scan"),
        "Should preserve end label: {}",
        fmt
    );
}

// =============================================================================
// Labeled BEGIN/END (compound statement)
// =============================================================================

#[test]
fn test_labeled_block_basic() {
    let sql = r#"blk: BEGIN
  SELECT 1;
END blk;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("blk:"), "Should preserve start label: {}", fmt);
    assert!(
        fmt.contains("END blk"),
        "Should preserve end label: {}",
        fmt
    );
}

#[test]
fn test_labeled_block_leave() {
    let sql = r#"outer: BEGIN
  IF done THEN
    LEAVE outer;
  END IF;
  SELECT 1;
END outer;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("outer:"), "Should preserve start label");
    assert!(fmt.contains("LEAVE outer"), "Should preserve LEAVE");
    assert!(fmt.contains("END outer"), "Should preserve end label");
}

// =============================================================================
// Nested labeled loops
// =============================================================================

#[test]
fn test_nested_labeled_loops() {
    let sql = r#"BEGIN
  outer: WHILE (TRUE) DO
    inner: WHILE (TRUE) DO
      IF done THEN
        LEAVE outer;
      END IF;
      IF skip THEN
        ITERATE inner;
      END IF;
    END WHILE inner;
  END WHILE outer;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("outer:"), "Should preserve outer label");
    assert!(fmt.contains("inner:"), "Should preserve inner label");
    assert!(fmt.contains("LEAVE outer"), "Should preserve LEAVE outer");
    assert!(
        fmt.contains("ITERATE inner"),
        "Should preserve ITERATE inner"
    );
    assert!(
        fmt.contains("END WHILE inner"),
        "Should preserve inner end label"
    );
    assert!(
        fmt.contains("END WHILE outer"),
        "Should preserve outer end label"
    );
}

// =============================================================================
// FOR ... AS ... DO (Databricks alternative to FOR ... IN ... DO)
// =============================================================================

#[test]
fn test_for_as_do_basic() {
    let sql = r#"BEGIN
  FOR row AS cursor1 DO
    SELECT row.col1;
  END FOR;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("FOR"), "Should preserve FOR");
    assert!(fmt.contains("AS"), "Should preserve AS keyword");
    assert!(fmt.contains("END FOR"), "Should preserve END FOR");
}

#[test]
fn test_for_as_do_with_label() {
    let sql = r#"BEGIN
  scan: FOR rec AS my_cursor DO
    SELECT rec.id;
  END FOR scan;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("scan:"), "Should preserve start label");
    assert!(fmt.contains("AS"), "Should preserve AS keyword");
    assert!(fmt.contains("END FOR scan"), "Should preserve end label");
}

#[test]
fn test_for_as_do_select_cursor() {
    let sql = r#"BEGIN
  FOR row AS SELECT id, name FROM users DO
    SELECT row.id;
  END FOR;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("AS"), "Should preserve AS keyword");
    assert!(fmt.contains("SELECT id"), "Should preserve cursor SELECT");
}

// =============================================================================
// FOR ... IN ... DO (existing syntax should still work)
// =============================================================================

#[test]
fn test_for_in_do_still_works() {
    let sql = r#"BEGIN
  FOR rec IN cursor1 DO
    SELECT rec.col1;
  END FOR;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("IN"), "Should preserve IN keyword");
    assert!(fmt.contains("END FOR"), "Should preserve END FOR");
}

#[test]
fn test_for_in_range_still_works() {
    let sql = r#"BEGIN
  FOR i IN 1..10 DO
    SELECT i;
  END FOR;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("IN"), "Should preserve IN keyword");
}

// =============================================================================
// AST-level verification: labels are parsed into correct spans
// =============================================================================

#[test]
fn test_labeled_while_ast_has_label_span() {
    let sql = r#"BEGIN
  my_label: WHILE (TRUE) DO
    BREAK;
  END WHILE my_label;
END;"#;
    let script = parse_sql(sql).expect("should parse labeled WHILE");
    assert_eq!(script.stmts.len(), 1);
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            assert_eq!(b.body.len(), 1, "block should contain 1 WHILE statement");
            match &b.body[0] {
                AstStmt::While(w) => {
                    assert!(w.label_span.is_some(), "WHILE should have label_span");
                    assert!(
                        w.end_label_span.is_some(),
                        "WHILE should have end_label_span"
                    );
                    let label_text = &sql
                        [w.label_span.unwrap().start as usize..w.label_span.unwrap().end as usize];
                    assert!(
                        label_text.contains("my_label"),
                        "label_span should cover 'my_label:' got '{}'",
                        label_text
                    );
                    let end_label_text = &sql[w.end_label_span.unwrap().start as usize
                        ..w.end_label_span.unwrap().end as usize];
                    assert_eq!(
                        end_label_text.trim(),
                        "my_label",
                        "end_label_span should cover 'my_label' got '{}'",
                        end_label_text
                    );
                }
                other => panic!("expected While, got {:?}", std::mem::discriminant(other)),
            }
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_labeled_loop_ast_has_label_span() {
    let sql = r#"BEGIN
  myloop: LOOP
    BREAK;
  END LOOP myloop;
END;"#;
    let script = parse_sql(sql).expect("should parse labeled LOOP");
    match &script.stmts[0] {
        AstStmt::Block(b) => match &b.body[0] {
            AstStmt::Loop(l) => {
                assert!(l.label_span.is_some(), "LOOP should have label_span");
                assert!(
                    l.end_label_span.is_some(),
                    "LOOP should have end_label_span"
                );
            }
            other => panic!("expected Loop, got {:?}", std::mem::discriminant(other)),
        },
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_labeled_block_ast_has_label_span() {
    let sql = "outer: BEGIN SELECT 1; END outer;";
    let script = parse_sql(sql).expect("should parse labeled block");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            assert!(b.label_span.is_some(), "Block should have label_span");
            assert!(
                b.end_label_span.is_some(),
                "Block should have end_label_span"
            );
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_unlabeled_while_no_label_span() {
    let sql = r#"BEGIN
  WHILE (TRUE) DO
    BREAK;
  END WHILE;
END;"#;
    let script = parse_sql(sql).expect("should parse unlabeled WHILE");
    match &script.stmts[0] {
        AstStmt::Block(b) => match &b.body[0] {
            AstStmt::While(w) => {
                assert!(
                    w.label_span.is_none(),
                    "unlabeled WHILE should NOT have label_span"
                );
                assert!(
                    w.end_label_span.is_none(),
                    "unlabeled WHILE should NOT have end_label_span"
                );
            }
            other => panic!("expected While, got {:?}", std::mem::discriminant(other)),
        },
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

// =============================================================================
// Idempotency: labeled constructs should format consistently on re-format
// =============================================================================

#[test]
fn test_labeled_while_idempotent() {
    let sql = r#"BEGIN
  lbl: WHILE (x > 0) DO
    SET x = x - 1;
  END WHILE lbl;
END;"#;
    let config = db_config();
    let first = format_sql_with_config(sql, &config).expect("first format should succeed");
    let second = format_sql_with_config(&first, &config).expect("second format should succeed");
    assert_eq!(
        first.trim(),
        second.trim(),
        "Labeled WHILE formatting should be idempotent"
    );
}

#[test]
fn test_for_as_do_idempotent() {
    let sql = r#"BEGIN
  FOR row AS cursor1 DO
    SELECT row.col1;
  END FOR;
END;"#;
    let config = db_config();
    let first = format_sql_with_config(sql, &config).expect("first format should succeed");
    let second = format_sql_with_config(&first, &config).expect("second format should succeed");
    assert_eq!(
        first.trim(),
        second.trim(),
        "FOR...AS...DO formatting should be idempotent"
    );
}
