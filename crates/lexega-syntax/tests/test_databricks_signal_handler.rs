// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for Databricks SQL Scripting: SIGNAL, RESIGNAL, GET DIAGNOSTICS,
// DECLARE CONDITION, DECLARE HANDLER, and BEGIN ATOMIC.

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
// SIGNAL
// =============================================================================

#[test]
fn test_signal_bare() {
    // Bare SIGNAL — re-signal current condition inside a handler
    let sql = "BEGIN\n  SIGNAL;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("SIGNAL"), "Should preserve SIGNAL: {}", fmt);
}

#[test]
fn test_signal_condition_name() {
    let sql = "BEGIN\n  SIGNAL my_error;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("SIGNAL"), "Should preserve SIGNAL: {}", fmt);
    assert!(
        fmt.contains("my_error"),
        "Should preserve condition name: {}",
        fmt
    );
}

#[test]
fn test_signal_sqlstate() {
    let sql = "BEGIN\n  SIGNAL SQLSTATE '45000';\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("SQLSTATE"),
        "Should preserve SQLSTATE: {}",
        fmt
    );
    assert!(
        fmt.contains("45000"),
        "Should preserve SQLSTATE value: {}",
        fmt
    );
}

#[test]
fn test_signal_sqlstate_value() {
    // SQLSTATE VALUE form (optional VALUE keyword)
    let sql = "BEGIN\n  SIGNAL SQLSTATE VALUE '45001';\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("VALUE"),
        "Should preserve VALUE keyword: {}",
        fmt
    );
    assert!(
        fmt.contains("45001"),
        "Should preserve SQLSTATE value: {}",
        fmt
    );
}

#[test]
fn test_signal_with_set_message() {
    let sql = "BEGIN\n  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Custom error';\nEND;";
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("SET"), "Should preserve SET clause: {}", fmt);
    assert!(
        fmt.contains("MESSAGE_TEXT"),
        "Should preserve MESSAGE_TEXT: {}",
        fmt
    );
    assert!(
        fmt.contains("Custom error"),
        "Should preserve message: {}",
        fmt
    );
}

#[test]
fn test_signal_with_set_message_and_arguments() {
    let sql = "BEGIN\n  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Error: %s %s', MESSAGE_ARGUMENTS = ('arg1', 'arg2');\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("MESSAGE_ARGUMENTS"),
        "Should preserve MESSAGE_ARGUMENTS: {}",
        fmt
    );
    assert!(fmt.contains("arg1"), "Should preserve first arg: {}", fmt);
    assert!(fmt.contains("arg2"), "Should preserve second arg: {}", fmt);
}

#[test]
fn test_signal_condition_with_set() {
    let sql = "BEGIN\n  SIGNAL my_error SET MESSAGE_TEXT = 'Something went wrong';\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("my_error"),
        "Should preserve condition name: {}",
        fmt
    );
    assert!(
        fmt.contains("Something went wrong"),
        "Should preserve message: {}",
        fmt
    );
}

// =============================================================================
// RESIGNAL
// =============================================================================

#[test]
fn test_resignal_bare() {
    let sql = "BEGIN\n  RESIGNAL;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("RESIGNAL"),
        "Should preserve RESIGNAL: {}",
        fmt
    );
}

#[test]
fn test_resignal_with_set_message() {
    let sql = "BEGIN\n  RESIGNAL SET MESSAGE_TEXT = 'Re-raised with context';\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("RESIGNAL"),
        "Should preserve RESIGNAL: {}",
        fmt
    );
    assert!(
        fmt.contains("Re-raised with context"),
        "Should preserve message: {}",
        fmt
    );
}

// =============================================================================
// GET DIAGNOSTICS
// =============================================================================

#[test]
fn test_get_diagnostics_single() {
    let sql = "BEGIN\n  GET DIAGNOSTICS CONDITION 1 msg = MESSAGE_TEXT;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("GET"), "Should preserve GET: {}", fmt);
    assert!(
        fmt.contains("DIAGNOSTICS"),
        "Should preserve DIAGNOSTICS: {}",
        fmt
    );
    assert!(
        fmt.contains("CONDITION"),
        "Should preserve CONDITION: {}",
        fmt
    );
    assert!(
        fmt.contains("MESSAGE_TEXT"),
        "Should preserve MESSAGE_TEXT: {}",
        fmt
    );
}

#[test]
fn test_get_diagnostics_multiple_items() {
    let sql = "BEGIN\n  GET DIAGNOSTICS CONDITION 1 v_msg = MESSAGE_TEXT, v_state = RETURNED_SQLSTATE;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("v_msg"),
        "Should preserve variable v_msg: {}",
        fmt
    );
    assert!(
        fmt.contains("MESSAGE_TEXT"),
        "Should preserve MESSAGE_TEXT: {}",
        fmt
    );
    assert!(
        fmt.contains("v_state"),
        "Should preserve variable v_state: {}",
        fmt
    );
    assert!(
        fmt.contains("RETURNED_SQLSTATE"),
        "Should preserve RETURNED_SQLSTATE: {}",
        fmt
    );
}

// =============================================================================
// DECLARE CONDITION
// =============================================================================

#[test]
fn test_declare_condition_basic() {
    let sql = "BEGIN\n  DECLARE my_error CONDITION FOR SQLSTATE '45000';\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("my_error"),
        "Should preserve condition name: {}",
        fmt
    );
    assert!(
        fmt.contains("CONDITION"),
        "Should preserve CONDITION keyword: {}",
        fmt
    );
    assert!(
        fmt.contains("SQLSTATE"),
        "Should preserve SQLSTATE: {}",
        fmt
    );
    assert!(
        fmt.contains("45000"),
        "Should preserve SQLSTATE value: {}",
        fmt
    );
}

#[test]
fn test_declare_condition_with_value_keyword() {
    let sql = "BEGIN\n  DECLARE divide_by_zero CONDITION FOR SQLSTATE VALUE '22012';\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("divide_by_zero"),
        "Should preserve condition name: {}",
        fmt
    );
    assert!(
        fmt.contains("VALUE"),
        "Should preserve VALUE keyword: {}",
        fmt
    );
    assert!(
        fmt.contains("22012"),
        "Should preserve SQLSTATE value: {}",
        fmt
    );
}

// =============================================================================
// DECLARE HANDLER
// =============================================================================

#[test]
fn test_declare_exit_handler_sqlexception() {
    let sql = "BEGIN\n  DECLARE EXIT HANDLER FOR SQLEXCEPTION\n  BEGIN\n    SET result = -1;\n  END;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("EXIT"),
        "Should preserve EXIT keyword: {}",
        fmt
    );
    assert!(
        fmt.contains("HANDLER"),
        "Should preserve HANDLER keyword: {}",
        fmt
    );
    assert!(
        fmt.contains("SQLEXCEPTION"),
        "Should preserve SQLEXCEPTION: {}",
        fmt
    );
}

#[test]
fn test_declare_continue_handler_not_found() {
    let sql = "BEGIN\n  DECLARE CONTINUE HANDLER FOR NOT FOUND\n    SET done = TRUE;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("CONTINUE"),
        "Should preserve CONTINUE keyword: {}",
        fmt
    );
    assert!(fmt.contains("NOT"), "Should preserve NOT: {}", fmt);
    assert!(fmt.contains("FOUND"), "Should preserve FOUND: {}", fmt);
}

#[test]
fn test_declare_handler_sqlstate() {
    let sql =
        "BEGIN\n  DECLARE EXIT HANDLER FOR SQLSTATE '45000'\n  BEGIN\n    SET x = 0;\n  END;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("SQLSTATE"),
        "Should preserve SQLSTATE: {}",
        fmt
    );
    assert!(
        fmt.contains("45000"),
        "Should preserve SQLSTATE value: {}",
        fmt
    );
}

#[test]
fn test_declare_handler_condition_name() {
    let sql = "BEGIN\n  DECLARE my_error CONDITION FOR SQLSTATE '45000';\n  DECLARE EXIT HANDLER FOR my_error\n    SET x = 0;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("my_error"),
        "Should preserve condition name: {}",
        fmt
    );
}

#[test]
fn test_declare_handler_multiple_conditions() {
    let sql = "BEGIN\n  DECLARE EXIT HANDLER FOR SQLEXCEPTION, NOT FOUND\n  BEGIN\n    SET x = 0;\n  END;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("SQLEXCEPTION"),
        "Should preserve SQLEXCEPTION: {}",
        fmt
    );
    assert!(fmt.contains("NOT"), "Should preserve NOT: {}", fmt);
    assert!(fmt.contains("FOUND"), "Should preserve FOUND: {}", fmt);
}

// =============================================================================
// BEGIN ATOMIC
// =============================================================================

#[test]
fn test_begin_atomic_basic() {
    let sql = "BEGIN ATOMIC\n  SET x = 1;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("ATOMIC"),
        "Should preserve ATOMIC keyword: {}",
        fmt
    );
    assert!(fmt.contains("BEGIN"), "Should preserve BEGIN: {}", fmt);
}

#[test]
fn test_begin_atomic_with_body() {
    let sql = "BEGIN ATOMIC\n  INSERT INTO t VALUES (1);\n  UPDATE t SET x = 2;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("ATOMIC"), "Should preserve ATOMIC: {}", fmt);
    assert!(fmt.contains("INSERT"), "Should preserve INSERT: {}", fmt);
    assert!(fmt.contains("UPDATE"), "Should preserve UPDATE: {}", fmt);
}

// =============================================================================
// Combined: full handler pattern
// =============================================================================

#[test]
fn test_full_handler_pattern() {
    // A realistic pattern combining DECLARE CONDITION, DECLARE HANDLER, SIGNAL
    let sql = r#"BEGIN
  DECLARE custom_err CONDITION FOR SQLSTATE '45000';
  DECLARE EXIT HANDLER FOR custom_err
  BEGIN
    SET result = -1;
  END;
  IF x < 0 THEN
    SIGNAL custom_err SET MESSAGE_TEXT = 'x must be non-negative';
  END IF;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("custom_err"),
        "Should preserve condition name: {}",
        fmt
    );
    assert!(fmt.contains("HANDLER"), "Should preserve HANDLER: {}", fmt);
    assert!(fmt.contains("SIGNAL"), "Should preserve SIGNAL: {}", fmt);
    assert!(
        fmt.contains("x must be non-negative"),
        "Should preserve message: {}",
        fmt
    );
}

#[test]
fn test_resignal_in_handler() {
    // RESIGNAL inside an exception handler
    let sql = r#"BEGIN
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    RESIGNAL SET MESSAGE_TEXT = 'Caught and re-raised';
  END;
  SELECT 1;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("RESIGNAL"),
        "Should preserve RESIGNAL: {}",
        fmt
    );
    assert!(
        fmt.contains("Caught and re-raised"),
        "Should preserve message: {}",
        fmt
    );
}

#[test]
fn test_get_diagnostics_in_handler() {
    // GET DIAGNOSTICS inside a handler
    let sql = r#"BEGIN
  DECLARE v_msg STRING;
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    GET DIAGNOSTICS CONDITION 1 v_msg = MESSAGE_TEXT;
    SET result = v_msg;
  END;
  SELECT 1 / 0;
END;"#;
    let fmt = format_and_verify(sql);
    assert!(fmt.contains("GET"), "Should preserve GET: {}", fmt);
    assert!(
        fmt.contains("DIAGNOSTICS"),
        "Should preserve DIAGNOSTICS: {}",
        fmt
    );
    assert!(fmt.contains("v_msg"), "Should preserve variable: {}", fmt);
}

// =============================================================================
// AST verification tests
// =============================================================================

#[test]
fn test_signal_parses_as_signal_variant() {
    let sql = "BEGIN\n  SIGNAL SQLSTATE '45000';\nEND;";
    let script = parse_sql(sql).expect("should parse");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            assert!(
                b.body.iter().any(|s| matches!(s, AstStmt::Signal { .. })),
                "Block body should contain Signal variant, got: {:?}",
                b.body
                    .iter()
                    .map(std::mem::discriminant)
                    .collect::<Vec<_>>()
            );
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_resignal_parses_as_resignal_variant() {
    let sql = "BEGIN\n  RESIGNAL;\nEND;";
    let script = parse_sql(sql).expect("should parse");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            assert!(
                b.body.iter().any(|s| matches!(s, AstStmt::Resignal { .. })),
                "Block body should contain Resignal variant"
            );
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_get_diagnostics_parses_correctly() {
    let sql = "BEGIN\n  GET DIAGNOSTICS CONDITION 1 v = MESSAGE_TEXT;\nEND;";
    let script = parse_sql(sql).expect("should parse");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            assert!(
                b.body
                    .iter()
                    .any(|s| matches!(s, AstStmt::GetDiagnostics { .. })),
                "Block body should contain GetDiagnostics variant"
            );
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_declare_condition_parses_correctly() {
    let sql = "BEGIN\n  DECLARE my_err CONDITION FOR SQLSTATE '45000';\nEND;";
    let script = parse_sql(sql).expect("should parse");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let has = b
                .body
                .iter()
                .chain(b.decls.iter())
                .any(|s| matches!(s, AstStmt::DeclareCondition { .. }));
            assert!(has, "Should contain DeclareCondition variant");
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_declare_handler_parses_correctly() {
    let sql = "BEGIN\n  DECLARE EXIT HANDLER FOR SQLEXCEPTION\n    SET x = 0;\nEND;";
    let script = parse_sql(sql).expect("should parse");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            let has = b
                .body
                .iter()
                .chain(b.decls.iter())
                .any(|s| matches!(s, AstStmt::DeclareHandler(_)));
            assert!(has, "Should contain DeclareHandler variant");
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_begin_atomic_parses_with_flag() {
    let sql = "BEGIN ATOMIC\n  SET x = 1;\nEND;";
    let script = parse_sql(sql).expect("should parse");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            assert!(
                b.atomic_span.is_some(),
                "Should have atomic_span set for BEGIN ATOMIC"
            );
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

#[test]
fn test_begin_without_atomic() {
    let sql = "BEGIN\n  SET x = 1;\nEND;";
    let script = parse_sql(sql).expect("should parse");
    match &script.stmts[0] {
        AstStmt::Block(b) => {
            assert!(
                b.atomic_span.is_none(),
                "Should NOT have atomic_span for regular BEGIN"
            );
        }
        other => panic!("expected Block, got {:?}", std::mem::discriminant(other)),
    }
}

// =============================================================================
// DECLARE CURSOR — FOR READ ONLY / FOR UPDATE
// =============================================================================

#[test]
fn test_declare_cursor_for_read_only() {
    let sql = "BEGIN\n  DECLARE c CURSOR FOR SELECT id FROM t FOR READ ONLY;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("FOR READ ONLY"),
        "Should preserve FOR READ ONLY: {}",
        fmt
    );
    assert!(fmt.contains("SELECT"), "Should contain SELECT: {}", fmt);
}

#[test]
fn test_declare_cursor_for_update() {
    let sql = "BEGIN\n  DECLARE c CURSOR FOR SELECT id FROM t FOR UPDATE;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("FOR UPDATE"),
        "Should preserve FOR UPDATE: {}",
        fmt
    );
}

#[test]
fn test_declare_cursor_no_trailing_for() {
    let sql = "BEGIN\n  DECLARE c CURSOR FOR SELECT id FROM t;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("CURSOR FOR"),
        "Should contain CURSOR FOR: {}",
        fmt
    );
    assert!(fmt.contains("FROM t"), "Should contain FROM t: {}", fmt);
}

#[test]
fn test_declare_cursor_complex_query() {
    let sql = "BEGIN\n  DECLARE c CURSOR FOR SELECT a, b FROM t WHERE x > 1 ORDER BY a FOR READ ONLY;\nEND;";
    let fmt = format_and_verify(sql);
    assert!(
        fmt.contains("ORDER BY"),
        "Should preserve ORDER BY: {}",
        fmt
    );
    assert!(
        fmt.contains("FOR READ ONLY"),
        "Should preserve FOR READ ONLY: {}",
        fmt
    );
}
