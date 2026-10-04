// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for BigQuery standalone scripting constructs (IF/WHILE/FOR/LOOP/REPEAT/CASE)
// BigQuery allows scripting constructs at top level without BEGIN..END wrapping.
// These tests verify that the parser dispatches correctly to existing scripting parsers
// and that formatter round-trips preserve semantics.

use lexega_syntax::dialect::bigquery;
use lexega_syntax::{format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig};

fn bq_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = bigquery();
    config
}

fn format_and_verify_bq(sql: &str) -> String {
    let config = bq_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("BigQuery format failed:\n{}\nSQL:\n{}", e, sql));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref()).unwrap_or_else(
        |e| {
            panic!(
                "BigQuery round-trip verification failed:\n{}\nFormatted:\n{}\nSQL:\n{}",
                e, formatted, sql
            )
        },
    );
    formatted
}

// =============================================================================
// Standalone IF / ELSEIF / ELSE / END IF
// =============================================================================

#[test]
fn test_standalone_if_simple() {
    let sql = "IF x > 0 THEN SELECT 'positive'; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("IF x > 0 THEN"), "Should preserve IF: {}", fmt);
    assert!(fmt.contains("END IF"), "Should preserve END IF: {}", fmt);
}

#[test]
fn test_standalone_if_else() {
    let sql = "IF x > 0 THEN SELECT 'positive'; ELSE SELECT 'non-positive'; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("ELSE"), "Should preserve ELSE: {}", fmt);
}

#[test]
fn test_standalone_if_elseif_else() {
    let sql = "IF x > 0 THEN SELECT 'positive'; ELSEIF x = 0 THEN SELECT 'zero'; ELSE SELECT 'negative'; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("ELSEIF"), "Should preserve ELSEIF: {}", fmt);
}

#[test]
fn test_standalone_if_multiple_stmts() {
    let sql = "IF x > 0 THEN SET y = 1; SET z = 2; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("SET y = 1"),
        "Should preserve first SET: {}",
        fmt
    );
    assert!(
        fmt.contains("SET z = 2"),
        "Should preserve second SET: {}",
        fmt
    );
}

#[test]
fn test_standalone_if_with_comparison() {
    let sql = "IF EXISTS(SELECT 1 FROM t WHERE id = 5) THEN SELECT 'found'; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("EXISTS"), "Should preserve EXISTS: {}", fmt);
}

#[test]
fn test_standalone_if_no_parens() {
    // BigQuery doesn't require parentheses around condition
    let sql = "IF TRUE THEN SELECT 1; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IF TRUE THEN"),
        "Should preserve condition without parens: {}",
        fmt
    );
}

// =============================================================================
// Standalone WHILE / DO / END WHILE
// =============================================================================

#[test]
fn test_standalone_while_simple() {
    let sql = "WHILE x < 10 DO SET x = x + 1; END WHILE;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("WHILE"), "Should preserve WHILE: {}", fmt);
    assert!(
        fmt.contains("END WHILE"),
        "Should preserve END WHILE: {}",
        fmt
    );
}

#[test]
fn test_standalone_while_complex_condition() {
    let sql = "WHILE x < 10 AND y > 0 DO SET x = x + 1; SET y = y - 1; END WHILE;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("AND"),
        "Should preserve complex condition: {}",
        fmt
    );
}

// =============================================================================
// Standalone FOR / IN / DO / END FOR
// =============================================================================

#[test]
fn test_standalone_for_select() {
    let sql =
        "FOR record IN (SELECT word FROM dataset.words LIMIT 5) DO SELECT record.word; END FOR;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("FOR record IN"),
        "Should preserve FOR loop: {}",
        fmt
    );
    assert!(fmt.contains("END FOR"), "Should preserve END FOR: {}", fmt);
}

#[test]
fn test_standalone_for_with_insert() {
    let sql = "FOR r IN (SELECT id, name FROM source_table) DO INSERT INTO target_table VALUES (r.id, r.name); END FOR;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("FOR r IN"), "Should preserve FOR: {}", fmt);
}

// =============================================================================
// Standalone LOOP / END LOOP
// =============================================================================

#[test]
fn test_standalone_loop_simple() {
    let sql = "LOOP SET x = x + 1; IF x >= 10 THEN BREAK; END IF; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("LOOP"), "Should preserve LOOP: {}", fmt);
    assert!(
        fmt.contains("END LOOP"),
        "Should preserve END LOOP: {}",
        fmt
    );
}

#[test]
fn test_standalone_loop_with_leave() {
    let sql = "LOOP SET x = x + 1; IF x >= 10 THEN LEAVE; END IF; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("LEAVE"), "Should preserve LEAVE: {}", fmt);
}

#[test]
fn test_standalone_loop_with_iterate() {
    let sql = "LOOP SET x = x + 1; IF x = 5 THEN ITERATE; END IF; IF x >= 10 THEN LEAVE; END IF; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("ITERATE"), "Should preserve ITERATE: {}", fmt);
    assert!(fmt.contains("LEAVE"), "Should preserve LEAVE: {}", fmt);
}

// =============================================================================
// Standalone REPEAT / UNTIL / END REPEAT
// =============================================================================

#[test]
fn test_standalone_repeat_simple() {
    let sql = "REPEAT SET x = x + 1; UNTIL x >= 3 END REPEAT;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("REPEAT"), "Should preserve REPEAT: {}", fmt);
    assert!(fmt.contains("UNTIL"), "Should preserve UNTIL: {}", fmt);
    assert!(
        fmt.contains("END REPEAT"),
        "Should preserve END REPEAT: {}",
        fmt
    );
}

// =============================================================================
// Standalone CASE (statement-level, not expression)
// =============================================================================

#[test]
fn test_standalone_case_searched() {
    let sql = "CASE WHEN x = 1 THEN SELECT 'one'; WHEN x = 2 THEN SELECT 'two'; ELSE SELECT 'other'; END CASE;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("CASE"), "Should preserve CASE: {}", fmt);
    assert!(
        fmt.contains("END CASE"),
        "Should preserve END CASE: {}",
        fmt
    );
}

#[test]
fn test_standalone_case_simple() {
    let sql =
        "CASE x WHEN 1 THEN SELECT 'one'; WHEN 2 THEN SELECT 'two'; ELSE SELECT 'other'; END CASE;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("CASE x"),
        "Should preserve simple CASE: {}",
        fmt
    );
}

// =============================================================================
// BREAK / CONTINUE (Keywords)
// =============================================================================

#[test]
fn test_standalone_break() {
    let sql = "LOOP IF done THEN BREAK; END IF; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("BREAK"), "Should preserve BREAK: {}", fmt);
}

#[test]
fn test_standalone_continue() {
    let sql = "LOOP IF skip THEN CONTINUE; END IF; SET x = x + 1; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("CONTINUE"),
        "Should preserve CONTINUE: {}",
        fmt
    );
}

// =============================================================================
// LEAVE / ITERATE (Identifiers, BigQuery synonyms)
// =============================================================================

#[test]
fn test_standalone_leave() {
    let sql = "LOOP IF done THEN LEAVE; END IF; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("LEAVE"), "Should preserve LEAVE: {}", fmt);
}

#[test]
fn test_standalone_iterate() {
    let sql = "LOOP IF skip THEN ITERATE; END IF; SET x = x + 1; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("ITERATE"), "Should preserve ITERATE: {}", fmt);
}

#[test]
fn test_top_level_leave_standalone() {
    // LEAVE at top level (outside loop) — should still parse as Break
    let sql = "LEAVE;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("LEAVE"),
        "Should preserve standalone LEAVE: {}",
        fmt
    );
}

#[test]
fn test_top_level_iterate_standalone() {
    // ITERATE at top level (outside loop) — should still parse as Continue
    let sql = "ITERATE;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("ITERATE"),
        "Should preserve standalone ITERATE: {}",
        fmt
    );
}

// =============================================================================
// RETURN
// =============================================================================

#[test]
fn test_standalone_return() {
    let sql = "RETURN;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("RETURN"), "Should preserve RETURN: {}", fmt);
}

// =============================================================================
// RAISE
// =============================================================================

#[test]
fn test_standalone_raise_simple() {
    let sql = "RAISE;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("RAISE"), "Should preserve RAISE: {}", fmt);
}

#[test]
fn test_standalone_raise_with_message() {
    let sql = "RAISE USING MESSAGE = 'Something went wrong';";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("RAISE"), "Should preserve RAISE: {}", fmt);
    assert!(fmt.contains("MESSAGE"), "Should preserve MESSAGE: {}", fmt);
}

// =============================================================================
// Nested constructs
// =============================================================================

#[test]
fn test_nested_if_in_while() {
    let sql = "WHILE x < 10 DO IF x = 5 THEN SET x = x + 2; ELSE SET x = x + 1; END IF; END WHILE;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("WHILE"),
        "Should preserve outer WHILE: {}",
        fmt
    );
    assert!(
        fmt.contains("IF x = 5"),
        "Should preserve inner IF: {}",
        fmt
    );
}

#[test]
fn test_nested_loop_in_for() {
    let sql = "FOR r IN (SELECT 1 AS id) DO LOOP SET x = x + 1; IF x > 5 THEN BREAK; END IF; END LOOP; END FOR;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("FOR r IN"),
        "Should preserve outer FOR: {}",
        fmt
    );
    assert!(fmt.contains("LOOP"), "Should preserve inner LOOP: {}", fmt);
}

#[test]
fn test_nested_if_if() {
    let sql = "IF x > 0 THEN IF y > 0 THEN SELECT 'both positive'; END IF; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IF x > 0"),
        "Should preserve outer IF: {}",
        fmt
    );
    assert!(
        fmt.contains("IF y > 0"),
        "Should preserve inner IF: {}",
        fmt
    );
}

// =============================================================================
// Multi-statement scripts mixing DML and scripting
// =============================================================================

#[test]
fn test_mixed_declare_and_if() {
    let sql = "DECLARE x INT64 DEFAULT 0;\nIF x = 0 THEN SELECT 'zero'; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("DECLARE"), "Should preserve DECLARE: {}", fmt);
    assert!(fmt.contains("IF x = 0"), "Should preserve IF: {}", fmt);
}

#[test]
fn test_mixed_dml_and_scripting() {
    let sql = "DECLARE x INT64 DEFAULT 0;\nSET x = 5;\nWHILE x > 0 DO SET x = x - 1; END WHILE;\nSELECT x;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("DECLARE"), "Should preserve DECLARE: {}", fmt);
    assert!(fmt.contains("WHILE"), "Should preserve WHILE: {}", fmt);
    assert!(
        fmt.contains("SELECT x"),
        "Should preserve trailing SELECT: {}",
        fmt
    );
}

#[test]
fn test_realistic_bq_script() {
    let sql = r#"
DECLARE x INT64 DEFAULT 0;
DECLARE y INT64;
SET y = 10;
WHILE x < y DO
  IF x = 5 THEN
    SET x = x + 2;
    ITERATE;
  END IF;
  SET x = x + 1;
END WHILE;
SELECT x;
"#;
    let fmt = format_and_verify_bq(sql.trim());
    assert!(fmt.contains("DECLARE"), "Should preserve DECLARE: {}", fmt);
    assert!(fmt.contains("WHILE"), "Should preserve WHILE: {}", fmt);
    assert!(fmt.contains("ITERATE"), "Should preserve ITERATE: {}", fmt);
    assert!(
        fmt.contains("SELECT x"),
        "Should preserve trailing SELECT: {}",
        fmt
    );
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn test_if_without_else() {
    let sql = "IF TRUE THEN SELECT 1; END IF;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("IF TRUE"),
        "Should parse IF without ELSE: {}",
        fmt
    );
}

#[test]
fn test_while_single_stmt() {
    let sql = "WHILE TRUE DO SELECT 1; END WHILE;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("WHILE TRUE DO"),
        "Should parse simple WHILE: {}",
        fmt
    );
}

#[test]
fn test_case_single_when() {
    let sql = "CASE WHEN TRUE THEN SELECT 1; END CASE;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("CASE"),
        "Should parse single WHEN CASE: {}",
        fmt
    );
}

#[test]
fn test_loop_immediate_leave() {
    let sql = "LOOP LEAVE; END LOOP;";
    let fmt = format_and_verify_bq(sql);
    assert!(fmt.contains("LOOP"), "Should parse LOOP: {}", fmt);
    assert!(fmt.contains("LEAVE"), "Should parse LEAVE: {}", fmt);
}

// =============================================================================
// EXECUTE IMMEDIATE ... USING expr AS alias (named binding)
// =============================================================================

#[test]
fn test_execute_immediate_using_alias() {
    // Regression: the `AS alias` tail used to split off as a phantom statement.
    let sql = "EXECUTE IMMEDIATE 'SELECT @a + @b' USING x AS a, 2 AS b;";

    let dialect = bigquery();
    let script =
        lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("should parse");
    assert_eq!(
        script.stmts.len(),
        1,
        "USING alias must not split the statement"
    );
    match &script.stmts[0] {
        lexega_syntax::ast::AstStmt::ExecuteImmediate { using_args, .. } => {
            assert_eq!(using_args.len(), 2, "both bind args should be captured");
            assert!(
                using_args.iter().all(|a| a.alias.is_some()),
                "each arg should carry its alias"
            );
        }
        _ => panic!("expected ExecuteImmediate"),
    }

    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("USING x AS a, 2 AS b"),
        "aliases should survive formatting: {}",
        fmt
    );
}

#[test]
fn test_execute_immediate_using_mixed_alias() {
    // Bare and aliased args may be mixed in one USING list.
    let sql = "EXECUTE IMMEDIATE 'SELECT ?, @b' USING x, 2 AS b;";
    let fmt = format_and_verify_bq(sql);
    assert!(
        fmt.contains("USING x, 2 AS b"),
        "mixed USING list should survive formatting: {}",
        fmt
    );
}
