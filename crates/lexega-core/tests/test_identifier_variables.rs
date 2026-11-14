// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `IDENTIFIER($v)` and `IDENTIFIER(:v)` name the object whose name the
//! variable holds, where the script says what it holds. The observable is
//! `DML-WRITE-XSCHEMA`: `INSERT INTO IDENTIFIER($t) … FROM core.s` spans two
//! schemas only where `$t` is read as `sandbox.t`.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const XSCHEMA: &str = "DML-WRITE-XSCHEMA";

fn rule_ids(sql: &str) -> (HashSet<String>, HashSet<String>) {
    let report = analyze_risk(sql).expect("should analyze successfully");
    let ids = |entries: &[RuleMatch]| {
        entries
            .iter()
            .map(|m| match m {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect()
    };
    (ids(&report.findings), ids(&report.context))
}

/// The rule is reported as context.
fn fires(sql: &str) -> bool {
    rule_ids(sql).1.contains(XSCHEMA)
}

/// The rule is in neither the findings nor the context.
fn silent(sql: &str) -> bool {
    let (findings, context) = rule_ids(sql);
    !findings.contains(XSCHEMA) && !context.contains(XSCHEMA)
}

#[test]
fn a_session_variable_set_to_a_literal_names_the_table() {
    assert!(fires(
        "SET t = 'sandbox.t';\nINSERT INTO IDENTIFIER($t) (a) SELECT a FROM core.s;"
    ));
}

#[test]
fn a_session_variable_naming_the_same_schema_stays_silent() {
    assert!(silent(
        "SET t = 'core.t';\nINSERT INTO IDENTIFIER($t) (a) SELECT a FROM core.s;"
    ));
}

#[test]
fn a_read_through_a_variable_is_named_by_its_text() {
    assert!(fires(
        "SET s = 'core.s';\nINSERT INTO sandbox.t (a) SELECT a FROM IDENTIFIER($s);"
    ));
}

#[test]
fn a_variable_no_statement_set_is_not_known() {
    assert!(silent(
        "INSERT INTO IDENTIFIER($t) (a) SELECT a FROM core.s;"
    ));
}

#[test]
fn a_variable_set_to_a_concatenation_is_not_known() {
    assert!(silent(
        "SET t = 'sandbox.' || 't';\nINSERT INTO IDENTIFIER($t) (a) SELECT a FROM core.s;"
    ));
}

#[test]
fn the_last_assignment_before_the_statement_is_read() {
    assert!(silent(
        "SET t = 'sandbox.t';\nSET t = 'core.t';\nINSERT INTO IDENTIFIER($t) (a) SELECT a FROM core.s;"
    ));
    assert!(fires(
        "SET t = 'core.t';\nINSERT INTO IDENTIFIER($t) (a) SELECT a FROM sandbox.s;\nSET t = 'sandbox.t';"
    ));
}

#[test]
fn a_call_leaves_a_session_variable_unknown() {
    assert!(silent(
        "SET t = 'sandbox.t';\nCALL refresh();\nINSERT INTO IDENTIFIER($t) (a) SELECT a FROM core.s;"
    ));
}

#[test]
fn a_scripting_variable_names_the_table_in_its_block() {
    assert!(fires(
        "BEGIN\n  LET t := 'sandbox.t';\n  INSERT INTO IDENTIFIER(:t) (a) SELECT a FROM core.s;\nEND;"
    ));
}

#[test]
fn an_assignment_in_a_branch_leaves_the_variable_unknown() {
    assert!(silent(
        "BEGIN\n  LET t := 'core.t';\n  IF (1 = 1) THEN\n    t := 'sandbox.t';\n  END IF;\n  INSERT INTO IDENTIFIER(:t) (a) SELECT a FROM core.s;\nEND;"
    ));
}

#[test]
fn an_assignment_in_a_loop_leaves_the_variable_unknown_in_the_loop() {
    assert!(silent(
        "BEGIN\n  LET t := 'sandbox.t';\n  FOR i IN 1 TO 2 DO\n    INSERT INTO IDENTIFIER(:t) (a) SELECT a FROM core.s;\n    t := 'core.t';\n  END FOR;\nEND;"
    ));
}

#[test]
fn a_session_variable_set_in_a_procedure_body_is_not_known_after_it() {
    assert!(silent(
        "SET t = 'core.t';\nCREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS\nBEGIN\n  SET t = 'sandbox.t';\n  RETURN 'x';\nEND;\nINSERT INTO IDENTIFIER($t) (a) SELECT a FROM core.s;"
    ));
}
