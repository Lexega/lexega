// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Cross-dialect tautology detection tests for row access / RLS policies.
//!
//! Covers:
//!   - Snowflake CREATE ROW ACCESS POLICY (body → TRUE)
//!   - BigQuery  CREATE ROW ACCESS POLICY ... FILTER USING (TRUE)
//!   - PostgreSQL CREATE/ALTER POLICY ... USING (TRUE) / WITH CHECK (TRUE)
//!   - CASE expression tautology (all branches TRUE)
//!   - Negative tests: safe policies should NOT fire RAP-ALLOW-ALL/PG-RLS-WEAK-CHECK

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;

// ─── helpers ────────────────────────────────────────────────────────────────

fn has_rule(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.signals.iter().any(|s| match s {
        RuleMatch::Analysis(ref p) => p.matched_rule == rule_id,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// RAP-ALLOW-ALL — Snowflake: body → TRUE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_sf_row_access_policy_true_fires_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p AS (uid INT) RETURNS BOOLEAN -> TRUE;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "TRUE body should trigger RAP-ALLOW-ALL"
    );
    assert!(report.summary.critical_count >= 1);
}

#[test]
fn test_sf_row_access_policy_1eq1_fires_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p AS (uid INT) RETURNS BOOLEAN -> 1 = 1;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "1=1 body should trigger RAP-ALLOW-ALL"
    );
}

#[test]
fn test_sf_row_access_policy_safe_no_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p AS (uid INT) RETURNS BOOLEAN -> uid = CURRENT_USER();";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        !has_rule(&report, "RAP-ALLOW-ALL"),
        "Safe policy should NOT trigger RAP-ALLOW-ALL"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RAP-ALLOW-ALL — BigQuery: FILTER USING (TRUE)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_bq_row_access_policy_true_fires_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p ON t FILTER USING (TRUE);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "FILTER USING (TRUE) should trigger RAP-ALLOW-ALL"
    );
    assert!(report.summary.critical_count >= 1);
}

#[test]
fn test_bq_row_access_policy_1eq1_fires_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p ON t FILTER USING (1 = 1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "FILTER USING (1=1) should trigger RAP-ALLOW-ALL"
    );
}

#[test]
fn test_bq_row_access_policy_safe_no_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p ON t FILTER USING (user_id = SESSION_USER());";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        !has_rule(&report, "RAP-ALLOW-ALL"),
        "Safe BQ policy should NOT trigger RAP-ALLOW-ALL"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// RAP-ALLOW-ALL — PostgreSQL: USING (TRUE)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_pg_create_policy_using_true_fires_rap_allow_all() {
    let sql = "CREATE POLICY p ON t USING (TRUE);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "PG CREATE POLICY USING (TRUE) should trigger RAP-ALLOW-ALL. Signals: {:?}",
        report.signals
    );
    assert!(report.summary.critical_count >= 1);
}

#[test]
fn test_pg_create_policy_using_1eq1_fires_rap_allow_all() {
    let sql = "CREATE POLICY p ON t USING (1 = 1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "PG CREATE POLICY USING (1=1) should trigger RAP-ALLOW-ALL. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_pg_alter_policy_using_true_fires_rap_allow_all() {
    let sql = "ALTER POLICY p ON t USING (TRUE);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "PG ALTER POLICY USING (TRUE) should trigger RAP-ALLOW-ALL. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_pg_create_policy_safe_no_rap_allow_all() {
    let sql = "CREATE POLICY p ON t USING (user_id = current_user);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        !has_rule(&report, "RAP-ALLOW-ALL"),
        "Safe PG USING policy should NOT trigger RAP-ALLOW-ALL"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// PG-RLS-WEAK-CHECK — PostgreSQL: WITH CHECK (TRUE)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_pg_create_policy_with_check_true_fires_pgc008() {
    let sql = "CREATE POLICY p ON t WITH CHECK (TRUE);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "PG-RLS-WEAK-CHECK"),
        "PG WITH CHECK (TRUE) should trigger PG-RLS-WEAK-CHECK. Signals: {:?}",
        report.signals
    );
    assert!(report.summary.critical_count >= 1);
}

#[test]
fn test_pg_create_policy_with_check_1eq1_fires_pgc008() {
    let sql = "CREATE POLICY p ON t WITH CHECK (1 = 1);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "PG-RLS-WEAK-CHECK"),
        "PG WITH CHECK (1=1) should trigger PG-RLS-WEAK-CHECK. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_pg_alter_policy_with_check_true_fires_pgc008() {
    let sql = "ALTER POLICY p ON t WITH CHECK (TRUE);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "PG-RLS-WEAK-CHECK"),
        "PG ALTER POLICY WITH CHECK (TRUE) should trigger PG-RLS-WEAK-CHECK. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_pg_create_policy_safe_with_check_no_pgc008() {
    let sql = "CREATE POLICY p ON t WITH CHECK (user_id = current_user);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        !has_rule(&report, "PG-RLS-WEAK-CHECK"),
        "Safe PG WITH CHECK should NOT trigger PG-RLS-WEAK-CHECK"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Combined USING + WITH CHECK — both fire
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_pg_policy_both_using_and_check_tautology() {
    let sql = "CREATE POLICY p ON t USING (TRUE) WITH CHECK (TRUE);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "USING (TRUE) should fire RAP-ALLOW-ALL. Signals: {:?}",
        report.signals
    );
    assert!(
        has_rule(&report, "PG-RLS-WEAK-CHECK"),
        "WITH CHECK (TRUE) should fire PG-RLS-WEAK-CHECK. Signals: {:?}",
        report.signals
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// CASE expression tautology (all branches TRUE)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_sf_policy_case_all_true_fires_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p AS (uid INT) RETURNS BOOLEAN -> CASE WHEN uid > 0 THEN TRUE ELSE TRUE END;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "CASE with all-TRUE branches should trigger RAP-ALLOW-ALL. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_pg_policy_case_all_true_fires_rap_allow_all() {
    let sql = "CREATE POLICY p ON t USING (CASE WHEN x > 0 THEN TRUE ELSE TRUE END);";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        has_rule(&report, "RAP-ALLOW-ALL"),
        "PG USING CASE all-TRUE should trigger RAP-ALLOW-ALL. Signals: {:?}",
        report.signals
    );
}

#[test]
fn test_sf_policy_case_mixed_no_rap_allow_all() {
    let sql = "CREATE ROW ACCESS POLICY p AS (uid INT) RETURNS BOOLEAN -> CASE WHEN uid = 1 THEN TRUE ELSE FALSE END;";
    let report = analyze_risk(sql).expect("analysis should succeed");
    assert!(
        !has_rule(&report, "RAP-ALLOW-ALL"),
        "CASE with mixed TRUE/FALSE branches should NOT trigger RAP-ALLOW-ALL"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Extended tautology recognition: NOT FALSE, COALESCE(TRUE,…), constant
// comparisons (`1<2`). Folded by the shared `is_always_true` recognizer, so
// they fire across Snowflake row-access and PostgreSQL USING / WITH CHECK.
// ═══════════════════════════════════════════════════════════════════════════

fn fires_rap(sql: &str) -> bool {
    has_rule(
        &analyze_risk(sql).expect("analysis should succeed"),
        "RAP-ALLOW-ALL",
    )
}

#[test]
fn test_extended_tautology_forms_fire_rap_allow_all() {
    let always_true = [
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> NOT FALSE;",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> NOT (1 = 2);",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> COALESCE(TRUE, x > 0);",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 < 2;",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 10 > 2;",
    ];
    for sql in always_true {
        assert!(
            fires_rap(sql),
            "always-true predicate must fire RAP-ALLOW-ALL: {sql}"
        );
    }
}

#[test]
fn test_extended_tautology_negatives_do_not_fire() {
    // Conservative: non-constant predicates, false comparisons, NOT TRUE, and
    // COALESCE whose first arg is not provably true must NOT fire.
    let not_tautologies = [
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> x > 0;",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 > 2;",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 10 < 2;",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> NOT TRUE;",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> COALESCE(x > 0, TRUE);",
    ];
    for sql in not_tautologies {
        assert!(
            !fires_rap(sql),
            "non-tautology must NOT fire RAP-ALLOW-ALL: {sql}"
        );
    }
}

#[test]
fn test_extended_tautology_pg_using_and_check() {
    assert!(
        has_rule(
            &analyze_risk("CREATE POLICY p ON t USING (NOT FALSE);").expect("ok"),
            "RAP-ALLOW-ALL"
        ),
        "PG USING (NOT FALSE) must fire RAP-ALLOW-ALL"
    );
    assert!(
        has_rule(
            &analyze_risk("CREATE POLICY p ON t WITH CHECK (COALESCE(TRUE, a = b));").expect("ok"),
            "PG-RLS-WEAK-CHECK"
        ),
        "PG WITH CHECK (COALESCE(TRUE,…)) must fire PG-RLS-WEAK-CHECK"
    );
}

#[test]
fn test_in_list_constant_tautology_recognition() {
    // `<lit> [NOT] IN (<lit>, …)` folds with SQL three-valued NULL logic.
    let always_true = [
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 IN (1, 2);",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 IN (1, NULL);", // match → TRUE despite NULL
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 5 NOT IN (1, 2);",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 'a' IN ('a', 'b');",
    ];
    for sql in always_true {
        assert!(
            fires_rap(sql),
            "constant IN tautology must fire RAP-ALLOW-ALL: {sql}"
        );
    }
    let not_tautologies = [
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 IN (2, 3);",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> x IN (1, 2);", // column needle
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 IN (2, NULL);", // no match + NULL → unknown
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 NOT IN (1, 2);",
        "CREATE ROW ACCESS POLICY p AS (x INT) RETURNS BOOLEAN -> 1 NOT IN (2, NULL);", // NOT IN with NULL → unknown
    ];
    for sql in not_tautologies {
        assert!(
            !fires_rap(sql),
            "non-tautology IN must NOT fire RAP-ALLOW-ALL: {sql}"
        );
    }
}
