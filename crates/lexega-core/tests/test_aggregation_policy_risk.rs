// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;

#[test]
fn test_aggregation_policy_no_constraint_critical() {
    let sql = "CREATE AGGREGATION POLICY test_policy AS () RETURNS AGGREGATION_CONSTRAINT -> NO_AGGREGATION_CONSTRAINT;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should generate signals
    assert!(
        report.summary.total_reported_signals > 0,
        "Should generate signals for NO_AGGREGATION_CONSTRAINT"
    );

    // Should have critical signal for NO_AGGREGATION_CONSTRAINT
    assert!(
        report.summary.critical_count >= 1,
        "Should have at least one critical signal"
    );

    // Should find SNW-AGGPOL-NOCONST violation
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-NOCONST"
        }),
        "Should find SNW-AGGPOL-NOCONST (NO_AGGREGATION_CONSTRAINT violation)"
    );
}

#[test]
fn test_aggregation_policy_low_group_size_critical() {
    let sql = "CREATE AGGREGATION POLICY test_policy AS () RETURNS AGGREGATION_CONSTRAINT -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 2);";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have critical signal for dangerously low MIN_GROUP_SIZE
    assert!(
        report.summary.critical_count >= 1,
        "Should have critical signal for MIN_GROUP_SIZE < 3"
    );

    // Should find SNW-AGGPOL-GRPSZ-CRIT violation
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-GRPSZ-CRIT"
        }),
        "Should find SNW-AGGPOL-GRPSZ-CRIT (dangerously low MIN_GROUP_SIZE)"
    );
}

#[test]
fn test_aggregation_policy_strong_group_size_positive() {
    let sql = "CREATE AGGREGATION POLICY test_policy AS () RETURNS AGGREGATION_CONSTRAINT -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 10);";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have positive signal for strong MIN_GROUP_SIZE
    assert!(
        report.summary.low_count >= 1,
        "Should have low-level signal for strong MIN_GROUP_SIZE"
    );

    // Should find SNW-AGGPOL-GRPSZ-STRONG (positive signal)
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-GRPSZ-STRONG"
        }),
        "Should find SNW-AGGPOL-GRPSZ-STRONG (strong aggregation protection)"
    );
}

#[test]
fn test_alter_aggregation_policy_protection_removed() {
    let sql = "ALTER AGGREGATION POLICY test_policy SET BODY -> NO_AGGREGATION_CONSTRAINT;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have critical signal for protection removal
    assert!(
        report.summary.critical_count >= 1,
        "Should have critical signal for protection removal"
    );

    // Should find SNW-AGGPOL-NOCONST-CHG violation
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-NOCONST-CHG"
        }),
        "Should find SNW-AGGPOL-NOCONST-CHG (protection removed)"
    );
}

#[test]
fn test_drop_aggregation_policy_critical() {
    let sql = "DROP AGGREGATION POLICY test_policy;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have critical signal for dropping policy
    assert!(
        report.summary.critical_count >= 1,
        "Should have critical signal for dropping policy"
    );

    // Should find SNW-AGGPOL-DROP violation
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-DROP"
        }),
        "Should find SNW-AGGPOL-DROP (aggregation policy dropped)"
    );
}

#[test]
fn test_aggregation_policy_conditional_logic() {
    // Simplified: Use the exact same CASE pattern as the working fixture
    let sql = "CREATE AGGREGATION POLICY test_policy AS () RETURNS AGGREGATION_CONSTRAINT ->
  CASE
    WHEN CURRENT_ROLE() IN ('ANALYST', 'DATA_SCIENTIST') THEN AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5)
    ELSE NO_AGGREGATION_CONSTRAINT
  END;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should detect both conditional logic and NO_AGGREGATION_CONSTRAINT
    assert!(
        report.summary.total_reported_signals >= 2,
        "Should detect multiple governance signals"
    );

    // Should find SNW-AGGPOL-COND (conditional policy)
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-COND"
        }),
        "Should find SNW-AGGPOL-COND (conditional aggregation policy)"
    );

    // Should also find SNW-AGGPOL-NOCONST (NO_AGGREGATION_CONSTRAINT in CASE branch)
    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-NOCONST"
        }),
        "Should find SNW-AGGPOL-NOCONST (NO_AGGREGATION_CONSTRAINT in policy body)"
    );
}

#[test]
fn test_table_set_aggregation_policy_fires_attach_rule() {
    // ALTER TABLE … SET AGGREGATION POLICY attaches a privacy policy to the table.
    let sql = "ALTER TABLE t SET AGGREGATION POLICY agg_pol;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "TBL-AGGPOL-SET"
        }),
        "Should find TBL-AGGPOL-SET (aggregation policy attached to table)"
    );
}

#[test]
fn test_table_unset_aggregation_policy_unchanged() {
    // UNSET AGGREGATION POLICY remains covered by TBL-AGGPOL-RMV and must NOT
    // be misclassified as an attach.
    let sql = "ALTER TABLE t UNSET AGGREGATION POLICY;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    assert!(
        report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "TBL-AGGPOL-RMV"
        }),
        "Should find TBL-AGGPOL-RMV (aggregation policy removed)"
    );
    assert!(
        !report.signals.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "TBL-AGGPOL-SET"
        }),
        "UNSET must not fire the attach rule TBL-AGGPOL-SET"
    );
}
