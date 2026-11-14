// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;

#[test]
fn test_aggregation_policy_no_constraint_critical() {
    let sql = "CREATE AGGREGATION POLICY test_policy AS () RETURNS AGGREGATION_CONSTRAINT -> NO_AGGREGATION_CONSTRAINT;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should generate findings
    assert!(
        report.summary.total_reported_findings > 0,
        "Should generate findings for NO_AGGREGATION_CONSTRAINT"
    );

    // Should have critical finding for NO_AGGREGATION_CONSTRAINT
    assert!(
        report.summary.critical_count >= 1,
        "Should have at least one critical finding"
    );

    // Should find SNW-AGGPOL-NOCONST violation
    assert!(
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-NOCONST"
        }),
        "Should find SNW-AGGPOL-NOCONST (NO_AGGREGATION_CONSTRAINT violation)"
    );
}

#[test]
fn test_aggregation_policy_low_group_size_high() {
    let sql = "CREATE AGGREGATION POLICY test_policy AS () RETURNS AGGREGATION_CONSTRAINT -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 2);";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have high finding for dangerously low MIN_GROUP_SIZE
    assert!(
        report.summary.high_count >= 1,
        "Should have critical finding for MIN_GROUP_SIZE < 3"
    );

    // Should find SNW-AGGPOL-GRPSZ-CRIT violation
    assert!(
        report.findings.iter().any(|f| {
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

    // Should have positive context entry for strong MIN_GROUP_SIZE
    assert!(
        report.summary.info_count >= 1,
        "Should have info-level context for strong MIN_GROUP_SIZE"
    );

    // Should find SNW-AGGPOL-GRPSZ-STRONG (positive context entry)
    assert!(
        report.context.iter().any(|f| {
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

    // Should have critical finding for protection removal
    assert!(
        report.summary.critical_count >= 1,
        "Should have critical finding for protection removal"
    );

    // Should find SNW-AGGPOL-NOCONST-CHG violation
    assert!(
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-NOCONST-CHG"
        }),
        "Should find SNW-AGGPOL-NOCONST-CHG (protection removed)"
    );
}

#[test]
fn test_drop_aggregation_policy_medium() {
    let sql = "DROP AGGREGATION POLICY test_policy;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    // Should have medium finding for dropping policy
    assert!(
        report.summary.medium_count >= 1,
        "Should have medium finding for dropping policy"
    );

    // Should find SNW-AGGPOL-DROP violation
    assert!(
        report.findings.iter().any(|f| {
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
        report.entries().count() >= 2,
        "Should detect multiple governance findings"
    );

    // Should find SNW-AGGPOL-COND (conditional policy)
    assert!(
        report.context.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-COND"
        }),
        "Should find SNW-AGGPOL-COND (conditional aggregation policy)"
    );

    // The ELSE is what every other role gets, and it is unconstrained.
    assert!(
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "SNW-AGGPOL-NOCONST"
        }),
        "Should find SNW-AGGPOL-NOCONST (the default path is unconstrained)"
    );
}

fn aggpol_findings(sql: &str) -> Vec<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    report
        .findings
        .iter()
        .map(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule.clone()
        })
        .collect()
}

#[test]
fn test_aggregation_policy_exempted_role_is_not_no_constraint() {
    // The documented pattern: one authorised role is exempt, everyone else is constrained.
    let create = "CREATE AGGREGATION POLICY p AS () RETURNS AGGREGATION_CONSTRAINT ->
  CASE
    WHEN CURRENT_ROLE() = 'ADMIN' THEN NO_AGGREGATION_CONSTRAINT()
    ELSE AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5)
  END;";
    let alter = "ALTER AGGREGATION POLICY p SET BODY ->
  CASE
    WHEN CURRENT_ROLE() = 'ADMIN' THEN NO_AGGREGATION_CONSTRAINT()
    ELSE AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5)
  END;";
    assert!(!aggpol_findings(create).contains(&"SNW-AGGPOL-NOCONST".to_string()));
    assert!(!aggpol_findings(alter).contains(&"SNW-AGGPOL-NOCONST-CHG".to_string()));
}

#[test]
fn test_aggregation_policy_unconstrained_default_is_no_constraint() {
    // A constrained WHEN does not matter: the ELSE is unconstrained, or absent
    // (the default is NULL, undecided).
    for body in [
        "CASE WHEN CURRENT_ROLE() = 'ANALYST' THEN AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5) ELSE NO_AGGREGATION_CONSTRAINT() END",
        "CASE WHEN CURRENT_ROLE() = 'ANALYST' THEN AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5) END",
    ] {
        let create = format!(
            "CREATE AGGREGATION POLICY p AS () RETURNS AGGREGATION_CONSTRAINT -> {body};"
        );
        let alter = format!("ALTER AGGREGATION POLICY p SET BODY -> {body};");
        assert!(aggpol_findings(&create).contains(&"SNW-AGGPOL-NOCONST".to_string()), "{create}");
        assert!(aggpol_findings(&alter).contains(&"SNW-AGGPOL-NOCONST-CHG".to_string()), "{alter}");
    }
}

#[test]
fn test_aggregation_policy_every_branch_unconstrained_is_no_constraint() {
    let create = "CREATE AGGREGATION POLICY p AS () RETURNS AGGREGATION_CONSTRAINT ->
  CASE
    WHEN CURRENT_ROLE() = 'ADMIN' THEN NO_AGGREGATION_CONSTRAINT()
    ELSE NO_AGGREGATION_CONSTRAINT()
  END;";
    let alter = "ALTER AGGREGATION POLICY p SET BODY ->
  CASE
    WHEN CURRENT_ROLE() = 'ADMIN' THEN NO_AGGREGATION_CONSTRAINT()
    ELSE NO_AGGREGATION_CONSTRAINT()
  END;";
    assert!(aggpol_findings(create).contains(&"SNW-AGGPOL-NOCONST".to_string()));
    assert!(aggpol_findings(alter).contains(&"SNW-AGGPOL-NOCONST-CHG".to_string()));
}

#[test]
fn test_table_set_aggregation_policy_fires_attach_rule() {
    // ALTER TABLE … SET AGGREGATION POLICY attaches a privacy policy to the table.
    let sql = "ALTER TABLE t SET AGGREGATION POLICY agg_pol;";

    let report = analyze_risk(sql).expect("should analyze successfully");

    assert!(
        report.context.iter().any(|f| {
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
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "TBL-AGGPOL-RMV"
        }),
        "Should find TBL-AGGPOL-RMV (aggregation policy removed)"
    );
    assert!(
        !report.entries().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == "TBL-AGGPOL-SET"
        }),
        "UNSET must not fire the attach rule TBL-AGGPOL-SET"
    );
}
