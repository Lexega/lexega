// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;

fn has_finding(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report.entries().any(|s| s.rule_id() == Some(rule_id))
}

fn get_finding_count(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> usize {
    use lexega_core::analyzer::RuleMatch;
    report
        .entries()
        .filter(|s| s.rule_id() == Some(rule_id))
        .map(|s| match s {
            RuleMatch::Analysis(a) => a.evidence_count.unwrap_or(1),
        })
        .sum()
}

#[test]
fn test_function_set_secure_finding() {
    let sql = "ALTER FUNCTION my_func(INT) SET SECURE;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "INFO-UDF-SECURE-ADD"),
        "Should find INFO-UDF-SECURE-ADD (Function Secured) finding"
    );
    assert_eq!(report.summary.info_count, 1, "Should have 1 info finding");
}

#[test]
fn test_function_unset_secure_finding() {
    let sql = "ALTER FUNCTION my_func(INT) UNSET SECURE;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "UDF-SECURE-RMV"),
        "Should find UDF-SECURE-RMV (Function SECURE Removed) finding"
    );
    assert!(
        report.summary.medium_count >= 1,
        "Should have at least 1 medium finding"
    );
}

#[test]
fn test_function_external_access_finding() {
    let sql = r#"ALTER FUNCTION my_func(INT) 
        SET EXTERNAL_ACCESS_INTEGRATIONS = (my_integration);"#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "UDF-EXTACC-CFG"),
        "Should find UDF-EXTACC-CFG (Function External Access Configured) finding"
    );
    assert!(
        report.summary.medium_count >= 1,
        "Should have at least 1 medium finding"
    );
}

#[test]
fn test_function_secrets_finding() {
    let sql = r#"ALTER FUNCTION my_func(INT) 
        SET SECRETS = ('my_secret' = my_secret_obj);"#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "UDF-EXTACC-CFG"),
        "Should find UDF-EXTACC-CFG (Function External Access Configured) finding for secrets"
    );
}

#[test]
fn test_procedure_set_secure_finding() {
    let sql = "ALTER PROCEDURE my_proc(INT) SET SECURE;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "INFO-PROC-SECURE-ADD"),
        "Should find INFO-PROC-SECURE-ADD (Procedure Secured) finding"
    );
    assert_eq!(report.summary.info_count, 1, "Should have 1 info finding");
}

#[test]
fn test_procedure_unset_secure_finding() {
    let sql = "ALTER PROCEDURE my_proc(INT) UNSET SECURE;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "PROC-SECURE-RMV"),
        "Should find PROC-SECURE-RMV (Procedure SECURE Removed) finding"
    );
    assert!(
        report.summary.medium_count >= 1,
        "Should have at least 1 medium finding"
    );
}

#[test]
fn test_procedure_execute_as_owner_finding() {
    let sql = "ALTER PROCEDURE my_proc(INT) EXECUTE AS OWNER;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "PROC-EXECAS-OWNER"),
        "Should find PROC-EXECAS-OWNER (Procedure EXECUTE AS OWNER) finding"
    );
    assert!(
        report.summary.low_count >= 1,
        "Should have at least 1 low finding"
    );
}

#[test]
fn test_procedure_execute_as_caller_finding() {
    let sql = "ALTER PROCEDURE my_proc(INT) EXECUTE AS CALLER;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "PROC-EXECAS-CALLER"),
        "Should find PROC-EXECAS-CALLER (Procedure EXECUTE AS CALLER) finding"
    );
    assert!(
        report.summary.info_count >= 1,
        "Should have at least 1 info finding"
    );
}

#[test]
fn test_procedure_execute_as_restricted_caller_finding() {
    let sql = "ALTER PROCEDURE my_proc(INT) EXECUTE AS RESTRICTED CALLER;";
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "PROC-EXECAS-RESTRICT"),
        "Should find PROC-EXECAS-RESTRICT (Procedure EXECUTE AS RESTRICTED CALLER) finding"
    );
    assert!(
        report.summary.info_count >= 1,
        "Should have at least 1 info finding"
    );
}

#[test]
fn test_procedure_external_access_finding() {
    let sql = r#"ALTER PROCEDURE my_proc(INT) 
        SET EXTERNAL_ACCESS_INTEGRATIONS = (my_integration);"#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "PROC-EXTACC-CFG"),
        "Should find PROC-EXTACC-CFG (Procedure External Access Configured) finding"
    );
    assert!(
        report.summary.medium_count >= 1,
        "Should have at least 1 medium finding"
    );
}

#[test]
fn test_procedure_secrets_finding() {
    let sql = r#"ALTER PROCEDURE my_proc(INT) 
        SET SECRETS = ('my_secret' = my_secret_obj);"#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    assert!(
        has_finding(&report, "PROC-EXTACC-CFG"),
        "Should find PROC-EXTACC-CFG (Procedure External Access Configured) finding for secrets"
    );
}

#[test]
fn test_multi_statement_function_findings() {
    let sql = r#"
        ALTER FUNCTION func1(INT) SET SECURE;
        ALTER FUNCTION func2(VARCHAR) UNSET SECURE;
        ALTER FUNCTION func3(INT) SET EXTERNAL_ACCESS_INTEGRATIONS = (int1);
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Should have one of each finding type
    assert!(
        has_finding(&report, "INFO-UDF-SECURE-ADD"),
        "Should find INFO-UDF-SECURE-ADD"
    );
    assert!(
        has_finding(&report, "UDF-SECURE-RMV"),
        "Should find UDF-SECURE-RMV"
    );
    assert!(
        has_finding(&report, "UDF-EXTACC-CFG"),
        "Should find UDF-EXTACC-CFG"
    );

    // Verify counts
    assert_eq!(
        get_finding_count(&report, "INFO-UDF-SECURE-ADD"),
        1,
        "Should have 1 INFO-UDF-SECURE-ADD"
    );
    assert_eq!(
        get_finding_count(&report, "UDF-SECURE-RMV"),
        1,
        "Should have 1 UDF-SECURE-RMV"
    );
    assert_eq!(
        get_finding_count(&report, "UDF-EXTACC-CFG"),
        1,
        "Should have 1 UDF-EXTACC-CFG"
    );
}

#[test]
fn test_multi_statement_procedure_findings() {
    let sql = r#"
        ALTER PROCEDURE proc1(INT) SET SECURE;
        ALTER PROCEDURE proc2(VARCHAR) UNSET SECURE;
        ALTER PROCEDURE proc3(INT) EXECUTE AS OWNER;
        ALTER PROCEDURE proc4(INT) EXECUTE AS CALLER;
        ALTER PROCEDURE proc5(INT) EXECUTE AS RESTRICTED CALLER;
        ALTER PROCEDURE proc6(INT) SET EXTERNAL_ACCESS_INTEGRATIONS = (int1);
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Should have one of each finding type
    assert!(
        has_finding(&report, "INFO-PROC-SECURE-ADD"),
        "Should find INFO-PROC-SECURE-ADD"
    );
    assert!(
        has_finding(&report, "PROC-SECURE-RMV"),
        "Should find PROC-SECURE-RMV"
    );
    assert!(
        has_finding(&report, "PROC-EXECAS-OWNER"),
        "Should find PROC-EXECAS-OWNER"
    );
    assert!(
        has_finding(&report, "PROC-EXECAS-CALLER"),
        "Should find PROC-EXECAS-CALLER"
    );
    assert!(
        has_finding(&report, "PROC-EXECAS-RESTRICT"),
        "Should find PROC-EXECAS-RESTRICT"
    );
    assert!(
        has_finding(&report, "PROC-EXTACC-CFG"),
        "Should find PROC-EXTACC-CFG"
    );

    // Verify counts
    assert_eq!(
        get_finding_count(&report, "INFO-PROC-SECURE-ADD"),
        1,
        "Should have 1 INFO-PROC-SECURE-ADD"
    );
    assert_eq!(
        get_finding_count(&report, "PROC-SECURE-RMV"),
        1,
        "Should have 1 PROC-SECURE-RMV"
    );
    assert_eq!(
        get_finding_count(&report, "PROC-EXECAS-OWNER"),
        1,
        "Should have 1 PROC-EXECAS-OWNER"
    );
    assert_eq!(
        get_finding_count(&report, "PROC-EXECAS-CALLER"),
        1,
        "Should have 1 PROC-EXECAS-CALLER"
    );
    assert_eq!(
        get_finding_count(&report, "PROC-EXECAS-RESTRICT"),
        1,
        "Should have 1 PROC-EXECAS-RESTRICT"
    );
    assert_eq!(
        get_finding_count(&report, "PROC-EXTACC-CFG"),
        1,
        "Should have 1 PROC-EXTACC-CFG"
    );
}

#[test]
fn test_combined_function_procedure_findings() {
    let sql = r#"
        ALTER FUNCTION my_func(INT) UNSET SECURE;
        ALTER PROCEDURE my_proc(INT) EXECUTE AS RESTRICTED CALLER;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Both findings should be present
    assert!(
        has_finding(&report, "UDF-SECURE-RMV"),
        "Should find UDF-SECURE-RMV (Function SECURE Removed)"
    );
    assert!(
        has_finding(&report, "PROC-EXECAS-RESTRICT"),
        "Should find PROC-EXECAS-RESTRICT (Procedure EXECUTE AS RESTRICTED CALLER)"
    );

    // UDF-SECURE-RMV is medium, PROC-EXECAS-RESTRICT is info
    assert!(
        report.summary.medium_count >= 1,
        "Should have at least 1 medium finding"
    );
    assert!(
        report.summary.info_count >= 1,
        "Should have at least 1 info finding"
    );
}

#[test]
fn test_multiple_secure_changes() {
    let sql = r#"
        ALTER FUNCTION func1(INT) SET SECURE;
        ALTER FUNCTION func2(INT) SET SECURE;
        ALTER FUNCTION func3(INT) UNSET SECURE;
        ALTER FUNCTION func4(INT) UNSET SECURE;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Should deduplicate by rule but track evidence count
    assert_eq!(
        get_finding_count(&report, "INFO-UDF-SECURE-ADD"),
        2,
        "Should have 2 instances of Function Secured"
    );
    assert_eq!(
        get_finding_count(&report, "UDF-SECURE-RMV"),
        2,
        "Should have 2 instances of Function SECURE Removed"
    );
}

#[test]
fn test_risk_summary_counts() {
    let sql = r#"
        ALTER FUNCTION func1(INT) SET SECURE;
        ALTER FUNCTION func2(INT) UNSET SECURE;
        ALTER PROCEDURE proc1(INT) EXECUTE AS OWNER;
        ALTER PROCEDURE proc2(INT) EXECUTE AS RESTRICTED CALLER;
    "#;
    let report = analyze_risk(sql).expect("analysis should succeed");

    // Verify risk level distribution
    assert_eq!(
        report.summary.info_count, 2,
        "Should have 2 info findings (Function Secured + EXECUTE AS RESTRICTED CALLER)"
    );
    assert_eq!(
        report.summary.low_count, 1,
        "Should have 1 low finding (EXECUTE AS OWNER)"
    );
    assert_eq!(
        report.summary.medium_count, 1,
        "Should have 1 medium finding (Function SECURE Removed)"
    );
}

// A Snowflake procedure created without EXECUTE AS runs with its owner's
// rights, as one that writes EXECUTE AS OWNER does.
#[test]
fn a_snowflake_procedure_without_execute_as_runs_as_its_owner() {
    for sql in [
        "CREATE OR REPLACE PROCEDURE p(u STRING) RETURNS STRING LANGUAGE SQL AS $$ BEGIN RETURN 1; END; $$;",
        "CREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE JAVASCRIPT AS $$ return 1; $$;",
    ] {
        let report = analyze_risk(sql).expect("analysis should succeed");
        assert!(has_finding(&report, "PROC-EXECAS-OWNER"), "{sql}");
    }
    let report = analyze_risk(
        "CREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE SQL EXECUTE AS CALLER AS $$ BEGIN RETURN 1; END; $$;",
    )
    .expect("analysis should succeed");
    assert!(!has_finding(&report, "PROC-EXECAS-OWNER"));
}
