// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for unknown syntax governance integration
///
/// Verifies that unknown Snowflake syntax detected by the defensive design pattern
/// is properly surfaced to the governance layer and generates appropriate risk signals.
use lexega_core::analyzer::{AnalysisReport, RiskLevel};
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, FormatterConfig};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Analyze SQL and generate risk report
fn analyze_sql(sql: &str) -> AnalysisReport {
    analyze_risk(sql).expect("Risk analysis should succeed")
}

/// Check if report contains a signal with specific rule code
fn has_signal_with_rule(report: &AnalysisReport, rule_code: &str) -> bool {
    report.signals.iter().any(|f| {
        let lexega_core::analyzer::RuleMatch::Analysis(p) = f;
        p.matched_rule == rule_code
    })
}

/// Get signal by rule code
fn get_signal_by_rule<'a>(
    report: &'a AnalysisReport,
    rule_code: &str,
) -> Option<&'a lexega_core::analyzer::AnalysisSignal> {
    report.signals.iter().find_map(|f| {
        let lexega_core::analyzer::RuleMatch::Analysis(p) = f;
        if p.matched_rule == rule_code {
            Some(p)
        } else {
            None
        }
    })
}

/// Count signals with specific rule code
fn count_signals_with_rule(report: &AnalysisReport, rule_code: &str) -> usize {
    report
        .signals
        .iter()
        .filter(|f| {
            let lexega_core::analyzer::RuleMatch::Analysis(p) = f;
            p.matched_rule == rule_code
        })
        .count()
}

// ============================================================================
// ALTER STAGE UNKNOWN SYNTAX TESTS
// ============================================================================

#[test]
fn test_alter_stage_unknown_property_generates_snw_unknown() {
    let sql = "ALTER STAGE my_stage SET UNKNOWN_PROPERTY = 'value';";

    let report = analyze_sql(sql);

    // Should have SNW-UNKNOWN signal for unknown syntax
    assert!(
        has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should generate SNW-UNKNOWN signal for unknown ALTER STAGE property"
    );

    // Verify signal details
    let signal = get_signal_by_rule(&report, "SNW-UNKNOWN").unwrap();
    assert_eq!(signal.risk_level, RiskLevel::High);
    assert!(
        signal
            .message
            .to_lowercase()
            .contains("cannot verify compliance")
            || signal
                .message
                .to_lowercase()
                .contains("cannot verify compliance"),
        "Message should explain compliance gap. Got: {}",
        signal.message
    );
    assert!(
        signal.message.to_lowercase().contains("unknown"),
        "Message should mention unknown syntax. Got: {}",
        signal.message
    );
}

#[test]
fn test_alter_stage_multiple_unknowns_single_signal() {
    let sql = "
        ALTER STAGE my_stage 
        SET UNKNOWN_PROP1 = 'val1' 
            UNKNOWN_PROP2 = 'val2';
    ";

    let report = analyze_sql(sql);

    // Should have exactly one SNW-UNKNOWN signal (count embedded in message)
    assert_eq!(
        count_signals_with_rule(&report, "SNW-UNKNOWN"),
        1,
        "Should generate single signal with count for multiple unknowns in same statement"
    );

    let signal = get_signal_by_rule(&report, "SNW-UNKNOWN").unwrap();
    assert!(
        signal.message.to_lowercase().contains("unknown")
            || signal.message.to_lowercase().contains("unrecognized"),
        "Message should indicate multiple unknowns. Got: {}",
        signal.message
    );
}

#[test]
fn test_alter_stage_known_properties_no_snw_unknown() {
    let sql = "
        ALTER STAGE my_stage 
        SET ENCRYPTION = (TYPE = 'AWS_SSE_KMS')
            TAG owner = 'data_team';
    ";

    let report = analyze_sql(sql);

    // Should NOT have SNW-UNKNOWN signal (all properties known)
    assert!(
        !has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should not generate SNW-UNKNOWN for known properties"
    );
}

#[test]
fn test_alter_stage_mixed_known_unknown() {
    // Use two separate statements - one with known property, one with unknown
    let sql = "
        ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'AWS_SSE_KMS');
        ALTER STAGE my_stage SET UNKNOWN_NEW_PARAM = 'value';
    ";

    let report = analyze_sql(sql);

    // Should have SNW-UNKNOWN for unknown property
    assert!(
        has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should generate SNW-UNKNOWN for unknown property"
    );

    // Should also have encryption signal (known property analysis still works)
    assert!(
        report.signals.iter().any(|f| {
            let lexega_core::analyzer::RuleMatch::Analysis(p) = f;
            p.message.to_lowercase().contains("encryption")
        }),
        "Should still analyze known properties (encryption)"
    );
}

#[test]
fn test_alter_stage_multi_property_known_analyzes_non_primary_property() {
    let sql = "
        ALTER STAGE my_stage
        SET URL = 's3://bucket/path'
            ENCRYPTION = (TYPE = 'NONE');
    ";

    let report = analyze_sql(sql);

    assert!(
        !has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should not generate SNW-UNKNOWN for known multi-property ALTER STAGE SET"
    );

    assert!(
        report.signals.iter().any(|f| {
            let lexega_core::analyzer::RuleMatch::Analysis(p) = f;
            p.message.to_lowercase().contains("encryption")
                && p.message.to_lowercase().contains("disabled")
        }),
        "Should detect encryption disabled even when ENCRYPTION is not the first SET property"
    );
}

// ============================================================================
// CREATE STAGE UNKNOWN SYNTAX TESTS
// ============================================================================

#[test]
fn test_create_stage_unknown_clause_generates_snw_unknown() {
    let sql = "
        CREATE STAGE my_stage
        URL = 's3://bucket/path'
        UNKNOWN_CLAUSE = 'value';
    ";

    let report = analyze_sql(sql);

    // Should have SNW-UNKNOWN signal
    assert!(
        has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should generate SNW-UNKNOWN signal for unknown CREATE STAGE clause"
    );

    let signal = get_signal_by_rule(&report, "SNW-UNKNOWN").unwrap();
    assert_eq!(signal.risk_level, RiskLevel::High);
    assert!(
        signal
            .message
            .to_lowercase()
            .contains("cannot verify compliance")
            || signal.message.to_lowercase().contains("unknown"),
        "Message should explain compliance gap. Got: {}",
        signal.message
    );
}

#[test]
fn test_create_stage_multiple_unknowns() {
    let sql = "
        CREATE STAGE my_stage
        URL = 's3://bucket/path'
        UNKNOWN_CLAUSE1 = 'value1'
        UNKNOWN_CLAUSE2 = 'value2';
    ";

    let report = analyze_sql(sql);

    // Should have one SNW-UNKNOWN signal with count
    let count = count_signals_with_rule(&report, "SNW-UNKNOWN");
    assert_eq!(count, 1, "Should have single SNW-UNKNOWN signal with count");

    let signal = get_signal_by_rule(&report, "SNW-UNKNOWN").unwrap();
    assert!(
        signal.message.to_lowercase().contains("unknown")
            || signal.message.to_lowercase().contains("unrecognized"),
        "Message should indicate multiple unknowns. Got: {}",
        signal.message
    );
}

#[test]
fn test_create_stage_known_clauses_no_snw_unknown() {
    let sql = "
        CREATE STAGE my_stage
        URL = 's3://bucket/path'
        CREDENTIALS = (AWS_KEY_ID = 'key')
        ENCRYPTION = (TYPE = 'AWS_SSE_S3');
    ";

    let report = analyze_sql(sql);

    // Should NOT have SNW-UNKNOWN (all clauses known)
    assert!(
        !has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should not generate SNW-UNKNOWN for known clauses"
    );
}

// ============================================================================
// MULTI-STATEMENT TESTS (Critical for NodeId collision bugs)
// ============================================================================

#[test]
fn test_multi_statement_each_unknown_detected() {
    let sql = "
        ALTER STAGE stage1 SET UNKNOWN_PROP1 = 'val1';
        ALTER STAGE stage2 SET UNKNOWN_PROP2 = 'val2';
        CREATE STAGE stage3 URL = 's3://bucket' UNKNOWN_CLAUSE = 'val3';
    ";

    let report = analyze_sql(sql);

    // Should have 3 SNW-UNKNOWN signals (one per statement)
    let count = count_signals_with_rule(&report, "SNW-UNKNOWN");
    assert_eq!(
        count, 3,
        "Should detect unknown syntax in all 3 statements (not just last one - verify get_stmt_node_id updated)"
    );
}

#[test]
fn test_multi_statement_mixed_known_unknown() {
    let sql = "
        ALTER STAGE stage1 SET ENCRYPTION = (TYPE = 'NONE');  -- Known (should trigger C050)
        ALTER STAGE stage2 SET UNKNOWN_PROP = 'value';        -- Unknown (should trigger SNW-UNKNOWN)
        ALTER STAGE stage3 SET TAG owner = 'team';            -- Known (no critical signal)
    ";

    let report = analyze_sql(sql);

    // Should have both SNW-UNKNOWN (unknown) and known-property signals
    assert!(
        has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should detect unknown property in statement 2"
    );

    // Should also have signals from known properties (encryption disabled)
    assert!(
        report.signals.iter().any(|f| {
            let lexega_core::analyzer::RuleMatch::Analysis(p) = f;
            p.message.to_lowercase().contains("encryption")
        }),
        "Should still detect known property issues (encryption disabled)"
    );

    // Verify all statements were analyzed (not just last)
    assert!(
        report.signals.len() >= 2,
        "Should have signals from multiple statements"
    );
}

// ============================================================================
// FORMATTING PRESERVATION TESTS
// ============================================================================

#[test]
fn test_format_preserves_unknown_syntax() {
    let sql = "ALTER STAGE my_stage SET UNKNOWN_PROPERTY = 'value';";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Should format even with unknown syntax");

    // Unknown syntax should be preserved exactly
    assert!(
        formatted.contains("UNKNOWN_PROPERTY"),
        "Formatted output should preserve unknown property name"
    );

    // Should still parse and analyze after formatting
    let report = analyze_sql(&formatted);
    assert!(
        has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "SNW-UNKNOWN signal should persist after formatting"
    );
}

#[test]
fn test_format_round_trip_with_unknowns() {
    // Simple unknown property test
    let sql = "ALTER STAGE my_stage SET UNKNOWN_PARAM = 'value';";

    // Format once
    let formatted1 =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("Should format");

    // Format again (round-trip)
    let formatted2 = format_sql_with_config(&formatted1, &FormatterConfig::default())
        .expect("Should format again");

    // Both should generate same SNW-UNKNOWN signal
    let report1 = analyze_sql(&formatted1);
    let report2 = analyze_sql(&formatted2);

    assert!(
        has_signal_with_rule(&report1, "SNW-UNKNOWN"),
        "First formatting should detect unknown syntax"
    );
    assert!(
        has_signal_with_rule(&report2, "SNW-UNKNOWN"),
        "Round-trip formatting should preserve unknown syntax detection"
    );

    // Signal details should be consistent
    let f1 = get_signal_by_rule(&report1, "SNW-UNKNOWN").unwrap();
    let f2 = get_signal_by_rule(&report2, "SNW-UNKNOWN").unwrap();
    assert_eq!(
        f1.risk_level, f2.risk_level,
        "Risk level should be consistent across round-trip"
    );
}

// ============================================================================
// RISK LEVEL TESTS
// ============================================================================

#[test]
fn test_unknown_syntax_risk_level_is_high() {
    let sql = "ALTER STAGE my_stage SET UNKNOWN_PROP = 'value';";

    let report = analyze_sql(sql);

    let signal = get_signal_by_rule(&report, "SNW-UNKNOWN").unwrap();

    // Risk level should be HIGH (not CRITICAL)
    // Rationale: Cannot verify compliance, but might be legitimate new feature
    assert_eq!(
        signal.risk_level,
        RiskLevel::High,
        "Unknown syntax should be HIGH risk (might be legitimate new feature)"
    );
}

#[test]
fn test_unknown_syntax_appears_in_summary() {
    let sql = "ALTER STAGE my_stage SET UNKNOWN_PROP = 'value';";

    let report = analyze_sql(sql);

    // Should appear in summary counts
    assert!(
        report.summary.high_count >= 1,
        "Should increment high-risk count"
    );

    assert!(
        report.summary.total_reported_signals >= 1,
        "Should increment total signal count"
    );
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_empty_script_no_snw_unknown() {
    let sql = "";

    match analyze_risk(sql) {
        Ok(report) => {
            assert!(!has_signal_with_rule(&report, "SNW-UNKNOWN"));
        }
        Err(_) => {
            // Empty script might not parse, that's okay
        }
    }
}

#[test]
fn test_comment_only_no_snw_unknown() {
    let sql = "-- Just a comment";

    match analyze_risk(sql) {
        Ok(report) => {
            assert!(!has_signal_with_rule(&report, "SNW-UNKNOWN"));
        }
        Err(_) => {
            // Comment-only might not parse as statement, that's okay
        }
    }
}

#[test]
fn test_only_select_no_snw_unknown() {
    let sql = "SELECT * FROM table;";

    let report = analyze_sql(sql);

    // SELECT statements don't have extras field, should not generate SNW-UNKNOWN
    assert!(
        !has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Non-STAGE statements should not generate SNW-UNKNOWN"
    );
}

// ============================================================================
// INTEGRATION WITH OTHER signals
// ============================================================================

#[test]
fn test_unknown_syntax_does_not_suppress_other_signals() {
    let sql = "
        ALTER STAGE stage1 SET ENCRYPTION = (TYPE = 'NONE');
        ALTER STAGE stage2 SET UNKNOWN_PROP = 'value';
    ";

    let report = analyze_sql(sql);

    // Should have both SNW-UNKNOWN and encryption signals
    assert!(
        has_signal_with_rule(&report, "SNW-UNKNOWN"),
        "Should have SNW-UNKNOWN"
    );

    // Should also have encryption disabled signal (if that rule is active)
    // This verifies unknown syntax doesn't break normal analysis
    assert!(
        report.signals.len() >= 2,
        "Should have signals from both statements"
    );
}

#[test]
fn test_high_risk_summary_includes_unknown() {
    let sql = "ALTER STAGE my_stage SET UNKNOWN_PROP = 'value';";

    let report = analyze_sql(sql);

    // Summary should reflect HIGH risk signal
    assert!(
        report.summary.high_count >= 1,
        "Summary high_count should include unknown syntax signals"
    );
}

// ============================================================================
// KNOWN PARSER GAPS
//
// Statements the parser does not yet support degrade gracefully to an opaque
// (skipped) statement rather than crashing or silently vanishing. These tests
// pin the current behavior and act as tripwires: when support is implemented,
// they fail, prompting an update to assert correct parsing + governance.
// ============================================================================

/// `ALTER RESOURCE MONITOR ... SET ...` is now parsed and analyzed (gap
/// closed). It is a typed statement that fires the resource-monitor
/// credit-quota governance signal rather than degrading to a skipped
/// opaque statement.
#[test]
fn test_alter_resource_monitor_analyzed() {
    let sql = "ALTER RESOURCE MONITOR prod_spend_limit SET CREDIT_QUOTA = 999999;";

    let report = analyze_sql(sql);

    // Now counted as analyzed, not skipped.
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "ALTER RESOURCE MONITOR should be analyzed"
    );
    assert_eq!(
        report.summary.statements_skipped, 0,
        "ALTER RESOURCE MONITOR should no longer be skipped"
    );
    // Raising the spend cap surfaces the credit-quota change signal.
    assert!(
        has_signal_with_rule(&report, "SNW-RESMON-QUOTA-CHG"),
        "ALTER RESOURCE MONITOR SET CREDIT_QUOTA should fire SNW-RESMON-QUOTA-CHG"
    );
}

// ============================================================================
// Partial recognition: kind known, payload degraded
// ============================================================================
//
// A statement whose VERB is recognized (so it lowers to a known StatementKind,
// not Opaque) but whose PAYLOAD fell through to a recognition sink — an ALTER
// TABLE with a swallowed/Unknown/GovernanceSpan action, or a GRANT/REVOKE that
// degraded to an Unparsed shape — must surface as `statements_partial` and
// lower confidence, instead of riding through as fully analyzed / HIGH.

use lexega_core::analyzer::ConfidenceLevel;

#[test]
fn test_alter_table_swallowed_action_is_partial() {
    // The action clause is unrecognized; parse_table_name swallows it, leaving
    // zero actions. The statement is still an ALTER TABLE (analyzed), but the
    // dropped action must be visible as partial + degraded confidence.
    let report = analyze_sql("ALTER TABLE t FROBNICATE WIDGETS;");
    assert_eq!(report.summary.statements_partial, 1, "should be partial");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "verb recognized — not skipped"
    );
    // Partial is a subset of analyzed (the verb + target are known).
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.analysis_confidence,
        ConfidenceLevel::Medium,
        "partial payload must drop confidence below High"
    );
}

#[test]
fn test_clean_alter_table_is_not_partial() {
    let report = analyze_sql("ALTER TABLE t ADD COLUMN c INT;");
    assert_eq!(
        report.summary.statements_partial, 0,
        "fully-recognized ALTER must not be partial"
    );
    assert_eq!(report.summary.analysis_confidence, ConfidenceLevel::High);
}

#[test]
fn test_recognized_rls_toggle_is_not_partial() {
    // Regression guard: the ROW LEVEL SECURITY recognition work means this is a
    // typed action, not a sink — it must stay fully analyzed.
    let report = lexega_core::api::analyze_risk_with_policy_config(
        "ALTER TABLE t DISABLE ROW LEVEL SECURITY;",
        &{
            let mut c = lexega_core::analyzer::AnalysisConfig::default();
            c.dialect = Some(std::sync::Arc::new(lexega_core::PostgresDialect));
            c
        },
    )
    .expect("analysis ok");
    assert_eq!(
        report.summary.statements_partial, 0,
        "recognized RLS toggle must not be partial"
    );
}
