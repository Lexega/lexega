// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP SERVICE` statement family
//! (Snowpark Container Services). Covers the SNW-SERVICE-* rules, the
//! EXTERNAL_ACCESS_INTEGRATIONS egress recognition (shared with STREAMLIT), the
//! ALTER SET/UNSET/RESUME/SUSPEND actions, and byte-exact formatting of the
//! `IN COMPUTE POOL` binding plus every FROM form — including a multi-line
//! inline `$$ … $$` YAML spec body (captured, not analyzed).

use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.signals)
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_create_service_fires_new() {
    let rules =
        analyze_and_get_rules("CREATE SERVICE s IN COMPUTE POOL p FROM SPECIFICATION 'spec';");
    assert!(rules.contains("SNW-SERVICE-NEW"), "got {rules:?}");
}

#[test]
fn test_create_service_without_eai_is_not_external_access() {
    let rules =
        analyze_and_get_rules("CREATE SERVICE s IN COMPUTE POOL p FROM SPECIFICATION 'spec';");
    assert!(rules.contains("SNW-SERVICE-NEW"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-SERVICE-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_create_service_with_eai_fires_external_access() {
    let rules = analyze_and_get_rules(
        "CREATE SERVICE s IN COMPUTE POOL p FROM SPECIFICATION 'spec' EXTERNAL_ACCESS_INTEGRATIONS=(eai1,eai2);",
    );
    assert!(rules.contains("SNW-SERVICE-NEW"), "got {rules:?}");
    assert!(
        rules.contains("SNW-SERVICE-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_alter_service_set_eai_fires_external_access() {
    let rules = analyze_and_get_rules("ALTER SERVICE s SET EXTERNAL_ACCESS_INTEGRATIONS=(eai1);");
    assert!(
        rules.contains("SNW-SERVICE-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
}

#[test]
fn test_alter_service_suspend_resume_are_benign() {
    for sql in [
        "ALTER SERVICE s SUSPEND;",
        "ALTER SERVICE s RESUME;",
        "ALTER SERVICE IF EXISTS s SET MIN_INSTANCES=2;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(
            !rules.iter().any(|r| r.starts_with("SNW-SERVICE")),
            "{sql} -> {rules:?}"
        );
    }
}

#[test]
fn test_drop_service_analyzes() {
    let report = analyze_risk("DROP SERVICE s;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_service_dollar_spec_body_fires_and_formats() {
    // The inline `$$ … $$` YAML spec body is captured for span coverage but not
    // analyzed; the statement still recognizes as a service and round-trips.
    let sql = "CREATE SERVICE s IN COMPUTE POOL p FROM SPECIFICATION $$\nspec:\n  containers:\n  - name: main\n    image: /db/sc/repo/img\n$$ EXTERNAL_ACCESS_INTEGRATIONS=(eai1);";
    let rules = analyze_and_get_rules(sql);
    assert!(rules.contains("SNW-SERVICE-NEW"), "got {rules:?}");
    assert!(
        rules.contains("SNW-SERVICE-EXTERNAL-ACCESS"),
        "got {rules:?}"
    );
    assert_formats_safe(sql);
}

#[test]
fn test_service_forms_format_safe() {
    assert_formats_safe("CREATE SERVICE s IN COMPUTE POOL p FROM SPECIFICATION 'inline';");
    assert_formats_safe(
        "CREATE SERVICE s IN COMPUTE POOL p FROM @stage SPECIFICATION_FILE='svc.yaml';",
    );
    assert_formats_safe(
        "CREATE OR REPLACE SERVICE db.sc.s IN COMPUTE POOL p FROM SPECIFICATION 'x' QUERY_WAREHOUSE=wh MIN_INSTANCES=1;",
    );
    assert_formats_safe("ALTER SERVICE s SUSPEND;");
    assert_formats_safe("ALTER SERVICE IF EXISTS s SET MIN_INSTANCES=2;");
    assert_formats_safe("ALTER SERVICE s UNSET COMMENT;");
    assert_formats_safe("DROP SERVICE s;");
}
