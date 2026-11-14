// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake NETWORK RULE lifecycle statements.
//!
//! Covers parsing/formatting round-trips for CREATE / ALTER / DROP
//! NETWORK RULE, the SNW-NETRULE-* governance rules, and routing
//! disambiguation against NETWORK POLICY.

use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn extract_rule_ids(findings: &[RuleMatch]) -> HashSet<String> {
    findings
        .iter()
        .map(|f| match f {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.findings)
}

fn analyze_and_get_context(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.context)
}

/// Rule ids across findings and context.
fn analyze_and_get_entries(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    let mut ids = extract_rule_ids(&report.findings);
    ids.extend(extract_rule_ids(&report.context));
    ids
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ───────────────────────── formatting ─────────────────────────

#[test]
fn test_network_rule_formatting_variants() {
    assert_formats_safe(
        "CREATE NETWORK RULE allow_api TYPE = HOST_PORT VALUE_LIST = ('api.example.com:443') MODE = EGRESS;\n\
         CREATE OR REPLACE NETWORK RULE IF NOT EXISTS db1.sch1.office_ips TYPE = IPV4 VALUE_LIST = ('10.0.0.0/24', '192.168.1.1') MODE = INGRESS COMMENT = 'office';\n\
         CREATE NETWORK RULE vpce TYPE = AWSVPCEID VALUE_LIST = ('vpce-123') MODE = INTERNAL_STAGE;\n\
         ALTER NETWORK RULE IF EXISTS allow_api SET VALUE_LIST = ('api2.example.com:443');\n\
         ALTER NETWORK RULE allow_api SET COMMENT = 'updated';\n\
         ALTER NETWORK RULE allow_api UNSET COMMENT;\n\
         DROP NETWORK RULE allow_api;\n\
         DROP NETWORK RULE IF EXISTS db1.sch1.office_ips;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_network_rule_create() {
    let sql = "CREATE NETWORK RULE r1 TYPE = IPV4 VALUE_LIST = ('10.0.0.1') MODE = INGRESS;";
    let context = analyze_and_get_context(sql);
    assert!(context.contains("SNW-NETRULE-NEW"), "got {context:?}");
    let rules = analyze_and_get_entries(sql);
    assert!(
        !rules.contains("SNW-NETRULE-EGRESS-NEW"),
        "INGRESS must not fire the egress rule, got {rules:?}"
    );

    let rules = analyze_and_get_rules(
        "CREATE NETWORK RULE r2 TYPE = HOST_PORT VALUE_LIST = ('x.io:443') MODE = EGRESS;",
    );
    assert!(rules.contains("SNW-NETRULE-EGRESS-NEW"), "got {rules:?}");
}

#[test]
fn test_network_rule_values_changed_medium() {
    let report = analyze_risk("ALTER NETWORK RULE r1 SET VALUE_LIST = ('evil.example.com:443');")
        .expect("should analyze");
    let rules = extract_rule_ids(&report.findings);
    assert!(rules.contains("SNW-NETRULE-VALUES-CHG"), "got {rules:?}");
    assert!(
        report.summary.medium_count >= 1,
        "destination replacement is medium severity"
    );
}

#[test]
fn test_network_rule_drop() {
    let rules = analyze_and_get_rules("DROP NETWORK RULE IF EXISTS r1;");
    assert!(rules.contains("SNW-NETRULE-DROP"), "got {rules:?}");
}

// ───────────────────────── negative / routing cases ─────────────────────────

#[test]
fn test_network_policy_does_not_fire_netrule_rules() {
    let rules = analyze_and_get_entries(
        "CREATE NETWORK POLICY np1 ALLOWED_IP_LIST = ('1.2.3.4');\n\
         ALTER NETWORK POLICY np1 SET ALLOWED_IP_LIST = ('5.6.7.8');\n\
         DROP NETWORK POLICY np1;",
    );
    assert!(
        !rules.iter().any(|r| r.contains("NETRULE")),
        "network POLICY statements must not fire SNW-NETRULE-*, got {rules:?}"
    );
}

#[test]
fn test_comment_property_not_swallowed_by_mode_value() {
    // Regression: a Keyword property name (COMMENT) directly after
    // another property's value must start a new property, not extend
    // the previous value (is_likely_property_name keyword fix).
    let rules = analyze_and_get_rules(
        "CREATE NETWORK RULE r TYPE = HOST_PORT VALUE_LIST = ('a.io:1') MODE = EGRESS COMMENT = 'x';",
    );
    assert!(
        rules.contains("SNW-NETRULE-EGRESS-NEW"),
        "MODE value must be EGRESS exactly, got {rules:?}"
    );
}

// ───────────────────────── target names ─────────────────────────

/// The DDL target each statement's facts name, as `database|schema|name`,
/// each part normalized.
fn target_parts(sql: &str) -> Vec<String> {
    let config = lexega_core::analyzer::AnalysisConfig {
        trace_mode: true,
        ..Default::default()
    };
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &config)
        .expect("should analyze successfully");
    report
        .statement_traces
        .iter()
        .filter_map(|s| s.facts.as_ref()?.ddl.as_ref()?.target.as_ref())
        .map(|t| {
            let part = |p: Option<&lexega_core::facts::IdentName>| {
                p.map_or(String::new(), |p| p.normalized.clone())
            };
            format!(
                "{}|{}|{}",
                part(t.name.database.as_ref()),
                part(t.name.schema.as_ref()),
                t.name.name.normalized
            )
        })
        .collect()
}

#[test]
fn a_network_rule_or_secret_is_named_by_each_part_of_its_name() {
    for (sql, parts) in [
        (
            "ALTER NETWORK RULE \"D1\".\"S 1\".\"rule_api x\" SET VALUE_LIST = ('api.example.com');",
            "D1|S 1|rule_api x",
        ),
        (
            "CREATE NETWORK RULE d1.s1.rule_api TYPE = HOST_PORT MODE = EGRESS VALUE_LIST = ('api.example.com');",
            "D1|S1|RULE_API",
        ),
        ("DROP NETWORK RULE s1.rule_api;", "|S1|RULE_API"),
        (
            "ALTER SECRET \"D1\".\"S 1\".\"sec_api x\" SET COMMENT = 'x';",
            "D1|S 1|sec_api x",
        ),
        (
            "CREATE SECRET d1.s1.sec_api TYPE = GENERIC_STRING SECRET_STRING = 'x';",
            "D1|S1|SEC_API",
        ),
    ] {
        assert_eq!(target_parts(sql), [parts], "{sql}");
    }
}

#[test]
fn an_account_or_schema_object_is_named_by_each_part_of_its_name() {
    for (sql, parts) in [
        (
            "CREATE GIT REPOSITORY \"D1\".\"S 1\".\"Repo X\" API_INTEGRATION = gi \
             ORIGIN = 'https://github.com/x/y.git';",
            "D1|S 1|Repo X",
        ),
        ("DROP STREAMLIT d1.s1.app;", "D1|S1|APP"),
        ("DROP SEMANTIC VIEW s1.sv;", "|S1|SV"),
        (
            "CREATE EXTERNAL FUNCTION d1.s1.f_ext(x STRING) RETURNS VARIANT \
             API_INTEGRATION = api_int AS 'https://x.example.com/f';",
            "D1|S1|F_EXT",
        ),
        (
            "CREATE DATA METRIC FUNCTION \"D1\".\"S 1\".\"Dmf X\"(arg_t TABLE(c INT)) \
             RETURNS NUMBER AS 'SELECT COUNT(*) FROM arg_t';",
            "D1|S 1|Dmf X",
        ),
        (
            "CREATE RESOURCE MONITOR IDENTIFIER('rm_month') WITH CREDIT_QUOTA = 100;",
            "||RM_MONTH",
        ),
        ("CREATE SHARE \"Sh Partner\";", "||Sh Partner"),
    ] {
        assert_eq!(target_parts(sql), [parts], "{sql}");
    }
}

#[test]
fn a_dropped_routine_is_named_without_its_argument_list() {
    for (sql, parts) in [
        ("DROP FUNCTION s1.\"MyFn\"(INT);", "|S1|MyFn"),
        ("DROP FUNCTION d1.s1.my_fn(INT, VARCHAR);", "D1|S1|MY_FN"),
        ("DROP PROCEDURE d1.s1.p_load();", "D1|S1|P_LOAD"),
        (
            "DROP FUNCTION IDENTIFIER('d1.s1.f_hash')(STRING);",
            "D1|S1|F_HASH",
        ),
        ("DROP FUNCTION s1.my_fn;", "|S1|MY_FN"),
    ] {
        assert_eq!(target_parts(sql), [parts], "{sql}");
    }
}
