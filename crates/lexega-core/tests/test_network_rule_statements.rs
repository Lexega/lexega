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
    let rules = analyze_and_get_rules(
        "CREATE NETWORK RULE r1 TYPE = IPV4 VALUE_LIST = ('10.0.0.1') MODE = INGRESS;",
    );
    assert!(rules.contains("SNW-NETRULE-NEW"), "got {rules:?}");
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
fn test_network_rule_values_changed_high() {
    let report = analyze_risk("ALTER NETWORK RULE r1 SET VALUE_LIST = ('evil.example.com:443');")
        .expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("SNW-NETRULE-VALUES-CHG"), "got {rules:?}");
    assert!(
        report.summary.high_count >= 1,
        "destination replacement is high severity"
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
    let rules = analyze_and_get_rules(
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
