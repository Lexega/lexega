// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for SNW-NETPOL-IPALLOW-ANY — a Snowflake network policy whose
//! ALLOWED_IP_LIST permits all IPv4 addresses (0.0.0.0/0), imposing no
//! source-IP restriction. The IP values are recognized into
//! `policy.variant.allowed_ip_lists` with a pre-computed `is_zero_route`;
//! the danger verdict is the YAML rule.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => report
            .signals
            .iter()
            .filter_map(|f| match f {
                RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
            })
            .collect(),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

#[test]
fn allow_all_ipv4_flags() {
    let rules = analyze_and_get_rules("CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('0.0.0.0/0');");
    assert!(rules.contains("SNW-NETPOL-IPALLOW-ANY"));
}

#[test]
fn allow_all_among_other_ranges_flags() {
    let rules = analyze_and_get_rules(
        "CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('10.0.0.0/8', '0.0.0.0/0');",
    );
    assert!(rules.contains("SNW-NETPOL-IPALLOW-ANY"));
}

#[test]
fn allow_all_via_alter_flags() {
    let rules =
        analyze_and_get_rules("ALTER NETWORK POLICY p SET ALLOWED_IP_LIST = ('0.0.0.0/0');");
    assert!(rules.contains("SNW-NETPOL-IPALLOW-ANY"));
}

#[test]
fn specific_cidr_does_not_flag() {
    let rules =
        analyze_and_get_rules("CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('192.168.1.0/24');");
    assert!(!rules.contains("SNW-NETPOL-IPALLOW-ANY"));
}

#[test]
fn zero_route_in_blocked_list_does_not_flag() {
    // A 0.0.0.0/0 in the BLOCKED list blocks everyone (a lockout, not an
    // exposure); only the ALLOWED list is judged by this rule.
    let rules = analyze_and_get_rules(
        "CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('192.168.1.0/24') \
         BLOCKED_IP_LIST = ('0.0.0.0/0');",
    );
    assert!(!rules.contains("SNW-NETPOL-IPALLOW-ANY"));
}

// ── NETWORK RULE: the same allow-all exposure via VALUE_LIST ─────────

#[test]
fn ingress_network_rule_allow_all_flags() {
    let rules = analyze_and_get_rules(
        "CREATE NETWORK RULE r TYPE = IPV4 MODE = INGRESS VALUE_LIST = ('0.0.0.0/0');",
    );
    assert!(rules.contains("SNW-NETRULE-INGRESS-ANY"));
}

#[test]
fn ingress_network_rule_specific_cidr_does_not_flag() {
    let rules = analyze_and_get_rules(
        "CREATE NETWORK RULE r TYPE = IPV4 MODE = INGRESS VALUE_LIST = ('10.0.0.0/8');",
    );
    assert!(!rules.contains("SNW-NETRULE-INGRESS-ANY"));
}

#[test]
fn egress_network_rule_allow_all_does_not_flag_ingress_rule() {
    // 0.0.0.0/0 on an EGRESS rule is an outbound concern, not the
    // inbound-exposure case this rule targets.
    let rules = analyze_and_get_rules(
        "CREATE NETWORK RULE r TYPE = IPV4 MODE = EGRESS VALUE_LIST = ('0.0.0.0/0');",
    );
    assert!(!rules.contains("SNW-NETRULE-INGRESS-ANY"));
}
