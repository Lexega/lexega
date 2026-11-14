// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::{analyze_risk, analyze_risk_with_policy_config};
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules, LoadError};

/// Whether a custom rule that holds where `trigger` holds of a `CREATE
/// NETWORK POLICY` fires on `sql`.
fn custom_rule_fires(sql: &str, trigger: &str) -> bool {
    let trigger = trigger.replace('\n', "\n          ");
    let yaml = format!(
        "rules:\n  - id: TEST-FIELDS\n    risk_level: info\n    message: compared\n    \
         triggers:\n      all_of:\n        - kind: create_network_policy\n        - {trigger}\n"
    );
    let loaded = load_v1_rules(&yaml).expect("rule loads");
    let config = AnalysisConfig {
        custom_rules: Some(
            build_v1_rule_corpus(loaded, false)
                .expect("corpus builds")
                .into(),
        ),
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config)
        .expect("analyzes")
        .entries()
        .any(|finding| {
            let RuleMatch::Analysis(analysis) = finding;
            analysis.matched_rule == "TEST-FIELDS"
        })
}

#[test]
fn a_list_is_compared_with_a_sibling_list() {
    // Every blocked address is also an allowed one.
    let blocked_allowed =
        "policy.variant.blocked_ip_lists:\n  all_in_field: policy.variant.allowed_ip_lists";
    let also_allowed = "CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('10.0.0.1', '10.0.0.2') \
                        BLOCKED_IP_LIST = ('10.0.0.2');";
    let not_allowed = "CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('10.0.0.1') \
                       BLOCKED_IP_LIST = ('10.0.0.2');";
    let none_blocked = "CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('10.0.0.1');";
    let none_allowed = "CREATE NETWORK POLICY p BLOCKED_IP_LIST = ('10.0.0.2');";
    assert!(custom_rule_fires(also_allowed, blocked_allowed));
    assert!(!custom_rule_fires(not_allowed, blocked_allowed));
    // An absent list is the empty one: no blocked address is in any list,
    // and a blocked address is in no absent one.
    assert!(custom_rule_fires(none_blocked, blocked_allowed));
    assert!(!custom_rule_fires(none_allowed, blocked_allowed));
    // Negated: a blocked address that is not allowed.
    let negated = format!("not:\n  {}", blocked_allowed.replace('\n', "\n  "));
    assert!(!custom_rule_fires(also_allowed, &negated));
    assert!(custom_rule_fires(not_allowed, &negated));
}

#[test]
fn a_field_compared_that_is_null_or_not_a_list() {
    let sql = "CREATE NETWORK POLICY p ALLOWED_IP_LIST = ('10.0.0.1') \
               BLOCKED_IP_LIST = ('10.0.0.1');";
    // `null` is the empty list on either side.
    assert!(custom_rule_fires(
        sql,
        "policy.target.name.schema:\n  all_in_field: policy.variant.allowed_ip_lists"
    ));
    assert!(!custom_rule_fires(
        sql,
        "policy.variant.blocked_ip_lists:\n  all_in_field: policy.target.name.schema"
    ));
    // A field that is not a list holds no item.
    assert!(!custom_rule_fires(
        sql,
        "policy.variant.blocked_ip_lists:\n  all_in_field: policy.variant.kind"
    ));
    assert!(!custom_rule_fires(
        sql,
        "policy.variant.kind:\n  all_in_field: policy.variant.allowed_ip_lists"
    ));
}

#[test]
fn a_malformed_field_comparison_is_refused_at_load() {
    let not_a_path = "invalid literal: all_in_field: requires a field path, not a literal";
    for (field, refusal) in [
        ("[policy.variant.allowed_ip_lists]", not_a_path),
        ("3", not_a_path),
        ("''", "empty field path"),
        ("policy..variant", "empty field path"),
    ] {
        let yaml = format!(
            "rules:\n  - id: TEST-FIELDS\n    risk_level: info\n    message: compared\n    \
             triggers:\n      policy.variant.blocked_ip_lists:\n        all_in_field: {field}\n"
        );
        match load_v1_rules(&yaml) {
            Err(LoadError::PredicateParse { message, .. }) => assert_eq!(message, refusal),
            Err(other) => panic!("{field}: {other}"),
            Ok(_) => panic!("{field}: loaded"),
        }
    }
}

#[test]
fn test_network_policy_risk_analysis() {
    let sql = r#"
        -- CREATE should trigger an info context entry
        CREATE NETWORK POLICY test_policy
          ALLOWED_IP_LIST = ('192.168.1.0/24')
          COMMENT = 'Test policy';
        
        -- ALTER SET should trigger MEDIUM finding
        ALTER NETWORK POLICY test_policy SET
          ALLOWED_IP_LIST = ('10.0.0.0/8');
        
        -- ALTER ADD should trigger MEDIUM finding
        ALTER NETWORK POLICY test_policy ADD
          BLOCKED_IP_LIST = ('172.16.0.0/12');
        
        -- DROP should trigger MEDIUM finding
        DROP NETWORK POLICY test_policy;
    "#;

    let report = analyze_risk(sql).expect("Risk analysis should succeed");

    // Verify statements were analyzed
    println!("=== Semantic Analysis Report ===");
    println!("Total findings: {}", report.summary.total_reported_findings);
    println!("Critical: {}", report.summary.critical_count);
    println!("High: {}", report.summary.high_count);
    println!("Medium: {}", report.summary.medium_count);
    println!("Low: {}", report.summary.low_count);
    println!(
        "\nStatements Analyzed: {}",
        report.summary.statements_analyzed
    );
    println!(
        "Security Operations: {}",
        report.summary.security_operations
    );

    // Should have findings
    assert!(
        report.summary.total_reported_findings > 0,
        "Should have findings from network policy operations"
    );

    // Should have classified as security operations
    assert!(
        report.summary.security_operations >= 4,
        "Should have at least 4 security operations (CREATE, 2 ALTERs, DROP)"
    );

    // Should have medium findings (ALTER SET, ALTER ADD, DROP)
    assert!(
        report.summary.medium_count >= 3,
        "Should have at least 3 medium findings"
    );

    // Print all findings for verification
    println!("\n=== findings ===");
    for (idx, finding) in report.entries().enumerate() {
        println!(
            "{}. [{:?}] {}",
            idx + 1,
            finding.risk_level(),
            finding.message()
        );
    }

    println!("\n✅ Network policy risk analysis working correctly!");
}

#[test]
fn test_network_policy_all_governance_findings() {
    let sql = r#"
        -- Test all governance findings
        CREATE NETWORK POLICY comprehensive_test
          ALLOWED_IP_LIST = ('192.168.1.0/24')
          BLOCKED_IP_LIST = ('10.0.0.0/8')
          ALLOWED_NETWORK_RULE_LIST = ('rule1');
        
        ALTER NETWORK POLICY comprehensive_test SET TAG owner = 'security';
        ALTER NETWORK POLICY comprehensive_test UNSET TAG owner;
        ALTER NETWORK POLICY comprehensive_test RENAME TO new_name;
        ALTER NETWORK POLICY comprehensive_test UNSET COMMENT;
    "#;

    let report = analyze_risk(sql).expect("Risk analysis should succeed");

    println!("\n=== COMPREHENSIVE GOVERNANCE findings TEST ===");
    println!("Total findings: {}", report.summary.total_reported_findings);
    println!(
        "Security Operations: {}",
        report.summary.security_operations
    );

    // Should detect CREATE with all lists
    let create_findings: Vec<_> = report
        .entries()
        .filter(|f| {
            f.message().contains("ALLOWED_IP_LIST")
                || f.message().contains("BLOCKED_IP_LIST")
                || f.message().contains("ALLOWED_NETWORK_RULE_LIST")
        })
        .collect();

    println!("\nCREATE property findings: {}", create_findings.len());
    assert!(
        create_findings.len() >= 3,
        "Should detect all 3 property types in CREATE"
    );

    // Should detect tag operations
    let tag_findings: Vec<_> = report
        .entries()
        .filter(|f| f.message().to_lowercase().contains("tag"))
        .collect();

    assert!(
        tag_findings.len() >= 2,
        "Should detect both SET TAG and UNSET TAG"
    );

    // Should detect rename
    let rename_findings: Vec<_> = report
        .entries()
        .filter(|f| f.message().contains("renamed"))
        .collect();

    println!("Rename findings: {}", rename_findings.len());
    assert!(
        !rename_findings.is_empty(),
        "Should detect RENAME operation"
    );

    println!("\n✅ All governance findings detected correctly!");
}
