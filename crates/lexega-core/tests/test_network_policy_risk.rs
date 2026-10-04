// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::api::analyze_risk;

#[test]
fn test_network_policy_risk_analysis() {
    let sql = r#"
        -- CREATE should trigger CRITICAL signal
        CREATE NETWORK POLICY test_policy
          ALLOWED_IP_LIST = ('192.168.1.0/24')
          COMMENT = 'Test policy';
        
        -- ALTER SET should trigger CRITICAL signal
        ALTER NETWORK POLICY test_policy SET
          ALLOWED_IP_LIST = ('10.0.0.0/8');
        
        -- ALTER ADD should trigger HIGH signal
        ALTER NETWORK POLICY test_policy ADD
          BLOCKED_IP_LIST = ('172.16.0.0/12');
        
        -- DROP should trigger CRITICAL signal
        DROP NETWORK POLICY test_policy;
    "#;

    let report = analyze_risk(sql).expect("Risk analysis should succeed");

    // Verify statements were analyzed
    println!("=== Semantic Analysis Report ===");
    println!("Total signals: {}", report.summary.total_reported_signals);
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

    // Should have signals
    assert!(
        report.summary.total_reported_signals > 0,
        "Should have signals from network policy operations"
    );

    // Should have classified as security operations
    assert!(
        report.summary.security_operations >= 4,
        "Should have at least 4 security operations (CREATE, 2 ALTERs, DROP)"
    );

    // Should have critical signals (CREATE, ALTER SET, DROP)
    assert!(
        report.summary.critical_count >= 1,
        "Should have at least 1 critical signal"
    );

    // Should have high signals (ALTER ADD)
    assert!(
        report.summary.high_count >= 1,
        "Should have at least 1 high signal"
    );

    // Print all signals for verification
    println!("\n=== signals ===");
    for (idx, signal) in report.signals.iter().enumerate() {
        println!(
            "{}. [{:?}] {}",
            idx + 1,
            signal.risk_level(),
            signal.message()
        );
    }

    println!("\n✅ Network policy risk analysis working correctly!");
}

#[test]
fn test_network_policy_all_governance_signals() {
    let sql = r#"
        -- Test all governance signals
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

    println!("\n=== COMPREHENSIVE GOVERNANCE signals TEST ===");
    println!("Total signals: {}", report.summary.total_reported_signals);
    println!(
        "Security Operations: {}",
        report.summary.security_operations
    );

    // Should detect CREATE with all lists
    let create_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| {
            f.message().contains("ALLOWED_IP_LIST")
                || f.message().contains("BLOCKED_IP_LIST")
                || f.message().contains("ALLOWED_NETWORK_RULE_LIST")
        })
        .collect();

    println!("\nCREATE property signals: {}", create_signals.len());
    assert!(
        create_signals.len() >= 3,
        "Should detect all 3 property types in CREATE"
    );

    // Should detect tag operations
    let tag_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| f.message().to_lowercase().contains("tag"))
        .collect();

    assert!(
        tag_signals.len() >= 2,
        "Should detect both SET TAG and UNSET TAG"
    );

    // Should detect rename
    let rename_signals: Vec<_> = report
        .signals
        .iter()
        .filter(|f| f.message().contains("renamed"))
        .collect();

    println!("Rename signals: {}", rename_signals.len());
    assert!(rename_signals.len() >= 1, "Should detect RENAME operation");

    println!("\n✅ All governance signals detected correctly!");
}
