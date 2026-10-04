// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, FormatterConfig};

#[test]
fn test_network_policy_formatter_create() {
    let sql = "CREATE NETWORK POLICY test ALLOWED_IP_LIST = ('192.168.1.0/24');";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Should format successfully");

    // Should preserve the statement structure
    assert!(
        formatted.contains("CREATE NETWORK POLICY"),
        "Should preserve CREATE NETWORK POLICY keywords"
    );
    assert!(
        formatted.contains("ALLOWED_IP_LIST"),
        "Should preserve property name"
    );
    assert!(
        formatted.contains("192.168.1.0/24"),
        "Should preserve IP address"
    );

    println!("✅ CREATE NETWORK POLICY formatted correctly");
}

#[test]
fn test_network_policy_formatter_alter() {
    let sql = "ALTER NETWORK POLICY test SET ALLOWED_IP_LIST = ('10.0.0.0/8');";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Should format successfully");

    assert!(
        formatted.contains("ALTER NETWORK POLICY"),
        "Should preserve ALTER NETWORK POLICY keywords"
    );
    assert!(formatted.contains("SET"), "Should preserve SET keyword");
    assert!(
        formatted.contains("10.0.0.0/8"),
        "Should preserve IP address"
    );

    println!("✅ ALTER NETWORK POLICY formatted correctly");
}

#[test]
fn test_network_policy_formatter_drop() {
    let sql = "DROP NETWORK POLICY test;";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Should format successfully");

    assert!(
        formatted.contains("DROP NETWORK POLICY"),
        "Should preserve DROP NETWORK POLICY keywords"
    );
    assert!(formatted.contains("test"), "Should preserve policy name");

    println!("✅ DROP NETWORK POLICY formatted correctly");
}

#[test]
fn test_network_policy_formatter_all_actions() {
    let sql = r#"
        CREATE OR REPLACE NETWORK POLICY comprehensive
          ALLOWED_IP_LIST = ('192.168.1.0/24')
          BLOCKED_IP_LIST = ('10.0.0.0/8')
          ALLOWED_NETWORK_RULE_LIST = ('rule1')
          COMMENT = 'Test';
        
        ALTER NETWORK POLICY comprehensive ADD ALLOWED_IP_LIST = ('172.16.0.0/12');
        ALTER NETWORK POLICY comprehensive REMOVE BLOCKED_IP_LIST = ('10.0.0.0/8');
        ALTER NETWORK POLICY comprehensive RENAME TO new_name;
        ALTER NETWORK POLICY comprehensive SET TAG owner = 'security';
        ALTER NETWORK POLICY comprehensive UNSET TAG owner;
        ALTER NETWORK POLICY comprehensive UNSET COMMENT;
        
        DROP NETWORK POLICY IF EXISTS old_policy;
    "#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("Should format all network policy operations");

    // Verify all operations are preserved
    assert!(
        formatted.contains("CREATE OR REPLACE"),
        "Should preserve CREATE OR REPLACE"
    );
    assert!(
        formatted.contains("ALLOWED_IP_LIST"),
        "Should preserve ALLOWED_IP_LIST"
    );
    assert!(
        formatted.contains("BLOCKED_IP_LIST"),
        "Should preserve BLOCKED_IP_LIST"
    );
    assert!(
        formatted.contains("ALLOWED_NETWORK_RULE_LIST"),
        "Should preserve ALLOWED_NETWORK_RULE_LIST"
    );
    assert!(formatted.contains("ADD"), "Should preserve ADD");
    assert!(formatted.contains("REMOVE"), "Should preserve REMOVE");
    assert!(formatted.contains("RENAME TO"), "Should preserve RENAME TO");
    assert!(formatted.contains("SET TAG"), "Should preserve SET TAG");
    assert!(formatted.contains("UNSET TAG"), "Should preserve UNSET TAG");
    assert!(
        formatted.contains("UNSET COMMENT"),
        "Should preserve UNSET COMMENT"
    );
    assert!(
        formatted.contains("DROP NETWORK POLICY IF EXISTS"),
        "Should preserve DROP IF EXISTS"
    );

    println!("✅ All network policy operations formatted correctly");
}
