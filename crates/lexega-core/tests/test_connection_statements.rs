// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake CONNECTION forms layered onto the shared connection
//! parser: `CREATE CONNECTION … COMMENT = '…'` / `AS REPLICA OF …` and
//! `ALTER CONNECTION … { ENABLE | DISABLE } FAILOVER` / `PRIMARY`, the
//! `ddl.connection.{is_replica, actions}` facts, the SNW-CONN-* rules,
//! byte-exact formatting, and no regression on Databricks `TYPE`/`OPTIONS`.

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
fn test_create_connection_replica_fires_rule() {
    let rules = analyze_and_get_rules("CREATE CONNECTION myconn AS REPLICA OF org1.acct1.conn1;");
    assert!(rules.contains("SNW-CONN-REPLICA"), "got {rules:?}");
}

#[test]
fn test_create_connection_plain_comment_is_not_replica() {
    // Snowflake `COMMENT = '…'` (with `=`) now parses, and a non-replica
    // connection must not fire the replica rule.
    let rules = analyze_and_get_rules("CREATE CONNECTION myconn COMMENT = 'primary conn';");
    assert!(!rules.contains("SNW-CONN-REPLICA"), "got {rules:?}");
}

#[test]
fn test_alter_connection_enable_failover_fires_rule() {
    let rules = analyze_and_get_rules(
        "ALTER CONNECTION myconn ENABLE FAILOVER TO ACCOUNTS org1.acct2, org1.acct3;",
    );
    assert!(rules.contains("SNW-CONN-FAILOVER-ENABLE"), "got {rules:?}");
}

#[test]
fn test_alter_connection_disable_failover_and_primary_are_benign() {
    // DISABLE FAILOVER reduces exposure and PRIMARY is an operational
    // promotion — both parse but fire no failover-exposure rule.
    let disable = analyze_and_get_rules("ALTER CONNECTION myconn DISABLE FAILOVER;");
    assert!(
        !disable.contains("SNW-CONN-FAILOVER-ENABLE"),
        "got {disable:?}"
    );
    let primary = analyze_and_get_rules("ALTER CONNECTION myconn PRIMARY;");
    assert!(
        !primary.contains("SNW-CONN-FAILOVER-ENABLE"),
        "got {primary:?}"
    );
}

#[test]
fn test_databricks_connection_fires_no_snw_rules() {
    let rules = analyze_and_get_rules(
        "CREATE CONNECTION myconn TYPE mysql OPTIONS (host 'h', user 'u', password 'p');",
    );
    assert!(!rules.contains("SNW-CONN-REPLICA"), "got {rules:?}");
    assert!(!rules.contains("SNW-CONN-FAILOVER-ENABLE"), "got {rules:?}");
}

#[test]
fn test_connection_forms_format_safe() {
    assert_formats_safe("CREATE CONNECTION myconn AS REPLICA OF org1.acct1.conn1;");
    assert_formats_safe("CREATE CONNECTION myconn COMMENT = 'c';");
    assert_formats_safe("ALTER CONNECTION myconn ENABLE FAILOVER TO ACCOUNTS org1.acct2;");
    assert_formats_safe("ALTER CONNECTION myconn PRIMARY;");
}
