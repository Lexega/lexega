// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake CREATE / DROP REPLICATION GROUP and FAILOVER GROUP.
//!
//! Covers parsing/formatting + the SNW-REPL-* / SNW-{REPLGRP,FGRP}-* rules,
//! especially the ALLOWED_ACCOUNTS cross-account egress recognition.

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
fn test_replication_group_formatting_variants() {
    assert_formats_safe(
        "CREATE FAILOVER GROUP fg1 OBJECT_TYPES = DATABASES, ROLES ALLOWED_DATABASES = db1, db2 ALLOWED_ACCOUNTS = myorg.account2, myorg.account3 IGNORE EDITION CHECK REPLICATION_SCHEDULE = '10 MINUTE';\n\
         CREATE REPLICATION GROUP rg1 OBJECT_TYPES = DATABASES ALLOWED_DATABASES = db1 ALLOWED_ACCOUNTS = myorg.acct2;\n\
         CREATE FAILOVER GROUP fg2 AS REPLICA OF myorg.primaryacct.fg1;\n\
         DROP FAILOVER GROUP fg1;\n\
         DROP REPLICATION GROUP IF EXISTS rg1;",
    );
}

// ───────────────────────── egress recognition ─────────────────────────

#[test]
fn test_failover_group_allowed_accounts_is_egress() {
    let report = analyze_risk(
        "CREATE FAILOVER GROUP fg OBJECT_TYPES = DATABASES ALLOWED_DATABASES = db1 ALLOWED_ACCOUNTS = myorg.account2, myorg.account3;",
    )
    .expect("should analyze");
    let rules = extract_rule_ids(&report.signals);
    assert!(rules.contains("SNW-FGRP-NEW"), "got {rules:?}");
    assert!(
        rules.contains("SNW-REPL-ACCOUNTS"),
        "ALLOWED_ACCOUNTS is cross-account egress, got {rules:?}"
    );
    assert!(
        report.summary.high_count >= 1,
        "cross-account replication is high severity"
    );
}

#[test]
fn test_replication_group_allowed_accounts_survives_ignore_edition_check() {
    // The interspersed value-less IGNORE EDITION CHECK must not corrupt the
    // ALLOWED_ACCOUNTS value scan.
    let rules = analyze_and_get_rules(
        "CREATE REPLICATION GROUP rg OBJECT_TYPES = DATABASES ALLOWED_ACCOUNTS = myorg.a, myorg.b IGNORE EDITION CHECK REPLICATION_SCHEDULE = '5 MINUTE';",
    );
    assert!(rules.contains("SNW-REPLGRP-NEW"), "got {rules:?}");
    assert!(rules.contains("SNW-REPL-ACCOUNTS"), "got {rules:?}");
}

#[test]
fn test_secondary_replica_form() {
    // AS REPLICA OF has no ALLOWED_ACCOUNTS — fires REPLICA, not ACCOUNTS.
    let rules =
        analyze_and_get_rules("CREATE FAILOVER GROUP fg AS REPLICA OF myorg.primaryacct.fg_src;");
    assert!(rules.contains("SNW-FGRP-NEW"), "got {rules:?}");
    assert!(rules.contains("SNW-REPL-REPLICA"), "got {rules:?}");
    assert!(
        !rules.contains("SNW-REPL-ACCOUNTS"),
        "a replica has no ALLOWED_ACCOUNTS, got {rules:?}"
    );
}

// ───────────────────────── drop ─────────────────────────

#[test]
fn test_drop_groups() {
    let rules = analyze_and_get_rules("DROP FAILOVER GROUP fg1;");
    assert!(rules.contains("SNW-FGRP-DROP"), "got {rules:?}");

    let rules = analyze_and_get_rules("DROP REPLICATION GROUP IF EXISTS rg1;");
    assert!(rules.contains("SNW-REPLGRP-DROP"), "got {rules:?}");
}

#[test]
fn test_group_kind_discrimination() {
    // A failover group must not fire the replication-group rule and vice versa.
    let rules = analyze_and_get_rules(
        "CREATE FAILOVER GROUP fg OBJECT_TYPES = DATABASES ALLOWED_ACCOUNTS = myorg.a;",
    );
    assert!(rules.contains("SNW-FGRP-NEW"), "got {rules:?}");
    assert!(!rules.contains("SNW-REPLGRP-NEW"), "got {rules:?}");

    let rules = analyze_and_get_rules(
        "CREATE REPLICATION GROUP rg OBJECT_TYPES = DATABASES ALLOWED_ACCOUNTS = myorg.a;",
    );
    assert!(rules.contains("SNW-REPLGRP-NEW"), "got {rules:?}");
    assert!(!rules.contains("SNW-FGRP-NEW"), "got {rules:?}");
}
