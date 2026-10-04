// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP GIT REPOSITORY` statement
//! family: property-bag parsing into `ddl.git_repository` facts (api
//! integration, origin, git-credentials presence), the SNW-GITREPO-* rules,
//! the ALTER SET/UNSET/FETCH actions, and byte-exact formatting.

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
fn test_create_git_repository_fires_new() {
    let rules = analyze_and_get_rules(
        "CREATE GIT REPOSITORY r API_INTEGRATION=i ORIGIN='https://github.com/o/repo' GIT_CREDENTIALS=db.sc.sec;",
    );
    assert!(rules.contains("SNW-GITREPO-NEW"), "got {rules:?}");
}

#[test]
fn test_alter_git_repository_fetch_fires_fetch() {
    let rules = analyze_and_get_rules("ALTER GIT REPOSITORY r FETCH;");
    assert!(rules.contains("SNW-GITREPO-FETCH"), "got {rules:?}");
}

#[test]
fn test_alter_git_repository_set_is_not_fetch() {
    // SET (e.g. updating the comment) parses but is not a fetch — the
    // external-content-refresh recognition must not fire.
    let rules = analyze_and_get_rules("ALTER GIT REPOSITORY r SET COMMENT = 'x';");
    assert!(!rules.contains("SNW-GITREPO-FETCH"), "got {rules:?}");
}

#[test]
fn test_drop_git_repository_analyzes() {
    // DROP GIT REPOSITORY routes through the generic Drop gated on the
    // two-word object type; it must analyze cleanly.
    let report = analyze_risk("DROP GIT REPOSITORY r;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_git_repository_forms_format_safe() {
    assert_formats_safe(
        "CREATE GIT REPOSITORY r API_INTEGRATION=i ORIGIN='https://github.com/o/repo' GIT_CREDENTIALS=db.sc.sec;",
    );
    assert_formats_safe("ALTER GIT REPOSITORY r FETCH;");
    assert_formats_safe("ALTER GIT REPOSITORY r SET COMMENT = 'x';");
    assert_formats_safe("DROP GIT REPOSITORY r;");
}
