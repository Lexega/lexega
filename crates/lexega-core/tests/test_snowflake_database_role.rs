// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake CREATE/ALTER/DROP DATABASE ROLE recognition.

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

// ── CREATE DATABASE ROLE is a role, not a database ──────────────────

#[test]
fn create_database_role_is_role_not_database() {
    let rules = analyze_and_get_rules("CREATE DATABASE ROLE analyst;");
    assert!(
        rules.contains("ROLE-NEW"),
        "should fire the role-create rule"
    );
    assert!(
        !rules.contains("INFO-DB-NEW"),
        "must NOT be misread as a database creation"
    );
}

#[test]
fn create_database_role_qualified_name() {
    let rules = analyze_and_get_rules("CREATE DATABASE ROLE db1.analyst;");
    assert!(rules.contains("ROLE-NEW"));
    assert!(!rules.contains("INFO-DB-NEW"));
}

#[test]
fn create_database_role_if_not_exists() {
    let rules = analyze_and_get_rules("CREATE DATABASE ROLE IF NOT EXISTS db1.analyst;");
    assert!(rules.contains("ROLE-NEW"));
    assert!(!rules.contains("INFO-DB-NEW"));
}

#[test]
fn create_or_replace_database_role() {
    let rules = analyze_and_get_rules("CREATE OR REPLACE DATABASE ROLE db1.analyst;");
    assert!(rules.contains("ROLE-NEW"));
    assert!(!rules.contains("INFO-DB-NEW"));
}

// ── ALTER / DROP DATABASE ROLE ──────────────────────────────────────

#[test]
fn alter_database_role_is_role() {
    let rules = analyze_and_get_rules("ALTER DATABASE ROLE db1.analyst SET COMMENT = 'x';");
    assert!(rules.contains("ROLE-CHG"));
}

#[test]
fn drop_database_role_is_role_not_database() {
    let rules = analyze_and_get_rules("DROP DATABASE ROLE db1.analyst;");
    assert!(rules.contains("ROLE-DROP"));
}

// ── No regression: a real database still parses as a database ───────

#[test]
fn create_real_database_unaffected() {
    let rules = analyze_and_get_rules("CREATE DATABASE realdb;");
    assert!(rules.contains("INFO-DB-NEW"));
    assert!(!rules.contains("ROLE-NEW"));
}

#[test]
fn create_quoted_database_named_role_is_database() {
    // A database genuinely named "role" must be quoted; its lexeme does
    // not match the ROLE keyword, so it stays a database.
    let rules = analyze_and_get_rules("CREATE DATABASE \"role\";");
    assert!(rules.contains("INFO-DB-NEW"));
    assert!(!rules.contains("ROLE-NEW"));
}

#[test]
fn drop_real_database_unaffected() {
    let rules = analyze_and_get_rules("DROP DATABASE realdb;");
    assert!(!rules.contains("ROLE-DROP"));
}
