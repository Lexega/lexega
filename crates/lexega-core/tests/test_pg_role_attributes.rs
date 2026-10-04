// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! PostgreSQL `CREATE/ALTER ROLE` capability-attribute recognition and the
//! governance rules that predicate on it (PG-ROLE-SUPERUSER / -BYPASSRLS /
//! -CREATEROLE / -REPLICATION).

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::ast::{AstRoleAttributeKind, AstStmt};
use lexega_core::{parse_stmt_from_str, PostgresDialect};
use std::collections::HashSet;
use std::sync::Arc;

fn attrs(sql: &str) -> Vec<(AstRoleAttributeKind, bool)> {
    let opts = match parse_stmt_from_str(sql) {
        Some(AstStmt::CreatePrincipal(p)) => p.options,
        Some(AstStmt::AlterPrincipal(p)) => p.options,
        other => panic!("expected CREATE/ALTER principal for {sql:?}, got {other:?}"),
    };
    opts.role_attributes
        .iter()
        .map(|a| (a.kind, a.negated))
        .collect()
}

fn pg_rules(sql: &str) -> HashSet<String> {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(PostgresDialect));
    match analyze_risk_with_policy_config(sql, &config) {
        Ok(report) => report
            .signals
            .iter()
            .map(|f| match f {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect(),
        Err(e) => panic!("parse error for {sql:?}: {e:?}"),
    }
}

#[test]
fn test_role_attribute_recognition() {
    use AstRoleAttributeKind as K;
    assert_eq!(
        attrs("CREATE ROLE r SUPERUSER CREATEDB LOGIN;"),
        vec![
            (K::Superuser, false),
            (K::CreateDb, false),
            (K::Login, false)
        ]
    );
}

#[test]
fn test_role_attribute_negated_forms() {
    use AstRoleAttributeKind as K;
    assert_eq!(
        attrs("CREATE ROLE r NOSUPERUSER NOLOGIN NOBYPASSRLS;"),
        vec![(K::Superuser, true), (K::Login, true), (K::BypassRls, true)]
    );
}

#[test]
fn test_pg_role_superuser_fires() {
    assert!(pg_rules("CREATE ROLE admin SUPERUSER;").contains("PG-ROLE-SUPERUSER"));
    assert!(pg_rules("ALTER ROLE admin SUPERUSER;").contains("PG-ROLE-SUPERUSER"));
}

#[test]
fn test_pg_role_negated_superuser_does_not_fire() {
    // Recognition/policy split: NOSUPERUSER is negated=true, so the
    // SUPERUSER rule (which requires negated:false) must stay silent.
    let rules = pg_rules("CREATE ROLE r NOSUPERUSER LOGIN;");
    assert!(
        !rules.contains("PG-ROLE-SUPERUSER"),
        "NOSUPERUSER must not fire PG-ROLE-SUPERUSER. Got: {rules:?}"
    );
}

#[test]
fn test_pg_role_bypassrls_createrole_replication_fire() {
    assert!(pg_rules("CREATE ROLE app LOGIN BYPASSRLS;").contains("PG-ROLE-BYPASSRLS"));
    assert!(pg_rules("ALTER ROLE r CREATEROLE;").contains("PG-ROLE-CREATEROLE"));
    assert!(pg_rules("CREATE ROLE rep REPLICATION;").contains("PG-ROLE-REPLICATION"));
}
