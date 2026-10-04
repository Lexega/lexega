// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// IR PolicyAttachmentPlan → public PolicyAttachmentFacts projection.
//
// Exercises the lowering path that the SNW-AUTHPOL-ON / OFF migration
// rests on, separate from the rule engine. Failures here pinpoint
// substrate bugs (lowering / projection); failures in
// `analyze_policy_attachment_facts.rs` pinpoint predicate / corpus bugs.

use lexega_core::ast::AstStmt;
use lexega_core::facts::extract::derive_facts_from_policy_attachment_plan;
use lexega_core::facts::policy_attachment::{
    PolicyAttachmentPrincipalKind, PolicyAttachmentTargetKind, PolicyAttachmentVerb,
};
use lexega_core::facts::statement::{StatementFacts, StatementKind};
use lexega_core::ir::PolicyAttachmentPlan;
use lexega_core::parse_sql;

fn project_first(src: &str) -> StatementFacts {
    let script = parse_sql(src).expect("parse_sql");
    assert_eq!(script.stmts.len(), 1, "expected single statement");
    let plan = match script.stmts.into_iter().next().unwrap() {
        AstStmt::AlterUser(u) => PolicyAttachmentPlan::from_alter_user(&u),
        AstStmt::AlterAccount(a) => {
            PolicyAttachmentPlan::from_alter_account(&a).expect("from_alter_account")
        }
        other => panic!(
            "expected AlterUser/AlterAccount, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    derive_facts_from_policy_attachment_plan(&plan, src)
}

#[test]
fn alter_user_set_authpol_yields_user_set_target_authpol() {
    let facts = project_first("ALTER USER alice SET AUTHENTICATION POLICY = my_pol;");
    assert_eq!(facts.kind, StatementKind::AlterUser);
    let pa = facts
        .policy_attachment
        .expect("policy_attachment populated");
    assert_eq!(pa.verb, PolicyAttachmentVerb::Set);
    assert_eq!(pa.principal_kind, PolicyAttachmentPrincipalKind::User);
    assert_eq!(
        pa.principal_name
            .as_ref()
            .expect("user name populated")
            .normalized,
        "ALICE"
    );
    assert_eq!(
        pa.target_kind,
        PolicyAttachmentTargetKind::AuthenticationPolicy
    );
    let policy = pa.policy.expect("policy populated for SET form");
    assert_eq!(policy.name.normalized, "MY_POL");
}

#[test]
fn alter_user_unset_authpol_has_no_policy() {
    let facts = project_first("ALTER USER alice UNSET AUTHENTICATION POLICY;");
    assert_eq!(facts.kind, StatementKind::AlterUser);
    let pa = facts.policy_attachment.unwrap();
    assert_eq!(pa.verb, PolicyAttachmentVerb::Unset);
    assert_eq!(pa.principal_kind, PolicyAttachmentPrincipalKind::User);
    assert!(
        pa.policy.is_none(),
        "UNSET form must not carry a policy ref"
    );
}

#[test]
fn alter_user_qualified_policy_keeps_database_and_schema() {
    let facts =
        project_first("ALTER USER alice SET AUTHENTICATION POLICY = sec.policies.strict_pol;");
    let pa = facts.policy_attachment.unwrap();
    let policy = pa.policy.unwrap();
    assert_eq!(policy.name.normalized, "STRICT_POL");
    assert_eq!(policy.schema.as_ref().unwrap().normalized, "POLICIES");
    assert_eq!(policy.database.as_ref().unwrap().normalized, "SEC");
    assert_eq!(policy.canonical, "SEC.POLICIES.STRICT_POL");
}

#[test]
fn alter_user_quoted_user_name_parses() {
    let facts = project_first("ALTER USER \"Bob\" SET AUTHENTICATION POLICY = my_pol;");
    let pa = facts.policy_attachment.unwrap();
    assert_eq!(pa.principal_kind, PolicyAttachmentPrincipalKind::User);
    let name = pa.principal_name.expect("user name populated");
    // The quoted form goes through identifier normalization. We don't
    // pin the exact normalized casing here (it's dialect-aware and
    // exercised exhaustively in identifier-normalization tests); we
    // just confirm the projection produces a non-empty name.
    assert!(!name.normalized.is_empty(), "got {:?}", name);
}

#[test]
fn alter_account_set_authpol_has_no_principal_name() {
    let facts = project_first("ALTER ACCOUNT SET AUTHENTICATION POLICY = acct_pol;");
    assert_eq!(facts.kind, StatementKind::AlterAccount);
    let pa = facts.policy_attachment.unwrap();
    assert_eq!(pa.verb, PolicyAttachmentVerb::Set);
    assert_eq!(pa.principal_kind, PolicyAttachmentPrincipalKind::Account);
    assert!(
        pa.principal_name.is_none(),
        "ALTER ACCOUNT carries no principal name"
    );
    let policy = pa.policy.unwrap();
    assert_eq!(policy.name.normalized, "ACCT_POL");
}

#[test]
fn alter_account_unset_authpol_has_neither_name_nor_policy() {
    let facts = project_first("ALTER ACCOUNT UNSET AUTHENTICATION POLICY;");
    assert_eq!(facts.kind, StatementKind::AlterAccount);
    let pa = facts.policy_attachment.unwrap();
    assert_eq!(pa.verb, PolicyAttachmentVerb::Unset);
    assert!(pa.principal_name.is_none());
    assert!(pa.policy.is_none());
}

#[test]
fn source_span_covers_entire_statement() {
    let sql = "ALTER USER alice SET AUTHENTICATION POLICY = my_pol;";
    let facts = project_first(sql);
    let span = facts.source_span.expect("source_span populated");
    // Span covers ALTER USER … my_pol (no semicolon — semicolons live in
    // gaps between statements).
    assert_eq!(span.start, 0);
    assert_eq!(span.end as usize, sql.len() - 1);
}
