// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests: IR PrivilegePlan → public PrivilegeFacts projection.

use lexega_core::ast::AstStmt;
use lexega_core::facts::extract::derive_facts_from_privilege_plan;
use lexega_core::facts::identity::{ObjectKind, PrincipalKind};
use lexega_core::facts::privilege::{Privilege, PrivilegeChangeKind};
use lexega_core::facts::statement::StatementKind;
use lexega_core::ir::{lower_grant_to_privilege_plan, lower_revoke_to_privilege_plan};
use lexega_core::parse_sql;

fn project_grant(src: &str) -> lexega_core::facts::statement::StatementFacts {
    let script = parse_sql(src).expect("parse_sql");
    assert_eq!(script.stmts.len(), 1);
    let plan = match script.stmts.into_iter().next().unwrap() {
        AstStmt::Grant(g) => lower_grant_to_privilege_plan(&g),
        _ => panic!("expected Grant"),
    };
    derive_facts_from_privilege_plan(&plan, src)
}

fn project_revoke(src: &str) -> lexega_core::facts::statement::StatementFacts {
    let script = parse_sql(src).expect("parse_sql");
    let plan = match script.stmts.into_iter().next().unwrap() {
        AstStmt::Revoke(r) => lower_revoke_to_privilege_plan(&r),
        _ => panic!("expected Revoke"),
    };
    derive_facts_from_privilege_plan(&plan, src)
}

#[test]
fn grant_select_on_table_yields_typed_privilege_facts() {
    let facts = project_grant("GRANT SELECT ON TABLE db.s.t TO ROLE analyst;");
    assert_eq!(facts.kind, StatementKind::Grant);
    let p = facts.privilege.expect("privilege facts populated");
    assert_eq!(p.kind, PrivilegeChangeKind::Grant);
    assert_eq!(p.privileges, vec![Privilege::Select]);
    let target = p.target.expect("target populated");
    assert_eq!(target.kind, ObjectKind::Table);
    assert_eq!(target.name.name.normalized, "T");
    assert_eq!(target.name.schema.unwrap().normalized, "S");
    assert_eq!(target.name.database.unwrap().normalized, "DB");
    assert_eq!(p.grantees.len(), 1);
    assert_eq!(p.grantees[0].kind, PrincipalKind::Role);
    assert_eq!(p.grantees[0].name.normalized, "ANALYST");
    assert!(!p.with_grant_option);
    assert!(!p.on_future);
    assert!(!p.on_all);
    assert!(!p.all_privileges);
}

#[test]
fn grant_with_grant_option_sets_flag() {
    let facts = project_grant("GRANT SELECT ON TABLE t TO ROLE r WITH GRANT OPTION;");
    let p = facts.privilege.unwrap();
    assert!(p.with_grant_option);
}

#[test]
fn grant_all_privileges_marks_all_privileges_flag_and_emits_all_privilege() {
    let facts = project_grant("GRANT ALL PRIVILEGES ON SCHEMA db.s TO ROLE r;");
    let p = facts.privilege.unwrap();
    assert!(p.all_privileges);
    assert_eq!(p.privileges, vec![Privilege::All]);
}

#[test]
fn grant_on_all_tables_marks_on_all_with_schema_target() {
    let facts = project_grant("GRANT USAGE ON ALL TABLES IN SCHEMA db.s TO ROLE r;");
    let p = facts.privilege.unwrap();
    assert!(p.on_all);
    assert!(!p.on_future);
    let target = p.target.unwrap();
    assert_eq!(target.kind, ObjectKind::Schema);
    assert_eq!(target.name.canonical, "DB.S");
}

#[test]
fn grant_on_future_tables_marks_on_future_with_database_target() {
    let facts = project_grant("GRANT SELECT ON FUTURE TABLES IN DATABASE db TO ROLE r;");
    let p = facts.privilege.unwrap();
    assert!(p.on_future);
    assert!(!p.on_all);
    let target = p.target.unwrap();
    assert_eq!(target.kind, ObjectKind::Database);
    assert_eq!(target.name.canonical, "DB");
}

#[test]
fn grant_role_targets_role_objectkind() {
    let facts = project_grant("GRANT ROLE r1 TO ROLE r2;");
    let p = facts.privilege.unwrap();
    assert!(p.privileges.is_empty()); // Role-grant carries no privileges
    let target = p.target.unwrap();
    assert_eq!(target.kind, ObjectKind::Role);
    assert_eq!(target.name.name.normalized, "R1");
    assert_eq!(p.grantees[0].kind, PrincipalKind::Role);
    assert_eq!(p.grantees[0].name.normalized, "R2");
}

#[test]
fn grant_database_role_grantee_uses_other_principal_kind() {
    let facts = project_grant("GRANT USAGE ON DATABASE db TO DATABASE ROLE db.dbr;");
    let p = facts.privilege.unwrap();
    let g = &p.grantees[0];
    match &g.kind {
        PrincipalKind::Other(name) => {
            assert_eq!(name.normalized, "DATABASE_ROLE");
        }
        other => panic!("expected Other('database_role'), got {:?}", other),
    }
    // Last component of qualified name lands on the IdentName.
    assert_eq!(g.name.normalized, "DBR");
}

#[test]
fn grant_to_user_grantee() {
    let facts = project_grant("GRANT USAGE ON DATABASE db TO USER u;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.grantees[0].kind, PrincipalKind::User);
    assert_eq!(p.grantees[0].name.normalized, "U");
}

#[test]
fn grant_to_share_grantee() {
    let facts = project_grant("GRANT USAGE ON DATABASE db TO SHARE s;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.grantees[0].kind, PrincipalKind::Share);
}

#[test]
fn grant_imported_privileges_preserves_typed_privilege() {
    let facts = project_grant("GRANT IMPORTED PRIVILEGES ON DATABASE shared_db TO ROLE r;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.privileges, vec![Privilege::ImportedPrivileges]);
}

#[test]
fn grant_create_table_two_word_privilege() {
    let facts = project_grant("GRANT CREATE TABLE ON SCHEMA db.s TO ROLE r;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.privileges, vec![Privilege::CreateTable]);
}

#[test]
fn grant_apply_masking_policy_three_word_privilege() {
    let facts = project_grant("GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE r;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.privileges, vec![Privilege::ApplyMaskingPolicy]);
    // ON ACCOUNT → no target
    assert!(p.target.is_none());
}

#[test]
fn grant_unrecognized_privilege_falls_back_to_other() {
    let facts = project_grant("GRANT BIND SERVICE ENDPOINT ON ACCOUNT TO ROLE r;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.privileges.len(), 1);
    match &p.privileges[0] {
        Privilege::Other(ident) => {
            assert_eq!(ident.normalized, "BIND SERVICE ENDPOINT");
        }
        other => panic!("expected Other privilege, got {:?}", other),
    }
}

#[test]
fn grant_ownership_with_copy_current_grants_sets_flag() {
    let facts = project_grant("GRANT OWNERSHIP ON TABLE t TO ROLE r COPY CURRENT GRANTS;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.privileges, vec![Privilege::Ownership]);
    assert!(p.copy_current_grants);
}

#[test]
fn grant_ownership_with_revoke_current_grants_does_not_set_copy_flag() {
    let facts = project_grant("GRANT OWNERSHIP ON SCHEMA db.s TO ROLE r REVOKE CURRENT GRANTS;");
    let p = facts.privilege.unwrap();
    assert!(!p.copy_current_grants);
}

#[test]
fn revoke_select_yields_revoke_kind() {
    let facts = project_revoke("REVOKE SELECT ON TABLE t FROM ROLE r CASCADE;");
    assert_eq!(facts.kind, StatementKind::Revoke);
    let p = facts.privilege.unwrap();
    assert_eq!(p.kind, PrivilegeChangeKind::Revoke);
    assert_eq!(p.privileges, vec![Privilege::Select]);
}

#[test]
fn quoted_identifiers_preserve_raw_and_normalize() {
    let facts = project_grant(
        r#"GRANT SELECT ON TABLE "Mixed DB"."Mixed Schema"."My Table" TO ROLE "Quoted Role";"#,
    );
    let p = facts.privilege.unwrap();
    let target = p.target.unwrap();
    // Raw preserved with quotes; normalized strips quoting.
    assert_eq!(target.name.name.raw, r#""My Table""#);
    assert_eq!(target.name.name.normalized, "My Table");
    assert_eq!(target.name.canonical, "Mixed DB.Mixed Schema.My Table");
    assert_eq!(p.grantees[0].name.raw, r#""Quoted Role""#);
    assert_eq!(p.grantees[0].name.normalized, "Quoted Role");
}

#[test]
fn iceberg_table_object_kind_falls_back_to_generic() {
    // ObjectKind has no IcebergTable variant; projection lands on
    // Generic without losing the name.
    let facts = project_grant("GRANT SELECT ON ICEBERG TABLE db.s.it1 TO ROLE r;");
    let p = facts.privilege.unwrap();
    let target = p.target.unwrap();
    assert_eq!(target.kind, ObjectKind::Generic);
    assert_eq!(target.name.canonical, "DB.S.IT1");
}

#[test]
fn unparsed_falls_through_to_empty_facts_with_revoke_kind() {
    // Unparseable bodies degrade to AstGrantShape::Unparsed, which the
    // projection turns into empty PrivilegeFacts (no privileges, no
    // target, no grantees) but preserves the action discriminator.
    let facts = project_grant("GRANT GIBBERISH NONSENSE FOO BAR;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.kind, PrivilegeChangeKind::Grant);
    assert!(p.privileges.is_empty());
    assert!(p.target.is_none());
    assert!(p.grantees.is_empty());
}

// ── MSSQL T-SQL shapes ───────────────────────────────────────────────

fn project_grant_mssql(src: &str) -> lexega_core::facts::statement::StatementFacts {
    let dialect = lexega_core::dialect::mssql();
    let script =
        lexega_core::parse_sql_with_dialect(src, dialect.as_ref()).expect("parse_sql_with_dialect");
    assert_eq!(script.stmts.len(), 1);
    let plan = match script.stmts.into_iter().next().unwrap() {
        AstStmt::Grant(g) => lower_grant_to_privilege_plan(&g),
        _ => panic!("expected Grant"),
    };
    derive_facts_from_privilege_plan(&plan, src)
}

fn project_revoke_mssql(src: &str) -> lexega_core::facts::statement::StatementFacts {
    let dialect = lexega_core::dialect::mssql();
    let script =
        lexega_core::parse_sql_with_dialect(src, dialect.as_ref()).expect("parse_sql_with_dialect");
    assert_eq!(script.stmts.len(), 1);
    let plan = match script.stmts.into_iter().next().unwrap() {
        AstStmt::Revoke(r) => lower_revoke_to_privilege_plan(&r),
        _ => panic!("expected Revoke"),
    };
    derive_facts_from_privilege_plan(&plan, src)
}

fn expect_other_privilege(p: &Privilege, normalized: &str) {
    match p {
        Privilege::Other(name) => assert_eq!(name.normalized, normalized),
        other => panic!("expected Privilege::Other({normalized}), got {other:?}"),
    }
}

#[test]
fn mssql_server_tier_grant_yields_other_privilege_without_target() {
    let facts = project_grant_mssql("GRANT CONTROL SERVER TO bad_login;");
    assert_eq!(facts.kind, StatementKind::Grant);
    let p = facts.privilege.expect("privilege facts populated");
    assert_eq!(p.kind, PrivilegeChangeKind::Grant);
    assert_eq!(p.privileges.len(), 1);
    expect_other_privilege(&p.privileges[0], "CONTROL SERVER");
    assert!(p.target.is_none(), "server-tier permission has no target");
    assert_eq!(p.grantees.len(), 1);
    assert_eq!(p.grantees[0].name.normalized, "BAD_LOGIN");
}

#[test]
fn mssql_control_on_database_class_yields_database_target() {
    let facts = project_grant_mssql("GRANT CONTROL ON DATABASE::proddb TO u2;");
    let p = facts.privilege.unwrap();
    expect_other_privilege(&p.privileges[0], "CONTROL");
    let target = p.target.expect("target populated");
    assert_eq!(target.kind, ObjectKind::Database);
}

#[test]
fn mssql_revoke_class_qualified_yields_typed_facts() {
    let facts = project_revoke_mssql("REVOKE SELECT ON OBJECT::dbo.t FROM u1 CASCADE;");
    assert_eq!(facts.kind, StatementKind::Revoke);
    let p = facts.privilege.unwrap();
    assert_eq!(p.kind, PrivilegeChangeKind::Revoke);
    assert_eq!(p.privileges, vec![Privilege::Select]);
    assert!(p.target.is_some());
    assert_eq!(p.grantees.len(), 1);
    assert_eq!(p.grantees[0].name.normalized, "U1");
}

#[test]
fn mssql_multi_grantee_grant_projects_all_principals() {
    let facts = project_grant_mssql("GRANT SELECT ON OBJECT::dbo.t TO u1, u2;");
    let p = facts.privilege.unwrap();
    assert_eq!(p.grantees.len(), 2);
    assert_eq!(p.grantees[0].name.normalized, "U1");
    assert_eq!(p.grantees[1].name.normalized, "U2");
}
