// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL GRANT / REVOKE / DENY typed-parse coverage.
//!
//! Server-tier permissions (`GRANT CONTROL SERVER TO x`) omit the `ON`
//! clause; the privilege list must terminate at `TO` / `FROM` instead of
//! swallowing the principal, which would leave the body `Unparsed`.
//! REVOKE dispatches to the dedicated MSSQL
//! parser for `<class>::securable` qualifiers, server-tier shapes,
//! `GRANT OPTION FOR`, and `CASCADE`.

use lexega_syntax::ast::{
    AstCascadeMode, AstGrantObject, AstGrantShape, AstObjectKind, AstPrivilegeKind, AstRevokeShape,
    AstStmt,
};
use lexega_syntax::dialect::mssql;
use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect,
    FormatterConfig,
};

fn parse_one_mssql(src: &str) -> AstStmt {
    let dialect = mssql();
    let script = parse_sql_with_dialect(src, dialect.as_ref()).expect("parse_sql_with_dialect");
    assert_eq!(
        script.stmts.len(),
        1,
        "expected exactly one statement, got {}",
        script.stmts.len()
    );
    script.stmts.into_iter().next().unwrap()
}

fn expect_grant_privilege_body(stmt: AstStmt) -> lexega_syntax::ast::AstPrivilegeGrantBody {
    match stmt {
        AstStmt::Grant(g) => match g.shape {
            AstGrantShape::Privilege(b) => b,
            s => panic!("expected typed Privilege grant shape, got {:?}", s),
        },
        other => panic!(
            "expected AstStmt::Grant, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

fn expect_revoke(stmt: AstStmt) -> Box<lexega_syntax::ast::AstRevoke> {
    match stmt {
        AstStmt::Revoke(r) => r,
        other => panic!(
            "expected AstStmt::Revoke, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

fn expect_revoke_privilege_body(
    shape: AstRevokeShape,
) -> lexega_syntax::ast::AstPrivilegeRevokeBody {
    match shape {
        AstRevokeShape::Privilege(b) => b,
        s => panic!("expected typed Privilege revoke shape, got {:?}", s),
    }
}

fn other_privilege(lexemes: &[&str]) -> AstPrivilegeKind {
    AstPrivilegeKind::Other {
        lexemes: lexemes.iter().map(|s| s.to_string()).collect(),
    }
}

// ── GRANT: server-tier (no ON clause) ────────────────────────────────

#[test]
fn grant_control_server_typed_with_empty_objects() {
    let body = expect_grant_privilege_body(parse_one_mssql("GRANT CONTROL SERVER TO bad_login;"));
    assert!(
        body.objects.is_empty(),
        "server-tier grant carries no objects"
    );
    assert_eq!(body.privileges.privileges.len(), 1);
    assert_eq!(
        body.privileges.privileges[0].kind,
        other_privilege(&["CONTROL", "SERVER"])
    );
    assert_eq!(body.grantees.len(), 1);
}

#[test]
fn grant_alter_any_login_typed() {
    let body = expect_grant_privilege_body(parse_one_mssql("GRANT ALTER ANY LOGIN TO l;"));
    assert!(body.objects.is_empty());
    assert_eq!(
        body.privileges.privileges[0].kind,
        other_privilege(&["ALTER", "ANY", "LOGIN"])
    );
}

// ── GRANT: class qualifiers + multi-grantee ──────────────────────────

#[test]
fn grant_object_class_multi_grantee_typed() {
    let body =
        expect_grant_privilege_body(parse_one_mssql("GRANT SELECT ON OBJECT::dbo.t TO u1, u2;"));
    assert_eq!(body.grantees.len(), 2);
    assert_eq!(body.objects.len(), 1);
    match &body.objects[0] {
        AstGrantObject::Single { object_kind, .. } => {
            assert_eq!(
                *object_kind,
                AstObjectKind::Other {
                    lexemes: vec!["OBJECT".to_string()]
                }
            );
        }
        o => panic!("expected Single object, got {:?}", o),
    }
}

#[test]
fn grant_database_class_typed() {
    let body = expect_grant_privilege_body(parse_one_mssql("GRANT CONTROL ON DATABASE::db1 TO r;"));
    match &body.objects[0] {
        AstGrantObject::Single { object_kind, .. } => {
            assert_eq!(*object_kind, AstObjectKind::Database);
        }
        o => panic!("expected Single object, got {:?}", o),
    }
    assert_eq!(
        body.privileges.privileges[0].kind,
        other_privilege(&["CONTROL"])
    );
}

// ── DENY: server-tier ────────────────────────────────────────────────

#[test]
fn deny_server_tier_grantees_populated() {
    let stmt = parse_one_mssql("DENY CONTROL SERVER TO public;");
    let deny = match stmt {
        AstStmt::Deny(d) => d,
        other => panic!(
            "expected AstStmt::Deny, got {:?}",
            std::mem::discriminant(&other)
        ),
    };
    // Regression: TO was swallowed into the privilege lexemes and the
    // body degraded to empty privileges/grantees.
    assert_eq!(deny.privileges.privileges.len(), 1);
    assert_eq!(
        deny.privileges.privileges[0].kind,
        other_privilege(&["CONTROL", "SERVER"])
    );
    assert_eq!(deny.grantees.len(), 1);
}

// ── REVOKE: MSSQL shapes ─────────────────────────────────────────────

#[test]
fn revoke_object_class_cascade_typed() {
    let r = expect_revoke(parse_one_mssql(
        "REVOKE SELECT ON OBJECT::dbo.t FROM u1 CASCADE;",
    ));
    assert_eq!(r.cascade_mode, Some(AstCascadeMode::Cascade));
    assert!(r.grant_option_for.is_none());
    let body = expect_revoke_privilege_body(r.shape);
    assert_eq!(body.privileges.privileges[0].kind, AstPrivilegeKind::Select);
    assert_eq!(body.grantees.len(), 1);
    match &body.objects[0] {
        AstGrantObject::Single { object_kind, .. } => {
            assert_eq!(
                *object_kind,
                AstObjectKind::Other {
                    lexemes: vec!["OBJECT".to_string()]
                }
            );
        }
        o => panic!("expected Single object, got {:?}", o),
    }
}

#[test]
fn revoke_server_tier_typed_with_empty_objects() {
    let r = expect_revoke(parse_one_mssql("REVOKE CONTROL SERVER FROM l;"));
    let body = expect_revoke_privilege_body(r.shape);
    assert!(body.objects.is_empty());
    assert_eq!(
        body.privileges.privileges[0].kind,
        other_privilege(&["CONTROL", "SERVER"])
    );
}

#[test]
fn revoke_grant_option_for_typed() {
    let r = expect_revoke(parse_one_mssql(
        "REVOKE GRANT OPTION FOR SELECT ON OBJECT::dbo.t FROM u1;",
    ));
    assert!(r.grant_option_for.is_some());
    let body = expect_revoke_privilege_body(r.shape);
    assert_eq!(body.privileges.privileges[0].kind, AstPrivilegeKind::Select);
}

#[test]
fn revoke_accepts_to_keyword_for_principals() {
    // T-SQL REVOKE admits both `TO` and `FROM` before the principal list.
    let r = expect_revoke(parse_one_mssql("REVOKE SELECT ON dbo.t TO u1;"));
    let body = expect_revoke_privilege_body(r.shape);
    assert_eq!(body.grantees.len(), 1);
}

#[test]
fn revoke_multi_grantee_with_as_principal() {
    let r = expect_revoke(parse_one_mssql(
        "REVOKE SELECT ON OBJECT::dbo.t FROM u1, u2 CASCADE AS dbo;",
    ));
    assert_eq!(r.cascade_mode, Some(AstCascadeMode::Cascade));
    let body = expect_revoke_privilege_body(r.shape);
    assert_eq!(body.grantees.len(), 2);
}

// ── Formatter guard ──────────────────────────────────────────────────

fn format_and_verify_mssql(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = mssql();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("Formatting verification failed: {}", e));
}

#[test]
fn formatter_safe_on_typed_mssql_dcl_shapes() {
    format_and_verify_mssql("GRANT CONTROL SERVER TO public;");
    format_and_verify_mssql("GRANT IMPERSONATE ON LOGIN::sa TO some_login;");
    format_and_verify_mssql("REVOKE SELECT ON OBJECT::dbo.t FROM u1 CASCADE;");
    format_and_verify_mssql("REVOKE GRANT OPTION FOR SELECT ON OBJECT::dbo.t FROM u1;");
    format_and_verify_mssql("DENY CONTROL SERVER TO public;");
}
