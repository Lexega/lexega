// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for the typed GRANT / REVOKE parser.
// Verify that the Snowflake GRANT / REVOKE grammar lifts from
// AstGrantShape::Unparsed / AstRevokeShape::Unparsed into typed shapes.

use lexega_syntax::ast::{
    AstCascadeMode, AstGrantObject, AstGrantShape, AstGrantee, AstObjectKind, AstObjectScope,
    AstOwnershipDisposition, AstPluralObjectKind, AstPrivilegeKind, AstRevokeShape, AstStmt,
};
use lexega_syntax::parse_sql;

fn parse_one(src: &str) -> AstStmt {
    let script = parse_sql(src).expect("parse_sql failed");
    assert_eq!(
        script.stmts.len(),
        1,
        "expected exactly one statement, got {}",
        script.stmts.len()
    );
    script.stmts.into_iter().next().unwrap()
}

fn expect_grant(stmt: AstStmt) -> Box<lexega_syntax::ast::AstGrant> {
    match stmt {
        AstStmt::Grant(g) => g,
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

#[test]
fn grant_select_on_table_to_role_typed() {
    let g = expect_grant(parse_one("GRANT SELECT ON TABLE db.s.t TO ROLE r;"));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        s => panic!("expected Privilege shape, got {:?}", s),
    };
    assert!(body.privileges.all.is_none());
    assert_eq!(body.privileges.privileges.len(), 1);
    assert_eq!(body.privileges.privileges[0].kind, AstPrivilegeKind::Select);
    assert_eq!(body.objects.len(), 1);
    match &body.objects[0] {
        AstGrantObject::Single { object_kind, .. } => {
            assert_eq!(*object_kind, AstObjectKind::Table);
        }
        o => panic!("expected Single object, got {:?}", o),
    }
    assert_eq!(body.grantees.len(), 1);
    match &body.grantees[0] {
        AstGrantee::Role {
            role_keyword_span: Some(_),
            ..
        } => {}
        g => panic!(
            "expected Role grantee with explicit ROLE keyword, got {:?}",
            g
        ),
    }
    assert!(body.with_grant_option.is_none());
}

#[test]
fn grant_multi_privileges_with_grant_option() {
    let g = expect_grant(parse_one(
        "GRANT SELECT, INSERT, UPDATE ON TABLE t TO ROLE r WITH GRANT OPTION;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        s => panic!("expected Privilege shape, got {:?}", s),
    };
    assert_eq!(body.privileges.privileges.len(), 3);
    assert_eq!(body.privileges.privileges[0].kind, AstPrivilegeKind::Select);
    assert_eq!(body.privileges.privileges[1].kind, AstPrivilegeKind::Insert);
    assert_eq!(body.privileges.privileges[2].kind, AstPrivilegeKind::Update);
    assert!(body.with_grant_option.is_some());
}

#[test]
fn grant_all_privileges_on_schema() {
    let g = expect_grant(parse_one("GRANT ALL PRIVILEGES ON SCHEMA db.s TO ROLE r;"));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        s => panic!("expected Privilege shape, got {:?}", s),
    };
    let all = body.privileges.all.expect("expected ALL privileges marker");
    assert!(all.privileges_keyword);
    assert!(body.privileges.privileges.is_empty());
    match &body.objects[0] {
        AstGrantObject::Single { object_kind, .. } => {
            assert_eq!(*object_kind, AstObjectKind::Schema);
        }
        o => panic!("expected Single Schema object, got {:?}", o),
    }
}

#[test]
fn grant_all_without_privileges_keyword() {
    let g = expect_grant(parse_one("GRANT ALL ON DATABASE db TO ROLE r;"));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    let all = body.privileges.all.expect("expected ALL marker");
    assert!(!all.privileges_keyword);
}

#[test]
fn grant_usage_on_all_tables_in_schema() {
    let g = expect_grant(parse_one(
        "GRANT USAGE ON ALL TABLES IN SCHEMA db.s TO ROLE r;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    match &body.objects[0] {
        AstGrantObject::AllInScope {
            plural_kind, scope, ..
        } => {
            assert_eq!(*plural_kind, AstPluralObjectKind::Tables);
            assert!(matches!(scope, AstObjectScope::Schema { .. }));
        }
        o => panic!("expected AllInScope, got {:?}", o),
    }
}

#[test]
fn grant_select_on_future_tables_in_database() {
    let g = expect_grant(parse_one(
        "GRANT SELECT ON FUTURE TABLES IN DATABASE db TO ROLE r;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    match &body.objects[0] {
        AstGrantObject::FutureInScope {
            plural_kind, scope, ..
        } => {
            assert_eq!(*plural_kind, AstPluralObjectKind::Tables);
            assert!(matches!(scope, AstObjectScope::Database { .. }));
        }
        o => panic!("expected FutureInScope, got {:?}", o),
    }
}

#[test]
fn grant_role_to_role() {
    let g = expect_grant(parse_one("GRANT ROLE r1 TO ROLE r2;"));
    match g.shape {
        AstGrantShape::Role(body) => {
            assert!(matches!(body.grantee, AstGrantee::Role { .. }));
        }
        s => panic!("expected Role shape, got {:?}", s),
    }
}

#[test]
fn grant_database_role() {
    let g = expect_grant(parse_one("GRANT DATABASE ROLE db.dbr TO ROLE r;"));
    match g.shape {
        AstGrantShape::DatabaseRole(_) => {}
        s => panic!("expected DatabaseRole shape, got {:?}", s),
    }
}

#[test]
fn grant_ownership_with_copy_current_grants() {
    let g = expect_grant(parse_one(
        "GRANT OWNERSHIP ON TABLE t TO ROLE r COPY CURRENT GRANTS;",
    ));
    match g.shape {
        AstGrantShape::Ownership(body) => {
            assert!(matches!(body.object, AstGrantObject::Single { .. }));
            assert!(matches!(body.grantee, AstGrantee::Role { .. }));
            assert_eq!(body.disposition, Some(AstOwnershipDisposition::Copy));
        }
        s => panic!("expected Ownership shape, got {:?}", s),
    }
}

#[test]
fn grant_ownership_with_revoke_current_grants() {
    let g = expect_grant(parse_one(
        "GRANT OWNERSHIP ON SCHEMA db.s TO ROLE r REVOKE CURRENT GRANTS;",
    ));
    match g.shape {
        AstGrantShape::Ownership(body) => {
            assert_eq!(body.disposition, Some(AstOwnershipDisposition::Revoke));
        }
        _ => panic!("expected Ownership shape"),
    }
}

#[test]
fn grant_function_signature() {
    let g = expect_grant(parse_one(
        "GRANT USAGE ON FUNCTION db.s.fn1(NUMBER, VARCHAR) TO ROLE r;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    let object = body
        .objects
        .into_iter()
        .next()
        .expect("expected one object");
    let sig = match object {
        AstGrantObject::Single {
            object_kind: AstObjectKind::Function,
            function_signature: Some(s),
            ..
        } => s,
        o => panic!("expected Single Function with signature, got {:?}", o),
    };
    assert_eq!(sig.args.len(), 2);
}

#[test]
fn grant_to_user_grantee() {
    let g = expect_grant(parse_one("GRANT USAGE ON DATABASE db TO USER u;"));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    assert!(matches!(
        body.grantees.as_slice(),
        [AstGrantee::User { .. }]
    ));
}

#[test]
fn grant_to_share_grantee() {
    let g = expect_grant(parse_one("GRANT USAGE ON DATABASE db TO SHARE s;"));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    assert!(matches!(
        body.grantees.as_slice(),
        [AstGrantee::Share { .. }]
    ));
}

#[test]
fn grant_to_group_grantee() {
    // Redshift permission group. Regression: the bare-name fallback used to
    // swallow `GROUP` as the role name and strand `analysts`. The grantee
    // must classify as Group (never collapse to Role) with the name span
    // pointing at `analysts`.
    let src = "GRANT SELECT ON public.events TO GROUP analysts;";
    let g = expect_grant(parse_one(src));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    match body.grantees.as_slice() {
        [AstGrantee::Group { name_span, .. }] => {
            assert_eq!(
                &src[name_span.start as usize..name_span.end as usize],
                "analysts"
            );
        }
        other => panic!("expected single Group grantee, got {other:?}"),
    }
}

#[test]
fn grant_imported_privileges_two_word() {
    let g = expect_grant(parse_one(
        "GRANT IMPORTED PRIVILEGES ON DATABASE shared_db TO ROLE r;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    assert_eq!(body.privileges.privileges.len(), 1);
    assert_eq!(
        body.privileges.privileges[0].kind,
        AstPrivilegeKind::ImportedPrivileges
    );
}

#[test]
fn grant_create_table_two_word_privilege() {
    let g = expect_grant(parse_one("GRANT CREATE TABLE ON SCHEMA db.s TO ROLE r;"));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    assert_eq!(body.privileges.privileges.len(), 1);
    assert_eq!(
        body.privileges.privileges[0].kind,
        AstPrivilegeKind::CreateTable
    );
}

#[test]
fn grant_apply_masking_policy_three_word_privilege() {
    let g = expect_grant(parse_one(
        "GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE r;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    assert_eq!(
        body.privileges.privileges[0].kind,
        AstPrivilegeKind::ApplyMaskingPolicy
    );
    assert!(matches!(
        body.objects.as_slice(),
        [AstGrantObject::Account { .. }]
    ));
}

#[test]
fn grant_unrecognized_privilege_falls_back_to_other() {
    let g = expect_grant(parse_one(
        "GRANT BIND SERVICE ENDPOINT ON ACCOUNT TO ROLE r;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    let priv0 = &body.privileges.privileges[0];
    match &priv0.kind {
        AstPrivilegeKind::Other { lexemes } => {
            assert_eq!(
                lexemes,
                &vec![
                    "BIND".to_string(),
                    "SERVICE".to_string(),
                    "ENDPOINT".to_string()
                ]
            );
        }
        k => panic!("expected Other privilege, got {:?}", k),
    }
}

#[test]
fn revoke_select_with_cascade() {
    let r = expect_revoke(parse_one("REVOKE SELECT ON TABLE t FROM ROLE r CASCADE;"));
    assert_eq!(r.cascade_mode, Some(AstCascadeMode::Cascade));
    assert!(r.grant_option_for.is_none());
    assert!(matches!(r.shape, AstRevokeShape::Privilege(_)));
}

#[test]
fn revoke_select_with_restrict() {
    let r = expect_revoke(parse_one("REVOKE SELECT ON TABLE t FROM ROLE r RESTRICT;"));
    assert_eq!(r.cascade_mode, Some(AstCascadeMode::Restrict));
}

#[test]
fn revoke_grant_option_for_prefix() {
    let r = expect_revoke(parse_one(
        "REVOKE GRANT OPTION FOR SELECT ON TABLE t FROM ROLE r CASCADE;",
    ));
    assert!(r.grant_option_for.is_some());
    assert_eq!(r.cascade_mode, Some(AstCascadeMode::Cascade));
    let body = match r.shape {
        AstRevokeShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    assert_eq!(body.privileges.privileges[0].kind, AstPrivilegeKind::Select);
}

#[test]
fn revoke_role_from_user() {
    let r = expect_revoke(parse_one("REVOKE ROLE r1 FROM USER u;"));
    let body = match r.shape {
        AstRevokeShape::Role(b) => b,
        s => panic!("expected Role shape, got {:?}", s),
    };
    assert!(matches!(body.grantee, AstGrantee::User { .. }));
}

#[test]
fn revoke_database_role() {
    let r = expect_revoke(parse_one("REVOKE DATABASE ROLE db.dbr FROM ROLE r;"));
    assert!(matches!(r.shape, AstRevokeShape::DatabaseRole(_)));
}

#[test]
fn grant_quoted_identifiers() {
    let g = expect_grant(parse_one(
        r#"GRANT SELECT ON TABLE "Mixed Case DB"."Mixed Schema"."My Table" TO ROLE "Quoted Role";"#,
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    // Object name span should cover the full quoted three-part name.
    match &body.objects[0] {
        AstGrantObject::Single { name_span, .. } => {
            let raw = &g.span;
            assert!(name_span.start > raw.start);
            assert!(name_span.end <= raw.end);
        }
        _ => panic!("expected Single object"),
    }
}

#[test]
fn grant_external_volume_two_word_object_kind() {
    let g = expect_grant(parse_one("GRANT USAGE ON EXTERNAL VOLUME v1 TO ROLE r;"));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    match &body.objects[0] {
        AstGrantObject::Single { object_kind, .. } => {
            assert_eq!(*object_kind, AstObjectKind::ExternalVolume);
        }
        _ => panic!("expected Single object"),
    }
}

#[test]
fn grant_row_access_policy_three_word_object_kind() {
    let g = expect_grant(parse_one(
        "GRANT APPLY ON ROW ACCESS POLICY db.s.rap1 TO ROLE r;",
    ));
    let body = match g.shape {
        AstGrantShape::Privilege(b) => b,
        _ => panic!("expected Privilege shape"),
    };
    match &body.objects[0] {
        AstGrantObject::Single { object_kind, .. } => {
            assert_eq!(*object_kind, AstObjectKind::RowAccessPolicy);
        }
        _ => panic!("expected Single object"),
    }
}

#[test]
fn grant_unparsed_falls_back_for_unknown_form() {
    // A clearly-malformed GRANT — no object, no grantee — falls back to Unparsed
    // rather than panicking.
    let g = expect_grant(parse_one("GRANT GIBBERISH NONSENSE FOO BAR;"));
    assert!(matches!(g.shape, AstGrantShape::Unparsed { .. }));
}
