// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SHOW statement typed-recognition tests: parser classification
//! (`AstShowKind` / `ShowScope` / grants subkinds) + formatter
//! round-trip safety.

use lexega_syntax::ast::{
    AstShow, AstShowKind, AstStmt, ShowGrantsObject, ShowGrantsRelation, ShowGrantsSpec,
    ShowPolicyKind, ShowPrincipalKind, ShowScope,
};
use lexega_syntax::formatter::config::FormatterConfig;
use lexega_syntax::{format_sql_with_config, parse_stmt_from_str, verify_formatting_safe};

fn show(sql: &str) -> Box<AstShow> {
    match parse_stmt_from_str(sql).unwrap_or_else(|| panic!("parse returned no statement: {sql:?}"))
    {
        AstStmt::Show(s) => s,
        other => panic!("expected SHOW for {sql:?}, got {other:?}"),
    }
}

fn grants(sql: &str) -> ShowGrantsSpec {
    match show(sql).kind {
        AstShowKind::Grants(spec) => spec,
        other => panic!("expected GRANTS for {sql:?}, got {other:?}"),
    }
}

#[test]
fn object_classes_classify() {
    assert_eq!(show("SHOW TABLES").kind, AstShowKind::Tables);
    assert_eq!(show("SHOW OBJECTS").kind, AstShowKind::Objects);
    assert_eq!(show("SHOW VIEWS").kind, AstShowKind::Views);
    assert_eq!(
        show("SHOW MATERIALIZED VIEWS").kind,
        AstShowKind::MaterializedViews
    );
    assert_eq!(
        show("SHOW EXTERNAL TABLES").kind,
        AstShowKind::ExternalTables
    );
    assert_eq!(show("SHOW DYNAMIC TABLES").kind, AstShowKind::DynamicTables);
    assert_eq!(show("SHOW COLUMNS").kind, AstShowKind::Columns);
    assert_eq!(show("SHOW DATABASES").kind, AstShowKind::Databases);
    assert_eq!(show("SHOW SCHEMAS").kind, AstShowKind::Schemas);
    assert_eq!(show("SHOW WAREHOUSES").kind, AstShowKind::Warehouses);
    assert_eq!(show("SHOW USERS").kind, AstShowKind::Users);
    assert_eq!(show("SHOW ROLES").kind, AstShowKind::Roles);
    assert_eq!(show("SHOW TASKS").kind, AstShowKind::Tasks);
    assert_eq!(show("SHOW STREAMS").kind, AstShowKind::Streams);
    assert_eq!(show("SHOW FUNCTIONS").kind, AstShowKind::Functions);
    assert_eq!(show("SHOW USER FUNCTIONS").kind, AstShowKind::Functions);
    assert_eq!(show("SHOW PRIMARY KEYS").kind, AstShowKind::PrimaryKeys);
    assert_eq!(show("SHOW FILE FORMATS").kind, AstShowKind::FileFormats);
}

#[test]
fn policy_families_classify() {
    assert_eq!(
        show("SHOW MASKING POLICIES").kind,
        AstShowKind::Policies(ShowPolicyKind::Masking)
    );
    assert_eq!(
        show("SHOW ROW ACCESS POLICIES").kind,
        AstShowKind::Policies(ShowPolicyKind::RowAccess)
    );
    assert_eq!(
        show("SHOW NETWORK POLICIES").kind,
        AstShowKind::Policies(ShowPolicyKind::Network)
    );
    assert_eq!(
        show("SHOW PASSWORD POLICIES").kind,
        AstShowKind::Policies(ShowPolicyKind::Password)
    );
}

#[test]
fn long_tail_falls_back_to_other() {
    assert_eq!(
        show("SHOW REGIONS").kind,
        AstShowKind::Other("REGIONS".to_string())
    );
    assert_eq!(
        show("SHOW LOCKS").kind,
        AstShowKind::Other("LOCKS".to_string())
    );
}

#[test]
fn in_scope_is_typed() {
    let s = show("SHOW TABLES IN ACCOUNT");
    assert_eq!(s.kind, AstShowKind::Tables);
    assert_eq!(s.scope, Some(ShowScope::Account));

    let s = show("SHOW TABLES IN DATABASE my_db");
    assert!(matches!(&s.scope, Some(ShowScope::Database(Some(n))) if n.text == "my_db"));

    let s = show("SHOW TABLES IN SCHEMA my_db.my_schema");
    assert!(matches!(&s.scope, Some(ShowScope::Schema(Some(n))) if n.text == "my_db.my_schema"));

    let s = show("SHOW COLUMNS IN TABLE my_db.my_schema.my_table");
    assert_eq!(s.kind, AstShowKind::Columns);
    assert!(matches!(&s.scope, Some(ShowScope::Table(n)) if n.text == "my_db.my_schema.my_table"));
}

#[test]
fn terse_modifier_captured() {
    let s = show("SHOW TERSE TABLES");
    assert_eq!(s.kind, AstShowKind::Tables);
    assert!(s.terse_span.is_some());
}

#[test]
fn versions_in_model_edge() {
    // VERSIONS is an uncommon class; `IN MODEL` is object-grammar, not a
    // recognized scope kind, so it lands in `ShowScope::Other`.
    let s = show("SHOW VERSIONS IN MODEL my_model");
    assert_eq!(s.kind, AstShowKind::Other("VERSIONS".to_string()));
    assert!(
        matches!(&s.scope, Some(ShowScope::Other { kind, name: Some(n) }) if kind == "MODEL" && n.text == "my_model")
    );
}

#[test]
fn grants_current_user() {
    let g = grants("SHOW GRANTS");
    assert!(!g.future);
    assert!(matches!(g.relation, ShowGrantsRelation::CurrentUser));
}

#[test]
fn grants_on_object() {
    let g = grants("SHOW GRANTS ON ACCOUNT");
    assert!(matches!(
        g.relation,
        ShowGrantsRelation::On(ShowGrantsObject::Account)
    ));

    let g = grants("SHOW GRANTS ON TABLE t");
    match g.relation {
        ShowGrantsRelation::On(ShowGrantsObject::Named { object_class, name }) => {
            assert_eq!(object_class, "TABLE");
            assert_eq!(name.text, "t");
        }
        other => panic!("expected ON TABLE, got {other:?}"),
    }
}

#[test]
fn grants_to_and_of_principal() {
    let g = grants("SHOW GRANTS TO ROLE analyst");
    match g.relation {
        ShowGrantsRelation::To(p) => {
            assert_eq!(p.kind, ShowPrincipalKind::Role);
            assert_eq!(p.name.text, "analyst");
        }
        other => panic!("expected TO ROLE, got {other:?}"),
    }

    let g = grants("SHOW GRANTS TO USER bob");
    assert!(matches!(
        &g.relation,
        ShowGrantsRelation::To(p) if p.kind == ShowPrincipalKind::User && p.name.text == "bob"
    ));

    let g = grants("SHOW GRANTS OF ROLE analyst");
    assert!(matches!(
        &g.relation,
        ShowGrantsRelation::Of(p) if p.kind == ShowPrincipalKind::Role
    ));
}

#[test]
fn future_grants() {
    let g = grants("SHOW FUTURE GRANTS IN SCHEMA s");
    assert!(g.future);
    assert!(matches!(
        &g.relation,
        ShowGrantsRelation::In(ShowScope::Schema(Some(n))) if n.text == "s"
    ));

    let g = grants("SHOW FUTURE GRANTS TO ROLE analyst");
    assert!(g.future);
    assert!(matches!(
        &g.relation,
        ShowGrantsRelation::To(p) if p.kind == ShowPrincipalKind::Role
    ));
}

#[test]
fn multi_statement_no_collision() {
    let script = lexega_syntax::parse_sql("SHOW TABLES; SHOW VIEWS; SHOW GRANTS;").expect("parse");
    let kinds: Vec<AstShowKind> = script
        .stmts
        .iter()
        .filter_map(|s| match s {
            AstStmt::Show(sh) => Some(sh.kind.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(kinds.len(), 3);
    assert_eq!(kinds[0], AstShowKind::Tables);
    assert_eq!(kinds[1], AstShowKind::Views);
    assert!(matches!(kinds[2], AstShowKind::Grants(_)));
}

fn roundtrip(sql: &str) {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("format failed for {sql:?}: {e:?}"));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("unsafe reformat of {sql:?}: {e}"));
}

#[test]
fn formatter_roundtrip_safe() {
    for sql in [
        "SHOW TABLES;",
        "SHOW TERSE MATERIALIZED VIEWS;",
        "SHOW ROW ACCESS POLICIES;",
        "SHOW TABLES LIKE 'emp%' IN SCHEMA my_db.my_schema STARTS WITH 'E' LIMIT 5 FROM 'tok';",
        "SHOW COLUMNS IN TABLE my_db.my_schema.my_table;",
        "SHOW GRANTS;",
        "SHOW GRANTS ON TABLE t;",
        "SHOW GRANTS TO ROLE analyst;",
        "SHOW FUTURE GRANTS IN SCHEMA s;",
        "SHOW VERSIONS IN MODEL my_model;",
        "SHOW TABLES; SHOW VIEWS; SHOW GRANTS;",
    ] {
        roundtrip(sql);
    }
}
