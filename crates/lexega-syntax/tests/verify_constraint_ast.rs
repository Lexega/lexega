// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::ast::{AstConstraintKind, AstStmt};
use lexega_syntax::parse_sql;

#[test]
fn test_primary_key_parses_successfully() {
    let src = "CREATE TABLE t (id NUMBER, CONSTRAINT pk PRIMARY KEY (id))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    // Check that details were parsed
    assert!(
        constraint.details.is_some(),
        "PRIMARY KEY should parse successfully"
    );

    let details = constraint.details.as_ref().unwrap();

    // Check constraint name
    assert!(details.name.is_some(), "CONSTRAINT pk should have name");
    let name_span = details.name.unwrap();
    assert_eq!(&src[name_span.start as usize..name_span.end as usize], "pk");

    // Check constraint kind
    match &details.kind {
        AstConstraintKind::PrimaryKey { columns } => {
            assert_eq!(columns.len(), 1);
            let col_span = columns[0];
            assert_eq!(&src[col_span.start as usize..col_span.end as usize], "id");
        }
        _ => panic!("Expected PrimaryKey variant"),
    }
}

#[test]
fn test_primary_key_multi_column() {
    let src = "CREATE TABLE t (a INT, b INT, PRIMARY KEY (a, b))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    assert!(constraint.details.is_some());
    let details = constraint.details.as_ref().unwrap();

    // No explicit constraint name
    assert!(details.name.is_none());

    match &details.kind {
        AstConstraintKind::PrimaryKey { columns } => {
            assert_eq!(columns.len(), 2);
            assert_eq!(
                &src[columns[0].start as usize..columns[0].end as usize],
                "a"
            );
            assert_eq!(
                &src[columns[1].start as usize..columns[1].end as usize],
                "b"
            );
        }
        _ => panic!("Expected PrimaryKey variant"),
    }
}

#[test]
fn test_unique_constraint_parses() {
    let src = "CREATE TABLE t (email VARCHAR, UNIQUE (email))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    assert!(constraint.details.is_some());
    let details = constraint.details.as_ref().unwrap();

    match &details.kind {
        AstConstraintKind::Unique { columns } => {
            assert_eq!(columns.len(), 1);
            assert_eq!(
                &src[columns[0].start as usize..columns[0].end as usize],
                "email"
            );
        }
        _ => panic!("Expected Unique variant"),
    }
}

#[test]
fn test_unique_named_constraint() {
    let src = "CREATE TABLE t (a INT, b INT, CONSTRAINT uniq_ab UNIQUE (a, b))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    assert!(constraint.details.is_some());
    let details = constraint.details.as_ref().unwrap();

    // Check constraint name
    assert!(details.name.is_some());
    let name_span = details.name.unwrap();
    assert_eq!(
        &src[name_span.start as usize..name_span.end as usize],
        "uniq_ab"
    );

    match &details.kind {
        AstConstraintKind::Unique { columns } => {
            assert_eq!(columns.len(), 2);
        }
        _ => panic!("Expected Unique variant"),
    }
}

#[test]
fn test_foreign_key_parses() {
    let src = "CREATE TABLE t (user_id INT, FOREIGN KEY (user_id) REFERENCES users (id))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    assert!(constraint.details.is_some());
    let details = constraint.details.as_ref().unwrap();

    match &details.kind {
        AstConstraintKind::ForeignKey {
            columns,
            references_table,
            references_columns,
        } => {
            assert_eq!(columns.len(), 1);
            assert_eq!(
                &src[columns[0].start as usize..columns[0].end as usize],
                "user_id"
            );

            assert_eq!(
                &src[references_table.start as usize..references_table.end as usize],
                "users"
            );

            assert_eq!(references_columns.len(), 1);
            assert_eq!(
                &src[references_columns[0].start as usize..references_columns[0].end as usize],
                "id"
            );
        }
        _ => panic!("Expected ForeignKey variant"),
    }
}

#[test]
fn test_foreign_key_named_multi_column() {
    let src = "CREATE TABLE orders (cust_id INT, prod_id INT, CONSTRAINT fk_order FOREIGN KEY (cust_id, prod_id) REFERENCES products (customer_id, product_id))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    assert!(constraint.details.is_some());
    let details = constraint.details.as_ref().unwrap();

    // Check name
    assert!(details.name.is_some());
    let name_span = details.name.unwrap();
    assert_eq!(
        &src[name_span.start as usize..name_span.end as usize],
        "fk_order"
    );

    match &details.kind {
        AstConstraintKind::ForeignKey {
            columns,
            references_table,
            references_columns,
        } => {
            assert_eq!(columns.len(), 2);
            assert_eq!(
                &src[columns[0].start as usize..columns[0].end as usize],
                "cust_id"
            );
            assert_eq!(
                &src[columns[1].start as usize..columns[1].end as usize],
                "prod_id"
            );

            assert_eq!(
                &src[references_table.start as usize..references_table.end as usize],
                "products"
            );

            assert_eq!(references_columns.len(), 2);
            assert_eq!(
                &src[references_columns[0].start as usize..references_columns[0].end as usize],
                "customer_id"
            );
            assert_eq!(
                &src[references_columns[1].start as usize..references_columns[1].end as usize],
                "product_id"
            );
        }
        _ => panic!("Expected ForeignKey variant"),
    }
}

#[test]
fn test_foreign_key_qualified_table_name() {
    let src = "CREATE TABLE t (id INT, FOREIGN KEY (id) REFERENCES db.schema.users (id))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    assert!(constraint.details.is_some());
    let details = constraint.details.as_ref().unwrap();

    match &details.kind {
        AstConstraintKind::ForeignKey {
            references_table, ..
        } => {
            assert_eq!(
                &src[references_table.start as usize..references_table.end as usize],
                "db.schema.users"
            );
        }
        _ => panic!("Expected ForeignKey variant"),
    }
}

#[test]
fn test_multiple_constraints_in_one_table() {
    let src = "CREATE TABLE t (id INT, email VARCHAR, CONSTRAINT pk PRIMARY KEY (id), CONSTRAINT uniq_email UNIQUE (email))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 2);

    // First constraint: PRIMARY KEY
    let constraint1 = &ct.constraints[0];
    assert!(constraint1.details.is_some());
    let details1 = constraint1.details.as_ref().unwrap();
    assert!(matches!(
        details1.kind,
        AstConstraintKind::PrimaryKey { .. }
    ));

    // Second constraint: UNIQUE
    let constraint2 = &ct.constraints[1];
    assert!(constraint2.details.is_some());
    let details2 = constraint2.details.as_ref().unwrap();
    assert!(matches!(details2.kind, AstConstraintKind::Unique { .. }));
}

#[test]
fn test_constraint_span_still_valid() {
    let src = "CREATE TABLE t (id INT, CONSTRAINT pk PRIMARY KEY (id))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    // Verify full_span covers entire constraint
    let full_text = &src[constraint.full_span.start as usize..constraint.full_span.end as usize];
    assert_eq!(full_text, "CONSTRAINT pk PRIMARY KEY (id)");
}

#[test]
fn test_check_constraint_falls_back_to_span() {
    let src = "CREATE TABLE t (age INT, CHECK (age > 0))";

    let script = parse_sql(src).expect("script");
    let ct = match &script.stmts[0] {
        AstStmt::CreateTable(ct) => ct,
        _ => panic!("expected CREATE TABLE"),
    };

    assert_eq!(ct.constraints.len(), 1);
    let constraint = &ct.constraints[0];

    // CHECK constraints should fall back to span-only (details = None)
    assert!(
        constraint.details.is_none(),
        "CHECK constraints should not be parsed yet"
    );

    // But full_span should still be valid
    let full_text = &src[constraint.full_span.start as usize..constraint.full_span.end as usize];
    assert_eq!(full_text, "CHECK (age > 0)");
}
