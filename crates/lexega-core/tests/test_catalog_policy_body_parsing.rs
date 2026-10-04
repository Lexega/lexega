// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for catalog policy body table extraction
//!
//! This tests the feature that parses policy bodies to extract table dependencies.

use lexega_core::catalog::extract_tables_from_policy_body;

#[test]
fn test_extract_tables_from_exists_subquery() {
    // Typical row access policy body
    let body = "EXISTS (SELECT 1 FROM security.admin_users WHERE user_id = current_user())";
    let tables = extract_tables_from_policy_body(body);

    assert_eq!(tables.len(), 1, "Should find one table reference");
    assert_eq!(tables[0].name.name, "admin_users");
    assert_eq!(tables[0].schema.name, "security");
}

#[test]
fn test_extract_tables_from_case_with_exists() {
    // Typical masking policy body
    let body = r#"CASE 
        WHEN current_role() IN ('ADMIN', 'DBA') THEN val 
        WHEN EXISTS (SELECT 1 FROM lookup.authorized_viewers WHERE email = current_user()) THEN val
        ELSE '***MASKED***' 
    END"#;

    let tables = extract_tables_from_policy_body(body);

    assert_eq!(tables.len(), 1, "Should find one table reference");
    assert_eq!(tables[0].name.name, "authorized_viewers");
    assert_eq!(tables[0].schema.name, "lookup");
}

#[test]
fn test_extract_multiple_tables_from_complex_body() {
    // Complex policy body with multiple table references
    let body = r#"CASE 
        WHEN EXISTS (SELECT 1 FROM security.admins WHERE id = current_user()) THEN val 
        WHEN EXISTS (SELECT 1 FROM access.group_members gm JOIN access.groups g ON gm.group_id = g.id WHERE g.name = 'viewers') THEN val
        ELSE NULL 
    END"#;

    let tables = extract_tables_from_policy_body(body);

    // Should find: security.admins, access.group_members, access.groups
    assert!(
        tables.len() >= 2,
        "Should find at least 2 table references, found: {:?}",
        tables
    );
}

#[test]
fn test_extract_tables_from_simple_boolean() {
    // Simple boolean policy body
    let body = "current_role() IN ('ADMIN')";
    let tables = extract_tables_from_policy_body(body);

    // No tables in this body
    assert!(tables.is_empty(), "Should find no table references");
}

#[test]
fn test_extract_tables_from_fully_qualified() {
    // Fully qualified table name - policy args are bare identifiers per Snowflake docs
    let body =
        "EXISTS (SELECT 1 FROM prod_db.analytics.user_permissions WHERE user_id = current_user())";
    let tables = extract_tables_from_policy_body(body);

    assert_eq!(tables.len(), 1, "Should find one table reference");
    assert_eq!(tables[0].name.name, "user_permissions");
    assert_eq!(tables[0].schema.name, "analytics");
    assert_eq!(tables[0].database.name, "prod_db");
}

#[test]
fn test_enrich_policy_dependencies() {
    use lexega_core::catalog::{
        enrich_policy_dependencies, CatalogIdent, CatalogObjectName, CatalogPolicy,
        CatalogPolicyKind, CatalogSnapshot,
    };

    let mut snapshot = CatalogSnapshot {
        schema_version: lexega_core::CATALOG_SCHEMA_VERSION,
        generated_at: None,
        source: Some("test".to_string()),
        databases: vec![],
        policies: vec![CatalogPolicy {
            name: CatalogObjectName {
                database: CatalogIdent::from_name("DB"),
                schema: CatalogIdent::from_name("SCHEMA"),
                name: CatalogIdent::from_name("TEST_POLICY"),
            },
            kind: CatalogPolicyKind::RowAccessPolicy,
            body: Some("EXISTS (SELECT 1 FROM security.users WHERE id = user_id)".to_string()),
            ddl: None,
            signature: None,
            return_type: None,
            body_table_dependencies: vec![], // Initially empty
            comment: None,
            created_at: None,
            last_modified_at: None,
            owner: None,
        }],
        policy_references: vec![],
        grants: None,
        provider: None,
    };

    // Before enrichment
    assert!(snapshot.policies[0].body_table_dependencies.is_empty());

    // Enrich
    enrich_policy_dependencies(&mut snapshot);

    // After enrichment - should have the table dependency
    assert!(
        !snapshot.policies[0].body_table_dependencies.is_empty(),
        "Should have extracted table dependencies"
    );
    assert_eq!(
        snapshot.policies[0].body_table_dependencies[0].name.name,
        "users"
    );
}
