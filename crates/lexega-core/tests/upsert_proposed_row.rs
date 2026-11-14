// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A column read through the row an upsert proposes is a column of the
//! upsert's target: the catalog is asked whether the target has it.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::{
    analyze_query_facts_with_catalog, analyze_risk_with_policy_config_and_catalog_index,
};
use lexega_core::catalog::{
    CatalogColumn, CatalogDatabase, CatalogIdent, CatalogSchema, CatalogSnapshot, CatalogTable,
    CatalogTableKind, CATALOG_SCHEMA_VERSION,
};
use lexega_core::CatalogIndex;

fn ident(name: &str) -> CatalogIdent {
    CatalogIdent {
        name: name.to_string(),
    }
}

/// `TEST_DB.PUBLIC.USERS (ID, EMAIL)`.
fn users_catalog() -> CatalogIndex {
    let column = |name: &str| CatalogColumn {
        name: ident(name),
        data_type: Some("VARCHAR".to_string()),
        nullable: Some(true),
        tags: vec![],
    };
    let snapshot = CatalogSnapshot {
        schema_version: CATALOG_SCHEMA_VERSION,
        listing: lexega_core::catalog::CatalogListing::Inventory,
        generated_at: None,
        source: Some("unit-test".to_string()),
        policies: vec![],
        policy_references: vec![],
        grants: None,
        provider: None,
        databases: vec![CatalogDatabase {
            name: ident("TEST_DB"),
            schemas: vec![CatalogSchema {
                name: ident("PUBLIC"),
                tables: vec![CatalogTable {
                    name: ident("USERS"),
                    kind: CatalogTableKind::Table,
                    columns: vec![column("ID"), column("EMAIL")],
                    row_count_estimate: None,
                    row_count_estimate_as_of: None,
                    bytes_estimate: None,
                    bytes_estimate_as_of: None,
                    constraints: vec![],
                    comment: None,
                    tags: vec![],
                }],
            }],
        }],
    };
    CatalogIndex::from_snapshot(snapshot).expect("valid snapshot")
}

fn rule_ids(sql: &str) -> Vec<String> {
    analyze_query_facts_with_catalog(sql, &users_catalog())
        .expect("analyzes")
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

fn mysql_rule_ids(sql: &str) -> Vec<String> {
    let config = AnalysisConfig {
        trace_mode: true,
        dialect: Some(lexega_core::dialect::mysql()),
        ..Default::default()
    };
    analyze_risk_with_policy_config_and_catalog_index(sql, &config, &users_catalog())
        .expect("analyzes")
        .findings
        .iter()
        .filter_map(|finding| finding.rule_id().map(String::from))
        .collect()
}

const UNKNOWN: &str = "CAT-COL-UNKNOWN";

#[test]
fn a_proposed_column_the_target_lacks_is_reported() {
    for sql in [
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') \
         ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.nope",
        // With no column list, and with a column list that names it.
        "INSERT INTO test_db.public.users VALUES (1, 'a') \
         ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.nope",
        "INSERT INTO test_db.public.users (id, nope) VALUES (1, 'a') \
         ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.nope",
        // In the action's WHERE and in a query nested in the action.
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') \
         ON CONFLICT (id) DO UPDATE SET email = 'b' WHERE EXCLUDED.nope IS NULL",
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') \
         ON CONFLICT (id) DO UPDATE SET email = (SELECT EXCLUDED.nope)",
    ] {
        let ids = rule_ids(sql);
        assert!(ids.iter().any(|id| id == UNKNOWN), "{sql}: {ids:?}");
    }
}

#[test]
fn a_proposed_column_the_target_has_is_not_reported() {
    for sql in [
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') \
         ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email",
        // A column the INSERT does not write, and no column list.
        "INSERT INTO test_db.public.users (id) VALUES (1) \
         ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email",
        "INSERT INTO test_db.public.users VALUES (1, 'a') \
         ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email RETURNING email",
    ] {
        let ids = rule_ids(sql);
        assert!(!ids.iter().any(|id| id == UNKNOWN), "{sql}: {ids:?}");
    }
}

#[test]
fn a_mysql_proposed_row_is_checked_by_alias_and_by_values() {
    for sql in [
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') AS new \
         ON DUPLICATE KEY UPDATE email = new.nope",
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') \
         ON DUPLICATE KEY UPDATE email = VALUES(nope)",
        // `VALUES` takes a column of the target, not a name of the list.
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') AS new (m, n) \
         ON DUPLICATE KEY UPDATE email = VALUES(m)",
    ] {
        let ids = mysql_rule_ids(sql);
        assert!(ids.iter().any(|id| id == UNKNOWN), "{sql}: {ids:?}");
    }
    for sql in [
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') AS new \
         ON DUPLICATE KEY UPDATE email = new.email",
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') \
         ON DUPLICATE KEY UPDATE email = VALUES(email)",
        // A row alias's column list names the written columns, read
        // through the alias or bare.
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') AS new (i, e) \
         ON DUPLICATE KEY UPDATE email = new.e",
        "INSERT INTO test_db.public.users (id, email) VALUES (1, 'a') AS new (m, n) \
         ON DUPLICATE KEY UPDATE email = m + n",
        // With no column list the names are columns of no table.
        "INSERT INTO test_db.public.users VALUES (1, 'a') AS new (m, n) \
         ON DUPLICATE KEY UPDATE email = n",
    ] {
        let ids = mysql_rule_ids(sql);
        assert!(!ids.iter().any(|id| id == UNKNOWN), "{sql}: {ids:?}");
    }
}
