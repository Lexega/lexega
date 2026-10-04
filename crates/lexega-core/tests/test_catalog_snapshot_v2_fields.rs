// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::{
    catalog::CatalogConstraintKind, CatalogError, CatalogSnapshot, CATALOG_SCHEMA_VERSION,
};

fn write_temp_catalog_snapshot(json: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let mut path = std::env::temp_dir();
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let filename = format!(
        "lexega_catalog_snapshot_v2_fields_test_{}_{}_{}.json",
        std::process::id(),
        unique,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    path.push(filename);
    std::fs::write(&path, json).expect("should write temp catalog snapshot");
    path
}

#[test]
fn catalog_snapshot_loads_row_and_bytes_estimates_and_constraints() {
    let json = r#"{
  "schema_version": 2,
  "generated_at": "2025-01-01T00:00:00Z",
  "source": "unit-test",
  "databases": [
    {
      "name": { "name": "DB1", "case_sensitive": false },
      "schemas": [
        {
          "name": { "name": "PUBLIC", "case_sensitive": false },
          "tables": [
            {
              "name": { "name": "T1", "case_sensitive": false },
              "kind": "Table",
              "columns": [
                { "name": { "name": "ID", "case_sensitive": false }, "data_type": "NUMBER", "nullable": false },
                { "name": { "name": "EMAIL", "case_sensitive": false }, "data_type": "VARCHAR", "nullable": true }
              ],
              "row_count_estimate": 123,
              "row_count_estimate_as_of": "2025-01-02T03:04:05Z",
              "bytes_estimate": 456,
              "bytes_estimate_as_of": "2025-01-02T03:04:05Z",
              "constraints": [
                {
                  "kind": "PrimaryKey",
                  "name": "PK_T1",
                  "columns": [ { "name": "ID", "case_sensitive": false } ],
                  "enforced": false,
                  "rely": true
                },
                {
                  "kind": "ForeignKey",
                  "name": "FK_T1_REF",
                  "columns": [ { "name": "ID", "case_sensitive": false } ],
                  "ref_table": {
                    "database": { "name": "DB1", "case_sensitive": false },
                    "schema": { "name": "PUBLIC", "case_sensitive": false },
                    "name": { "name": "REF", "case_sensitive": false }
                  },
                  "ref_columns": [ { "name": "RID", "case_sensitive": false } ],
                  "enforced": null,
                  "rely": null
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}"#;

    let path = write_temp_catalog_snapshot(json);

    let snapshot = CatalogSnapshot::load_from_path(&path).expect("should load snapshot");
    assert_eq!(snapshot.schema_version, CATALOG_SCHEMA_VERSION);

    let t1 = &snapshot.databases[0].schemas[0].tables[0];
    assert_eq!(t1.row_count_estimate, Some(123));
    assert!(t1.row_count_estimate_as_of.is_some());
    assert_eq!(t1.bytes_estimate, Some(456));
    assert!(t1.bytes_estimate_as_of.is_some());

    assert_eq!(t1.constraints.len(), 2);
    assert_eq!(t1.constraints[0].kind, CatalogConstraintKind::PrimaryKey);
    assert_eq!(t1.constraints[0].name.as_deref(), Some("PK_T1"));

    // Cleanup
    let _ = std::fs::remove_file(&path);
}

#[test]
fn catalog_snapshot_rejects_non_v2_schema() {
    let json = r#"{ "schema_version": 1, "databases": [] }"#;
    let path = write_temp_catalog_snapshot(json);

    let err = CatalogSnapshot::load_from_path(&path).expect_err("should reject v1 snapshot");
    match err {
        CatalogError::SchemaVersionMismatch { expected, found } => {
            assert_eq!(expected, CATALOG_SCHEMA_VERSION);
            assert_eq!(found, 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

// Sanity check against a catalog snapshot pulled into the working directory.
#[test]
#[ignore = "reads .lexega/catalog.v2.json, which only a local catalog pull creates"]
fn local_catalog_v2_snapshot_loads_if_present() {
    let path = std::path::Path::new(".lexega/catalog.v2.json");
    if !path.is_file() {
        return;
    }

    let snapshot =
        CatalogSnapshot::load_from_path(path).expect("local catalog snapshot should load");
    assert_eq!(snapshot.schema_version, CATALOG_SCHEMA_VERSION);
    assert!(!snapshot.databases.is_empty());
}
