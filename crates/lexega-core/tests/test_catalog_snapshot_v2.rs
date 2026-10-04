// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::CatalogSnapshot;

fn write_temp_catalog_snapshot(json: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let mut path = std::env::temp_dir();
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let filename = format!(
        "lexega_catalog_snapshot_v2_test_{}_{}_{}.json",
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
fn catalog_loads_schema_v2_with_stats_and_constraints() {
    let catalog_json = r#"{
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
              "name": { "name": "PARENT", "case_sensitive": false },
              "kind": "Table",
              "row_count_estimate": 10,
              "row_count_estimate_as_of": "2025-01-01T00:00:00Z",
              "bytes_estimate": 1234,
              "bytes_estimate_as_of": "2025-01-01T00:00:00Z",
              "constraints": [
                {
                  "kind": "PrimaryKey",
                  "name": "PK_PARENT",
                  "columns": [ { "name": "ID", "case_sensitive": false } ],
                  "enforced": true,
                  "rely": false
                }
              ],
              "columns": [
                { "name": { "name": "ID", "case_sensitive": false }, "data_type": "NUMBER", "nullable": false }
              ]
            },
            {
              "name": { "name": "CHILD", "case_sensitive": false },
              "kind": "Table",
              "constraints": [
                {
                  "kind": "ForeignKey",
                  "name": "FK_CHILD_PARENT",
                  "columns": [ { "name": "PARENT_ID", "case_sensitive": false } ],
                  "ref_table": {
                    "database": { "name": "DB1", "case_sensitive": false },
                    "schema": { "name": "PUBLIC", "case_sensitive": false },
                    "name": { "name": "PARENT", "case_sensitive": false }
                  },
                  "ref_columns": [ { "name": "ID", "case_sensitive": false } ]
                }
              ],
              "columns": [
                { "name": { "name": "PARENT_ID", "case_sensitive": false }, "data_type": "NUMBER", "nullable": false }
              ]
            }
          ]
        }
      ]
    }
  ]
}"#;

    let path = write_temp_catalog_snapshot(catalog_json);
    let snapshot = CatalogSnapshot::load_from_path(&path).expect("should load v2 snapshot");

    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.databases.len(), 1);
    assert_eq!(snapshot.databases[0].schemas.len(), 1);
    assert_eq!(snapshot.databases[0].schemas[0].tables.len(), 2);

    let parent = &snapshot.databases[0].schemas[0].tables[0];
    assert!(parent.row_count_estimate.is_some());
    assert!(parent.bytes_estimate.is_some());
    assert_eq!(parent.constraints.len(), 1);

    let _ = std::fs::remove_file(&path);
}
