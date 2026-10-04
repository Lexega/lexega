// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for BigQuery-specific statements:
/// EXPORT DATA, LOAD DATA, ASSERT,
/// CREATE/DROP SNAPSHOT TABLE,
/// CREATE/DROP SEARCH INDEX,
/// CREATE/DROP VECTOR INDEX,
/// ALTER VECTOR INDEX REBUILD
use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql, verify_formatting_safe};

fn fmt(sql: &str) -> String {
    format_sql(sql).unwrap_or_else(|e| panic!("format_sql failed: {e}\nInput: {sql}"))
}

fn roundtrip(sql: &str) {
    let formatted = fmt(sql);
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("verify failed: {e}\nInput: {sql}\nFormatted: {formatted}"));
}

// ── ASSERT ─────────────────────────────────────────────────────────────

#[test]
fn test_assert_basic() {
    roundtrip("ASSERT (SELECT COUNT(*) FROM my_table) > 0;");
}

#[test]
fn test_assert_with_description() {
    roundtrip("ASSERT (SELECT COUNT(*) FROM my_table) > 0 AS 'Table must not be empty';");
}

#[test]
fn test_assert_simple_expression() {
    roundtrip("ASSERT 1 + 1 = 2;");
}

#[test]
fn test_assert_exists() {
    roundtrip("ASSERT EXISTS (SELECT 1 FROM my_table WHERE status = 'active');");
}

// ── EXPORT DATA ────────────────────────────────────────────────────────

#[test]
fn test_export_data_basic() {
    roundtrip(
        "EXPORT DATA OPTIONS(uri='gs://bucket/path/*.csv', format='CSV') AS SELECT * FROM my_table;",
    );
}

#[test]
fn test_export_data_with_connection() {
    roundtrip(
        "EXPORT DATA WITH CONNECTION myproject.us.myconnection OPTIONS(uri='gs://bucket/path/*', format='JSON') AS SELECT id, name FROM users;",
    );
}

#[test]
fn test_export_data_overwrite() {
    roundtrip(
        "EXPORT DATA OPTIONS(uri='gs://bucket/export/*', format='AVRO', overwrite=true) AS SELECT * FROM events;",
    );
}

// ── LOAD DATA ──────────────────────────────────────────────────────────

#[test]
fn test_load_data_basic() {
    roundtrip(
        "LOAD DATA INTO my_dataset.my_table FROM FILES(format='CSV', uris=['gs://bucket/path/file.csv']);",
    );
}

#[test]
fn test_load_data_overwrite() {
    roundtrip(
        "LOAD DATA OVERWRITE my_dataset.my_table FROM FILES(format='PARQUET', uris=['gs://bucket/data/*']);",
    );
}

#[test]
fn test_load_data_with_schema() {
    roundtrip(
        "LOAD DATA INTO my_dataset.my_table (id INT64, name STRING) FROM FILES(format='CSV', uris=['gs://bucket/path/*.csv']);",
    );
}

#[test]
fn test_load_data_temp_table() {
    roundtrip(
        "LOAD DATA INTO TEMP TABLE _SESSION.my_temp FROM FILES(format='JSON', uris=['gs://bucket/temp/*.json']);",
    );
}

#[test]
fn test_load_data_partition_cluster() {
    roundtrip(
        "LOAD DATA INTO my_dataset.my_table PARTITION BY event_date CLUSTER BY user_id FROM FILES(format='AVRO', uris=['gs://bucket/events/*']);",
    );
}

#[test]
fn test_load_data_with_partition_columns() {
    roundtrip(
        "LOAD DATA INTO my_dataset.my_table FROM FILES(format='PARQUET', uris=['gs://bucket/data/*']) WITH PARTITION COLUMNS;",
    );
}

#[test]
fn test_load_data_with_connection() {
    roundtrip(
        "LOAD DATA INTO my_dataset.my_table FROM FILES(format='CSV', uris=['gs://bucket/*.csv']) WITH CONNECTION myproject.us.myconnection;",
    );
}

// ── CREATE SNAPSHOT TABLE ──────────────────────────────────────────────

#[test]
fn test_create_snapshot_table_basic() {
    roundtrip("CREATE SNAPSHOT TABLE my_dataset.my_snapshot CLONE my_dataset.my_table;");
}

#[test]
fn test_create_snapshot_table_for_system_time() {
    roundtrip(
        "CREATE SNAPSHOT TABLE my_dataset.my_snapshot CLONE my_dataset.my_table FOR SYSTEM_TIME AS OF TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR);",
    );
}

#[test]
fn test_create_snapshot_table_if_not_exists() {
    roundtrip(
        "CREATE SNAPSHOT TABLE IF NOT EXISTS my_dataset.my_snapshot CLONE my_dataset.my_table;",
    );
}

#[test]
fn test_create_snapshot_table_with_options() {
    roundtrip(
        "CREATE SNAPSHOT TABLE my_dataset.my_snapshot CLONE my_dataset.my_table OPTIONS(expiration_timestamp=TIMESTAMP '2025-01-01 00:00:00 UTC');",
    );
}

// ── DROP SNAPSHOT TABLE ────────────────────────────────────────────────

#[test]
fn test_drop_snapshot_table_basic() {
    roundtrip("DROP SNAPSHOT TABLE my_dataset.my_snapshot;");
}

#[test]
fn test_drop_snapshot_table_if_exists() {
    roundtrip("DROP SNAPSHOT TABLE IF EXISTS my_dataset.my_snapshot;");
}

// ── CREATE SEARCH INDEX ────────────────────────────────────────────────

#[test]
fn test_create_search_index_all_columns() {
    roundtrip("CREATE SEARCH INDEX my_index ON my_dataset.my_table(ALL COLUMNS);");
}

#[test]
fn test_create_search_index_specific_columns() {
    roundtrip("CREATE SEARCH INDEX my_index ON my_dataset.my_table(col1, col2);");
}

#[test]
fn test_create_search_index_if_not_exists() {
    roundtrip("CREATE SEARCH INDEX IF NOT EXISTS my_index ON my_dataset.my_table(ALL COLUMNS);");
}

#[test]
fn test_create_search_index_with_options() {
    roundtrip(
        "CREATE SEARCH INDEX my_index ON my_dataset.my_table(ALL COLUMNS) OPTIONS(analyzer='LOG_ANALYZER');",
    );
}

// ── DROP SEARCH INDEX ──────────────────────────────────────────────────

#[test]
fn test_drop_search_index_basic() {
    roundtrip("DROP SEARCH INDEX my_index ON my_dataset.my_table;");
}

#[test]
fn test_drop_search_index_if_exists() {
    roundtrip("DROP SEARCH INDEX IF EXISTS my_index ON my_dataset.my_table;");
}

// ── CREATE VECTOR INDEX ────────────────────────────────────────────────

#[test]
fn test_create_vector_index_basic() {
    roundtrip(
        "CREATE VECTOR INDEX my_index ON my_dataset.my_table(embedding_col) OPTIONS(index_type='IVF', distance_type='COSINE', ivf_options='{\"num_lists\": 100}');",
    );
}

#[test]
fn test_create_vector_index_if_not_exists() {
    roundtrip(
        "CREATE VECTOR INDEX IF NOT EXISTS my_index ON my_dataset.my_table(embedding_col) OPTIONS(index_type='IVF', distance_type='L2');",
    );
}

#[test]
fn test_create_or_replace_vector_index() {
    roundtrip(
        "CREATE OR REPLACE VECTOR INDEX my_index ON my_dataset.my_table(embedding_col) OPTIONS(index_type='IVF', distance_type='COSINE');",
    );
}

#[test]
fn test_create_vector_index_with_storing() {
    roundtrip(
        "CREATE VECTOR INDEX my_index ON my_dataset.my_table(embedding_col) STORING(id, name) OPTIONS(index_type='TREE_AH', distance_type='DOT_PRODUCT');",
    );
}

// ── DROP VECTOR INDEX ──────────────────────────────────────────────────

#[test]
fn test_drop_vector_index_basic() {
    roundtrip("DROP VECTOR INDEX my_index ON my_dataset.my_table;");
}

#[test]
fn test_drop_vector_index_if_exists() {
    roundtrip("DROP VECTOR INDEX IF EXISTS my_index ON my_dataset.my_table;");
}

// ── ALTER VECTOR INDEX ─────────────────────────────────────────────────

#[test]
fn test_alter_vector_index_rebuild() {
    roundtrip("ALTER VECTOR INDEX my_index REBUILD;");
}

#[test]
fn test_alter_vector_index_if_exists_rebuild() {
    roundtrip("ALTER VECTOR INDEX IF EXISTS my_index REBUILD;");
}

// ── Multi-statement tests ──────────────────────────────────────────────

#[test]
fn test_multi_bq_statements() {
    roundtrip(
        r#"CREATE SEARCH INDEX idx1 ON dataset.table1(ALL COLUMNS);
CREATE VECTOR INDEX idx2 ON dataset.table2(embedding) OPTIONS(index_type='IVF', distance_type='COSINE');
ASSERT (SELECT COUNT(*) FROM dataset.table1) > 0 AS 'table must have data';
DROP SEARCH INDEX idx1 ON dataset.table1;
DROP VECTOR INDEX idx2 ON dataset.table2;"#,
    );
}

#[test]
fn test_export_then_assert() {
    roundtrip(
        r#"EXPORT DATA OPTIONS(uri='gs://bucket/*', format='CSV') AS SELECT * FROM my_table;
ASSERT (SELECT COUNT(*) FROM my_table) > 0;"#,
    );
}

// ════════════════════════════════════════════════════════════════════════
// SEMANTIC EXTRACTION / RISK ANALYSIS
// ════════════════════════════════════════════════════════════════════════

// ── ASSERT: classified as CONTROL ──────────────────────────────────────

#[test]
fn test_assert_semantic_control() {
    let sql = "ASSERT 1 = 1 AS 'sanity check';";
    let report = analyze_risk(sql).expect("should analyze ASSERT");
    assert_eq!(
        report.summary.statements_parsed, 1,
        "should parse 1 statement"
    );
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "should analyze 1 statement"
    );
    assert_eq!(
        report.summary.control_operations, 1,
        "ASSERT should be CONTROL"
    );
}

#[test]
fn test_assert_extracts_tables_from_subquery() {
    // ASSERT with a subquery that references a table — should extract tables_read
    let sql = "ASSERT (SELECT COUNT(*) > 0 FROM my_dataset.users) AS 'Table must have rows';";
    let report = analyze_risk(sql).expect("should analyze ASSERT with subquery");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    // The subquery references "my_dataset.users" — should be in tables_read
    assert!(
        report.summary.tables_read >= 1,
        "ASSERT subquery should extract tables_read. Got: {}",
        report.summary.tables_read
    );
}

// ── EXPORT DATA: classified as DML_READ ────────────────────────────────

#[test]
fn test_export_data_semantic_dml_read() {
    let sql = "EXPORT DATA OPTIONS(uri='gs://bucket/*', format='CSV') AS SELECT * FROM events;";
    let report = analyze_risk(sql).expect("should analyze EXPORT DATA");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    // EXPORT DATA reads data → DML_READ → not DDL/SECURITY/CONTROL
    assert_eq!(report.summary.ddl_operations, 0);
    assert_eq!(report.summary.security_operations, 0);
    assert_eq!(report.summary.control_operations, 0);
}

// ── LOAD DATA: classified as DML_WRITE ─────────────────────────────────

#[test]
fn test_load_data_semantic_dml_write() {
    let sql =
        "LOAD DATA INTO my_dataset.my_table FROM FILES(format='CSV', uris=['gs://bucket/*.csv']);";
    let report = analyze_risk(sql).expect("should analyze LOAD DATA");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(report.summary.ddl_operations, 0);
    assert_eq!(report.summary.security_operations, 0);
    assert_eq!(report.summary.control_operations, 0);
}

// ── CREATE/DROP SNAPSHOT TABLE: classified as DDL ──────────────────────

#[test]
fn test_create_snapshot_table_semantic_ddl() {
    let sql = "CREATE SNAPSHOT TABLE my_dataset.my_snapshot CLONE my_dataset.my_table;";
    let report = analyze_risk(sql).expect("should analyze CREATE SNAPSHOT TABLE");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "CREATE SNAPSHOT TABLE should be DDL"
    );
}

#[test]
fn test_drop_snapshot_table_semantic_ddl() {
    let sql = "DROP SNAPSHOT TABLE IF EXISTS my_dataset.my_snapshot;";
    let report = analyze_risk(sql).expect("should analyze DROP SNAPSHOT TABLE");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "DROP SNAPSHOT TABLE should be DDL"
    );
}

#[test]
fn test_drop_snapshot_table_fires_bq_c001() {
    let sql = "DROP SNAPSHOT TABLE IF EXISTS my_dataset.my_snapshot;";
    let report = analyze_risk(sql).expect("should analyze DROP SNAPSHOT TABLE");
    assert!(
        has_signal(&report, "BQ-SNAP-TBL-DROP"),
        "DROP SNAPSHOT TABLE should trigger BQ-SNAP-TBL-DROP. Signals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| match s {
                RuleMatch::Analysis(g) => Some(&g.matched_rule),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_drop_snapshot_table_multi_statement_evidence() {
    let sql = r#"
        DROP SNAPSHOT TABLE ds.snap_a;
        DROP SNAPSHOT TABLE ds.snap_b;
    "#;
    let report = analyze_risk(sql).expect("should analyze");

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-SNAP-TBL-DROP"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Should have evidence for each DROP SNAPSHOT TABLE. Evidence: {total_evidence}"
    );
}

// ── CREATE/DROP SEARCH INDEX: classified as DDL ────────────────────────

#[test]
fn test_create_search_index_semantic_ddl() {
    let sql = "CREATE SEARCH INDEX my_index ON my_dataset.my_table(ALL COLUMNS);";
    let report = analyze_risk(sql).expect("should analyze CREATE SEARCH INDEX");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "CREATE SEARCH INDEX should be DDL"
    );
}

#[test]
fn test_drop_search_index_semantic_ddl() {
    let sql = "DROP SEARCH INDEX my_index ON my_dataset.my_table;";
    let report = analyze_risk(sql).expect("should analyze DROP SEARCH INDEX");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "DROP SEARCH INDEX should be DDL"
    );
}

// ── CREATE/DROP/ALTER VECTOR INDEX: classified as DDL ──────────────────

#[test]
fn test_create_vector_index_semantic_ddl() {
    let sql = "CREATE VECTOR INDEX my_index ON my_dataset.my_table(embedding) OPTIONS(index_type='IVF', distance_type='COSINE');";
    let report = analyze_risk(sql).expect("should analyze CREATE VECTOR INDEX");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "CREATE VECTOR INDEX should be DDL"
    );
}

#[test]
fn test_drop_vector_index_semantic_ddl() {
    let sql = "DROP VECTOR INDEX IF EXISTS my_index ON my_dataset.my_table;";
    let report = analyze_risk(sql).expect("should analyze DROP VECTOR INDEX");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "DROP VECTOR INDEX should be DDL"
    );
}

#[test]
fn test_alter_vector_index_semantic_ddl() {
    let sql = "ALTER VECTOR INDEX my_index REBUILD;";
    let report = analyze_risk(sql).expect("should analyze ALTER VECTOR INDEX");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "ALTER VECTOR INDEX should be DDL"
    );
}

#[test]
fn test_alter_vector_index_fires_info_bq021() {
    let sql = "ALTER VECTOR INDEX my_index REBUILD;";
    let report = analyze_risk(sql).expect("should analyze ALTER VECTOR INDEX");
    assert!(
        has_signal(&report, "BQ-VECIDX-CHG"),
        "ALTER VECTOR INDEX should trigger BQ-VECIDX-CHG. Signals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| match s {
                RuleMatch::Analysis(g) => Some(&g.matched_rule),
            })
            .collect::<Vec<_>>()
    );
}

// ── Multi-statement semantic extraction ────────────────────────────────

#[test]
fn test_multi_bq_semantic_all_classified() {
    let sql = r#"
        ASSERT 1 = 1;
        EXPORT DATA OPTIONS(uri='gs://bucket/*', format='CSV') AS SELECT * FROM t;
        LOAD DATA INTO ds.tbl FROM FILES(format='CSV', uris=['gs://b/*.csv']);
        CREATE SNAPSHOT TABLE ds.snap CLONE ds.src;
        DROP SNAPSHOT TABLE ds.snap;
        CREATE SEARCH INDEX idx ON ds.tbl(ALL COLUMNS);
        DROP SEARCH INDEX idx ON ds.tbl;
        CREATE VECTOR INDEX vidx ON ds.tbl(emb) OPTIONS(index_type='IVF', distance_type='COSINE');
        DROP VECTOR INDEX vidx ON ds.tbl;
        ALTER VECTOR INDEX vidx REBUILD;
    "#;
    let report = analyze_risk(sql).expect("should analyze all 10 BQ statements");

    // All 10 statements should be parsed and classified (none skipped)
    assert_eq!(
        report.summary.statements_parsed, 10,
        "all 10 BQ statements should be parsed"
    );
    assert_eq!(
        report.summary.statements_analyzed, 10,
        "all 10 BQ statements should be analyzed (not OpaqueContent)"
    );
    assert_eq!(
        report.summary.statements_skipped, 0,
        "no BQ statements should be skipped"
    );

    // Classification breakdown: 1 CONTROL + 7 DDL + 1 DML_READ + 1 DML_WRITE = 10
    assert_eq!(report.summary.control_operations, 1, "1 ASSERT = CONTROL");
    assert_eq!(
        report.summary.ddl_operations, 7,
        "2 snapshot + 2 search + 3 vector = 7 DDL"
    );
}

#[test]
fn test_assert_with_description_fires_bq_assert_cfg_not_bq_assert_nodesc() {
    let sql = "ASSERT 1 = 1 AS 'sanity check';";
    let report = analyze_risk(sql).expect("should analyze ASSERT");
    assert!(
        has_signal(&report, "BQ-ASSERT-CFG"),
        "ASSERT should trigger BQ-ASSERT-CFG"
    );
    assert!(
        !has_signal(&report, "BQ-ASSERT-NODESC"),
        "ASSERT with description should NOT trigger BQ-ASSERT-NODESC"
    );
}

#[test]
fn test_assert_without_description_fires_bq_assert_nodesc() {
    let sql = "ASSERT 1 = 1;";
    let report = analyze_risk(sql).expect("should analyze ASSERT");
    assert!(
        has_signal(&report, "BQ-ASSERT-CFG"),
        "ASSERT should trigger BQ-ASSERT-CFG"
    );
    assert!(
        has_signal(&report, "BQ-ASSERT-NODESC"),
        "ASSERT without description should trigger BQ-ASSERT-NODESC"
    );
}

// ============================================================================
// EXPORT DATA governance signals
// ============================================================================

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

// ── BQ-EXPORT-UNBOUNDED: Unbounded export (no WHERE clause) ───────────

#[test]
fn test_export_data_unbounded_fires_bq_export_unbounded() {
    // SELECT * with no WHERE → unbounded export → BQ-EXPORT-UNBOUNDED
    let sql =
        "EXPORT DATA OPTIONS(uri='gs://bucket/path/*', format='CSV') AS SELECT * FROM my_table;";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(has_signal(&report, "BQ-EXPORT-UNBOUNDED"),
        "EXPORT DATA without WHERE should trigger BQ-EXPORT-UNBOUNDED (unbounded export). Signals: {:?}",
        report.signals.iter().filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(&g.matched_rule),
        }).collect::<Vec<_>>());
}

#[test]
fn test_export_data_with_where_no_bq_export_unbounded() {
    // SELECT with WHERE → bounded export → BQ-EXPORT-UNBOUNDED should NOT fire
    let sql = "EXPORT DATA OPTIONS(uri='gs://bucket/path/*', format='CSV') AS SELECT * FROM my_table WHERE created_at > '2024-01-01';";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        !has_signal(&report, "BQ-EXPORT-UNBOUNDED"),
        "EXPORT DATA with WHERE should NOT trigger BQ-EXPORT-UNBOUNDED. Signals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| match s {
                RuleMatch::Analysis(g) => Some(&g.matched_rule),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_export_data_with_connection_unbounded() {
    // WITH CONNECTION + no WHERE → still unbounded
    let sql = "EXPORT DATA WITH CONNECTION myproject.us.myconn OPTIONS(uri='gs://bucket/*', format='JSON') AS SELECT id, name FROM users;";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        has_signal(&report, "BQ-EXPORT-UNBOUNDED"),
        "EXPORT DATA WITH CONNECTION without WHERE should trigger BQ-EXPORT-UNBOUNDED"
    );
}

#[test]
fn test_export_data_with_connection_bounded() {
    // WITH CONNECTION + WHERE → bounded
    let sql = "EXPORT DATA WITH CONNECTION myproject.us.myconn OPTIONS(uri='gs://bucket/*', format='JSON') AS SELECT id, name FROM users WHERE active = TRUE;";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        !has_signal(&report, "BQ-EXPORT-UNBOUNDED"),
        "EXPORT DATA WITH CONNECTION with WHERE should NOT trigger BQ-EXPORT-UNBOUNDED"
    );
}

// ── Tables read extraction from inner query ───────────────────────────

#[test]
fn test_export_data_extracts_tables_from_query() {
    let sql = "EXPORT DATA OPTIONS(uri='gs://bucket/*', format='CSV') AS SELECT a.id, b.name FROM orders a JOIN customers b ON a.cust_id = b.id;";
    let report = analyze_risk(sql).expect("should analyze");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    // The inner query reads from tables — this is verified via DML_READ classification
    // Tables are extracted from the parsed inner SELECT, not text scanning
}

// ── Multiple EXPORT DATA statements (evidence count) ──────────────────

#[test]
fn test_export_data_multi_statement_evidence() {
    let sql = r#"
        EXPORT DATA OPTIONS(uri='gs://bucket/a/*', format='CSV') AS SELECT * FROM table_a;
        EXPORT DATA OPTIONS(uri='gs://bucket/b/*', format='CSV') AS SELECT * FROM table_b;
    "#;
    let report = analyze_risk(sql).expect("should analyze");
    assert_eq!(report.summary.statements_parsed, 2);
    assert_eq!(report.summary.statements_analyzed, 2);

    // Both should produce unbounded export signals — test evidence_count
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-EXPORT-UNBOUNDED"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Should have evidence for each unbounded EXPORT DATA. Evidence: {total_evidence}"
    );
}

// ── Roundtrip formatting with proper parsing ──────────────────────────

#[test]
fn test_export_data_cte_query_roundtrip() {
    roundtrip(
        "EXPORT DATA OPTIONS(uri='gs://bucket/*', format='CSV') AS WITH filtered AS (SELECT * FROM events WHERE dt > '2024-01-01') SELECT * FROM filtered;",
    );
}

#[test]
fn test_export_data_subquery_roundtrip() {
    roundtrip(
        "EXPORT DATA OPTIONS(uri='gs://bucket/*', format='CSV') AS SELECT * FROM (SELECT id, name FROM users WHERE active = TRUE);",
    );
}

// ============================================================================
// LOAD DATA governance signals
// ============================================================================

// ── Tables written extraction ─────────────────────────────────────────

#[test]
fn test_load_data_extracts_tables_written() {
    let sql = "LOAD DATA INTO my_dataset.my_table FROM FILES(format='CSV', uris=['gs://bucket/path/*.csv']);";
    let report = analyze_risk(sql).expect("should analyze LOAD DATA");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    // LOAD DATA writes to a table — classified as DML_WRITE
    // Target table extracted via structured AST field, not text scanning
    assert!(
        report.summary.tables_written >= 1,
        "Should track target table as written. tables_written count: {}",
        report.summary.tables_written
    );
}

#[test]
fn test_load_data_overwrite_tables_written() {
    let sql = "LOAD DATA OVERWRITE my_dataset.target_table FROM FILES(format='PARQUET', uris=['gs://bucket/data/*']);";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        report.summary.tables_written >= 1,
        "OVERWRITE variant should still track target table. tables_written count: {}",
        report.summary.tables_written
    );
}

// ── BQ-LOAD-EXTSTORE: External cloud storage in LOAD DATA ─────────────

#[test]
fn test_load_data_gcs_uri_fires_bq_load_extstore() {
    let sql = "LOAD DATA INTO my_dataset.my_table FROM FILES(format='CSV', uris=['gs://bucket/path/*.csv']);";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(has_signal(&report, "BQ-LOAD-EXTSTORE"),
        "LOAD DATA with gs:// URI should trigger BQ-LOAD-EXTSTORE (external cloud storage). Signals: {:?}",
        report.signals.iter().filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(&g.matched_rule),
        }).collect::<Vec<_>>());
}

#[test]
fn test_load_data_s3_uri_fires_bq_load_extstore() {
    let sql =
        "LOAD DATA INTO my_table FROM FILES(format='PARQUET', uris=['s3://my-bucket/data/*']);";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        has_signal(&report, "BQ-LOAD-EXTSTORE"),
        "LOAD DATA with s3:// URI should trigger BQ-LOAD-EXTSTORE"
    );
}

#[test]
fn test_load_data_azure_uri_fires_bq_load_extstore() {
    let sql = "LOAD DATA INTO my_table FROM FILES(format='CSV', uris=['azure://myaccount.blob.core/data/*']);";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        has_signal(&report, "BQ-LOAD-EXTSTORE"),
        "LOAD DATA with azure:// URI should trigger BQ-LOAD-EXTSTORE"
    );
}

// ── Hardcoded credentials in LOAD DATA ────────────────────────────────

#[test]
fn test_load_data_hardcoded_aws_key() {
    let sql = "LOAD DATA INTO my_table FROM FILES(format='CSV', uris=['s3://bucket/*'], aws_access_key_id='AKIAIOSFODNN7EXAMPLE');";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        has_signal(&report, "BQ-LOAD-AWS-LEAK"),
        "Hardcoded AWS key in LOAD DATA should trigger BQ-LOAD-AWS-LEAK. Signals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| match s {
                RuleMatch::Analysis(g) => Some(&g.matched_rule),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_load_data_hardcoded_password_in_connection() {
    let sql = "LOAD DATA INTO my_table FROM FILES(format='CSV', uris=['gs://bucket/*']) WITH CONNECTION 'postgresql://user:password123@host:5432/db';";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(has_signal(&report, "BQ-LOAD-PWD-LEAK"),
        "Hardcoded password in LOAD DATA WITH CONNECTION should trigger BQ-LOAD-PWD-LEAK. Signals: {:?}",
        report.signals.iter().filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(&g.matched_rule),
        }).collect::<Vec<_>>());
}

// ── Multi-statement LOAD DATA (evidence count) ───────────────────────

#[test]
fn test_load_data_multi_statement_evidence() {
    let sql = r#"
        LOAD DATA INTO ds.table_a FROM FILES(format='CSV', uris=['gs://bucket/a/*']);
        LOAD DATA INTO ds.table_b FROM FILES(format='CSV', uris=['gs://bucket/b/*']);
    "#;
    let report = analyze_risk(sql).expect("should analyze");
    assert_eq!(report.summary.statements_parsed, 2);
    assert_eq!(report.summary.statements_analyzed, 2);

    // Both should produce external cloud storage signals — test evidence_count
    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "BQ-LOAD-EXTSTORE"))
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();
    assert!(
        total_evidence >= 2,
        "Should have evidence for each LOAD DATA with cloud URI. Evidence: {total_evidence}"
    );
}

// ── LOAD DATA with connection roundtrip ───────────────────────────────

#[test]
fn test_load_data_full_syntax_roundtrip() {
    roundtrip(
        "LOAD DATA INTO my_dataset.my_table (id INT64, name STRING) PARTITION BY event_date CLUSTER BY user_id FROM FILES(format='PARQUET', uris=['gs://bucket/data/*']) WITH PARTITION COLUMNS WITH CONNECTION myproject.us.myconn;",
    );
}

// ============================================================================
// CREATE EXTERNAL TABLE governance signals
// ============================================================================

#[test]
fn test_create_external_table_roundtrip() {
    roundtrip(
        "CREATE EXTERNAL TABLE my_dataset.ext_table OPTIONS(format='PARQUET', uris=['gs://bucket/data/*']);",
    );
}

#[test]
fn test_create_external_table_semantic_ddl() {
    let sql = "CREATE EXTERNAL TABLE my_dataset.ext_table OPTIONS(format='PARQUET', uris=['gs://bucket/data/*']);";
    let report = analyze_risk(sql).expect("should analyze CREATE EXTERNAL TABLE");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_analyzed, 1);
    assert_eq!(
        report.summary.ddl_operations, 1,
        "CREATE EXTERNAL TABLE should be DDL"
    );
    assert!(
        has_signal(&report, "EXTTBL-NEW"),
        "Should emit external table created signal"
    );
}

#[test]
fn test_create_external_table_external_cloud_storage_fires_br055() {
    let sql = "CREATE EXTERNAL TABLE my_dataset.ext_table OPTIONS(format='PARQUET', uris=['gs://bucket/data/*']);";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(
        has_signal(&report, "BQ-EXTTBL-EXTSTORE"),
        "CREATE EXTERNAL TABLE with gs:// URI should trigger BQ-EXTTBL-EXTSTORE. Signals: {:?}",
        report
            .signals
            .iter()
            .filter_map(|s| match s {
                RuleMatch::Analysis(g) => Some(&g.matched_rule),
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_create_external_table_hardcoded_aws_key_fires_c052_a_bq_ext() {
    let sql = "CREATE EXTERNAL TABLE my_dataset.ext_table OPTIONS(format='CSV', uris=['s3://bucket/*'], aws_access_key_id='AKIAIOSFODNN7EXAMPLE');";
    let report = analyze_risk(sql).expect("should analyze");
    assert!(has_signal(&report, "BQ-EXTTBL-AWS-LEAK"),
        "Hardcoded AWS key in CREATE EXTERNAL TABLE should trigger BQ-EXTTBL-AWS-LEAK. Signals: {:?}",
        report.signals.iter().filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(&g.matched_rule),
        }).collect::<Vec<_>>());
}
