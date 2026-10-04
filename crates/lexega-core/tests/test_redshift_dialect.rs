// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Amazon Redshift dialect: tokenization, parsing, and format round-trip tests.
//!
//! Redshift is forked from PostgreSQL 8.0.2 but diverges on its reserved-word
//! list, capability flags, and bulk-I/O vocabulary. These tests exercise real
//! Redshift SQL end-to-end through the dialect-aware production entrypoints.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect::redshift, format_sql_with_config, parse_sql_with_dialect,
    verify_formatting_safe_with_dialect, AstStmt, FormatterConfig,
};

/// Rule IDs fired by analyzing `sql` under the Redshift dialect.
fn rs_rule_ids(sql: &str) -> Vec<String> {
    let cfg = AnalysisConfig {
        dialect: Some(redshift()),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("analysis should succeed");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(g)| g.matched_rule.clone())
        .collect()
}

fn rs_config() -> FormatterConfig {
    FormatterConfig {
        dialect: redshift(),
        ..Default::default()
    }
}

/// Format with the Redshift dialect and assert the round-trip preserves semantics.
fn format_and_verify(sql: &str) -> String {
    let config = rs_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref()).unwrap_or_else(
        |e| {
            panic!(
                "Round-trip unsafe:\n{}\n→\n{}\nError: {}",
                sql, formatted, e
            )
        },
    );
    formatted
}

/// Assert every statement parses to a concrete AST variant (no OpaqueContent fallback).
fn assert_no_opaque(sql: &str) {
    let script =
        parse_sql_with_dialect(sql, redshift().as_ref()).expect("Redshift SQL should parse");
    for stmt in &script.stmts {
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
}

#[test]
fn test_basic_select_roundtrip() {
    format_and_verify("SELECT 1;");
    format_and_verify("SELECT id, name FROM users WHERE id = 1;");
}

#[test]
fn test_create_table_with_distribution_and_sort_keys() {
    let sql = "CREATE TABLE sales (\n  id BIGINT IDENTITY(1,1),\n  region VARCHAR(20) ENCODE lzo,\n  amount DECIMAL(18,2) ENCODE az64,\n  ts TIMESTAMP\n)\nDISTSTYLE KEY\nDISTKEY (region)\nCOMPOUND SORTKEY (ts, region);";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_interleaved_sortkey() {
    let sql = "CREATE TABLE t (a INT, b INT) DISTSTYLE EVEN INTERLEAVED SORTKEY (a, b);";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_materialized_view() {
    let sql = "CREATE MATERIALIZED VIEW mv_sales AS SELECT region, SUM(amount) FROM sales GROUP BY region;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_late_binding_view() {
    // Late-binding views reference tables that may not exist at creation time;
    // the WITH NO SCHEMA BINDING suffix follows the AS query.
    let sql = "CREATE VIEW v_sales AS SELECT * FROM spectrum.ext_sales WITH NO SCHEMA BINDING;";
    assert_no_opaque(sql);
    let out = format_and_verify(sql);
    assert!(
        out.to_uppercase().contains("WITH NO SCHEMA BINDING"),
        "late-binding marker dropped:\n{}",
        out
    );
}

#[test]
fn test_late_binding_does_not_break_cte() {
    // A leading CTE WITH inside the view body must NOT be mistaken for the
    // trailing late-binding clause.
    let sql = "CREATE VIEW v AS WITH c AS (SELECT 1 AS x) SELECT x FROM c;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_grant_to_group() {
    let sql = "GRANT SELECT ON sales TO GROUP analysts;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_vacuum_and_analyze() {
    assert_no_opaque("VACUUM FULL sales;");
    assert_no_opaque("ANALYZE sales;");
    format_and_verify("VACUUM FULL sales;");
    format_and_verify("ANALYZE sales;");
}

#[test]
fn test_alter_table_append() {
    let sql = "ALTER TABLE sales APPEND FROM sales_staging;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_plpgsql_procedure_with_dollar_body() {
    let sql = "CREATE PROCEDURE update_sales(amt DECIMAL) AS $$ BEGIN UPDATE sales SET amount = amt; END; $$ LANGUAGE plpgsql;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_type_cast_and_concat_operators() {
    // :: cast and || concat are both supported in Redshift.
    let sql = "SELECT (a || b)::VARCHAR FROM t;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_window_function() {
    let sql = "SELECT region, SUM(amount) OVER (PARTITION BY region) FROM sales;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_unload_parses_and_roundtrips() {
    let sql = "UNLOAD ('SELECT * FROM sales') TO 's3://bucket/out/' IAM_ROLE 'arn:aws:iam::123456789012:role/MyRole' PARALLEL OFF ALLOWOVERWRITE;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_unload_inline_credentials_flagged() {
    // Hardcoded AWS keys in an UNLOAD CREDENTIALS blob must surface the same
    // credential-exposure findings as Snowflake COPY INTO <location>.
    let sql = "UNLOAD ('SELECT 1') TO 's3://b/o/' CREDENTIALS 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE;aws_secret_access_key=wJalrXUtnFEMI';";
    assert_no_opaque(sql);
    let ids = rs_rule_ids(sql);
    assert!(ids.contains(&"CRED-AWS-LEAK".to_string()), "ids={:?}", ids);
    // The secret half is AWS credential material too, so it is owned by
    // CRED-AWS-LEAK — one AWS finding, not an AWS + password double-count.
    assert!(!ids.contains(&"CRED-PWD-LEAK".to_string()), "ids={:?}", ids);
}

#[test]
fn test_unload_modern_credentials_flagged() {
    let sql = "UNLOAD ('SELECT 1') TO 's3://b/o/' ACCESS_KEY_ID 'AKIAIOSFODNN7EXAMPLE' SECRET_ACCESS_KEY 'wJalrXUtnFEMI';";
    let ids = rs_rule_ids(sql);
    assert!(ids.contains(&"CRED-AWS-LEAK".to_string()), "ids={:?}", ids);
}

#[test]
fn test_unload_iam_role_is_not_flagged() {
    // IAM_ROLE is the secure form — it must NOT trip the hardcoded-key rules.
    let sql =
        "UNLOAD ('SELECT 1') TO 's3://b/o/' IAM_ROLE 'arn:aws:iam::123456789012:role/MyRole';";
    assert_no_opaque(sql);
    let ids = rs_rule_ids(sql);
    assert!(!ids.contains(&"CRED-AWS-LEAK".to_string()), "ids={:?}", ids);
    assert!(!ids.contains(&"CRED-PWD-LEAK".to_string()), "ids={:?}", ids);
}

#[test]
fn test_multi_statement_roundtrip() {
    let sql = "CREATE TABLE t (id INT) DISTSTYLE ALL;\nINSERT INTO t VALUES (1);\nSELECT * FROM t;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

// ───────────────────────── COPY (bulk load) ─────────────────────────

#[test]
fn test_redshift_copy_parses_and_roundtrips() {
    let sql = "COPY users FROM 's3://bucket/p' IAM_ROLE 'arn:aws:iam::123456789012:role/MyRole' REGION 'us-east-1' GZIP FORMAT AS PARQUET;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_redshift_copy_inline_credentials_flagged() {
    // Hardcoded AWS keys in a COPY CREDENTIALS blob must surface the same
    // credential-exposure findings as UNLOAD / COPY INTO <location>.
    let sql = "COPY users FROM 's3://b/p' CREDENTIALS 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE;aws_secret_access_key=wJalrXUtnFEMI';";
    assert_no_opaque(sql);
    let ids = rs_rule_ids(sql);
    assert!(ids.contains(&"CRED-AWS-LEAK".to_string()), "ids={:?}", ids);
    // Secret half is AWS credential material → owned by CRED-AWS-LEAK, so no
    // AWS + password double-count.
    assert!(!ids.contains(&"CRED-PWD-LEAK".to_string()), "ids={:?}", ids);
}

#[test]
fn test_redshift_copy_modern_credentials_flagged() {
    let sql = "COPY users FROM 's3://b/p' ACCESS_KEY_ID 'AKIAIOSFODNN7EXAMPLE' SECRET_ACCESS_KEY 'wJalrXUtnFEMI';";
    let ids = rs_rule_ids(sql);
    assert!(ids.contains(&"CRED-AWS-LEAK".to_string()), "ids={:?}", ids);
}

#[test]
fn test_redshift_copy_iam_role_is_not_flagged() {
    // IAM_ROLE is the secure form — an ARN is not a hardcoded key.
    let sql = "COPY users FROM 's3://b/p' IAM_ROLE 'arn:aws:iam::123456789012:role/MyRole';";
    assert_no_opaque(sql);
    let ids = rs_rule_ids(sql);
    assert!(!ids.contains(&"CRED-AWS-LEAK".to_string()), "ids={:?}", ids);
    assert!(!ids.contains(&"CRED-PWD-LEAK".to_string()), "ids={:?}", ids);
}

// ───────────────────── CREATE / ALTER GROUP ─────────────────────

#[test]
fn test_create_group_parses() {
    let sql = "CREATE GROUP analysts;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_alter_group_membership_parses() {
    assert_no_opaque("ALTER GROUP analysts ADD USER analyst;");
    assert_no_opaque("ALTER GROUP analysts DROP USER analyst;");
    assert_no_opaque("ALTER GROUP analysts RENAME TO data_team;");
    format_and_verify("ALTER GROUP analysts ADD USER analyst;");
}

// ───────────────────── VACUUM / ANALYZE modes ─────────────────────

#[test]
fn test_vacuum_redshift_modes() {
    for sql in [
        "VACUUM DELETE ONLY sales;",
        "VACUUM SORT ONLY sales;",
        "VACUUM REINDEX sales;",
        "VACUUM RECLUSTER sales;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_analyze_compression() {
    assert_no_opaque("ANALYZE COMPRESSION sales;");
    format_and_verify("ANALYZE COMPRESSION sales;");
    // Plain ANALYZE still works.
    assert_no_opaque("ANALYZE sales;");
    format_and_verify("ANALYZE sales;");
}

#[test]
fn test_alter_table_add_column_encode() {
    let sql = "ALTER TABLE sales ADD COLUMN note VARCHAR(100) ENCODE zstd;";
    assert_no_opaque(sql);
    // Round-trip preserves the ENCODE attribute (semantic safety verified).
    format_and_verify(sql);
}

// ───────────────────── GRANT-to-PUBLIC parity ─────────────────────

#[test]
fn test_grant_bare_object_to_public_flagged() {
    // Redshift/PG bare-object GRANT (no TABLE keyword) must fire GRT-TO-PUBLIC.
    let ids = rs_rule_ids("GRANT SELECT ON sales TO PUBLIC;");
    assert!(ids.contains(&"GRT-TO-PUBLIC".to_string()), "ids={:?}", ids);
}

#[test]
fn test_grant_bare_object_all_priv_flagged() {
    let ids = rs_rule_ids("GRANT ALL ON sales TO bob;");
    assert!(ids.contains(&"GRT-ALL-PRIV".to_string()), "ids={:?}", ids);
}

// ───────────── Redshift physical-attribute governance ─────────────

#[test]
fn test_rs_diststyle_all_fires() {
    let ids = rs_rule_ids("CREATE TABLE dim (a INT) DISTSTYLE ALL;");
    assert!(ids.contains(&"RS-DIST-ALL".to_string()), "ids={:?}", ids);
    // Silent on DISTSTYLE KEY / EVEN.
    let ids = rs_rule_ids("CREATE TABLE f (a INT) DISTSTYLE KEY DISTKEY(a) SORTKEY(a);");
    assert!(!ids.contains(&"RS-DIST-ALL".to_string()), "ids={:?}", ids);
}

#[test]
fn test_rs_backup_no_fires() {
    let ids = rs_rule_ids("CREATE TABLE staging (a INT) BACKUP NO DISTKEY(a);");
    assert!(ids.contains(&"RS-BACKUP-NO".to_string()), "ids={:?}", ids);
    // Silent on BACKUP YES.
    let ids = rs_rule_ids("CREATE TABLE t (a INT) BACKUP YES;");
    assert!(!ids.contains(&"RS-BACKUP-NO".to_string()), "ids={:?}", ids);
}

#[test]
fn test_rs_sortkey_interleaved_fires() {
    let ids = rs_rule_ids("CREATE TABLE t (a INT, b INT) INTERLEAVED SORTKEY (a, b);");
    assert!(
        ids.contains(&"RS-SORTKEY-INTERLEAVED".to_string()),
        "ids={:?}",
        ids
    );
    // Silent on COMPOUND / bare SORTKEY.
    let ids = rs_rule_ids("CREATE TABLE t (a INT, b INT) COMPOUND SORTKEY (a, b);");
    assert!(
        !ids.contains(&"RS-SORTKEY-INTERLEAVED".to_string()),
        "ids={:?}",
        ids
    );
}

// ───────────────────────────── Spectrum ─────────────────────────────

#[test]
fn test_spectrum_external_schema_data_catalog_parses() {
    use lexega_core::ast::AstExternalSchemaSource;
    let sql = "CREATE EXTERNAL SCHEMA spectrum_schema FROM DATA CATALOG DATABASE 'spectrumdb' \
               IAM_ROLE 'arn:aws:iam::123456789012:role/myRole' CREATE EXTERNAL DATABASE IF NOT EXISTS;";
    assert_no_opaque(sql);
    format_and_verify(sql);

    let script = parse_sql_with_dialect(sql, redshift().as_ref()).expect("parse");
    match &script.stmts[0] {
        AstStmt::CreateExternalSchema(s) => {
            assert_eq!(s.source_kind, AstExternalSchemaSource::DataCatalog);
            assert!(s.iam_role_span.is_some(), "iam_role captured");
            assert!(
                s.database_literal_span.is_some(),
                "database literal captured"
            );
            assert!(
                s.create_external_database_span.is_some(),
                "trailing CREATE EXTERNAL DATABASE consumed into the same statement"
            );
        }
        other => panic!("expected CreateExternalSchema, got {:?}", other),
    }
    // Exactly one statement — the trailing CREATE EXTERNAL DATABASE was NOT
    // re-parsed as a second statement.
    assert_eq!(script.stmts.len(), 1, "single statement");
}

#[test]
fn test_spectrum_external_schema_hive_metastore_parses() {
    use lexega_core::ast::AstExternalSchemaSource;
    let sql = "CREATE EXTERNAL SCHEMA hive_schema FROM HIVE METASTORE DATABASE 'hivedb' \
               URI 'host.example.com' PORT 9083 IAM_ROLE 'arn:aws:iam::123456789012:role/myRole';";
    assert_no_opaque(sql);
    format_and_verify(sql);
    let script = parse_sql_with_dialect(sql, redshift().as_ref()).expect("parse");
    match &script.stmts[0] {
        AstStmt::CreateExternalSchema(s) => {
            assert_eq!(s.source_kind, AstExternalSchemaSource::HiveMetastore);
            assert!(s.uri_span.is_some(), "uri captured");
            assert!(s.port_span.is_some(), "port captured");
        }
        other => panic!("expected CreateExternalSchema, got {:?}", other),
    }
}

#[test]
fn test_spectrum_external_table_stored_as_parses() {
    let sql = "CREATE EXTERNAL TABLE spectrum_schema.sales (id INT, amt DECIMAL(18,2)) \
               STORED AS PARQUET LOCATION 's3://bucket/sales/';";
    assert_no_opaque(sql);
    format_and_verify(sql);
    let script = parse_sql_with_dialect(sql, redshift().as_ref()).expect("parse");
    match &script.stmts[0] {
        AstStmt::CreateExternalTable(s) => {
            assert!(s.schema_span.is_some(), "column list captured");
            assert!(s.stored_as_span.is_some(), "STORED AS captured");
            assert!(s.location_span.is_some(), "bare LOCATION captured (no '=')");
        }
        other => panic!("expected CreateExternalTable, got {:?}", other),
    }
}

#[test]
fn test_spectrum_external_table_row_format_parses() {
    // ROW FORMAT must NOT misroute to the Snowflake ROW ACCESS POLICY path.
    let sql = "CREATE EXTERNAL TABLE spectrum_schema.logs (line VARCHAR(4000)) \
               ROW FORMAT DELIMITED FIELDS TERMINATED BY '\\t' STORED AS TEXTFILE LOCATION 's3://bucket/logs/';";
    assert_no_opaque(sql);
    format_and_verify(sql);
    let script = parse_sql_with_dialect(sql, redshift().as_ref()).expect("parse");
    match &script.stmts[0] {
        AstStmt::CreateExternalTable(s) => {
            assert!(s.row_format_span.is_some(), "ROW FORMAT captured");
            assert!(s.stored_as_span.is_some(), "STORED AS captured");
            assert!(s.location_span.is_some(), "LOCATION captured");
            assert!(
                s.row_access_policy_span.is_none(),
                "ROW FORMAT must not be parsed as ROW ACCESS POLICY"
            );
        }
        other => panic!("expected CreateExternalTable, got {:?}", other),
    }
}

#[test]
fn test_spectrum_external_schema_fires_extdata_new() {
    let ids = rs_rule_ids(
        "CREATE EXTERNAL SCHEMA sc FROM DATA CATALOG DATABASE 'db' \
         IAM_ROLE 'arn:aws:iam::123456789012:role/myRole';",
    );
    assert!(
        ids.contains(&"SPECTRUM-EXTDATA-NEW".to_string()),
        "ids={:?}",
        ids
    );
    // A plain internal schema is not an external data source — must stay silent.
    let internal = rs_rule_ids("CREATE SCHEMA reporting;");
    assert!(
        !internal.contains(&"SPECTRUM-EXTDATA-NEW".to_string()),
        "internal CREATE SCHEMA must not fire SPECTRUM-EXTDATA-NEW; ids={:?}",
        internal
    );
}

#[test]
fn test_spectrum_external_table_s3_fires_extstore() {
    let ids = rs_rule_ids(
        "CREATE EXTERNAL TABLE s.t (id INT) STORED AS PARQUET LOCATION 's3://bucket/p/';",
    );
    assert!(
        ids.contains(&"BQ-EXTTBL-EXTSTORE".to_string()),
        "S3 LOCATION should fire external-storage signal; ids={:?}",
        ids
    );
}

#[test]
fn test_spectrum_clean_arn_no_credential_leak() {
    // A clean IAM role ARN is a reference, NOT a hardcoded secret — no leak.
    let ids = rs_rule_ids(
        "CREATE EXTERNAL SCHEMA sc FROM DATA CATALOG DATABASE 'db' \
         IAM_ROLE 'arn:aws:iam::123456789012:role/myRole';",
    );
    for leak in [
        "BQ-EXTTBL-AWS-LEAK",
        "BQ-EXTTBL-PWD-LEAK",
        "BQ-EXTTBL-APIKEY-LEAK",
        "BQ-EXTTBL-CONNSTR-LEAK",
    ] {
        assert!(
            !ids.contains(&leak.to_string()),
            "clean arn must not fire {}; ids={:?}",
            leak,
            ids
        );
    }
}

#[test]
fn test_spectrum_embedded_key_fires_leak() {
    // An AKIA literal embedded where a role is expected IS a hardcoded key.
    let ids = rs_rule_ids(
        "CREATE EXTERNAL TABLE s.t (id INT) STORED AS PARQUET LOCATION 's3://b/p/' \
         IAM_ROLE 'AKIAIOSFODNN7EXAMPLE';",
    );
    assert!(
        ids.contains(&"BQ-EXTTBL-AWS-LEAK".to_string()),
        "embedded AKIA key should fire AWS-LEAK; ids={:?}",
        ids
    );
}

// ───────────────────────────── Datashare ─────────────────────────────

#[test]
fn test_datashare_create_parses() {
    let sql = "CREATE DATASHARE ds1;";
    assert_no_opaque(sql);
    format_and_verify(sql);
    let script = parse_sql_with_dialect(sql, redshift().as_ref()).expect("parse");
    assert!(matches!(script.stmts[0], AstStmt::CreateDatashare(_)));
}

#[test]
fn test_datashare_alter_add_table_parses() {
    use lexega_core::ast::{AstAlterDatashareActionKind, AstDatashareObjectKind};
    let sql = "ALTER DATASHARE ds1 ADD TABLE public.t1;";
    assert_no_opaque(sql);
    format_and_verify(sql);
    let script = parse_sql_with_dialect(sql, redshift().as_ref()).expect("parse");
    match &script.stmts[0] {
        AstStmt::AlterDatashare(s) => match &s.action.kind {
            AstAlterDatashareActionKind::AddObject { object_kind, .. } => {
                assert_eq!(*object_kind, AstDatashareObjectKind::Table);
            }
            other => panic!("expected AddObject(Table), got {:?}", other),
        },
        other => panic!("expected AlterDatashare, got {:?}", other),
    }
}

#[test]
fn test_datashare_alter_add_schema_and_set_parse() {
    for sql in [
        "ALTER DATASHARE ds1 ADD SCHEMA public;",
        "ALTER DATASHARE ds1 SET PUBLICACCESSIBLE TRUE;",
        "ALTER DATASHARE ds1 SET INCLUDENEW = TRUE FOR SCHEMA public;",
        "ALTER DATASHARE ds1 REMOVE TABLE public.t1;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_datashare_create_fires_new() {
    let ids = rs_rule_ids("CREATE DATASHARE ds1;");
    assert!(
        ids.contains(&"RS-DATASHARE-NEW".to_string()),
        "ids={:?}",
        ids
    );
    // ALTER DATASHARE is not a creation — must not fire the NEW rule.
    let altered = rs_rule_ids("ALTER DATASHARE ds1 ADD TABLE public.t1;");
    assert!(
        !altered.contains(&"RS-DATASHARE-NEW".to_string()),
        "ALTER must not fire RS-DATASHARE-NEW; ids={:?}",
        altered
    );
}

#[test]
fn test_datashare_publicaccessible_fires_critical() {
    let ids = rs_rule_ids("ALTER DATASHARE ds1 SET PUBLICACCESSIBLE TRUE;");
    assert!(
        ids.contains(&"RS-DATASHARE-PUBLIC".to_string()),
        "ids={:?}",
        ids
    );
    // Also fires on the CREATE form's inline SET.
    let ids = rs_rule_ids("CREATE DATASHARE ds1 SET PUBLICACCESSIBLE TRUE;");
    assert!(
        ids.contains(&"RS-DATASHARE-PUBLIC".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn test_datashare_publicaccessible_false_silent() {
    // Explicitly making it private must NOT fire the public-exposure rule.
    let ids = rs_rule_ids("ALTER DATASHARE ds1 SET PUBLICACCESSIBLE FALSE;");
    assert!(
        !ids.contains(&"RS-DATASHARE-PUBLIC".to_string()),
        "PUBLICACCESSIBLE FALSE must stay silent; ids={:?}",
        ids
    );
}

#[test]
fn test_datashare_add_object_fires() {
    let ids = rs_rule_ids("ALTER DATASHARE ds1 ADD TABLE public.t1;");
    assert!(
        ids.contains(&"RS-DATASHARE-OBJ-ADD".to_string()),
        "ids={:?}",
        ids
    );
    // REMOVE must not fire the ADD rule.
    let ids = rs_rule_ids("ALTER DATASHARE ds1 REMOVE TABLE public.t1;");
    assert!(
        !ids.contains(&"RS-DATASHARE-OBJ-ADD".to_string()),
        "REMOVE must not fire OBJ-ADD; ids={:?}",
        ids
    );
}

#[test]
fn test_datashare_includenew_fires() {
    let ids = rs_rule_ids("ALTER DATASHARE ds1 SET INCLUDENEW = TRUE FOR SCHEMA public;");
    assert!(
        ids.contains(&"RS-DATASHARE-INCLUDENEW".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn test_datashare_includenew_false_silent() {
    // Disabling auto-inclusion (`INCLUDENEW = FALSE`) is the safe direction and
    // must NOT fire the implicit-sharing rule.
    let ids = rs_rule_ids("ALTER DATASHARE ds1 SET INCLUDENEW = FALSE FOR SCHEMA public;");
    assert!(
        !ids.contains(&"RS-DATASHARE-INCLUDENEW".to_string()),
        "INCLUDENEW = FALSE must stay silent; ids={:?}",
        ids
    );
}

#[test]
fn test_datashare_multi_statement_no_collision() {
    // Distinct datashares back-to-back — guards against NodeId/span collision.
    let sql =
        "CREATE DATASHARE ds1;\nCREATE DATASHARE ds2;\nALTER DATASHARE ds1 ADD TABLE public.t1;";
    assert_no_opaque(sql);
    format_and_verify(sql);
    let script = parse_sql_with_dialect(sql, redshift().as_ref()).expect("parse");
    assert_eq!(script.stmts.len(), 3, "three distinct statements");
}

// ── SELECT-expression nuances (SIMILAR TO / APPROXIMATE / TRIM / SUBSTRING) ──

#[test]
fn test_similar_to_predicate() {
    // SIMILAR TO must parse as a typed predicate via the main Pratt entry-point
    // and round-trip exactly.
    let sql = "SELECT name FROM t WHERE code SIMILAR TO '[0-9]+';";
    assert_no_opaque(sql);
    let out = format_and_verify(sql);
    assert!(out.contains("SIMILAR TO '[0-9]+'"), "got:\n{out}");
}

#[test]
fn test_approximate_count_distinct() {
    // Redshift APPROXIMATE modifier precedes the aggregate function name.
    let sql = "SELECT APPROXIMATE COUNT(DISTINCT user_id) FROM events;";
    assert_no_opaque(sql);
    let out = format_and_verify(sql);
    assert!(
        out.contains("APPROXIMATE COUNT(DISTINCT user_id)"),
        "got:\n{out}"
    );
}

#[test]
fn test_approximate_percentile_within_group() {
    let sql = "SELECT APPROXIMATE PERCENTILE_DISC(0.5) WITHIN GROUP (ORDER BY x) FROM t;";
    assert_no_opaque(sql);
    let out = format_and_verify(sql);
    assert!(
        out.contains("APPROXIMATE PERCENTILE_DISC(0.5)"),
        "got:\n{out}"
    );
}

#[test]
fn test_approximate_over_window() {
    // Postfix OVER converts the call into a WindowFn; APPROXIMATE must survive.
    let sql = "SELECT APPROXIMATE COUNT(DISTINCT user_id) OVER (PARTITION BY region) FROM events;";
    assert_no_opaque(sql);
    let out = format_and_verify(sql);
    assert!(
        out.contains("APPROXIMATE COUNT(DISTINCT user_id)"),
        "got:\n{out}"
    );
}

#[test]
fn test_trim_ansi_forms() {
    for sql in [
        "SELECT TRIM(BOTH 'x' FROM name) FROM t;",
        "SELECT TRIM(LEADING FROM name) FROM t;",
        "SELECT TRIM(TRAILING ' ' FROM name) FROM t;",
        "SELECT TRIM('xyz' FROM name) FROM t;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_trim_ansi_roundtrip_exact() {
    // Typed Trim node must reproduce spec keyword, chars, and FROM byte-exact.
    let sql = "SELECT TRIM(BOTH 'x' FROM name) FROM t;";
    let out = format_and_verify(sql);
    assert!(out.contains("TRIM(BOTH 'x' FROM name)"), "got:\n{out}");
}

#[test]
fn test_trim_comma_form_stays_function_call() {
    // Comma form has no FROM separator — must fall back to a plain call.
    for sql in [
        "SELECT TRIM(name) FROM t;",
        "SELECT TRIM(name, 'x') FROM t;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_substring_ansi_forms() {
    for sql in [
        "SELECT SUBSTRING(name FROM 2 FOR 3) FROM t;",
        "SELECT SUBSTRING(name FROM 2) FROM t;",
        "SELECT SUBSTRING(name FOR 3) FROM t;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_substring_ansi_roundtrip_exact() {
    let sql = "SELECT SUBSTRING(name FROM 2 FOR 3) FROM t;";
    let out = format_and_verify(sql);
    assert!(out.contains("SUBSTRING(name FROM 2 FOR 3)"), "got:\n{out}");
}

#[test]
fn test_substring_comma_form_stays_function_call() {
    for sql in [
        "SELECT SUBSTRING(name, 2, 3) FROM t;",
        "SELECT SUBSTRING(name) FROM t;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_trim_substring_nested_and_composed() {
    // Nested typed nodes + use inside WHERE / wrapping calls.
    let sql =
        "SELECT UPPER(TRIM(LEADING '0' FROM code)) FROM t WHERE SUBSTRING(code FROM 1 FOR 1) = 'A';";
    assert_no_opaque(sql);
    format_and_verify(sql);
    let nested = "SELECT SUBSTRING(TRIM(name) FROM 1 FOR 4) FROM t;";
    assert_no_opaque(nested);
    format_and_verify(nested);
}

#[test]
fn test_select_nuances_lower_through_ir() {
    // Exercise the IR lowering arms (Trim/Substring → FuncCall, APPROXIMATE →
    // AggregateCall.approximate) end-to-end through the analyzer — must not panic.
    for sql in [
        "SELECT APPROXIMATE COUNT(DISTINCT user_id) FROM events;",
        "SELECT TRIM(BOTH 'x' FROM name) FROM t;",
        "SELECT SUBSTRING(name FROM 2 FOR 3) FROM t;",
        "SELECT name FROM t WHERE code SIMILAR TO '[0-9]+';",
    ] {
        let _ = rs_rule_ids(sql);
    }
}

// ── Projection-level trailing EXCLUDE clause (Redshift) ──────────────────────

#[test]
fn test_projection_exclude_trailing_clause() {
    // Redshift `EXCLUDE (cols)` trails the whole projection list — distinct from
    // the BigQuery/Snowflake star-attached form. The exclude follows a non-star
    // item, so it cannot be glued to the `*`.
    for sql in [
        "SELECT *, NULL AS example EXCLUDE (col1, col2) FROM table1;",
        "SELECT t.*, x EXCLUDE (a, b) FROM t;",
        "SELECT *, col_a, col_b EXCLUDE (col_a) FROM t;",
        "SELECT * EXCLUDE (a) FROM t;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_projection_exclude_roundtrip_preserves_clause() {
    let sql = "SELECT *, NULL AS example EXCLUDE (col1, col2) FROM table1;";
    let out = format_and_verify(sql);
    assert!(out.contains("EXCLUDE (col1"), "got:\n{out}");
}

#[test]
fn test_exclude_as_plain_alias_still_parses() {
    // `exclude` not followed by `(` is still a legal bare column alias — the
    // trailing-clause disambiguation only fires on `EXCLUDE (`.
    let sql = "SELECT a exclude FROM t;";
    assert_no_opaque(sql);
    format_and_verify(sql);
}

#[test]
fn test_except_remains_set_operator_not_exclude() {
    // The trailing hook is gated to EXCLUDE; a trailing EXCEPT stays the set
    // operator (Redshift `except_is_star_modifier()` is false).
    for sql in [
        "SELECT a, b FROM t1 EXCEPT SELECT a, b FROM t2;",
        "SELECT a FROM t1 EXCEPT ALL SELECT a FROM t2;",
    ] {
        assert_no_opaque(sql);
        format_and_verify(sql);
    }
}

#[test]
fn test_projection_exclude_is_dialect_gated() {
    use lexega_core::dialect::postgres;
    let sql = "SELECT *, x EXCLUDE (a) FROM t;";
    // Redshift supports the clause → parses concretely.
    assert_no_opaque(sql);
    // A dialect without the clause must NOT reinterpret a trailing EXCLUDE as an
    // exclusion clause; `EXCLUDE` is a bare alias and the `(` is then invalid,
    // so the statement falls back to OpaqueContent rather than mis-parsing.
    let script = parse_sql_with_dialect(sql, postgres().as_ref()).expect("returns a script");
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "PostgreSQL must not parse the Redshift trailing EXCLUDE clause"
    );
}
