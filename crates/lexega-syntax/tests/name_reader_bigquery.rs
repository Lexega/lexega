// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shapes BigQuery names are written in, each read whole as the name it is.

mod name_shapes;

use lexega_syntax::dialect;
use name_shapes::reads_whole;

#[test]
fn bigquery_drop_table_function_function_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "DROP TABLE FUNCTION «my-proj.s1.tvf_orders»;",
            "DROP TABLE FUNCTION «my-proj.stage.tvf_orders»;",
        ],
    );
}

#[test]
fn bigquery_export_data_with_connection_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "EXPORT DATA WITH CONNECTION my-proj.s1.conn_us OPTIONS (uri = 'gs://b/*.csv', format = 'CSV') AS SELECT 1;",
            "EXPORT DATA WITH CONNECTION my-proj.stage.conn_us OPTIONS (uri = 'gs://b/*.csv', format = 'CSV') AS SELECT 1;",
        ],
    );
}

#[test]
fn bigquery_create_function_function_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CREATE FUNCTION «my-proj.s1.f_clean»(x STRING) RETURNS STRING AS (TRIM(x));",
            "CREATE FUNCTION «my-proj.stage.f_clean»(x STRING) RETURNS STRING AS (TRIM(x));",
        ],
    );
}

#[test]
fn bigquery_load_data_into_table() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "LOAD DATA INTO «my-proj.s1.orders» FROM FILES (format = 'CSV', uris = ['gs://b/x.csv']);",
            "LOAD DATA INTO «my-proj.stage.orders» FROM FILES (format = 'CSV', uris = ['gs://b/x.csv']);",
        ],
    );
}

#[test]
fn bigquery_create_model_model_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CREATE MODEL «my-proj.s1.m_churn» OPTIONS (model_type = 'linear_reg') AS SELECT 1 AS label;",
            "CREATE MODEL «my-proj.stage.m_churn» OPTIONS (model_type = 'linear_reg') AS SELECT 1 AS label;",
        ],
    );
}

#[test]
fn bigquery_drop_row_access_policy_on_table() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "DROP ROW ACCESS POLICY rap_us ON «my-proj.s1.orders»;",
            "DROP ROW ACCESS POLICY rap_us ON «my-proj.stage.orders»;",
        ],
    );
}

#[test]
fn bigquery_drop_all_row_access_policies_on_table() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "DROP ALL ROW ACCESS POLICIES ON «my-proj.s1.orders»;",
            "DROP ALL ROW ACCESS POLICIES ON «my-proj.stage.orders»;",
        ],
    );
}

#[test]
fn bigquery_create_row_access_policy_on_table() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CREATE ROW ACCESS POLICY rap_us ON «my-proj.s1.orders» GRANT TO ('user:a@example.com') FILTER USING (region = 'US');",
            "CREATE ROW ACCESS POLICY rap_us ON «my-proj.stage.orders» GRANT TO ('user:a@example.com') FILTER USING (region = 'US');",
        ],
    );
}

#[test]
fn bigquery_create_search_index_on_table() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CREATE SEARCH INDEX idx_s ON «my-proj.s1.orders» (ALL COLUMNS);",
            "CREATE SEARCH INDEX idx_s ON «my-proj.stage.orders» (ALL COLUMNS);",
        ],
    );
}

#[test]
fn bigquery_create_snapshot_table_snapshot_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CREATE SNAPSHOT TABLE «my-proj.s1.orders_snap» CLONE ds.orders;",
            "CREATE SNAPSHOT TABLE «my-proj.stage.orders_snap» CLONE ds.orders;",
        ],
    );
}

#[test]
fn bigquery_create_table_function_function_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CREATE TABLE FUNCTION «my-proj.s1.tvf_orders»(x INT64) AS SELECT x AS id;",
            "CREATE TABLE FUNCTION «my-proj.stage.tvf_orders»(x INT64) AS SELECT x AS id;",
        ],
    );
}

#[test]
fn bigquery_create_vector_index_on_table() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "CREATE VECTOR INDEX idx_v ON «my-proj.s1.orders» (embedding) OPTIONS (index_type = 'IVF');",
            "CREATE VECTOR INDEX idx_v ON «my-proj.stage.orders» (embedding) OPTIONS (index_type = 'IVF');",
        ],
    );
}

#[test]
fn bigquery_delete_without_from_and_a_region_qualified_name() {
    reads_whole(
        &dialect::bigquery(),
        &[
            "DELETE «my-proj.ds.t» WHERE TRUE;",
            "DELETE «ds.t» t WHERE t.id = 1;",
            "SELECT * FROM «my-proj.region-us.INFORMATION_SCHEMA.JOBS»;",
            "SELECT * FROM «region-europe-west2.INFORMATION_SCHEMA.JOBS»;",
        ],
    );
}
