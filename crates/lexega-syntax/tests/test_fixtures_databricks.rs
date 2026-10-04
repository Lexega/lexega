// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Fixture-based Databricks regression tests.
//! Covers CREATE FUNCTION ... RETURN and ALTER TABLE row filter / column mask.

use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe, DatabricksDialect,
    FormatterConfig,
};
use std::fs;

#[test]
fn test_databricks_row_filter_mask_fixture() {
    let sql = fs::read_to_string("tests/fixtures/test_databricks_row_filter_mask_function.sql")
        .expect("failed to read test_databricks_row_filter_mask_function.sql");

    let dialect = DatabricksDialect;
    let parsed = parse_sql_with_dialect(&sql, &dialect);
    assert!(
        parsed.is_ok(),
        "Databricks fixture should parse successfully: {:?}",
        parsed.err()
    );

    let cfg = FormatterConfig {
        dialect: lexega_syntax::dialect::databricks(),
        ..Default::default()
    };
    let formatted =
        format_sql_with_config(&sql, &cfg).expect("Databricks fixture should format successfully");

    verify_formatting_safe(&sql, &formatted).expect("Databricks fixture formatting should be safe");
}
