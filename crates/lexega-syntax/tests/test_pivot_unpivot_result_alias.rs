// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! PIVOT / UNPIVOT result-alias column lists must format byte-exact.
//!
//! In `… PIVOT (…) AS p (c1, c2)` the alias list's closing `)` is emitted
//! exactly once; a second one would trip the formatter's token-preservation
//! check. Guard the round-trip here.

use lexega_syntax::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn roundtrip(sql: &str, d: dialect::DialectRef) {
    let mut config = FormatterConfig::default();
    config.dialect = d;
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens (no stray paren)");
}

#[test]
fn test_pivot_result_alias_columns_snowflake() {
    roundtrip(
        "SELECT * FROM t PIVOT (SUM(x) FOR y IN ('a')) AS p (col1, col2)",
        dialect::snowflake(),
    );
    roundtrip(
        "SELECT * FROM t PIVOT (SUM(amt) FOR mon IN ('jan', 'feb')) AS p (a, b, c)",
        dialect::snowflake(),
    );
}

#[test]
fn test_pivot_result_alias_columns_mssql() {
    roundtrip(
        "SELECT * FROM t PIVOT (SUM(amt) FOR mon IN ([jan], [feb])) AS p (a, b)",
        dialect::mssql(),
    );
}

#[test]
fn test_unpivot_result_alias_columns() {
    roundtrip(
        "SELECT * FROM t UNPIVOT (val FOR name IN (a, b)) AS u (n, v)",
        dialect::snowflake(),
    );
}

#[test]
fn test_pivot_no_alias_columns_still_ok() {
    // Regression guard for the unchanged path (no result-alias column list).
    roundtrip(
        "SELECT * FROM t PIVOT (SUM(x) FOR y IN ('a')) AS p",
        dialect::snowflake(),
    );
}
