// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! PostgreSQL `CREATE MATERIALIZED VIEW … WITH [NO] DATA`.
//!
//! The trailing `WITH DATA` / `WITH NO DATA` clause belongs to the statement:
//! the realistic forms must parse as a single, analyzed statement and
//! round-trip byte-exact.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn check(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::postgres();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let report = analyze_risk_with_policy_config(
        sql,
        &AnalysisConfig {
            dialect: Some(dialect::postgres()),
            ..Default::default()
        },
    )
    .expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "WITH [NO] DATA must not orphan into a skipped statement: {sql}"
    );
}

#[test]
fn test_matview_with_no_data() {
    check("CREATE MATERIALIZED VIEW mv AS SELECT * FROM t WITH NO DATA;");
}

#[test]
fn test_matview_with_data() {
    check("CREATE MATERIALIZED VIEW mv AS SELECT * FROM t WITH DATA;");
}

#[test]
fn test_matview_if_not_exists_with_no_data() {
    check("CREATE MATERIALIZED VIEW IF NOT EXISTS mv AS SELECT a FROM t WHERE a > 0 WITH NO DATA;");
}

#[test]
fn test_matview_without_data_clause_unaffected() {
    check("CREATE MATERIALIZED VIEW mv AS SELECT * FROM t;");
}
