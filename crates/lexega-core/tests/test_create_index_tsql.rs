// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL Server CREATE INDEX with an index type or storage options.
//!
//! `CREATE [UNIQUE] CLUSTERED|NONCLUSTERED|COLUMNSTORE INDEX …`, plus the
//! trailing `WITH (…)` / `ON storage` / `FILESTREAM_ON` tail, must be
//! recognised whole (not skipped, not truncated) and round-trip byte-exact.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn check(sql: &str, d: dialect::DialectRef) {
    // Round-trip byte-exact.
    let mut config = FormatterConfig::default();
    config.dialect = d.clone();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    // Recognized, not skipped as OpaqueContent.
    let report = analyze_risk_with_policy_config(
        sql,
        &AnalysisConfig {
            dialect: Some(d),
            ..Default::default()
        },
    )
    .expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "statement must be analyzed, not skipped: {sql}"
    );
}

#[test]
fn test_nonclustered_index() {
    check(
        "CREATE NONCLUSTERED INDEX ix ON t (a, b);",
        dialect::mssql(),
    );
}

#[test]
fn test_clustered_index() {
    check("CREATE CLUSTERED INDEX ix ON t (a);", dialect::mssql());
}

#[test]
fn test_unique_clustered_index() {
    check(
        "CREATE UNIQUE CLUSTERED INDEX ix ON t (a);",
        dialect::mssql(),
    );
}

#[test]
fn test_clustered_columnstore_no_columns() {
    check(
        "CREATE CLUSTERED COLUMNSTORE INDEX cci ON t;",
        dialect::mssql(),
    );
}

#[test]
fn test_nonclustered_columnstore() {
    check(
        "CREATE NONCLUSTERED COLUMNSTORE INDEX ix ON t (a);",
        dialect::mssql(),
    );
}

#[test]
fn test_index_with_options_and_storage_tail() {
    check(
        "CREATE NONCLUSTERED INDEX ix ON t (a, b) INCLUDE (c, d) WHERE a > 0 WITH (ONLINE = ON, FILLFACTOR = 80);",
        dialect::mssql(),
    );
    check(
        "CREATE NONCLUSTERED INDEX ix ON t (a) WITH (DATA_COMPRESSION = PAGE) ON [PRIMARY] FILESTREAM_ON fsgroup;",
        dialect::mssql(),
    );
}

#[test]
fn test_plain_index_unaffected() {
    // PostgreSQL plain CREATE INDEX (no index-type modifier) — regression guard.
    check("CREATE INDEX ix ON t (a);", dialect::postgres());
    check(
        "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ix ON t USING btree (a) WHERE a > 0;",
        dialect::postgres(),
    );
    // PostgreSQL WITH storage params now captured too.
    check(
        "CREATE INDEX ix ON t (a) WITH (fillfactor = 70);",
        dialect::postgres(),
    );
}
