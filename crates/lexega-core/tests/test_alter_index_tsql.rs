// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL Server ALTER INDEX maintenance forms.
//!
//! `ALTER INDEX { name | ALL } ON <table> { REBUILD | REORGANIZE | DISABLE |
//! SET (…) }` (with optional PARTITION / WITH options) must be recognised
//! (not skipped) and round-trip byte-exact, alongside the PostgreSQL ALTER
//! INDEX forms.

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn check(sql: &str, d: dialect::DialectRef) {
    let mut config = FormatterConfig::default();
    config.dialect = d.clone();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

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
fn test_alter_index_rebuild() {
    check("ALTER INDEX ix ON dbo.t REBUILD;", dialect::mssql());
    check(
        "ALTER INDEX ix ON dbo.t REBUILD WITH (ONLINE = ON);",
        dialect::mssql(),
    );
    check(
        "ALTER INDEX ix ON t REBUILD PARTITION = 3 WITH (DATA_COMPRESSION = PAGE);",
        dialect::mssql(),
    );
}

#[test]
fn test_alter_index_reorganize() {
    check("ALTER INDEX ix ON t REORGANIZE;", dialect::mssql());
    check(
        "ALTER INDEX ix ON t REORGANIZE WITH (LOB_COMPACTION = ON);",
        dialect::mssql(),
    );
}

#[test]
fn test_alter_index_disable() {
    check("ALTER INDEX ix ON t DISABLE;", dialect::mssql());
}

#[test]
fn test_alter_index_all_and_set() {
    check("ALTER INDEX ALL ON t REORGANIZE;", dialect::mssql());
    check("ALTER INDEX ALL ON dbo.t REBUILD;", dialect::mssql());
    check(
        "ALTER INDEX ix ON t SET (ALLOW_PAGE_LOCKS = ON);",
        dialect::mssql(),
    );
}

#[test]
fn test_pg_alter_index_unaffected() {
    check("ALTER INDEX ix RENAME TO ix2;", dialect::postgres());
    check(
        "ALTER INDEX IF EXISTS ix SET TABLESPACE ts;",
        dialect::postgres(),
    );
    check(
        "ALTER INDEX ALL IN TABLESPACE old SET TABLESPACE new;",
        dialect::postgres(),
    );
}
